import asyncio, sys
import json
import random
import time

from curl_cffi.requests import AsyncSession

from web3 import AsyncWeb3
from loguru import logger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "x.com",
            "origin": "https://x.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120)
        self.auth_code = None

    async def get_auth_code(self, client_id, state, code_challenge):
        try:
            params = {
                'code_challenge': code_challenge,
                'code_challenge_method': 'plain',
                'client_id': client_id,
                'redirect_uri': 'https://nebx.io/login',
                'response_type': 'code',
                'scope': 'tweet.read users.read follows.read',
                'state': state
            }
            response = await self.Twitter.get('https://twitter.com/i/api/2/oauth2/authorize', params=params)
            if "code" in response.json() and response.json()["code"] == 353:
                self.Twitter.headers.update({"x-csrf-token": response.cookies["ct0"]})
                return await self.get_auth_code(client_id, state, code_challenge)
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.get_auth_code(client_id, state, code_challenge)
            elif 'auth_code' in response.json():
                self.auth_code = response.json()['auth_code']
                return True
            logger.error(f'{self.auth_token} 获取auth_code失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self, client_id, state, code_challenge):
        try:
            if not await self.get_auth_code(client_id, state, code_challenge):
                return False
            data = {
                'approval': 'true',
                'code': self.auth_code,
            }
            response = await self.Twitter.post('https://twitter.com/i/api/2/oauth2/authorize', data=data)
            if 'redirect_uri' in response.text:
                return True
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.twitter_authorize(client_id, state, code_challenge)
            logger.error(f'{self.auth_token}  推特授权失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特授权异常：{e}')
            return False

    async def follow(self):
        try:
            data = {
                'include_profile_interstitial_type': 1,
                'include_blocking': 1,
                'include_blocked_by': 1,
                'include_followed_by': 1,
                'include_want_retweets': 1,
                'include_mute_edge': 1,
                'include_can_dm': 1,
                'include_can_media_tag': 1,
                'include_ext_is_blue_verified': 1,
                'include_ext_verified_type': 1,
                'include_ext_profile_image_shape': 1,
                'skip_status': 1,
                'user_id': 1747452081911504896
            }
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            res = await self.Twitter.post('https://x.com/i/api/1.1/friendships/create.json', data=data, headers=headers)
            if res.status_code == 200:
                return True
            logger.error(f'{self.auth_token}  推特关注失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特关注异常：{e}')
            return False


class Nebx:
    def __init__(self, auth_token, inviteCode):
        RPC_list = [
            'https://arbitrum.llamarpc.com', 'https://arb1.arbitrum.io/rpc', 'https://rpc.ankr.com/arbitrum',
            'https://1rpc.io/arb', 'https://arb-pokt.nodies.app', 'https://arbitrum.blockpi.network/v1/rpc/public',
            'https://arbitrum-one.public.blastapi.io', 'https://arb-mainnet-public.unifra.io',
            'https://arbitrum-one-rpc.publicnode.com', 'https://arbitrum.meowrpc.com', 'https://arbitrum.drpc.org'
        ]
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(random.choice(RPC_list)))
        headers = {
            "Authorization": "Bearer cfcd208495d565ef66e7dff9f98764da-8bb56c77b9dded9f82d6b9ccc6dde965-ae26fe5b4ce38925e6f13a7167fed3ea",
            "Origin": "https://nebx.io",
            "Referer": "https://nebx.io/"
        }
        self.client = AsyncSession(timeout=120, headers=headers, impersonate="chrome120")
        self.Twitter = Twitter(auth_token)
        self.auth_token, self.inviteCode = auth_token, inviteCode

    def encode(self, info):
        encodeKey = self.client.headers.get('Authorization').split('-')[0].replace('Bearer ', '')[:16]
        key = encodeKey.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, key)
        padded_text = pad(info.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted).decode('utf-8')

    def decode(self, info):
        decodeKey = self.client.headers.get('Authorization').split('-')[2][:16]
        key = decodeKey.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, key)
        decrypted = unpad(cipher.decrypt(binascii.unhexlify(info)), AES.block_size)
        return decrypted.decode('utf-8')

    async def get_auth_code(self):
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.get(f'https://apiv1.nebx.io/login/xauth_url?sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                clientId = resdata['clientId']
                state = resdata['url'].split('state=')[1].split('&')[0]
                code_challenge = resdata['url'].split('code_challenge=')[1].split('&')[0]
                if await self.Twitter.twitter_authorize(clientId, state, code_challenge):
                    logger.success(f'{self.auth_token}  推特授权成功')
                    return await self.login(uuid, clientId, state)
            logger.error(f'{self.auth_token}  推特授权失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特授权异常：{e}')
            return False

    async def login(self, uuid, clientId, state):
        try:
            info = {
                "state": state,
                "code": self.Twitter.auth_code,
                "clientId": clientId,
                "inviteCode": self.inviteCode,
                "uuid": uuid
            }
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://apiv1.nebx.io/login/sign_in', data=f'sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                if 'token' in resdata:
                    self.client.headers.update({"Authorization": f"Bearer {resdata['token']}"})
                    return await self.check()
            logger.error(f'{self.auth_token}  登录失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  登录异常：{e}')
            return False

    async def check(self):
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://apiv1.nebx.io/user/check', data=f'sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                score = resdata['score']
                logger.success(f'{self.auth_token}  积分{score}')
                return await self.checkA()
            logger.error(f'{self.auth_token}  检测积分失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  登检测积分异常：{e}')
            return False

    async def checkA(self):
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://apiv1.nebx.io/user/check_award', data=f'sign={self.encode(info)}')
            if res.status_code == 200:
                return True
            logger.error(f'{self.auth_token}  领取积分失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  领取积分异常：{e}')
            return False


async def do(semaphore, inviteCode, auth_token):
    async with semaphore:
        for _ in range(3):
            if await Nebx(auth_token, inviteCode).get_auth_code():
                break


async def main(filePath, tread, inviteCode):
    semaphore = asyncio.Semaphore(int(tread))
    with open(filePath, 'r') as f:
        task = [do(semaphore, inviteCode, account_line.strip()) for account_line in f]
    await asyncio.gather(*task)


if __name__ == '__main__':
    print('hdd.cm 推特低至2毛')
    print('hdd.cm 推特低至2毛')
    print('账户文件格式：auth_token一行一个放txt')
    _filePath = input("请输入账户文件路径：").strip()
    _tread = input("请输入并发数：").strip()
    _inviteCode = input("请输入大号邀请码：").strip()
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main(_filePath, _tread, _inviteCode))

