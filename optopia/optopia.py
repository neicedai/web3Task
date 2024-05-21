import asyncio, sys, random, string, time
from curl_cffi.requests import AsyncSession
from eth_account.messages import encode_defunct
from web3 import AsyncWeb3
from loguru import logger

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "twitter.com",
            "origin": "https://twitter.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120, impersonate="chrome120")
        self.auth_code = None

    async def get_auth_code(self, client_id, state, code_challenge):
        try:
            params = {
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'client_id': client_id,
                'redirect_uri': 'https://quest-api.optopia.ai/twitter/callback',
                'response_type': 'code',
                'scope': 'follows.read follows.write tweet.read offline.access users.read',
                'state': state
            }
            response = await self.Twitter.get('https://x.com/i/api/2/oauth2/authorize', params=params)
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
            response = await self.Twitter.post('https://x.com/i/api/2/oauth2/authorize', data=data)
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


class Discord:
    def __init__(self, dc_token):
        self.dc_token = dc_token
        defaulf_headers = {'Authorization': dc_token}
        self.Discord = AsyncSession(headers=defaulf_headers, timeout=120, impersonate="chrome120")
        self.auth_code = None

    async def authorize(self):
        try:
            params = {
                'client_id': '1217364209399107624',
                'response_type': 'code',
                'redirect_uri': 'https://quest-api.optopia.ai/discord/callback',
                'scope': 'identify guilds.join'
            }
            json_data = {
                "guild_id": "1193273961476280451",
                "permissions": "0",
                "authorize": True,
                "integration_type": 0
            }
            res = await self.Discord.post('https://discord.com/api/v9/oauth2/authorize', params=params, json=json_data)
            if res.status_code == 200 and 'location' in res.text:
                location = res.json()['location'] + '&'
                self.auth_code = location.split('code=')[1].split('&')[0]
                return True
            logger.error(f'[{self.dc_token}] 获取Discord授权失败：{res.text}')
            return False
        except Exception as e:
            logger.error(f'[{self.dc_token}] 绑定discord异常：{e}')
            return False


class Optopia:
    def __init__(self, nstChannelID, nstPassword, private_key, auth_token, dc_token):
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://klaytn.api.onfinality.io/public'))
        session = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
        nstproxy = f"http://{nstChannelID}-residential-country_ANY-r_5m-s_{session}:{nstPassword}@gw-us.nstproxy.com:24125"
        self.client = AsyncSession(timeout=120, impersonate="chrome120", proxy=nstproxy)
        self.account = self.w3.eth.account.from_key(private_key)
        self.twitter = Twitter(auth_token)
        self.discord = Discord(dc_token)

    async def login(self):
        try:
            sig_msg = f"Welcome to Optopia.ai!\n\nThis request will not trigger a blockchain transaction or cost any gas fees. It is only used to authorise logging into Optopia.ai.\n\n\nYour authentication status will reset after 2 hours.\n\nWallet address:\n{self.account.address.lower()}\n\nNonce:\n{int(time.time() * 1000) % 100000}"
            signature = self.account.sign_message(encode_defunct(text=sig_msg)).signature.hex()
            msg = bytes(sig_msg, 'utf-8').hex()
            msg = f"0x{msg}"
            json_data = {
                "address": self.account.address.lower(),
                "msg": msg,
                "signed": signature,
                "inviter": "fooyao158",
                "family": "Optopia"
            }
            res = await self.client.post("https://quest-api.optopia.ai/login", json=json_data)
            if res.status_code == 200 and 'token' in res.json():
                token = res.json()['token']
                self.client.headers.update({"Authorization": f"Bearer {token}"})
                logger.success(f"[{self.account.address}] 登录成功")
                return await self.info()
            else:
                logger.error(f"[{self.account.address}] 登录失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 登录失败：{e}")
            return False

    async def info(self, do=False):
        try:
            res = await self.client.get(f'https://quest-api.optopia.ai/user/{self.account.address.lower()}')
            if res.status_code == 200:
                if res.json()['twitter']['id'] is None:
                    await self.bindTwitter()
                if res.json()['discord']['id'] is None:
                    await self.bindDiscord()
                if not res.json()['reTwittered']:
                    await self.reTwittered()
                if res.json()['twitter']['id'] is not None and res.json()['discord']['id'] is not None and res.json()['reTwittered']:
                    logger.success(f"[{self.account.address}] 任务全部成功")
                    return True
                if do:
                    logger.error(f"[{self.account.address}] 任务失败")
                    return False
                return await self.info(True)
            logger.error(f"[{self.account.address}] 获取信息失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 获取信息失败：{e}")
            return False

    async def bindTwitter(self):
        try:
            res = await self.client.get(f'https://quest-api.optopia.ai/twitter/login?address={self.account.address.lower()}', allow_redirects=False)
            if res.status_code == 302:
                location = res.headers['Location'] + '&'
                code_challenge = location.split('code_challenge=')[1].split('&')[0]
                state = location.split('state=')[1].split('&')[0]
                client_id = location.split('client_id=')[1].split('&')[0]
                if await self.twitter.twitter_authorize(client_id, state, code_challenge):
                    logger.success(f"[{self.account.address}] 推特授权成功")
                    return await self.twitterCallback(state)
            logger.error(f"[{self.account.address}] 推特授权失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 推特授权异常：{e}")
            return False

    async def twitterCallback(self, state):
        try:
            params = {
                'state': state,
                'code': self.twitter.auth_code
            }
            res = await self.client.get('https://quest-api.optopia.ai/twitter/callback', params=params, allow_redirects=False)
            if res.status_code == 302:
                return await self.twitterFollow()
            logger.error(f"[{self.account.address}] 推特回调失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 推特回调异常：{e}")
            return False

    async def twitterFollow(self):
        try:
            if await self.twitter.follow():
                logger.success(f"[{self.account.address}] 推特关注成功")
                return await self.checkFollowed()
            logger.error(f"[{self.account.address}] 推特关注失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 推特关注异常：{e}")
            return False

    async def checkFollowed(self):
        try:
            res = await self.client.get(f'https://quest-api.optopia.ai/checkFollowed?targetTwitterName=Optopia_AI')
            if res.status_code == 200:
                if res.json()['followed']:
                    return True
                logger.error(f"[{self.account.address}] 推特未关注")
                return False
            logger.error(f"[{self.account.address}] 获取推特关注状态失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 获取推特关注状态失败：{e}")
            return False

    async def bindDiscord(self):
        try:
            res = await self.client.get(f'https://quest-api.optopia.ai/discord/login?address={self.account.address.lower()}', allow_redirects=False)
            if res.status_code == 302 and await self.discord.authorize():
                logger.success(f"[{self.account.address}] 绑定Discord成功")
                return await self.discordCallback()
            logger.error(f"[{self.account.address}] 绑定Discord失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 绑定Discord异常：{e}")
            return False

    async def discordCallback(self):
        try:
            params = {'code': self.discord.auth_code}
            res = await self.client.get('https://quest-api.optopia.ai/discord/callback', params=params, allow_redirects=False)
            if res.status_code == 302:
                return True
            logger.error(f"[{self.account.address}] Discord回调失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] Discord回调异常：{e}")
            return False

    async def reTwittered(self):
        try:
            res = await self.client.post(f'https://quest-api.optopia.ai/reTwitter')
            if res.status_code == 200 and res.json()['success']:
                return True
            logger.error(f"[{self.account.address}] 推特转推失败")
            return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 推特转推异常：{e}")
            return False


async def do(semaphore, nstChannelID, nstPassword, private_key, auth_token, dc_token):
    async with semaphore:
        for _ in range(3):
            if await Optopia(nstChannelID, nstPassword, private_key, auth_token, dc_token).login():
                break


async def main(filePath, nstChannelID, nstPassword, tread):
    semaphore = asyncio.Semaphore(int(tread))
    task = []
    with open(filePath, 'r') as f:
        for account_line in f:
            account_line = account_line.strip().split('----')
            task.append(do(semaphore, nstChannelID, nstPassword, account_line[1].strip(), account_line[2].strip(), account_line[3].strip()))

    await asyncio.gather(*task)


if __name__ == '__main__':
    print('账户文件格式：地址----私钥----推特auth_token----Discord的token')
    _filePath = input("请输入账户文件路径：").strip()
    _nstChannelID = input("请输入nstproxy通道ID：").strip()
    _nstPassword = input("请输入nstproxy通道密码：").strip()
    _tread = input("请输入并发数：").strip()
    asyncio.run(main(_filePath, _nstChannelID, _nstPassword, _tread))
