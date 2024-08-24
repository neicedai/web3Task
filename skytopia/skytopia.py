import asyncio, sys, random, string
from eth_account.messages import encode_defunct
from curl_cffi.requests import AsyncSession
from loguru import logger
from web3 import AsyncWeb3

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
        self.authenticity_token, self.oauth_verifier = None, None

    async def get_twitter_token(self, oauth_token):
        try:
            params = {
                'oauth_token': oauth_token,
                'oauth_callback': 'https://points-api.lavanet.xyz/accounts/twitter/login/callback/'
            }
            response = await self.Twitter.get(f'https://api.twitter.com/oauth/authorize', params=params)
            if 'authenticity_token' in response.text:
                self.authenticity_token = response.text.split('authenticity_token" value="')[1].split('"')[0]
                return True
            logger.error(f'获取authenticity_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self, oauth_token):
        try:
            if not await self.get_twitter_token(oauth_token):
                return False
            data = {
                'authenticity_token': self.authenticity_token,
                'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}',
                'oauth_token': oauth_token
            }
            response = await self.Twitter.post('https://api.twitter.com/oauth/authorize', data=data)
            if 'oauth_verifier' in response.text:
                self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
                return True
            return False
        except Exception as e:
            logger.error(e)
            return False


class Sky:
    def __init__(self, nstproxy_Channel, nstproxy_Password, auth_token, private_key):
        self.session = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
        nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_{self.session}:{nstproxy_Password}@gw-us.nstproxy.com:24125"
        headers = {
            "App": "web",
            "X-App-Id": "7a8hxez99pgvdIroTaDZh9mfON97LO1wldDGVMwEhWsHo",
            "X-App-Key": "3XEhbwprbgf3akD8JplkTxYgx8JUIQT75hOIc9ldd8Wv6"
        }
        self.client = AsyncSession(timeout=120, proxy=nstproxy, impersonate="chrome120", headers=headers)
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://rpc.ankr.com/arbitrum'))
        self.account = self.w3.eth.account.from_key(private_key)
        self.twitter = Twitter(auth_token)

    async def getNonce(self):
        try:
            res = await self.client.get(f'https://backend.skytopia.io/api/v1/web/get_nonce?wallet_address={self.account.address}')
            if res.json()['status']:
                nonce = res.json()['data']['nonce']
                return await self.login(nonce)
            logger.success(f'{self.account.address} 获取token失败')
            return False
        except Exception as e:
            logger.error(f'{self.account.address} 获取token失败: {e}')
            return False

    async def login(self, nonce):
        try:
            signature = self.account.sign_message(encode_defunct(text=nonce)).signature.hex()
            json_data = {
                "wallet_address": self.account.address,
                "signature": signature,
                "nonce": nonce,
                "register_code": ""
            }
            res = await self.client.post('https://backend.skytopia.io/api/v1/common/login_by_wallet', json=json_data)
            if res.json()['status']:
                data = res.json()['data']
                self.client.headers.update({'Authentication': data})
                logger.success(f'{self.account.address} 登录成功')
                return await self.me()
            logger.error(f'{self.account.address} 登录失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.account.address} 登录失败: {e}')
            return False

    async def me(self):
        try:
            res = await self.client.get('https://points-api.lavanet.xyz/api/v4/users/me')
            if 'has_twitter' in res.text:
                user_server_hash = res.json()['user_server_hash']
                self.client.cookies.set('user_server_hash', user_server_hash)
                if not res.json()['has_twitter']:
                    return await self.bind_twitter()
                else:
                    logger.success(f'{self.account.address} 已绑定推特')
                    return True
            logger.error(f'{self.account.address} 获取信息失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.account.address} 获取信息失败: {e}')
            return False

    async def bind_twitter(self):
        try:
            res = await self.client.get('https://points-api.lavanet.xyz/accounts/twitter/login/', allow_redirects=False)
            if res.status_code == 302:
                location = res.headers['Location']
                oauth_token = location.split('oauth_token=')[1].split('&')[0]
                if await self.twitter.twitter_authorize(oauth_token):
                    return await self.callback(oauth_token)
            logger.error(f'{self.account.address} 绑定推特获取oauth_token失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.account.address} 绑定Twitter失败: {e}')
            return False

    async def callback(self, oauth_token):
        try:
            params = {
                'oauth_token': oauth_token,
                'oauth_verifier': self.twitter.oauth_verifier
            }
            res = await self.client.get('https://points-api.lavanet.xyz/accounts/twitter/login/callback/', params=params, allow_redirects=False)
            if res.status_code == 302 and res.headers['Location'] == '/api/v4/ok':
                logger.success(f'{self.account.address} 绑定推特成功')
                return True
            logger.error(f'{self.account.address} 绑定推特回调失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.account.address} 绑定推特回调失败: {e}')
            return False


async def do(semaphore, nstproxy_Channel, nstproxy_Password, account_line):
    async with semaphore:
        for _ in range(3):
            accounts = account_line.strip().split('----')
            if await Lava(nstproxy_Channel, nstproxy_Password, accounts[2].strip(), accounts[1].strip()).get_token():
                break


async def main(file_path, semaphore, nstproxy_Channel, nstproxy_Password):
    semaphore = asyncio.Semaphore(semaphore)
    with open(file_path, 'r') as f:
        task = [do(semaphore, nstproxy_Channel, nstproxy_Password, account_line) for account_line in f]
    await asyncio.gather(*task)


if __name__ == '__main__':
    _nstproxy_Channel = input('请输入nstproxy_频道:').strip()
    _nstproxy_Password = input('请输入nstproxy_密码:').strip()
    _semaphore = int(input('请输入并发数:').strip())
    _file_path = input('地址----私钥----auth_token文件:').strip()
    asyncio.run(main(_file_path, _semaphore, _nstproxy_Channel, _nstproxy_Password))
