import asyncio, sys, random, string
from curl_cffi.requests import AsyncSession
from loguru import logger
from eth_account.messages import encode_defunct
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
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120)
        self.authenticity_token, self.oauth_verifier = None, None

    async def get_twitter_token(self, oauth_token):
        try:
            response = await self.Twitter.get(f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}')
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


class Bridgem:
    def __init__(self, nstproxy_Channel, nstproxy_Password, private_key, auth_token, referralCode):
        self.session = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
        nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_{self.session}:{nstproxy_Password}@gw-us.nstproxy.com:24125"
        self.client = AsyncSession(timeout=120, impersonate="chrome120", proxy=nstproxy)
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://arbitrum.blockpi.network/v1/rpc/public'))
        self.account = self.w3.eth.account.from_key(private_key)
        self.referralCode = referralCode
        self.twitter = Twitter(auth_token)

    async def login(self):
        try:
            sig_msg = f'Welcome to BridgeM:\n{self.account.address}'
            signature = self.account.sign_message(encode_defunct(text=sig_msg)).signature.hex()
            params = {
                'addr': self.account.address,
                'sign': signature,
                'code': self.referralCode
            }
            res = await self.client.get('https://api.bridgem.io/login', params=params)
            if res.status_code == 200 and res.json().get('code') == 200:
                logger.success(f'{[self.account.address]} 登录成功')
                return await self.info()
            logger.error(f'{[self.account.address]} 登录失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.account.address]} 登录失败: {e}')
            return False

    async def info(self):
        try:
            res = await self.client.get('https://api.bridgem.io/info')
            if res.status_code == 200 and res.json().get('code') == 200:
                if res.json().get('data').get('twitter_id') == "":
                    logger.error(f'{[self.account.address]} 未绑定Twitter')
                    return await self.bindTwitter()
                progress = res.json().get('data').get('progress')
                if len(progress) == 0:
                    logger.error(f'{[self.account.address]} 未完成关注任务')
                    await self.follow_twitter()
                elif len(progress) == 1:
                    logger.error(f'{[self.account.address]} 未完成发推任务')
                    await self.post_twitter()
                elif len(progress) == 3:
                    logger.success(f'{[self.account.address]} 全部任务完成')
                    return True
                return False
            logger.error(f'{[self.account.address]} 获取信息失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.account.address]} 获取信息失败: {e}')
            return False

    async def bindTwitter(self):
        try:
            res = await self.client.get('https://api.bridgem.io/oauth_url')
            if res.status_code == 200 and res.json().get('code') == 200:
                oauth_token = res.json().get('data').get('authUrl').split('oauth_token=')[1]
                return await self.bind(oauth_token)
            logger.error(f'{[self.account.address]} 获取oauth_token失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.account.address]} 绑定Twitter失败: {e}')
            return False

    async def bind(self, oauth_token):
        try:
            if not await self.twitter.twitter_authorize(oauth_token):
                return False
            params = {
                'oauth_token': oauth_token,
                'oauth_verifier': self.twitter.oauth_verifier
            }
            res = await self.client.get(f'https://xauth.bridgem.io/callback', params=params, allow_redirects=False)
            if res.status_code == 302 and 'message=success' in res.text:
                return await self.info()
            logger.error(f'{[self.account.address]} 绑定失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.account.address]} 绑定失败: {e}')
            return False

    async def follow_twitter(self):
        try:
            res = await self.client.get('https://api.bridgem.io/follow_twitter')
            if res.status_code == 200 and res.json().get('code') == 200:
                logger.success(f'{[self.account.address]} 关注Twitter成功')
                return await self.info()
            logger.error(f'{[self.account.address]} 关注Twitter失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.account.address]} 关注Twitter失败: {e}')
            return False

    async def post_twitter(self):
        try:
            res = await self.client.get('https://api.bridgem.io/post_twitter')
            if res.status_code == 200 and res.json().get('code') == 200:
                logger.success(f'{[self.account.address]} 发送Twitter成功')
                return await self.info()
            logger.error(f'{[self.account.address]} 发送Twitter失败: {res.text}')
            return False
        except Exception as e:
            logger.error(f'{[self.account.address]} 发送Twitter失败: {e}')
            return False


async def do(semaphore, nstproxy_Channel, nstproxy_Password, account_line, referralCode):
    async with semaphore:
        accounts = account_line.strip().split('----')
        for _ in range(3):
            if await Bridgem(nstproxy_Channel, nstproxy_Password, accounts[1], accounts[2], referralCode).login():
                break


async def main(file_path, semaphore, nstproxy_Channel, nstproxy_Password, referralCode):
    semaphore = asyncio.Semaphore(semaphore)
    with open(file_path, 'r') as f:
        task = [do(semaphore, nstproxy_Channel, nstproxy_Password, account_line, referralCode) for account_line in f]
    await asyncio.gather(*task)


if __name__ == '__main__':
    _nstproxy_Channel = input('请输入nstproxy_频道:').strip()
    _nstproxy_Password = input('请输入nstproxy_密码:').strip()
    _semaphore = int(input('请输入并发数:').strip())
    _file_path = input('地址----私钥----auth_token文件:').strip()
    _referralCode = input('请输入推荐码:').strip()
    asyncio.run(main(_file_path, _semaphore, _nstproxy_Channel, _nstproxy_Password, _referralCode))
