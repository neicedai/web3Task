import asyncio, sys, random, string
from curl_cffi.requests import AsyncSession
from loguru import logger

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")


class CF:
    def __init__(self, clientKey):
        self.http = AsyncSession(timeout=120, impersonate="chrome120")
        self.clientKey = clientKey
        self.taskId = None

    async def createTaskcapsolver(self):
        json_data = {
            "clientKey": self.clientKey,
            "appId": "69AE5D43-F131-433D-92C8-0947B2CF150A",
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": 'https://airdrop.tari.com/quests',
                "websiteKey": '0x4AAAAAAAZjcPdX24N10Y-m'
            }
        }
        for _ in range(3):
            try:
                response = await self.http.post('https://api.capsolver.com/createTask', json=json_data)
                if response.json()['errorId'] == 0:
                    self.taskId = response.json()['taskId']

                    return True
            except:
                pass
        return False

    async def capsolver(self):
        if not await self.createTaskcapsolver():
            return None
        json_data = {
            "clientKey": self.clientKey,
            "taskId": self.taskId
        }
        for _ in range(30):
            try:
                response = await self.http.post('https://api.capsolver.com/getTaskResult', json=json_data)
                if response.json()['errorId'] == 0 and response.json()['status'] == 'ready':
                    return response.json()['solution']['token']
                elif response.json()['errorId'] == 1:
                    return None
            except:
                pass
            await asyncio.sleep(3)
        return None


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "twitter.com",
            "origin": "https://x.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120, impersonate="chrome120")
        self.authenticity_token, self.oauth_verifier = None, None

    async def get_twitter_token(self, oauth_token):
        try:
            response = await self.Twitter.get(f'https://api.x.com/oauth/authorize?oauth_token={oauth_token}')
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
                'redirect_after_login': f'https://api.x.com/oauth/authorize?oauth_token={oauth_token}',
                'oauth_token': oauth_token
            }
            response = await self.Twitter.post('https://api.x.com/oauth/authorize', data=data)
            if 'oauth_verifier' in response.text:
                self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
                return True
            return False
        except Exception as e:
            logger.error(e)
            return False


class Tari:
    def __init__(self, nstproxy_Channel, nstproxy_Password, auth_token, cap_clientKey, referralCode):
        self.session = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
        nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_{self.session}:{nstproxy_Password}@gw-us.nstproxy.com:24125"
        self.client = AsyncSession(timeout=120, impersonate="chrome120", proxy=nstproxy)
        self.referralCode = referralCode
        self.twitter = Twitter(auth_token)
        self.CF = CF(cap_clientKey)

    async def login(self):
        try:
            cf_token = await self.CF.capsolver()
            if cf_token is None:
                return False
            params = {
                'quest': 'airdrop',
                'token': cf_token,
                'referralCode': self.referralCode
            }
            res = await self.client.get('https://rwa.y.at/auth/twitter', params=params, allow_redirects=False)
            if res.status_code == 302:
                Location = res.headers['Location'] + '&'
                if 'oauth_token' in Location:
                    oauth_token = Location.split('oauth_token=')[1].split('&')[0]
                    if await self.twitter.twitter_authorize(oauth_token):
                        return await self.twitter_callback(oauth_token)
                return True
            logger.error(f'登录失败')
            return False
        except Exception as e:
            logger.error(f'登录失败 {e}')
            return False

    async def twitter_callback(self, oauth_token):
        try:
            params = {
                'oauth_token': oauth_token,
                'oauth_verifier': self.twitter.oauth_verifier
            }
            res = await self.client.get('https://rwa.y.at/auth/twitter/callback', params=params, allow_redirects=False)
            if res.status_code == 302:
                location = res.headers['Location']
                token = location.split('token=')[1].split('&')[0]
                self.client.headers.update({'Authorization': f'Bearer {token}'})
                return await self.quests()
            logger.error(f'推特回调失败')
            return False
        except Exception as e:
            logger.error(f'推特回调失败 {e}')
            return False

    async def quests(self):
        try:
            res = await self.client.get('https://airdrop.tari.com/api/user/quests')
            if res.status_code == 200:
                for quest in res.json()['quests']:
                    if quest['isActive'] and not quest['fulfilled']:
                        name = quest['name']
                        await self.doTask(name)
                return True
            logger.error(f'获取quests失败')
            return False
        except Exception as e:
            logger.error(f'获取quests失败 {e}')
            return False

    async def doTask(self, questName):
        try:
            res = await self.client.get(f'https://airdrop.tari.com/api/quest/verify/{questName}')
            if res.status_code == 200 and res.json()['success']:
                logger.success(f'完成任务{questName}成功')
                return True
            logger.error(f'完成任务{questName}失败')
            return False
        except Exception as e:
            logger.error(f'完成任务{questName}失败 {e}')
            return False


async def do(semaphore, nstproxy_Channel, nstproxy_Password, auth_token, _capsolver_clientKey, referralCode):
    async with semaphore:
        for _ in range(3):
            if await Tari(nstproxy_Channel, nstproxy_Password, auth_token.strip(), _capsolver_clientKey, referralCode).login():
                break


async def main(file_path, semaphore, nstproxy_Channel, nstproxy_Password, _capsolver_clientKey, referralCode):
    semaphore = asyncio.Semaphore(semaphore)
    with open(file_path, 'r') as f:
        task = [do(semaphore, nstproxy_Channel, nstproxy_Password, account_line, _capsolver_clientKey, referralCode) for account_line in f]
    await asyncio.gather(*task)

if __name__ == '__main__':
    _nstproxy_Channel = input('请输入nstproxy_频道:').strip()
    _nstproxy_Password = input('请输入nstproxy_密码:').strip()
    _capsolver_clientKey = input('请输入capsolver_clientKey:').strip()
    _semaphore = int(input('请输入并发数:').strip())
    _file_path = input('推特auth_token文件:').strip()
    _referralCode = input('请输入推荐码:').strip()
    asyncio.run(main(_file_path, _semaphore, _nstproxy_Channel, _nstproxy_Password, _capsolver_clientKey, _referralCode))
