import asyncio, sys, random, string
from curl_cffi.requests import AsyncSession
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


class tempmail:
    def __init__(self):
        self.url = 'https://www.1secmail.com/api/v1/'
        self.http = AsyncSession()
        self.login, self.domain, self.email = '', '', ''

    async def get_mail(self):
        for _ in range(5):
            try:
                res = await self.http.get(f'{self.url}?action=genRandomMailbox')
                if '@' in res.text:
                    self.email = res.json()[0]
                    self.login, self.domain = self.email.split('@')
                    return True
            except:
                pass
        return False

    async def get_code(self):
        for _ in range(20):
            try:
                res = await self.http.get(f'{self.url}?action=getMessages&login={self.login}&domain={self.domain}')
                if 'lingo' in res.text:
                    mailid = res.json()[0]['id']
                    res = await self.http.get(f'{self.url}?action=readMessage&id={mailid}&login={self.login}&domain={self.domain}')
                    allcode = res.text.split('oobCode=')[1].split('&')[0]
                    return allcode
            except:
                pass
            await asyncio.sleep(3)
        return None


class Lingo:
    def __init__(self, nstproxy_Channel, nstproxy_Password, auth_token):
        self.session = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
        nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_{self.session}:{nstproxy_Password}@gw-us.nstproxy.com:24125"
        self.client = AsyncSession(timeout=120, impersonate="chrome120", proxy=nstproxy)
        self.gclient = AsyncSession(timeout=120, impersonate="chrome120", proxy=nstproxy)
        self.twitter = Twitter(auth_token)
        self.tempmail = tempmail()

    async def login(self):
        try:
            res = await self.client.post('https://lingoislands.com/api/auth/twitter/login')
            if res.status_code == 201:
                oauth_token = res.text.split('oauth_token=')[1].split('"')[0]
                return await self.verify(oauth_token)
            logger.error(f'登录失败')
            return False
        except Exception as e:
            logger.error(f'登录失败 {e}')
            return False

    async def verify(self, oauth_token):
        try:
            if not await self.twitter.twitter_authorize(oauth_token):
                return False
            json_data = {
                "code": self.twitter.oauth_verifier,
                "state": oauth_token,
                "referralCode": "P66HL"
            }
            res = await self.client.post('https://lingoislands.com/api/auth/twitter/verify', json=json_data)
            if res.status_code == 201:
                jwt = res.json()['jwt']
                return await self.getToken(jwt)
            logger.error(f'推特验证失败')
            return False
        except Exception as e:
            logger.error(f'推特验证失败 {e}')
            return False

    async def getToken(self, jwt, follow=True):
        try:
            params = {"key": "AIzaSyCPZDWV7Dg_Oe2Lcy7MHKFm33-FaYTvOwI"}
            json_data = {
                'returnSecureToken': True,
                'token': jwt,
            }
            res = await self.gclient.post('https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken', params=params, json=json_data)
            if res.status_code == 200:
                idToken = res.json()['idToken']
                logger.success(f'获取Token成功')
                self.client.headers['Authorization'] = f'Bearer {idToken}'
                if follow:
                    return await self.follow()
                else:
                    return await self.sendCode(idToken)
            logger.error(f'获取Token失败')
            return False
        except Exception as e:
            logger.error(f'获取Token失败 {e}')
            return False

    async def sendCode(self, idToken):
        try:
            params = {"key": "AIzaSyCPZDWV7Dg_Oe2Lcy7MHKFm33-FaYTvOwI"}
            json_data = {'requestType': 'VERIFY_EMAIL', 'idToken': idToken}
            res = await self.gclient.post('https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode', params=params, json=json_data)
            if res.status_code == 200:
                logger.success(f'[{self.tempmail.email}] 发送验证码成功')
                return await self.updateToken()
            logger.error(f'[{self.tempmail.email}] 发送验证码失败')
            return False
        except Exception as e:
            logger.error(f'[{self.tempmail.email}] 发送验证码失败 {e}')
            return False

    async def follow(self):
        try:
            res = await self.client.post('https://lingoislands.com/api/twitter/follow')
            if res.status_code == 201 and res.json()['success']:
                logger.success(f'关注成功')
                return await self.sendEmail()
            logger.error(f'关注失败')
            return False
        except Exception as e:
            logger.error(f'关注失败 {e}')
            return False

    async def sendEmail(self):
        try:
            if not await self.tempmail.get_mail():
                logger.error(f'获取邮箱失败')
                return False
            json_data = {"email": self.tempmail.email}
            res = await self.client.patch('https://lingoislands.com/api/users/me', json=json_data)
            if res.status_code == 200:
                jwt = res.json()['jwt']
                logger.success(f'邮件{self.tempmail.email}发送成功')
                return await self.getToken(jwt, follow=False)
            logger.error(f'邮件发送失败')
            return False
        except Exception as e:
            logger.error(f'邮件发送失败 {e}')
            return False

    async def updateToken(self):
        try:
            oobCode = await self.tempmail.get_code()
            if not oobCode:
                logger.error(f'获取验证码失败')
                return False
            params = {"key": "AIzaSyCPZDWV7Dg_Oe2Lcy7MHKFm33-FaYTvOwI"}
            json_data = {'oobCode': oobCode}
            res = await self.gclient.post('https://identitytoolkit.googleapis.com/v1/accounts:update', params=params, json=json_data)
            if res.status_code == 200 and res.json()['emailVerified']:
                logger.success(f'绑定邮箱成功')
                return await self.emailVerify()
            logger.error(f'绑定邮箱失败')
            return False
        except Exception as e:
            logger.error(f'绑定邮箱失败 {e}')
            return False

    async def emailVerify(self):
        try:
            res = await self.client.post('https://lingoislands.com/api/users/email/verify')
            if res.status_code == 201:
                logger.success(f'邮件验证成功')
                return await self.mint()
            logger.error(f'邮件验证失败')
            return False
        except Exception as e:
            logger.error(f'邮件验证失败 {e}')
            return False

    async def mint(self):
        try:
            res = await self.client.post('https://lingoislands.com/api/mint/boarding')
            if res.status_code == 201 and res.json()['success']:
                logger.success(f'Mint成功')
                return True
            logger.error(f'Mint失败')
            return False
        except Exception as e:
            logger.error(f'Mint失败 {e}')
            return False


async def main():
    nstproxy_Channel = ''
    nstproxy_Password = ''
    auth_token = ''
    LI = Lingo(nstproxy_Channel, nstproxy_Password, auth_token)
    await LI.login()


if __name__ == '__main__':
    asyncio.run(main())
