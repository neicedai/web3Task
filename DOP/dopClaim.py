import random
import sys
from eth_account.messages import encode_defunct
from web3 import AsyncWeb3
import asyncio
import httpx
from loguru import logger

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <c>{level}</c> | <level>{message}</level>")


class DOP:
    def __init__(self, private_key):
        RPC = ['https://virginia.rpc.blxrbdn.com', 'https://cloudflare-eth.com', 'https://eth-pokt.nodies.app', 'https://eth.llamarpc.com', 'https://rpc.ankr.com/eth']
        self.web3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(random.choice(RPC)))
        self.http = httpx.AsyncClient(timeout=120, http2=True)
        self.account = self.web3.eth.account.from_key(private_key)
        abi = [
            {
                "inputs": [
                    {"internalType": "uint256", "name": "amountToClaim", "type": "uint256"},
                    {"internalType": "bytes32[]", "name": "merkleProof", "type": "bytes32[]"},
                    {"internalType": "uint256[]", "name": "ids", "type": "uint256[]"},
                    {"internalType": "uint256[]", "name": "quantity", "type": "uint256[]"},
                    {"internalType": "bool", "name": "claimNFT", "type": "bool"},
                    {"internalType": "bool", "name": "isKycRequired", "type": "bool"},
                    {"internalType": "uint8", "name": "v", "type": "uint8"},
                    {"internalType": "bytes32", "name": "r", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "s", "type": "bytes32"}
                ],
                "name": "claimDop",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "", "type": "address"}],
                "name": "isClaimed",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        self.dopClaimsAddress = self.web3.to_checksum_address('0x35f4817b14718C66DBBdBa085F5F8d2c3A4AA420')
        self.dopClaims = self.web3.eth.contract(address=self.dopClaimsAddress, abi=abi)
        self.tx, self.bytes = None, '0x0000000000000000000000000000000000000000000000000000000000000000'

    async def signin(self):
        try:
            msg = f'weareDOPdev{self.account.address.lower()}weareDOPdev'
            sign = self.account.sign_message(encode_defunct(text=msg))
            json_data = {
                "walletAddress": self.account.address.lower(),
                "sign": sign.signature.hex(),
            }
            res = await self.http.post('https://apiclaims.dop.org/auth/signin', json=json_data)
            if 200 == res.status_code:
                accessToken = res.json()['data']['accessToken']
                self.http.headers['Authorization'] = f'Bearer {accessToken}'
                logger.success(f'[{self.account.address}] 登录成功')
                return True
            elif 404 == res.status_code:
                with open("无空投.txt", 'a', encoding='utf-8') as f:
                    f.write(f'{self.account.address}----{self.account.key.hex()[2:]}\n')
                logger.error(f'[{self.account.address}] 无空投')
                return False
            else:
                logger.error(f'[{self.account.address}] 登录失败')
                return False
        except Exception as e:
            logger.error(f'[{self.account.address}] 登录失败 {e}')
            return False

    async def proof(self):
        try:
            if not await self.signin():
                return False
            res = await self.http.get('https://apiclaims.dop.org/claim/proof')
            if 200 == res.status_code:
                amountToClaim = res.json()['data']['proofData']['amount']
                amountToClaim = int(amountToClaim)
                merkleProof = res.json()['data']['merkleProof']
                self.tx = self.dopClaims.functions.claimDop(amountToClaim, merkleProof, [], [], False, False, 0, self.bytes, self.bytes)
                logger.success(f'[{self.account.address}] 获取proof成功')
                return True
            else:
                logger.error(f'[{self.account.address}] 获取proof失败')
                return False
        except Exception as e:
            logger.error(f'[{self.account.address}] 获取proof失败 {e}')
            return False

    async def claim(self):
        try:
            isClaimed = await self.dopClaims.functions.isClaimed(self.account.address).call()
            if isClaimed:
                with open("已领取.txt", 'a', encoding='utf-8') as f:
                    f.write(f'{self.account.address}----{self.account.key.hex()[2:]}\n')
                logger.error(f'[{self.account.address}] 已领取')
                return False
            if not await self.proof():
                return
            nonce = await self.web3.eth.get_transaction_count(self.account.address)
            tx = await self.tx.build_transaction({
                'from': self.account.address,
                'gas': 131000,
                'gasPrice': self.web3.to_wei(2.1, 'Gwei'),
                'chainId': 1,
                'nonce': nonce
            })
            signed_tx = self.account.sign_transaction(tx)
            tx_hash = await self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.success(f'[{self.account.address}] 领取交易已发送成功: {tx_hash.hex()}')
        except Exception as e:
            logger.error(f'[{self.account.address}] 领取交易发送失败 {e}')


async def main(account_path):
    for _ in range(10):
        try:
            with open("已领取.txt", 'r', encoding='utf-8') as f:
                claim_accounts = set(line.strip() for line in f)
        except FileNotFoundError:
            claim_accounts = set()

        try:
            with open("无空投.txt", 'r', encoding='utf-8') as f:
                claim_accounts = set(line.strip() for line in f) | claim_accounts
        except FileNotFoundError:
            pass

        with open(account_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip() in claim_accounts:
                    continue
                private_key = line.split('----')[1].strip()
                await DOP(private_key).claim()
        await asyncio.sleep(10)


if __name__ == '__main__':
    _account_path = input('请拖入你的文件:').strip()
    asyncio.run(main(_account_path))
