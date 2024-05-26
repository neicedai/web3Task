import asyncio, sys, random
import hashlib

from curl_cffi.requests import AsyncSession
from eth_account.messages import encode_defunct
from web3 import AsyncWeb3
from loguru import logger

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")

G_Nonce = None


class UXLink:
    def __init__(self, private_key: str):
        RPC_list = [
            'https://arbitrum.llamarpc.com', 'https://arb1.arbitrum.io/rpc', 'https://rpc.ankr.com/arbitrum',
            'https://1rpc.io/arb', 'https://arb-pokt.nodies.app', 'https://arbitrum.drpc.org',
            'https://arbitrum-one.public.blastapi.io', 'https://arb-mainnet-public.unifra.io',
            'https://arbitrum-one-rpc.publicnode.com', 'https://arbitrum.meowrpc.com'
        ]
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(random.choice(RPC_list)))
        self.client = AsyncSession()
        self.account = self.w3.eth.account.from_key(private_key)
        abi = [
            {
                "inputs": [
                    {"internalType": "address", "name": "nft", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"},
                    {"internalType": "bytes", "name": "signature", "type": "bytes"},
                    {"internalType": "string", "name": "transId", "type": "string"},
                ],
                "name": "mintWithUXUY",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                'inputs': [
                    {'internalType': 'address', 'name': '_spender', 'type': 'address'},
                    {'internalType': 'uint256', 'name': '_tokens', 'type': 'uint256'}
                ],
                'name': 'approve',
                'outputs': [{'internalType': 'bool', 'name': '', 'type': 'bool'}],
                'stateMutability': 'nonpayable',
                'type': 'function'
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "owner", "type": "address"},
                    {"internalType": "address", "name": "spender", "type": "address"}
                ],
                "name": "allowance",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                'inputs': [
                    {'internalType': 'address', 'name': '_user', 'type': 'address'}
                ],
                'name': 'balanceOf',
                'outputs': [{'internalType': 'uint256', 'name': '', 'type': 'uint256'}],
                'stateMutability': 'view',
                'type': 'function'
            }
        ]
        self.mint_add = self.w3.to_checksum_address('0x1b99c6fc1d0afb480a7979a55404330df27f605b')
        self.Mint = self.w3.eth.contract(address=self.mint_add, abi=abi)
        UXUY_add = self.w3.to_checksum_address('0xE2035f04040A135c4dA2f96AcA742143c57c79F9')
        self.UXUY = self.w3.eth.contract(address=UXUY_add, abi=abi)
        self.LINK_add = self.w3.to_checksum_address('0x50E75cAC7E0b4160aa8d80af9AfDF36043BF2486')
        self.LINK = self.w3.eth.contract(address=self.LINK_add, abi=abi)
        self.FRENS_add = self.w3.to_checksum_address('0x9191617302Ae1fc02b823530bDd7e167fD43aA36')
        self.FRENS = self.w3.eth.contract(address=self.FRENS_add, abi=abi)
        self.nonce, self.NFT_add, self.NFT = None, None, None

    async def getNonce(self):
        try:
            json_data = {"eventName": "dappLoginPage", "eventType": "loginInfo",
                         "eventValue": "{\"isInBinance\":false,\"userInfo\":{\"address\":\"\",\"userName\":\"\",\"userAvatar\":\"\",\"userGender\":0,\"userUid\":\"\",\"did\":\"\",\"location\":\"\",\"userBio\":\"\",\"defaultAddress\":\"\",\"bindEmail\":true,\"userStatus\":0,\"defaultWalletType\":0,\"needBindTg\":false,\"needBindX\":false,\"isBindTg\":false,\"isBindX\":false}}"}
            res = await self.client.post(f"https://api.uxlink.io/uxtag/event", json=json_data)
            if res.json()['success']:
                return res.json()['data']['eventResp']
            else:
                return None
        except Exception as e:
            logger.error(f"获取Nonce失败：{e}")
            return None

    async def login(self):
        global G_Nonce
        try:
            UXUY_balance = await self.UXUY.functions.balanceOf(self.account.address).call()
            if UXUY_balance > self.w3.to_wei(500, 'ether'):
                FRENS_balance = await self.FRENS.functions.balanceOf(self.account.address).call()
                if FRENS_balance == 0:
                    self.NFT_add, self.NFT = self.FRENS_add, self.FRENS

            if self.NFT_add is None and UXUY_balance > self.w3.to_wei(100, 'ether'):
                LINK_balance = await self.LINK.functions.balanceOf(self.account.address).call()
                if LINK_balance == 0:
                    self.NFT_add, self.NFT = self.LINK_add, self.LINK

            if self.NFT_add is None:
                logger.error(f"[{self.account.address}] 已领取或UXUY不足")
                return True

            if G_Nonce is None:
                G_Nonce = await self.getNonce()
            if G_Nonce is None:
                logger.error(f"[{self.account.address}] 获取Nonce失败")
                return False

            sig_msg = f'Welcome to UXLINK!\n\nClick to sign in and this request will not trigger a blockchain transaction or cost any gas fees.\n\nWallet address:\n{self.account.address}\n\nNonce:\n{hashlib.md5(G_Nonce.encode()).hexdigest()}'
            signature = self.account.sign_message(encode_defunct(text=sig_msg))
            json_data = {
                "address": self.account.address.lower(),
                "aliasName": "OKX Wallet",
                "walletType": 2,
                "inviteCode": "",
                "message": sig_msg,
                "signed": signature['signature'].hex()
            }
            res = await self.client.post("https://api.uxlink.io/user/wallet/verify", json=json_data)
            if res.json()['success']:
                logger.success(f"[{self.account.address}] 登录成功")
                accessToken = res.json()['data']['accessToken']
                self.client.headers.update({"Authorization": f"{accessToken}"})
                return await self.approve()
            else:
                G_Nonce = await self.getNonce()
                logger.error(f"[{self.account.address}] 登录失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 登录失败：{e}")
            return False

    async def approve(self):
        try:
            if self.nonce is None:
                self.nonce = await self.w3.eth.get_transaction_count(self.account.address)
            allowance = await self.UXUY.functions.allowance(self.account.address, self.mint_add).call()
            if self.NFT_add == self.LINK_add:
                min_allowance = self.w3.to_wei(100, 'ether')
            else:
                min_allowance = self.w3.to_wei(500, 'ether')

            if allowance < min_allowance:
                tx = await self.UXUY.functions.approve(self.mint_add, self.w3.to_wei(5000, 'ether')).build_transaction({
                    'from': self.account.address,
                    'nonce': self.nonce,
                    'chainId': 42161,
                    'gas': 75249,
                    'maxFeePerGas': self.w3.to_wei(0.02, 'gwei'),
                    'maxPriorityFeePerGas': 10,
                })
                tx['gas'] = await self.w3.eth.estimate_gas(tx)
                signed_tx = self.account.sign_transaction(tx)
                tx_hash = await self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash)
                if receipt.status == 1:
                    self.nonce += 1
                    logger.success(f"[{self.account.address}] 授权成功")
                    return await self.redeem()
            else:
                logger.success(f"[{self.account.address}] 已授权")
                return await self.redeem()
        except Exception as e:
            logger.error(f"[{self.account.address}] 授权失败：{e}")
            return False

    async def redeem(self):
        try:
            if self.NFT_add == self.LINK_add:
                nftCollectId = "1785637578171478020"
                NFT_name = "LINK"
            else:
                nftCollectId = "1785637578171478019"
                NFT_name = "FRENS"
            json_data = {
                "nftCollectId": nftCollectId,
                "walletAddress": self.account.address,
                "actionType": 1
            }
            res = await self.client.post("https://api.uxlink.io/nft/third/wallet/redeem", json=json_data)
            if res.json()['success']:
                signature = res.json()['data']['signature']
                transId = res.json()['data']['transId']
                signature = f"0x{signature.lower()}"
                tx = await self.Mint.functions.mintWithUXUY(self.NFT_add, 1, signature, transId).build_transaction({
                    'from': self.account.address,
                    'nonce': self.nonce,
                    'chainId': 42161,
                    'gas': 262262,
                    'maxFeePerGas': self.w3.to_wei(0.02, 'gwei'),
                    'maxPriorityFeePerGas': 10
                })
                tx['gas'] = await self.w3.eth.estimate_gas(tx)
                signed_tx = self.account.sign_transaction(tx)
                tx_hash = await self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash)
                if receipt.status == 1:
                    self.nonce += 1
                    logger.success(f"[{self.account.address}] 兑换{NFT_name}成功")
                    return True
            else:
                logger.error(f"[{self.account.address}] 获取MINT信息失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address}] 获取MINT信息失败：{e}")
            return False


async def do(semaphore, private_key):
    async with semaphore:
        for _ in range(3):
            if await UXLink(private_key).login():
                break


async def main(filePath):
    semaphore = asyncio.Semaphore(10)
    with open(filePath, 'r') as f:
        task = [do(semaphore, account_line.strip().split('----')[1].strip()) for account_line in f]
    await asyncio.gather(*task)


if __name__ == '__main__':
    _filePath = input("请输入账户文件路径：").strip()
    asyncio.run(main(_filePath))
