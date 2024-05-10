from web3 import Web3
import os
import json
address = "0xa403755F7eFb058Bd761434E1eFd2E282edAB63D" # 账户地址
private_key = "0xa93d4134405376bea10f296bd9c01e874f3f6560d44952c97a5f7999f539b771" #账户私钥
contract_address = "0x17F579b359ae54Ce99F8D18Adc69E3a18AC379Cb" #合约地址
curDir = os.path.dirname(os.path.abspath(__file__))

contract_abi = '[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"string\",\"name\":\"fileIndex\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"A\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"K\",\"type\":\"string\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"storageFileAuthEvent\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"string\",\"name\":\"fileIndex\",\"type\":\"string\"}],\"name\":\"submitAuditResultEvent\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"A\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"K\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"fileIndex\",\"type\":\"string\"}],\"name\":\"storeFileAuth\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"fileIndex\",\"type\":\"string\"}],\"name\":\"findFileAuthForIndex\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\",\"constant\":true},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"fileIndex\",\"type\":\"string\"},{\"components\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"},{\"internalType\":\"string[]\",\"name\":\"relatedStorageNodeList\",\"type\":\"string[]\"}],\"internalType\":\"struct StorageExcutor.AuditResult\",\"name\":\"auditResult\",\"type\":\"tuple\"}],\"name\":\"submitAuditResult\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"fileIndex\",\"type\":\"string\"}],\"name\":\"findAuditResultForFileIndex\",\"outputs\":[{\"components\":[{\"components\":[{\"internalType\":\"bool\",\"name\":\"success\",\"type\":\"bool\"},{\"internalType\":\"string[]\",\"name\":\"relatedStorageNodeList\",\"type\":\"string[]\"}],\"internalType\":\"struct StorageExcutor.AuditResult\",\"name\":\"audit\",\"type\":\"tuple\"},{\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"recoder\",\"type\":\"address\"}],\"internalType\":\"struct StorageExcutor.SubmitResult[]\",\"name\":\"\",\"type\":\"tuple[]\"}],\"stateMutability\":\"view\",\"type\":\"function\",\"constant\":true}]'
blockchain_url ="HTTP://127.0.0.1:7545"
class EthWorker():

    def __init__(self):
        self.web3 = Web3(Web3.HTTPProvider(blockchain_url))

    # Client
    def findFileAuthForIndex(self, fileIndex):
        """
        查找文件标签
        """
        contract = self.web3.eth.contract(address=contract_address, abi=contract_abi)
        fileAuth = (contract.functions.findFileAuthForIndex(fileIndex)
                    .call())
        return fileAuth

    def storeFileAuth(self,
                      fileIndex: str,
                      A: str,
                      K: str):
        """
        存储文件标签
        """
        try:
            contract = self.web3.eth.contract(address=contract_address, abi=contract_abi)
            tx_info = {
                "from": address,
                "gas": 2000000,  # 设置足够的gas
                "gasPrice": self.web3.to_wei("100", "gwei"),  # 设置gas价格
                "nonce": self.web3.eth.get_transaction_count(self.web3.to_checksum_address(address)),  # 非重放攻击保护
            }
            tx = contract.functions.storeFileAuth(
                A, K, fileIndex
            ).build_transaction(tx_info)
            signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
            # 发送交易
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            # 等待交易确认
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"交易已发送，交易哈希：{tx_hash.hex()}")
        except Exception as e:
            print(e)

    def submitAuditResult(self, fileIndex,mockAduitResult):
        """
        提交审计结果
        """
        try:
            contract = self.web3.eth.contract(address=contract_address, abi=contract_abi)
            tx_info = {
                "from": address,
                "gas": 2000000,  # 设置足够的gas
                "gasPrice": self.web3.to_wei("100", "gwei"),  # 设置gas价格
                "nonce": self.web3.eth.get_transaction_count(self.web3.to_checksum_address(address)),  # 非重放攻击保护
            }
            tx = contract.functions.submitAuditResult(
                fileIndex, mockAduitResult
            ).build_transaction(tx_info)
            signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
            # 发送交易
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            self.web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"交易已发送，交易哈希：{tx_hash.hex()}")
        except Exception as e:
            print(e)

    def findAuditResultForFileIndex(self, fileIndex):
        """
        获取文件审计结果
        """
        contract = self.web3.eth.contract(address=contract_address, abi=contract_abi)
        resultList = (contract.functions.findAuditResultForFileIndex(fileIndex)
                    .call())
        return resultList


    def getBlockInfo(self):
        if self.web3.is_connected():
            # 获取区块链信息
            chain_id = self.web3.eth.chain_id
            block_number = self.web3.eth.block_number
            peer_count = self.web3.net.peer_count

            print(f"Chain ID: {chain_id}")
            print(f"Block Number: {block_number}")
            print(f"Peer Count: {peer_count}\n")

            # 获取所有区块信息
            for block_num in range(0, block_number + 1):
                block = self.web3.eth.get_block(block_num)
                print(f"Block #{block_num}:")
                print(f"  Hash: {block['hash'].hex()}")
                print(f"  Parent Hash: {block['parentHash'].hex()}")
                print(f"  Miner: {block['miner']}")
                print(f"  Gas Limit: {block['gasLimit']}")
                print(f"  Gas Used: {block['gasUsed']}")
                print(f"  Timestamp: {block['timestamp']}")
                print(f"  Transactions: {len(block['transactions'])}\n")

        else:
            print("Failed to connect to Ganache RPC.")
