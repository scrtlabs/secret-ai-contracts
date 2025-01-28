import os
from time import sleep

from dotenv import load_dotenv
from secret_sdk.client.lcd import LCDClient
from secret_sdk.core.coins import Coins
from secret_sdk.key.mnemonic import MnemonicKey

load_dotenv()
chain_id = os.getenv('CHAIN_ID')
contract = os.getenv('CONTRACT_ADDRESS')
node_url = os.getenv('NODE_URL')
mnemonic = os.getenv('MNEMONIC')

print("chain_id: " + chain_id)
print("node_url: " + node_url)
print("contract: " + contract)
print("mnemonic: " + mnemonic)

mk = MnemonicKey(mnemonic=mnemonic)
secret = LCDClient(chain_id=chain_id, url=node_url)
wallet = secret.wallet(mk)

wallet_public_key = str(wallet.key.acc_address)

print("wallet_public_key: " + wallet_public_key)

contract_address = contract
sent_funds = Coins('10000uscrt')

handle_msg = {"register_worker" : {"ip_address" : "192.0.0.1", "payment_wallet" : wallet_public_key, "attestation_report": ""}}

t = wallet.execute_tx(
    contract_addr=contract_address,
    handle_msg=handle_msg,
    transfer_amount=sent_funds,
)

print(t)

assert t.code == 0, f"Transaction failed with code {t.code}: {t.rawlog}"
print("Transaction successful:", t.txhash)

sleep(10)

tx_info = secret.tx.tx_info(
    tx_hash=t.txhash,
)
print("Transaction info:", tx_info)
