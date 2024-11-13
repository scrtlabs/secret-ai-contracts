import os

from dotenv import load_dotenv
from secret_sdk.client.lcd import LCDClient

load_dotenv()
chain_id = os.getenv('CHAIN_ID')
contract = os.getenv('CONTRACT_ADDRESS')
node_url = os.getenv('NODE_URL')

print("chain_id: " + chain_id)
print("node_url: " + node_url)
print("contract: " + contract)

secret = LCDClient(chain_id=chain_id, url=node_url)

query = {"get_workers": {"address": "", "signature": "", "subscriber_public_key": ""}}

result = secret.wasm.contract_query(contract, query)

print(result)
