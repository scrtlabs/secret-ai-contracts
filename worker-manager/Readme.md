# Worker Manager Smart Contract

This smart contract is designed to manage a list of workers. Each worker is registered with their IP address, payment wallet, and an attestation report. The contract allows administrators and workers to interact with and update worker information, as well as query the current state of registered workers.

## Features

- **Register a Worker**: Allows the registration of a worker with their IP address, payment wallet, and attestation report.
- **Set Worker Wallet**: Allows a worker to update their payment wallet.
- **Set Worker Address**: Allows a worker to update their IP address.
- **Query Workers**: Allows querying of all registered workers.
- **Liveliness Reporting**: A placeholder for liveliness reporting (yet to be implemented).
- **Work Reporting**: A placeholder for work reporting (yet to be implemented).

## Contract Structure

### Messages

- **InstantiateMsg**: Used for instantiating the contract with an administrator.
- **ExecuteMsg**: Used to execute contract actions like registering a worker, setting worker details, etc.
- **QueryMsg**: Used to query the state of the contract, such as fetching workers or liveliness challenges.

### State

The contract stores the state using the following data structures:

- **State**: Holds the admin address.
- **Worker**: Stores a worker's information, such as IP address, payment wallet, and attestation report.
- **WORKERS_MAP**: A mapping that associates a worker's IP address with their information.

## Functions

### `try_register_worker`

Registers a worker by adding their IP address, payment wallet, and attestation report to the storage.

### `try_set_worker_wallet`

Allows a worker to update their payment wallet. It searches for a worker using the sender's address and updates their wallet.

### `try_set_worker_address`

Allows a worker to update their IP address. It searches for a worker using the sender's address and updates their IP address.

### `try_report_liveliness`

A placeholder function for reporting worker liveliness. This feature has yet to be implemented.

### `try_report_work`

A placeholder function for reporting a worker's work. This feature has yet to be implemented.

### `query_workers`

Queries all workers in storage and returns a list of their information.

### `query_liveliness_challenge`

Returns a liveliness challenge (placeholder response). This feature has yet to be implemented.

## How to Deploy

1. **Set up the CosmWasm environment**:
   - Install the required tools for working with CosmWasm contracts, such as Rust, Cargo, and CosmWasm CLI.
   
2. **Compile the Contract**:
   - Use `make build` to compile the contract to WebAssembly (Wasm).

3. **Deploy the Contract**:
   - Deploy the compiled contract to the Secret Network using the `secretcli` or other relevant tools.

4. **Interact with the Contract**:
   - Once deployed, you can interact with the contract using `secretcli` or by sending transactions via the Secret Network REST or gRPC endpoints.

## Example Queries and Transactions

### Register a Worker

To register a worker, execute the `RegisterWorker` action with the required parameters:

```bash
secretcli tx compute exec <contract_address> '{"register_worker":{"ip_address":"192.168.1.1","payment_wallet":"secret1xyz","attestation_report":""}}' --from <your_wallet>
```

### Query Workers

To query all workers, execute the `GetWorkers` query:

```bash
secretcli q compute query <contract_address> '{"get_workers": {"signature":<signed_msg_hex>, "subscriber_public_key":<pub_key_hex>}}' 
```

This Python example demonstrates signing a message with your private key and verifying it using the Secret SDK and secp256k1.

```python
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey
import secp256k1

chain_id = 'pulsar-3'
node_url = 'https://api.pulsar.scrttestnet.com'
mnemonic = 'grant rice replace explain federal release fix clever romance raise often wild taxi quarter soccer fiber love must tape steak together observe swap guitar'

mk = MnemonicKey(mnemonic=mnemonic)
secret = LCDClient(chain_id=chain_id, url=node_url)
wallet = secret.wallet(mk)

private_key_secp = secp256k1.PrivateKey(bytes.fromhex(mk.private_key.hex()))
message = bytes.fromhex(mk.public_key.key.hex())

signature = private_key_secp.ecdsa_sign(message)
signature_der = private_key_secp.ecdsa_serialize_compact(signature)

print("signature: ", signature_der.hex())

sig = private_key_secp.ecdsa_deserialize_compact(signature_der)

is_valid = private_key_secp.pubkey.ecdsa_verify(message, sig)
print("is_valid: ", is_valid)
```

Expected output:

```bash
pubkey:  034ee8249f67e136139c3ed94ad63288f6c1de45ce66fa883247211a698f440cdf
signature:  164a70762475db7f55b2fa2932ac35f761e27628ca13e9b8512137e256d93ea027ebcbb6725f23b3f720a4e00d5e57cbdc60c785437d943c62efba2bc5f61d85
is_valid:  True
```

### Set Worker Wallet

To update a worker's wallet:

```bash
secretcli tx compute exec <contract_address> '{"set_worker_wallet":{"ip_address":"192.168.1.1", "payment_wallet":"secret1newwallet"}}' --from <your_wallet>
```
### Set Worker Address

To update a worker's wallet:

```bash
secretcli tx compute exec <contract_address> '{"set_worker_address": {"new_ip_address": "<new_ip>", "old_ip_address": "<old_ip>>"}}' --from <your_wallet>
```

### Notes 

- Liveliness reporting and work reporting are placeholder features and have not been implemented yet.