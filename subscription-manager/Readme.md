# Claive Subscription Manager Contract

This repository contains a CosmWasm smart contract for managing subscriptions on Secret Network. The contract provides functionality to register and remove subscribers and includes admin management features. Secret Network's privacy features are utilized to keep subscriber data confidential and secure.

---

## Overview

The Claive Subscription Manager Contract is designed for subscription-based use cases, where an admin manages subscribers using their public keys. The contract keeps track of registered subscribers and ensures that only authorized admins can add or remove subscribers or change admin permissions.

### Contract State
The contract stores:
- **Admin Address**: The account that has permission to register or remove subscribers and manage admin rights.
- **Subscribers**: A mapping from a public key to the subscriber's status (active or inactive).

### Methods

1. **Instantiate**
    - Initializes the contract and sets the admin to the sender's address.
2. **Execute**
    - `RegisterSubscriber`: Adds a new subscriber using their public key. Only callable by the admin.
    - `RemoveSubscriber`: Removes a subscriber using their public key. Only callable by the admin.
    - `SetAdmin`: Changes the admin to a new address. Only callable by the current admin.
3. **Query**
    - `SubscriberStatus`: Checks if a subscriber with the given public key is active.

---

## Prerequisites

To use and deploy this contract, you'll need:
- [**SecretCLI**](https://docs.scrt.network/secret-network-documentation/infrastructure/secret-cli) for interacting with the Secret Network.
- [**LocalSecret**](https://docs.scrt.network/secret-network-documentation/development/readme-1/setting-up-your-environment) for local testing and development.

Please refer to the documentation above to install and familiarize yourself with these tools.

---

## Step 1: Build the Contract

### Prerequisites

- **Rust** and **wasm-opt** must be installed.
- Add the `wasm32-unknown-unknown` target for Rust if you haven’t done so:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```

### Build Instructions

1. **Build the Contract**:
   ```bash
   cargo build --release --target wasm32-unknown-unknown
   ```

2. **Optimize the Contract**:
   ```bash
   wasm-opt -Oz -o contract-opt.wasm target/wasm32-unknown-unknown/release/claive_subscription_manager.wasm
   ```

3. **Compress the Contract**:
   ```bash
   gzip -9 -c contract-opt.wasm > contract.wasm.gz
   ```

### Example Output
```bash
$ cargo build --release --target wasm32-unknown-unknown
   Compiling claive_subscription_manager v0.1.0 (/path/to/contract)
    Finished release [optimized] target(s) in 23.45s

$ wasm-opt -Oz -o contract-opt.wasm target/wasm32-unknown-unknown/release/claive_subscription_manager.wasm
# wasm-opt optimization completed

$ gzip -9 -c contract-opt.wasm > contract.wasm.gz
# Contract compressed successfully
```

---

## Step 2: Deploy the Contract

### Prerequisites

- **SecretCLI** must be configured.

### Deploy Instructions

1. **Deploy the Contract**:
   ```bash
   secretcli tx compute store contract.wasm.gz --gas 5000000 --from myWallet -y
   ```

2. **Get the `code_id`**:
   ```bash
   secretcli query compute list-code
   ```

### Example Output
```bash
$ secretcli tx compute store contract.wasm.gz --gas 5000000 --from myWallet -y
{
  "height": "0",
  "txhash": "DABA1EA6380DF252C844355109298681C28EC52BE0031E7E3B8730D8ECFC2BE0",
  "code": 0,
  "logs": []
}

$ secretcli query compute list-code
[
  {
    "code_id": 1,
    "creator": "secret1msmqzrp8ahvwe2jzk9n0xula0vnmv7vt3883y8",
    "code_hash": "afd0b5bda5a14dd41dc98d4cf112c1a239b5689796ac0fec4845db69d0a11f28"
  }
]
```

---

## Step 3: Instantiate the Contract

### Prerequisites

- You need the `code_id` from the previous step.

### Instantiate Instructions

1. **Instantiate the Contract**:
   ```bash
   secretcli tx compute instantiate <code_id> '{}' --from myWallet --label subContract -y
   ```

2. **Get the Contract Address**:
   ```bash
   secretcli query compute list-contract-by-code <code_id>
   ```

### Example Output
```bash
$ secretcli tx compute instantiate 1 '{}' --from myWallet --label subContract -y
{
  "height": "0",
  "txhash": "ACFD28FB7DE8ADC706B3595A32E2EA85219E203C9CA67EEF1DF5A7E23509FD9B",
  "code": 0,
  "logs": []
}

$ secretcli query compute list-contract-by-code 1
[
  {
    "contract_address": "secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf",
    "code_id": 1,
    "label": "subContract",
    "creator": "secret1msmqzrp8ahvwe2jzk9n0xula0vnmv7vt3883y8"
  }
]
```

---

## Use Cases

### Use Case 1: Register a Subscriber

**Description**: Register a subscriber using their public key. Only the admin can perform this action.

#### Command
```bash
secretcli tx compute execute <contract_address> '{"register_subscriber":{"public_key":"subscriber_pub_key"}}' --from myWallet -y
```

to get logs of the transaction use
```bash
secretcli q compute tx <tx_hash>
```

#### Example
```bash
$ secretcli tx compute execute secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{"register_subscriber":{"public_key":"subscriber_pub_key"}}' --from myWallet -y
{"height":"0","txhash":"F9435CA04E44FD924966089DBBBE395E7CA21422FF8D6A29BC31E9A0B016CCE4","codespace":"","code":0,"data":"","raw_log":"[]","logs":[],"info":"","gas_wanted":"0","gas_used":"0","tx":null,"timestamp":"","events":[]}
$ secretcli q compute tx F9435CA04E44FD924966089DBBBE395E7CA21422FF8D6A29BC31E9A0B016CCE4                                                                       
{
  "height": "0",
  "txhash": "F9435CA04E44FD924966089DBBBE395E7CA21422FF8D6A29BC31E9A0B016CCE4",
  "code": 0,
  "logs": [
    {
      "type": "wasm",
      "attributes": [
        {
          "key": "contract_address",
          "value": "secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf"
        },
        {
          "key": "action",
          "value": "register_subscriber"
        },
        {
          "key": "subscriber",
          "value": "subscriber_pub_key"
        }
      ]
    }
  ]
}
```

---

### Use Case 2: Query Subscriber Status

**Description**: Check if a subscriber is active or not.

#### Command
```bash
secretcli query compute query <contract_address> '{"subscriber_status":{"public_key":"subscriber_pub_key"}}'
```

#### Example
```bash
$ secretcli query compute query secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{"subscriber_status":{"public_key":"subscriber_pub_key"}}'
{
  "active": true
}
```

---

### Use Case 3: Remove a Subscriber

**Description**: Remove a subscriber using their public key. Only the admin can perform this action.

#### Command
```bash
secretcli tx compute execute <contract_address> '{"remove_subscriber":{"public_key":"subscriber_pub_key"}}' --from myWallet -y
```

#### Example
```bash
$ secretcli tx compute execute secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{"remove_subscriber":{"public_key":"subscriber_pub_key"}}' --from myWallet -y
{"height":"0","txhash":"C6E5113A94FDFA05FD5FB3214E6FA1E604AD927D1848C9CB191407BA11233E41","codespace":"","code":0,"data":"","raw_log":"[]","logs":[],"info":"","gas_wanted":"0","gas_used":"0","tx":null,"timestamp":"","events":[]}
$ secretcli q compute tx C6E5113A94FDFA05FD5FB3214E6FA1E604AD927D1848C9CB191407BA11233E41                                                                        
{
  "height": "0",
  "txhash": "C6E5113A94FDFA05FD5FB3214E6FA1E604AD927D1848C9CB191407BA11233E41",
  "code": 0,
  "logs": [
    {
      "type": "wasm",
      "attributes": [
        {
          "key": "contract_address",
          "value": "secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf"
        },
        {
          "key": "action",
          "value": "remove_subscriber"
        },
        {
          "key": "subscriber",
          "value": "subscriber_pub_key"
        }
      ]
    }
  ]
}
$ secretcli query  compute query secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{\"subscriber_status\":{\"public_key\":\"subscriber_pub_key\"}}'
{"active":false}
```

---

### Use Case 4: Set a New Admin

**Description**: Update the admin to a new public key. Only the current admin can perform this action.

#### Command
```bash
secretcli tx compute execute <contract_address> '{"set_admin":{"public_key":"new_admin_pub_key"}}' --from myWallet -y
```

#### Example
```bash
$ secretcli keys list
[{"name":"myNewWallet","type":"local","address":"secret1qvapn5ns28xrevn7kdudwvrp6a4fven2kzq8jc","pubkey":"{\"@type\":\"/cosmos.crypto.secp256k1.PubKey\",\"key\":\"AsKefYYrOHWvOfziuk/ITmcEpS6ZwWOTb6zlmqOu3FrW\"}"},{"name":"myWallet","type":"local","address":"secret1msmqzrp8ahvwe2jzk9n0xula0vnmv7vt3883y8","pubkey":"{\"@type\":\"/cosmos.crypto.secp256k1.PubKey\",\"key\":\"A5YOx9fAvahYlFqzyWAF38w3EuDTUtpZCyKW6Zk88NzO\"}"}]
$ secretcli tx compute execute secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{\"register_subscriber\":{\"public_key\":\"subscriber_pub_key\"}}' --from myNewWallet -y
{"height":"0","txhash":"2DB0821F55F1DCC51E29ACBAE529D9B3B14F2DA41D09BD0D05CB7C0436E1E9DC","codespace":"","code":0,"data":"","raw_log":"[]","logs":[],"info":"","gas_wanted":"0","gas_used":"0","tx":null,"timestamp":"","events":[]}
$ secretcli q compute tx 2DB0821F55F1DCC51E29ACBAE529D9B3B14F2DA41D09BD0D05CB7C0436E1E9DC                                                                          
{
    "answers": [
        {
            "type": "execute",
            "input": "afd0b5bda5a14dd41dc98d4cf112c1a239b5689796ac0fec4845db69d0a11f28{\"register_subscriber\":{\"public_key\":\"subscriber_pub_key\"}}"
        }
    ],
    "output_logs": [],
    "output_error": "message index 0: Generic error: Only admin can register subscribers"
}
$ secretcli tx compute execute secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{"set_admin":{"public_key":"secret1qvapn5ns28xrevn7kdudwvrp6a4fven2kzq8jc"}}' --from myWallet -y
{
  "height": "0",
  "txhash": "D5D86A32A654D3BBE7A4491F74BB96F68FC4481BECD00B5D10DFF271D76C75B2",
  "code": 0,
  "logs": []
}
$ secretcli q compute tx D5D86A32A654D3BBE7A4491F74BB96F68FC4481BECD00B5D10DFF271D76C75B2
{                
    "answers": [
        {
            "type": "execute",
            "input": "afd0b5bda5a14dd41dc98d4cf112c1a239b5689796ac0fec4845db69d0a11f28{\"set_admin\":{\"public_key\":\"secret1qvapn5ns28xrevn7kdudwvrp6a4fven2kzq8jc\"}}"
        }
    ],
    "output_logs": [
        {
            "type": "wasm",
                {
                    "key": "contract_address",
                    "value": "secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf"
                },
                {
                    "key": "action",
                    "value": "set_admin"
                },
                {
                    "key": "new_admin",
                    "value": "secret1qvapn5ns28xrevn7kdudwvrp6a4fven2kzq8jc"
                }
            ]
        }
    ]
}
$ secretcli tx compute execute secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf '{\"register_subscriber\":{\"public_key\":\"subscriber_pub_key\"}}' --from myNewWallet -y
{"height":"0","txhash":"C05875F06001649DF9D00D600AA3E07C7A0A6A3674E4F6336C9E4FEEF521E155","codespace":"","code":0,"data":"","raw_log":"[]","logs":[],"info":"","gas_wanted":"0","gas_used":"0","tx":null,"timestamp":"","events":[]}
$ secretcli q compute tx C05875F06001649DF9D00D600AA3E07C7A0A6A3674E4F6336C9E4FEEF521E155
{  
    "answers": [
        {
            "type": "execute",
            "input": "afd0b5bda5a14dd41dc98d4cf112c1a239b5689796ac0fec4845db69d0a11f28{\"register_subscriber\":{\"public_key\":\"subscriber_pub_key\"}}"
        }
    ],
    "output_logs": [
        {
            "type": "wasm",
            "attributes": [
                {
                    "key": "contract_address",
                    "value": "secret1nahrq5c0hf2v8fj703glsd7y3j7dccayadd9cf"
                },
                {
                    "key": "action",
                    "value": "register_subscriber"
                },
                {
                    "key": "subscriber",
                    "value": "subscriber_pub_key"
                }
            ]
        }
    ]
}

```
