# Claive Subscription Manager Contract

This repository contains a CosmWasm smart contract for managing subscriptions on Secret Network. The contract provides functionality to register and remove subscribers, manage API keys, and includes admin management features. Secret Network's privacy features are utilized to keep subscriber data confidential and secure.

---

## Overview

The Claive Subscription Manager Contract is designed for subscription-based use cases, where an admin manages subscribers using their public keys. The contract keeps track of registered subscribers and API keys, ensuring that only authorized admins can manage them.

### Contract State

The contract stores:

- **Admin Address**: The account that has permission to register or remove subscribers, manage API keys, and change admin rights.
- **Subscribers**: A mapping from a public key to the subscriber's status (active or inactive).
- **API Keys**: A mapping of API keys used for external access control. API keys can optionally be associated with an identity, and they are stored securely.

### Methods

#### 1. **Instantiate**

- Initializes the contract and sets the admin to the sender's address.

#### 2. **Execute**

- `RegisterSubscriber`: Adds a new subscriber using their public key. Only callable by the admin.
- `RemoveSubscriber`: Removes a subscriber using their public key. Only callable by the admin.
- `SetAdmin`: Changes the admin to a new address. Only callable by the current admin.
- `AddApiKey`: Adds a new API key for access control, with an optional identity. Only callable by the admin.
- `RevokeApiKey`: Revokes an existing API key. The contract verifies its existence before removal. Only callable by the admin.

#### 3. **Query**

- `SubscriberStatusWithPermit`: Checks if a subscriber with the given public key is active. Requires a valid permit signed by the admin.
- `ApiKeysWithPermit`: Returns a list of all registered API keys (**hashed by sha-256**). Requires a valid permit signed by the admin.
- `ApiKeysByIdentityWithPermit`: Retrieves API keys associated with a given identity. Requires admin authorization.
- `GetAdmin`: Returns the current admin address.

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
- Add the wasm32-unknown-unknown target for Rust if you haven’t done so:

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

---

## Step 2: Deploy the Contract

### Prerequisites

- **SecretCLI** must be configured.

### Deploy Instructions

1. **Deploy the Contract**:

```bash
secretcli tx compute store contract.wasm.gz --gas 5000000 --from myWallet -y
```

2. **Get the code_id**:

```bash
secretcli query compute list-code
```

---

## Step 3: Instantiate the Contract

### Prerequisites

- You need the code_id from the previous step.

### Instantiate Instructions

1. **Instantiate the Contract**:

```bash
secretcli tx compute instantiate <code_id> '{}' --from myWallet --label subContract -y
```

2. **Get the Contract Address**:

```bash
secretcli query compute list-contract-by-code <code_id>
```

---

## Use Cases

### Use Case 1: Register a Subscriber

**Description**: Register a subscriber using their public key. Only the admin can perform this action.

#### Command

```bash
secretcli tx compute execute <contract_address> '{"register_subscriber":{"public_key":"subscriber_pub_key"}}' --from myWallet -y
```

---

### Use Case 2: Query Subscriber Status with Permit

**Description**: Check if a subscriber is active or not. Requires a valid permit signed by the admin.

#### Command

```bash
secretcli query compute query <contract_address> '{"subscriber_status_with_permit":{"public_key":"subscriber_pub_key","permit":<permit_json>}}'
```

---

### Use Case 3: Remove a Subscriber

**Description**: Remove a subscriber using their public key. Only the admin can perform this action.

#### Command

```bash
secretcli tx compute execute <contract_address> '{"remove_subscriber":{"public_key":"subscriber_pub_key"}}' --from myWallet -y
```

---

### Use Case 4: Set a New Admin

**Description**: Update the admin to a new public key. Only the current admin can perform this action.

#### Command

```bash
secretcli tx compute execute <contract_address> '{"set_admin":{"public_key":"new_admin_pub_key"}}' --from myWallet -y
```

---

### Use Case 5: Add an API Key

**Description**: Add a new API key for access control. Only the admin can perform this action. The API key is hashed using SHA-256 before storage.

#### Command

```bash
secretcli tx compute execute <contract_address> '{"add_api_key":{"api_key":"new_api_key"}}' --from myWallet -y
```

---

### Use Case 6: Revoke an API Key

**Description**: Revoke an existing API key. Only the admin can perform this action. The API key must be provided in plaintext, and the contract verifies its hash before removal.

#### Command

```bash
secretcli tx compute execute <contract_address> '{"revoke_api_key":{"api_key":"api_key_to_revoke"}}' --from myWallet -y
```

---

### Use Case 7: Query API Keys with Permit

**Description**: Retrieve the list of all registered API keys in **hashed format**. Requires a valid permit signed by the admin.

#### Command

```bash
secretcli query compute query <contract_address> '{"api_keys_with_permit":{"permit":<permit_json>}}'
```

---

### Use Case 8: Query API Keys by Identity with Permit

**Description**: Retrieve all **actual API keys** associated with a given identity. Requires a valid permit signed by the admin.

#### Command

```bash
secretcli query compute query <contract_address> '{"api_keys_by_identity_with_permit":{"identity":"some_identity","permit":<permit_json>}}'
```

---

### Use Case 9: Get Admin Address

**Description**: Retrieve the current admin address.

#### Command

```bash
secretcli query compute query <contract_address> '{"get_admin":{}}'
```

---

