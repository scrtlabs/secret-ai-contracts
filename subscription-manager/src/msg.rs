use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use secret_toolkit::permit::Permit;


// Struct for the message used to instantiate the contract
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

// Enum representing the different executable messages that the contract can handle
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // Message to register a new subscriber using a public key
    RegisterSubscriber { public_key: String },

    // Message to remove a subscriber using a public key
    RemoveSubscriber { public_key: String },

    // Message to set a new admin for the contract using a public address
    SetAdmin { public_address: String },
    // Message to add an API key
    // Add an API key with an optional identity
    AddApiKey {
        api_key: String,
        identity: Option<String>, // Optional field to associate an API key with an identity
    },
    // Message to revoke an API key
    RevokeApiKey { api_key: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}

// Enum representing the different query messages that the contract can respond to
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    SubscriberStatusWithPermit {
        public_key: String,
        permit: Permit,
    },
    GetAdmin {},
    ApiKeysWithPermit {
        permit: Permit,
    },
    ApiKeysByIdentityWithPermit {
        identity: String,
        permit: Permit,
    }
}

// Struct used to respond to a query about a subscriber's status
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct SubscriberStatusResponse {
    // Indicates if the subscriber is active or not
    pub active: bool,
}

// Structure for API keys to respond to a query
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ApiKeyResponse {
    // Previously `key: String`,
    // Maybe rename to `hash: String` or `hashed_key: String`.
    pub hashed_key: String,
}

// Structure for GetApiKeysResponse
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetApiKeysResponse {
    pub api_keys: Vec<ApiKeyResponse>,
}

// Struct for the response of the `query_by_identity` query
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ApiKeysByIdentityResponse {
    pub api_keys: Vec<String>, // List of API keys associated with the identity
}