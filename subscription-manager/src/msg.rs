use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use secret_toolkit::permit::Permit;

/// Instantiate message for the contract
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

/// Execute message enum for the contract
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Register a new subscriber with a public key
    RegisterSubscriber { public_key: String },
    /// Remove an existing subscriber using a public key
    RemoveSubscriber { public_key: String },
    /// Set a new admin address for the contract
    SetAdmin { public_address: String },
    /// Add an API key with optional identity, name, and created timestamp
    AddApiKey {
        api_key: String,
        identity: Option<String>,
        name: Option<String>,    // optional field: name of the API key
        created: Option<u64>,    // optional field: creation timestamp
    },
    /// Revoke an existing API key
    RevokeApiKey { api_key: String },
}

/// Migrate message enum for contract migration
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}

/// Query message enum for the contract
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Query subscriber status with permit
    SubscriberStatusWithPermit {
        public_key: String,
        permit: Permit,
    },
    /// Get the admin address
    GetAdmin {},
    /// Query all API keys with permit (returns hashed API keys)
    ApiKeysWithPermit { permit: Permit },
    /// Query API keys by identity with permit (returns API key details)
    ApiKeysByIdentityWithPermit {
        identity: String,
        permit: Permit,
    },
}

/// Response structure for subscriber status query
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct SubscriberStatusResponse {
    pub active: bool,
}

/// Response structure for API keys query (hashed keys)
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ApiKeyResponse {
    pub hashed_key: String,
}

/// Response structure for GetApiKeys query
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetApiKeysResponse {
    pub api_keys: Vec<ApiKeyResponse>,
}

/// Structure returned in API keys by identity query containing key details
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ApiKeyDetail {
    pub api_key: String,
    pub name: Option<String>,
    pub created: Option<u64>,
}

/// Response structure for API keys by identity query
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ApiKeysByIdentityResponse {
    pub api_keys: Vec<ApiKeyDetail>,
}
