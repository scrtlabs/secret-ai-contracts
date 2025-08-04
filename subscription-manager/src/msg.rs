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
    RegisterSubscriber { public_key: String },
    RemoveSubscriber { public_key: String },
    SetAdmin { public_address: String },
    // The AddApiKey message now only requires identity, name, and created.
    AddApiKey {
        identity: String,
        name: Option<String>,
        created: Option<u64>,
    },
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
    /// Query identity by API key
    QueryIdentityByApiKey { api_key: String },
    QueryIdentityByApiKeyHash { api_key_hash: String }
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

/// Response for querying identity by full API key
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct IdentityResponse {
    pub identity: String,
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
