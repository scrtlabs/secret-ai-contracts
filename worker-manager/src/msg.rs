use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::Worker;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    RegisterWorker {
        ip_address: String,
        payment_wallet: String,
        attestation_report: String,
        worker_type: String,
    },
    SetWorkerWallet {
        ip_address: String,
        payment_wallet: String,
    },
    SetWorkerAddress {
        new_ip_address: String,
        old_ip_address: String,
    },
    SetWorkerType {
        ip_address: String,
        worker_type: String,
    },
    RemoveWorker {
        ip_address: String,
    },
    ReportLiveliness {},
    ReportWork {},
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetWorkers {
        signature: String,
        subscriber_public_key: String,
    },
    GetModels {
        signature: String,
        subscriber_public_key: String,
    },
    GetURLs {
        signature: String,
        subscriber_public_key: String,
        model: Option<String>,
    },
    GetLivelinessChallenge {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetWorkersResponse {
    pub workers: Vec<Worker>,
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetModelsResponse {
    pub models: Vec<String>,
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetURLsResponse {
    pub urls: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetLivelinessChallengeResponse {}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct SubscriberStatusResponse {
    pub active: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SubscriberStatusQuery {
    pub subscriber_status: SubscriberStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SubscriberStatus {
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {
    Migrate {},
    StdError {},
}
