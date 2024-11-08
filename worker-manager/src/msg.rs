
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
    },
    SetWorkerWallet {
        payment_wallet: String,
    },
    SetWorkerAddress {
        ip_address: String,
    },
    ReportLiveliness {},
    ReportWork {},
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetWorkers {
        address: String,
        signature: String,
        subscriber_public_key: String,
    },
    GetLivelinessChallenge {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetWorkersResponse {
    pub workers: Vec<Worker>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetLivelinessChallengeResponse {}
