use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    RegisterWorker {
        public_key: String,
        signature: String,
        ip_address: IpAddr,
        payment_wallet: String,
        attestation_report: String,
    },
    SetWorkerWallet {},
    SetWorkerAddress {},
    ReportLiveliness {},
    ReportWork {},
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetNextWorker {
        signature: String,
        subscriber_public_key: String,
    },
    GetLivelinessChallenge {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetNextWorkerResponse {
    pub ip_address: IpAddr,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct GetLivelinessChallengeResponse {}
