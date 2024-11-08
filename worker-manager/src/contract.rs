use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
// use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
// use sha2::{Digest, Sha256};

use crate::msg::{
    ExecuteMsg, GetLivelinessChallengeResponse, GetWorkersResponse, InstantiateMsg, QueryMsg,
};
use crate::state::{config, State, Worker, WORKERS_MAP};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        admin: info.sender.clone(),
    };

    deps.api
        .debug(format!("Contract was initialized by {}", info.sender).as_str());
    config(deps.storage).save(&state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::RegisterWorker {
            ip_address,
            payment_wallet,
            attestation_report,
        } => try_register_worker(deps, info, ip_address, payment_wallet, attestation_report),
        ExecuteMsg::SetWorkerWallet { payment_wallet } => {
            try_set_worker_wallet(deps, info, payment_wallet)
        }
        ExecuteMsg::SetWorkerAddress { ip_address } => {
            try_set_worker_address(deps, info, ip_address)
        }
        ExecuteMsg::ReportLiveliness {} => try_report_liveliness(deps, info),
        ExecuteMsg::ReportWork {} => try_report_work(deps, info),
    }
}

pub fn try_register_worker(
    _deps: DepsMut,
    _info: MessageInfo,
    ip_address: String,
    payment_wallet: String,
    attestation_report: String,
) -> StdResult<Response> {
    // let state = config_read(_deps.storage).load()?;
    // if _info.sender != state.admin {
    //     return Err(StdError::generic_err("Only admin can register workers"));
    // }

    let worker = Worker {
        ip_address,
        payment_wallet,
        attestation_report,
    };

    WORKERS_MAP.insert(_deps.storage, &worker.ip_address, &worker)?;

    Ok(Response::new().set_data(to_binary(&worker)?))
}

pub fn try_set_worker_wallet(
    _deps: DepsMut,
    _info: MessageInfo,
    payment_wallet: String,
) -> StdResult<Response> {
    let mut iter = WORKERS_MAP.iter(_deps.storage)?;

    let worker_entry = iter.find_map(|result| {
        if let Ok((_, worker)) = result {
            if worker.payment_wallet == _info.sender {
                return Some(worker);
            }
        }
        None
    });

    if let Some(worker) = worker_entry {
        let worker = Worker {
            payment_wallet,
            ip_address: worker.ip_address,
            attestation_report: worker.attestation_report,
        };

        WORKERS_MAP.insert(_deps.storage, &worker.ip_address, &worker)?;
        Ok(Response::new().set_data(to_binary(&worker)?))
    } else {
        Err(StdError::generic_err("Didn't find worker"))
    }
}

pub fn try_set_worker_address(
    _deps: DepsMut,
    _info: MessageInfo,
    ip_address: String,
) -> StdResult<Response> {
    let mut iter = WORKERS_MAP.iter(_deps.storage)?;

    let worker_entry = iter.find_map(|result| {
        if let Ok((_, worker)) = result {
            if worker.payment_wallet == _info.sender {
                return Some(worker);
            }
        }
        None
    });

    if let Some(worker) = worker_entry {
        let worker = Worker {
            payment_wallet: worker.payment_wallet,
            ip_address: ip_address.clone(),
            attestation_report: worker.attestation_report,
        };
        WORKERS_MAP.insert(_deps.storage, &ip_address, &worker)?;
        WORKERS_MAP.remove(_deps.storage, &ip_address)?;
        Ok(Response::new().set_data(to_binary(&worker)?))
    } else {
        Err(StdError::generic_err("Could not find the worker"))
    }
}

pub fn try_report_liveliness(_deps: DepsMut, _info: MessageInfo) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

pub fn try_report_work(_deps: DepsMut, _info: MessageInfo) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetWorkers {
            address,
            signature,
            subscriber_public_key,
        } => to_binary(&query_workers(
            deps,
            address,
            signature,
            subscriber_public_key,
        )?),
        QueryMsg::GetLivelinessChallenge {} => to_binary(&query_liveliness_challenge(deps)?),
    }
}

fn query_workers(
    _deps: Deps,
    _address: String,
    _signature: String,
    _sender_public_key: String,
) -> StdResult<GetWorkersResponse> {
    // let payload = format!("{}{}", _address, "_payload_message");
    // let is_valid = verify_signature(_sender_public_key, _signature, payload.as_bytes())?;
    // if !is_valid {
    //     return Err(StdError::generic_err("Invalid signature"));
    // }

    let workers: Vec<_> = WORKERS_MAP
        .iter(_deps.storage)?
        .map(|x| {
            if let Ok((_, worker)) = x {
                Some(worker)
            } else {
                None
            }
        })
        .filter_map(|x| x)
        .collect();

    Ok(GetWorkersResponse { workers })
}

fn query_liveliness_challenge(_deps: Deps) -> StdResult<GetLivelinessChallengeResponse> {
    // TODO: IMPLEMENT ME
    Ok(GetLivelinessChallengeResponse {})
}

// fn verify_signature(
//     public_key_hex: String,
//     signature_hex: String,
//     message: &[u8],
// ) -> StdResult<bool> {
//     let secp = Secp256k1::verification_only();
//     let public_key_bytes =
//         hex::decode(public_key_hex).map_err(|_| StdError::generic_err("Invalid public key hex"))?;
//     let public_key = PublicKey::from_slice(&public_key_bytes)
//         .map_err(|_| StdError::generic_err("Invalid public key"))?;
//     let signature_bytes =
//         hex::decode(signature_hex).map_err(|_| StdError::generic_err("Invalid signature hex"))?;
//     let signature = Signature::from_der(&signature_bytes)
//         .map_err(|_| StdError::generic_err("Invalid signature"))?;
//     let message_hash = sha2::Sha256::digest(message);
//     let message =
//         Message::from_slice(&message_hash).map_err(|_| StdError::generic_err("Invalid message"))?;
//     secp.verify_ecdsa(&message, &signature, &public_key)
//         .map(|_| true)
//         .map_err(|_| StdError::generic_err("Signature verification failed"))
// }
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{from_binary, testing::*};
    use cosmwasm_std::{Coin, Uint128};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info(
            "creator",
            &[Coin {
                denom: "earth".to_string(),
                amount: Uint128::new(1000),
            }],
        );
        let init_msg = InstantiateMsg {};

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn register_worker_success() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("admin", &[]);
        let msg = InstantiateMsg {};
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address: String::from("127.0.0.1"),
            payment_wallet: "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string(),
            attestation_report: "".to_string(),
        };
        let res = execute(deps.as_mut(), env, info, execute_msg).unwrap();
        assert_eq!(0, res.messages.len());
        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            worker,
            Worker {
                ip_address: String::from("127.0.0.1"),
                payment_wallet: "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string(),
                attestation_report: "".to_string(),
            }
        );
    }

    #[test]
    fn set_worker_wallet() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03", &[]);
        let msg = InstantiateMsg {};
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let ip_address = String::from("127.0.0.1");
        let payment_wallet = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string();
        let attestation_report = "".to_string();

        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address: ip_address.clone(),
            payment_wallet,
            attestation_report: attestation_report.clone(),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let new_payment_wallet = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450007".to_string();
        let execute_msg = ExecuteMsg::SetWorkerWallet {
            payment_wallet: new_payment_wallet.clone(),
        };
        let res = execute(deps.as_mut(), env, info, execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            worker,
            Worker {
                ip_address: ip_address.clone(),
                payment_wallet: new_payment_wallet,
                attestation_report,
            }
        );
    }

    #[test]
    fn set_worker_address() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03", &[]);
        let msg = InstantiateMsg {};
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let ip_address = String::from("127.0.0.1");
        let payment_wallet = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string();
        let attestation_report = "".to_string();

        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address,
            payment_wallet: payment_wallet.clone(),
            attestation_report: attestation_report.clone(),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let new_ip_address = String::from("147, 4, 4, 7");
        let execute_msg = ExecuteMsg::SetWorkerAddress {
            ip_address: new_ip_address.clone(),
        };
        let res = execute(deps.as_mut(), env, info, execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            worker,
            Worker {
                ip_address: new_ip_address,
                payment_wallet,
                attestation_report,
            }
        );
    }

    #[test]
    fn query_workers() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03", &[]);
        let msg = InstantiateMsg {};
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let ip_address_1 = String::from("127.0.0.1");
        let ip_address_2 = String::from("127, 0, 0, 2");
        let ip_address_3 = String::from("127, 0, 0, 3");

        let payment_wallet_1 = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string();
        let payment_wallet_2 = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s07".to_string();
        let attestation_report = "".to_string();

        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address: ip_address_1.clone(),
            payment_wallet: payment_wallet_1.clone(),
            attestation_report: attestation_report.clone(),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address: ip_address_2.clone(),
            payment_wallet: payment_wallet_1.clone(),
            attestation_report: attestation_report.clone(),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address: ip_address_3.clone(),
            payment_wallet: payment_wallet_2.clone(),
            attestation_report: attestation_report.clone(),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), execute_msg).unwrap();
        assert_eq!(0, res.messages.len());

        let query_msg = QueryMsg::GetWorkers {
            address: "".to_string(),
            signature: "".to_string(),
            subscriber_public_key: "".to_string(),
        };
        let res = query(deps.as_ref(), env, query_msg).unwrap();

        let workers: GetWorkersResponse = from_binary(&res).unwrap();
        assert_eq!(
            workers,
            GetWorkersResponse {
                workers: vec![
                    Worker {
                        ip_address: ip_address_1,
                        payment_wallet: payment_wallet_1.clone(),
                        attestation_report: attestation_report.clone(),
                    },
                    Worker {
                        ip_address: ip_address_2,
                        payment_wallet: payment_wallet_1.clone(),
                        attestation_report: attestation_report.clone(),
                    },
                    Worker {
                        ip_address: ip_address_3,
                        payment_wallet: payment_wallet_2,
                        attestation_report,
                    },
                ]
            }
        );
    }
}
