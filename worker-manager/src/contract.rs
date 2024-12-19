use crate::msg::{
    ExecuteMsg, GetLivelinessChallengeResponse, GetModelsResponse, GetURLsResponse,
    GetWorkersResponse, InstantiateMsg, MigrateMsg, QueryMsg, SubscriberStatus,
    SubscriberStatusQuery, SubscriberStatusResponse,
};
use crate::state::{config, State, Worker, WORKERS_MAP};
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use sha2::{Digest, Sha256};

const SUBSCRIBER_CONTRACT_ADDRESS: &str = "secret1ttm9axv8hqwjv3qxvxseecppsrw4cd68getrvr";
const SUBSCRIBER_CONTRACT_CODE_HASH: &str =
    "c67de4cbe83764424192372e39abc0e040150d890600adefd6358abb6f0165ae";

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
            worker_type,
        } => try_register_worker(
            deps,
            info,
            ip_address,
            payment_wallet,
            attestation_report,
            worker_type,
        ),
        ExecuteMsg::SetWorkerWallet {
            ip_address,
            payment_wallet,
        } => try_set_worker_wallet(deps, info, ip_address, payment_wallet),
        ExecuteMsg::SetWorkerAddress {
            new_ip_address,
            old_ip_address,
        } => try_set_worker_address(deps, info, new_ip_address, old_ip_address),
        ExecuteMsg::SetWorkerType {
            ip_address,
            worker_type,
        } => try_set_worker_type(deps, info, ip_address, worker_type),
        ExecuteMsg::RemoveWorker { ip_address } => try_remove_worker(deps, info, ip_address),
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
    worker_type: String,
) -> StdResult<Response> {
    let worker = Worker {
        ip_address,
        payment_wallet,
        attestation_report,
        worker_type,
    };

    WORKERS_MAP.insert(_deps.storage, &worker.ip_address, &worker)?;

    Ok(Response::new().set_data(to_binary(&worker)?))
}

pub fn try_set_worker_wallet(
    _deps: DepsMut,
    _info: MessageInfo,
    ip_address: String,
    payment_wallet: String,
) -> StdResult<Response> {
    let worker_entry = WORKERS_MAP.get(_deps.storage, &ip_address);
    if let Some(worker) = worker_entry {
        if _info.sender != worker.payment_wallet {
            return Err(StdError::generic_err(
                "Only the owner has the authority to modify the payment wallet",
            ));
        }
        let worker = Worker {
            payment_wallet,
            ip_address: worker.ip_address,
            attestation_report: worker.attestation_report,
            worker_type: worker.worker_type,
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
    new_ip_address: String,
    old_ip_address: String,
) -> StdResult<Response> {
    let worker_entry = WORKERS_MAP.get(_deps.storage, &old_ip_address);
    if let Some(worker) = worker_entry {
        if _info.sender != worker.payment_wallet {
            return Err(StdError::generic_err(
                "Only the owner has the authority to modify the IP address",
            ));
        }
        let worker = Worker {
            payment_wallet: worker.payment_wallet,
            ip_address: new_ip_address.clone(),
            attestation_report: worker.attestation_report,
            worker_type: worker.worker_type,
        };
        WORKERS_MAP.remove(_deps.storage, &old_ip_address)?;
        WORKERS_MAP.insert(_deps.storage, &new_ip_address, &worker)?;
        Ok(Response::new().set_data(to_binary(&worker)?))
    } else {
        Err(StdError::generic_err("Could not find the worker"))
    }
}

pub fn try_set_worker_type(
    _deps: DepsMut,
    _info: MessageInfo,
    ip_address: String,
    worker_type: String,
) -> StdResult<Response> {
    let worker_entry = WORKERS_MAP.get(_deps.storage, &ip_address);
    if let Some(worker) = worker_entry {
        if _info.sender != worker.payment_wallet {
            return Err(StdError::generic_err(
                "Only the owner has the authority to modify the worker_type",
            ));
        }
        let worker = Worker {
            payment_wallet: worker.payment_wallet,
            ip_address: worker.ip_address,
            attestation_report: worker.attestation_report,
            worker_type,
        };

        WORKERS_MAP.insert(_deps.storage, &worker.ip_address, &worker)?;
        Ok(Response::new().set_data(to_binary(&worker)?))
    } else {
        Err(StdError::generic_err("Didn't find worker"))
    }
}

pub fn try_remove_worker(
    _deps: DepsMut,
    _info: MessageInfo,
    ip_address: String,
) -> StdResult<Response> {
    let worker_entry = WORKERS_MAP.get(_deps.storage, &ip_address);
    if let Some(worker) = worker_entry {
        if _info.sender != worker.payment_wallet {
            return Err(StdError::generic_err(
                "Only the owner has the authority to remove the worker",
            ));
        }

        WORKERS_MAP.remove(_deps.storage, &ip_address)?;
        Ok(Response::new().set_data(to_binary(&worker)?))
    } else {
        Err(StdError::generic_err("Didn't find worker"))
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
            signature,
            subscriber_public_key,
        } => to_binary(&query_workers(deps, signature, subscriber_public_key)?),
        QueryMsg::GetLivelinessChallenge {} => to_binary(&query_liveliness_challenge(deps)?),
        QueryMsg::GetModels {
            signature,
            subscriber_public_key,
        } => to_binary(&query_models(deps, signature, subscriber_public_key)?),
        QueryMsg::GetURLs {
            signature,
            subscriber_public_key,
            model,
        } => to_binary(&query_urls(deps, signature, subscriber_public_key, model)?),
    }
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => Ok(Response::default()),
        MigrateMsg::StdError {} => Err(StdError::generic_err("this is an std error")),
    }
}

fn signature_verification(
    _deps: Deps,
    _signature: String,
    _sender_public_key: String,
) -> StdResult<bool> {
    let public_key_hex = _sender_public_key.clone();
    let signature_hex = _signature.clone();

    let public_key_bytes = hex::decode(public_key_hex.clone())
        .map_err(|_| StdError::generic_err("Invalid public key hex"))?;

    let signature_bytes =
        hex::decode(signature_hex).map_err(|_| StdError::generic_err("Invalid signature hex"))?;

    let message_hash = Sha256::digest(public_key_bytes.clone());

    _deps
        .api
        .secp256k1_verify(&message_hash, &signature_bytes, &public_key_bytes)
        .map_err(|e| {
            StdError::generic_err("Failed to verify signature: ".to_string() + &e.to_string())
        })
}

fn query_workers(
    _deps: Deps,
    _signature: String,
    _sender_public_key: String,
) -> StdResult<GetWorkersResponse> {
    let verify = signature_verification(_deps, _signature, _sender_public_key)?;
    if !verify {
        return Err(StdError::generic_err("Signature verification failed"));
    }

    // let subs = SubscriberStatusQuery {
    //     subscriber_status: SubscriberStatus {
    //         public_key: _sender_public_key,
    //     },
    // };

    // let query_msg = to_binary(&subs)?;

    // let res: Result<SubscriberStatusResponse, StdError> = _deps.querier.query(
    //     &cosmwasm_std::QueryRequest::Wasm(cosmwasm_std::WasmQuery::Smart {
    //         contract_addr: SUBSCRIBER_CONTRACT_ADDRESS.into(),
    //         code_hash: SUBSCRIBER_CONTRACT_CODE_HASH.into(),
    //         msg: query_msg,
    //     }),
    // );

    // match res {
    //     Ok(subscriber_status) => {
    //         if subscriber_status.active {
    //             let workers: Vec<_> = WORKERS_MAP
    //                 .iter(_deps.storage)?
    //                 .map(|x| {
    //                     if let Ok((_, worker)) = x {
    //                         Some(worker)
    //                     } else {
    //                         None
    //                     }
    //                 })
    //                 .filter_map(|x| x)
    //                 .collect();

    //             Ok(GetWorkersResponse { workers })
    //         } else {
    //             Err(StdError::generic_err("Subscriber isn't active"))
    //         }
    //     }
    //     Err(err) => Err(StdError::generic_err(
    //         "Failed to deserialize subscriber response: ".to_string() + &err.to_string(),
    //     )),
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

fn query_models(
    _deps: Deps,
    _signature: String,
    _sender_public_key: String,
) -> StdResult<GetModelsResponse> {
    let verify = signature_verification(_deps, _signature, _sender_public_key)?;
    if !verify {
        return Err(StdError::generic_err("Signature verification failed"));
    }

    Ok(GetModelsResponse {
        models: vec!["llama3.1:70b".into()],
    })
}

fn query_urls(
    _deps: Deps,
    _signature: String,
    _sender_public_key: String,
    _model: Option<String>,
) -> StdResult<GetURLsResponse> {
    let verify = signature_verification(_deps, _signature, _sender_public_key)?;
    if !verify {
        return Err(StdError::generic_err("Signature verification failed"));
    }

    Ok(GetURLsResponse {
        urls: vec!["https://ai1.myclaive.com:21434".into()],
    })
}

fn query_liveliness_challenge(_deps: Deps) -> StdResult<GetLivelinessChallengeResponse> {
    // TODO: IMPLEMENT ME
    Ok(GetLivelinessChallengeResponse {})
}

#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::{from_binary, testing::*, Api, OwnedDeps};
    use cosmwasm_std::{Coin, Uint128};
    use hex::ToHex;
    const IP_ADDRESS: &str = "127.0.0.1";
    const PAYMENT_WALLET: &str = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03";
    const ATTESTATION_REPORT: &str = "";
    const WORKER_TYPE: &str = "llama3.1:70b";

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

    fn init_contract() -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("admin", &[]);
        let msg = InstantiateMsg {};
        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        (res, deps)
    }

    fn register_worker(
        deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>,
        ip_address: String,
        payment_wallet: String,
        attestation_report: String,
        worker_type: String,
    ) -> StdResult<Response> {
        let execute_msg = ExecuteMsg::RegisterWorker {
            ip_address,
            payment_wallet: payment_wallet.clone(),
            attestation_report,
            worker_type,
        };
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(&payment_wallet, &[]),
            execute_msg,
        )
    }

    #[test]
    fn register_worker_success() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let res = register_worker(
            &mut deps,
            IP_ADDRESS.into(),
            PAYMENT_WALLET.into(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();

        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            worker,
            Worker {
                ip_address: IP_ADDRESS.into(),
                payment_wallet: PAYMENT_WALLET.into(),
                attestation_report: ATTESTATION_REPORT.into(),
                worker_type: WORKER_TYPE.into(),
            }
        );
    }

    #[test]
    fn set_worker_wallet() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let res = register_worker(
            &mut deps,
            IP_ADDRESS.into(),
            PAYMENT_WALLET.into(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let new_payment_wallet = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450007".to_string();
        let execute_msg = ExecuteMsg::SetWorkerWallet {
            ip_address: IP_ADDRESS.into(),
            payment_wallet: new_payment_wallet.clone(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(PAYMENT_WALLET, &[]),
            execute_msg,
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            worker,
            Worker {
                ip_address: IP_ADDRESS.into(),
                payment_wallet: new_payment_wallet,
                attestation_report: ATTESTATION_REPORT.into(),
                worker_type: WORKER_TYPE.into(),
            }
        );
    }

    #[test]
    fn set_worker_wallet_unauthorized() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let res = register_worker(
            &mut deps,
            IP_ADDRESS.into(),
            PAYMENT_WALLET.into(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let new_payment_wallet = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450007".to_string();
        let execute_msg = ExecuteMsg::SetWorkerWallet {
            ip_address: IP_ADDRESS.into(),
            payment_wallet: new_payment_wallet.clone(),
        };

        // set as sender foreign wallet
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(&new_payment_wallet, &[]),
            execute_msg,
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            StdError::generic_err("Only the owner has the authority to modify the payment wallet",)
        );
    }

    #[test]
    fn set_worker_address() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let res = register_worker(
            &mut deps,
            IP_ADDRESS.into(),
            PAYMENT_WALLET.into(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let new_ip_address = String::from("147.4.4.7");
        let execute_msg = ExecuteMsg::SetWorkerAddress {
            new_ip_address: new_ip_address.clone(),
            old_ip_address: IP_ADDRESS.into(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(PAYMENT_WALLET, &[]),
            execute_msg,
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(
            worker,
            Worker {
                ip_address: new_ip_address,
                payment_wallet: PAYMENT_WALLET.into(),
                attestation_report: ATTESTATION_REPORT.into(),
                worker_type: WORKER_TYPE.into(),
            }
        );
    }

    #[test]
    fn set_worker_address_unauthorized() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let res = register_worker(
            &mut deps,
            IP_ADDRESS.into(),
            PAYMENT_WALLET.into(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let new_ip_address = String::from("147.4.4.7");
        let execute_msg = ExecuteMsg::SetWorkerAddress {
            new_ip_address: new_ip_address.clone(),
            old_ip_address: IP_ADDRESS.into(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("fake_acc", &[]),
            execute_msg,
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            StdError::generic_err("Only the owner has the authority to modify the IP address",)
        );
    }

    #[test]
    fn remove_worker() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let ip_address_1 = String::from("127.0.0.1");
        let ip_address_2 = String::from("127.0.0.2");

        let payment_wallet_1 = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string();

        let res = register_worker(
            &mut deps,
            ip_address_1.clone(),
            payment_wallet_1.clone(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let res = register_worker(
            &mut deps,
            ip_address_2.clone(),
            payment_wallet_1.clone(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let execute_msg = ExecuteMsg::RemoveWorker {
            ip_address: ip_address_1.clone(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(PAYMENT_WALLET, &[]),
            execute_msg,
        )
        .unwrap();
        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(worker.ip_address, ip_address_1);

        let execute_msg = ExecuteMsg::RemoveWorker {
            ip_address: ip_address_2.clone(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(PAYMENT_WALLET, &[]),
            execute_msg,
        )
        .unwrap();
        let worker: Worker = from_binary(&res.data.unwrap()).unwrap();
        assert_eq!(worker.ip_address, ip_address_2);

        let execute_msg = ExecuteMsg::RemoveWorker {
            ip_address: ip_address_2.clone(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(PAYMENT_WALLET, &[]),
            execute_msg,
        );
        assert!(res.is_err());
    }

    #[test]
    fn query_workers() {
        let (res, mut deps) = init_contract();
        assert_eq!(res.unwrap().messages.len(), 0);

        let ip_address_1 = String::from("127.0.0.1");
        let ip_address_2 = String::from("127.0.0.2");
        let ip_address_3 = String::from("127.0.0.3");

        let payment_wallet_1 = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s03".to_string();
        let payment_wallet_2 = "secret1ap26qrlp8mcq2pg6r47w43l0y8zkqm8a450s07".to_string();

        let res = register_worker(
            &mut deps,
            ip_address_1.clone(),
            payment_wallet_1.clone(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let res = register_worker(
            &mut deps,
            ip_address_2.clone(),
            payment_wallet_1.clone(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let res = register_worker(
            &mut deps,
            ip_address_3.clone(),
            payment_wallet_2.clone(),
            ATTESTATION_REPORT.into(),
            WORKER_TYPE.into(),
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        let message =
            hex::decode("034ee8249f67e136139c3ed94ad63288f6c1de45ce66fa883247211a698f440cdf")
                .unwrap();
        let priv_key =
            hex::decode("f0a7b67eb9a719d54f8a9bfbfb187d8c296b97911a05bf5ca30494823e46beb6")
                .unwrap();

        let sign = deps.api.secp256k1_sign(&message, &priv_key).unwrap();

        let query_msg = QueryMsg::GetWorkers {
            signature: sign.encode_hex(),
            subscriber_public_key:
                "034ee8249f67e136139c3ed94ad63288f6c1de45ce66fa883247211a698f440cdf".to_string(),
        };
        let res = query(deps.as_ref(), mock_env(), query_msg);

        assert!(res.is_ok());
        dbg!(res);
    }
}
