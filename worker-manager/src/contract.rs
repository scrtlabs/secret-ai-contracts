use std::net::{IpAddr, Ipv4Addr};

use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use crate::msg::{
    ExecuteMsg, GetLivelinessChallengeResponse, GetNextWorkerResponse, InstantiateMsg, QueryMsg,
};
use crate::state::{config, State};

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
            public_key,
            signature,
            ip_address,
            payment_wallet,
            attestation_report,
        } => try_register_worker(
            deps,
            info,
            public_key,
            signature,
            ip_address,
            payment_wallet,
            attestation_report,
        ),
        ExecuteMsg::SetWorkerWallet {} => try_set_worker_wallet(deps, info),
        ExecuteMsg::SetWorkerAddress {} => try_set_worker_address(deps, info),
        ExecuteMsg::ReportLiveliness {} => try_report_liveliness(deps, info),
        ExecuteMsg::ReportWork {} => try_report_work(deps, info),
    }
}

pub fn try_register_worker(
    _deps: DepsMut,
    _info: MessageInfo,
    _public_key: String,
    _signature: String,
    _ip_address: IpAddr,
    _payment_wallet: String,
    _attestation_report: String,
) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

pub fn try_set_worker_wallet(_deps: DepsMut, _info: MessageInfo) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

pub fn try_set_worker_address(_deps: DepsMut, _info: MessageInfo) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
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
        QueryMsg::GetNextWorker {
            signature,
            subscriber_public_key,
        } => to_binary(&query_next_worker(deps, signature, subscriber_public_key)?),
        QueryMsg::GetLivelinessChallenge {} => to_binary(&query_liveliness_challenge(deps)?),
    }
}

fn query_next_worker(
    _deps: Deps,
    _signature: String,
    _sender_public_key: String,
) -> StdResult<GetNextWorkerResponse> {
    // TODO: IMPLEMENT ME
    Ok(GetNextWorkerResponse {
        ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    })
}

fn query_liveliness_challenge(_deps: Deps) -> StdResult<GetLivelinessChallengeResponse> {
    // TODO: IMPLEMENT ME
    Ok(GetLivelinessChallengeResponse {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::*;
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
}
