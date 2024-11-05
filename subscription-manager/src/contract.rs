use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, SubscriberStatusResponse};
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
        ExecuteMsg::RegisterSubscriber { address } => try_register_subscriber(deps, info, address),
        ExecuteMsg::RemoveSubscriber { address } => try_remove_subscriber(deps, info, address),
        ExecuteMsg::SetAdmin { address } => try_set_admin(deps, info, address),
    }
}

pub fn try_register_subscriber(
    _deps: DepsMut,
    _info: MessageInfo,
    _address: String,
) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

pub fn try_remove_subscriber(
    _deps: DepsMut,
    _info: MessageInfo,
    _address: String,
) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

pub fn try_set_admin(_deps: DepsMut, _info: MessageInfo, _address: String) -> StdResult<Response> {
    // TODO: IMPLEMENT ME
    Err(StdError::generic_err("not implemented"))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::SubscriberStatus {
            address,
            signature,
            sender_public_key,
        } => to_binary(&query_subscriber(
            deps,
            address,
            signature,
            sender_public_key,
        )?),
    }
}

fn query_subscriber(
    _deps: Deps,
    _address: String,
    _signature: String,
    _sender_public_key: String,
) -> StdResult<SubscriberStatusResponse> {
    // TODO: IMPLEMENT ME
    Ok(SubscriberStatusResponse { active: false })
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
