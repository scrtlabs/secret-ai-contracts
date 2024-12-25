use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult
};
use sha2::{Digest, Sha256};
use crate::msg::{ExecuteMsg, GetApiKeysResponse, InstantiateMsg, MigrateMsg, QueryMsg, SubscriberStatusResponse};
use crate::state::{config, config_read, ApiKey, State, Subscriber, API_KEY_MAP, SB_MAP};

// Entry point for contract initialization
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    // Set the admin to the sender who initializes the contract
    let state = State {
        admin: info.sender.clone(),
    };

    // Log a debug message
    deps.api
        .debug(format!("Contract was initialized by {}", info.sender).as_str());

    // Save the initial state
    config(deps.storage).save(&state)?;

    Ok(Response::default())
}

// Entry point for executing messages
#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        // Handle registration of a subscriber
        ExecuteMsg::RegisterSubscriber { public_key } => try_register_subscriber(deps, info, public_key),
        // Handle removal of a subscriber
        ExecuteMsg::RemoveSubscriber { public_key } => try_remove_subscriber(deps, info, public_key),
        // Handle setting a new admin
        ExecuteMsg::SetAdmin { public_key } => try_set_admin(deps, info, public_key),
        // Handle adding an API key
        ExecuteMsg::AddApiKey { api_key } => try_add_api_key(deps, info, api_key),
        // Handle revoking an API key
        ExecuteMsg::RevokeApiKey { api_key } => try_revoke_api_key(deps, info, api_key),
    }
}

// Function to add a new API key
pub fn try_add_api_key(
    deps: DepsMut,
    info: MessageInfo,
    api_key: String,
) -> StdResult<Response> {
    let config = config_read(deps.storage);
    let state = config.load()?;

    // Check if the sender is the admin
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can add API keys"));
    }

    // Check if the API key already exists
    if API_KEY_MAP.contains(deps.storage, &api_key) {
        return Err(StdError::generic_err("API key already exists"));
    }

    // Insert the API key into the map
    let api_key_data = ApiKey { key: api_key.clone() };
    API_KEY_MAP.insert(deps.storage, &api_key, &api_key_data)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "add_api_key")
        .add_attribute("api_key", api_key))
}

// Function to revoke an API key
pub fn try_revoke_api_key(
    deps: DepsMut,
    info: MessageInfo,
    api_key: String,
) -> StdResult<Response> {
    let config = config_read(deps.storage);
    let state = config.load()?;

    // Check if the sender is the admin
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can revoke API keys"));
    }

    // Check if the API key exists
    if !API_KEY_MAP.contains(deps.storage, &api_key) {
        return Err(StdError::generic_err("API key not found"));
    }

    // Remove the API key from the map
    API_KEY_MAP.remove(deps.storage, &api_key)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "revoke_api_key")
        .add_attribute("api_key", api_key))
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => Ok(Response::default()),
        MigrateMsg::StdError {} => Err(StdError::generic_err("this is an std error")),
    }
}

// Function to register a new subscriber
pub fn try_register_subscriber(
    _deps: DepsMut,
    _info: MessageInfo,
    _public_key: String,
) -> StdResult<Response> {
    // Check if the sender is the admin
    let config = config_read(_deps.storage);
    let state = config.load()?;
    if _info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can register subscribers"));
    }

    // Check if the subscriber is already registered
    let map_contains_sb = SB_MAP.contains(_deps.storage, &_public_key);
    if map_contains_sb {
        return Err(StdError::generic_err("Subscriber already registered"));
    }

    // Create a new subscriber and insert it into the map
    let subscriber = Subscriber { public_key: _public_key.clone(), status: true };
    SB_MAP.insert(_deps.storage, &_public_key, &subscriber)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // Return a response indicating successful registration
    Ok(Response::new()
        .add_attribute("action", "register_subscriber")
        .add_attribute("subscriber", _public_key))
}

// Function to remove a subscriber
pub fn try_remove_subscriber(
    _deps: DepsMut,
    _info: MessageInfo,
    _public_key: String,
) -> StdResult<Response> {
    // Check if the sender is the admin
    let config = config_read(_deps.storage);
    let state = config.load()?;
    if _info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can remove subscribers"));
    }

    // Check if the subscriber is registered
    let map_contains_sb = SB_MAP.contains(_deps.storage, &_public_key);
    if !map_contains_sb {
        return Err(StdError::generic_err("Subscriber not registered"));
    }

    // Remove the subscriber from the map
    SB_MAP.remove(_deps.storage, &_public_key)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // Return a response indicating successful removal
    Ok(Response::new()
        .add_attribute("action", "remove_subscriber")
        .add_attribute("subscriber", _public_key))
}

// Function to set a new admin
pub fn try_set_admin(_deps: DepsMut, _info: MessageInfo, _public_key: String) -> StdResult<Response> {
    let mut config = config(_deps.storage);
    let mut state = config.load()?;

    // Check if the sender is the current admin
    if _info.sender != state.admin {
        return Err(StdError::generic_err("Only the current admin can set a new admin"));
    }

    // Validate the new admin's public key
    let final_address = _deps.api.addr_validate(&_public_key).map_err(|err| {
        StdError::generic_err(format!("Invalid address: {}", err))
    })?;

    // Update the admin in the state
    state.admin = final_address;
    config.save(&state)?;

    // Return a response indicating successful admin update
    Ok(Response::new()
        .add_attribute("action", "set_admin")
        .add_attribute("new_admin", _public_key))
}

// Entry point for handling queries
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        // Handle query for subscriber status
        QueryMsg::SubscriberStatus { public_key } => to_binary(&query_subscriber(deps, public_key)?),
        QueryMsg::ApiKeys {} => to_binary(&query_api_keys(deps)?),
    }
}

// Function to check if a subscriber is active
fn query_subscriber(
    _deps: Deps,
    _public_key: String,
) -> StdResult<SubscriberStatusResponse> {
    // Check if the subscriber exists in the map
    let subscriber = SB_MAP.get(_deps.storage, &_public_key);
    if !subscriber.is_none() {
        return Ok(SubscriberStatusResponse { active: true });
    }

    // Return false if the subscriber is not found
    Ok(SubscriberStatusResponse { active: false })
}

// Function to query all API keys
pub fn query_api_keys(deps: Deps) -> StdResult<GetApiKeysResponse> {
    let api_keys: Vec<ApiKey> = API_KEY_MAP
        .iter(deps.storage)?
        .filter_map(|x| {
            if let Ok((_, api_key)) = x {
                Some(api_key)
            } else {
                None
            }
        })
        .collect();

    Ok(GetApiKeysResponse { api_keys })
}
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{attr, from_binary, Api, Coin, Uint128};
    use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature, SecretKey};

    #[test]
    fn add_and_query_api_keys() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let add_msg = ExecuteMsg::AddApiKey {
            api_key: "test_api_key".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        let query_msg = QueryMsg::ApiKeys {};
        let res = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let response: GetApiKeysResponse = from_binary(&res).unwrap();

        assert_eq!(response.api_keys, vec![ApiKey { key: "test_api_key".to_string() }]);
    }

    #[test]
    fn revoke_api_key() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let add_msg = ExecuteMsg::AddApiKey {
            api_key: "test_api_key".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        let revoke_msg = ExecuteMsg::RevokeApiKey {
            api_key: "test_api_key".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), revoke_msg).unwrap();

        let query_msg = QueryMsg::ApiKeys {};
        let res = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let response: GetApiKeysResponse = from_binary(&res).unwrap();

        assert!(response.api_keys.is_empty());
    }

    #[test]
    /// Test for successful initialization of the contract
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

        // Assert successful initialization
        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    /// Test successful registration of a subscriber by admin
    fn register_subscriber_success() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber1".to_string(),
        };

        // Execute the message to register the subscriber and check the response
        let res = execute(deps.as_mut(), mock_env(), info, register_msg).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "register_subscriber"),
                attr("subscriber", "subscriber1")
            ]
        );
    }

    #[test]
    /// Test registration attempt by a non-admin, expecting failure
    fn register_subscriber_unauthorized() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        let unauthorized_info = mock_info("not_admin", &[]);
        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber1".to_string(),
        };

        // Attempt to register with a non-admin account and expect an error
        let res = execute(deps.as_mut(), mock_env(), unauthorized_info, register_msg);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            StdError::generic_err("Only admin can register subscribers")
        );
    }

    #[test]
    /// Test successful removal of a subscriber by admin
    fn remove_subscriber_success() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        // Register a subscriber first
        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber1".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), register_msg).unwrap();

        // Now remove the subscriber
        let remove_msg = ExecuteMsg::RemoveSubscriber {
            public_key: "subscriber1".to_string(),
        };

        // Execute the message to remove the subscriber and check the response
        let res = execute(deps.as_mut(), mock_env(), info, remove_msg).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "remove_subscriber"),
                attr("subscriber", "subscriber1")
            ]
        );
    }

    #[test]
    /// Test removal attempt of a non-registered subscriber, expecting failure
    fn remove_subscriber_not_registered() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let remove_msg = ExecuteMsg::RemoveSubscriber {
            public_key: "subscriber1".to_string(),
        };

        // Attempt to remove a non-registered subscriber and expect an error
        let res = execute(deps.as_mut(), mock_env(), info, remove_msg);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            StdError::generic_err("Subscriber not registered")
        );
    }

    #[test]
    /// Test successful update of the admin by the current admin
    fn set_admin_success() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let set_admin_msg = ExecuteMsg::SetAdmin {
            public_key: "new_admin".to_string(),
        };

        // Execute the message to set a new admin and check the response
        let res = execute(deps.as_mut(), mock_env(), info, set_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "set_admin"),
                attr("new_admin", "new_admin")
            ]
        );

        // Check that the admin was updated successfully
        let config = config_read(&deps.storage).load().unwrap();
        assert_eq!(config.admin, Addr::unchecked("new_admin"));
    }

    #[test]
    /// Test admin update attempt by a non-admin, expecting failure
    fn set_admin_unauthorized() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        let unauthorized_info = mock_info("not_admin", &[]);
        let set_admin_msg = ExecuteMsg::SetAdmin {
            public_key: "new_admin".to_string(),
        };

        // Attempt to set a new admin with a non-admin account and expect an error
        let res = execute(deps.as_mut(), mock_env(), unauthorized_info, set_admin_msg);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            StdError::generic_err("Only the current admin can set a new admin")
        );
    }

    #[test]
    /// Test querying for a registered subscriber, expecting active status
    fn query_registered_subscriber() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        // Register a subscriber
        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber_public_key".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info, register_msg).unwrap();

        // Query for the registered subscriber and check the response
        let query_msg = QueryMsg::SubscriberStatus {
            public_key: "subscriber_public_key".to_string(),
        };
        let bin = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let response: SubscriberStatusResponse = from_binary(&bin).unwrap();

        // Check that the subscriber is active
        assert!(response.active);
    }

    #[test]
    /// Test querying for an unregistered subscriber, expecting inactive status
    fn query_unregistered_subscriber() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        // Query for an unregistered subscriber and check the response
        let query_msg = QueryMsg::SubscriberStatus {
            public_key: "unregistered_public_key".to_string(),
        };
        let bin = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let response: SubscriberStatusResponse = from_binary(&bin).unwrap();

        // Check that the subscriber is not active
        assert!(!response.active);
    }

    #[test]
    /// Test querying for a subscriber after removal, expecting inactive status
    fn query_subscriber_after_removal() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        // Register a subscriber
        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber_public_key".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), register_msg).unwrap();

        // Remove the subscriber
        let remove_msg = ExecuteMsg::RemoveSubscriber {
            public_key: "subscriber_public_key".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info, remove_msg).unwrap();

        // Query for the subscriber after removal and check the response
        let query_msg = QueryMsg::SubscriberStatus {
            public_key: "subscriber_public_key".to_string(),
        };
        let bin = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let response: SubscriberStatusResponse = from_binary(&bin).unwrap();

        // Check that the subscriber is not active
        assert!(!response.active);
    }

}