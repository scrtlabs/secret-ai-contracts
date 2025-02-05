use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult,
};
use secret_toolkit::permit::{validate, Permit};
use sha2::{Digest, Sha256};

use crate::msg::{
    ApiKeyDetail, ApiKeyResponse, ApiKeysByIdentityResponse, ExecuteMsg, GetApiKeysResponse,
    InstantiateMsg, MigrateMsg, QueryMsg, SubscriberStatusResponse,
};
use crate::state::{config, config_read, ApiKey, State, Subscriber, API_KEY_MAP, SB_MAP};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    // Set admin as the sender of the instantiate message
    let state = State {
        admin: info.sender.clone(),
    };

    // Log initialization debug message
    deps.api
        .debug(format!("Contract was initialized by {}", info.sender).as_str());

    // Save state to storage
    config(deps.storage).save(&state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::RegisterSubscriber { public_key } => {
            try_register_subscriber(deps, info, public_key)
        }
        ExecuteMsg::RemoveSubscriber { public_key } => {
            try_remove_subscriber(deps, info, public_key)
        }
        ExecuteMsg::SetAdmin { public_address } => try_set_admin(deps, info, public_address),
        ExecuteMsg::AddApiKey {
            api_key,
            identity,
            name,
            created,
        } => try_add_api_key(deps, info, api_key, identity, name, created),
        ExecuteMsg::RevokeApiKey { api_key } => try_revoke_api_key(deps, info, api_key),
    }
}

/// Adds an API key with optional identity, name, and creation timestamp
pub fn try_add_api_key(
    deps: DepsMut,
    info: MessageInfo,
    api_key: String,
    identity: Option<String>,
    name: Option<String>,
    created: Option<u64>,
) -> StdResult<Response> {
    // Load current contract state to verify admin privileges
    let state = config_read(deps.storage).load()?;

    // Only admin can add API keys
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can add API keys"));
    }

    // Check if API key already exists
    if API_KEY_MAP.contains(deps.storage, &api_key) {
        return Err(StdError::generic_err("API key already exists"));
    }

    // Create a new API key entry with provided details
    let api_key_data = ApiKey {
        identity,
        name,
        created,
    };

    // Insert the API key data into storage
    API_KEY_MAP
        .insert(deps.storage, &api_key, &api_key_data)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "add_api_key")
        .add_attribute("stored_key", api_key))
}

/// Revokes (removes) an existing API key
pub fn try_revoke_api_key(
    deps: DepsMut,
    info: MessageInfo,
    api_key: String,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;

    // Only admin can revoke API keys
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can revoke API keys"));
    }

    // Check if API key exists
    if !API_KEY_MAP.contains(deps.storage, &api_key) {
        return Err(StdError::generic_err("API key not found"));
    }

    // Remove the API key from storage
    API_KEY_MAP
        .remove(deps.storage, &api_key)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "revoke_api_key")
        .add_attribute("removed_key", api_key))
}

#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => {
            // // Iterate through all API keys and remove them
            // let keys_to_remove: Vec<String> = API_KEY_MAP
            //     .iter_keys(deps.storage)?
            //     .filter_map(|key_result| key_result.ok())
            //     .collect();
            //
            // for key in keys_to_remove {
            //     API_KEY_MAP.remove(deps.storage, &key)?;
            // }

            Ok(Response::new()
                .add_attribute("action", "migrate")
                .add_attribute("status", "api_key_map_cleared"))
        }
        MigrateMsg::StdError {} => Err(StdError::generic_err("this is an std error")),
    }
}

/// Registers a subscriber using a public key
pub fn try_register_subscriber(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can register subscribers"));
    }

    // Check if subscriber already exists
    if SB_MAP.contains(deps.storage, &public_key) {
        return Err(StdError::generic_err("Subscriber already registered"));
    }

    let subscriber = Subscriber { status: true };
    SB_MAP
        .insert(deps.storage, &public_key, &subscriber)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "register_subscriber")
        .add_attribute("subscriber", public_key))
}

/// Removes a subscriber using a public key
pub fn try_remove_subscriber(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can remove subscribers"));
    }

    // Check if subscriber exists
    if !SB_MAP.contains(deps.storage, &public_key) {
        return Err(StdError::generic_err("Subscriber not registered"));
    }

    SB_MAP
        .remove(deps.storage, &public_key)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "remove_subscriber")
        .add_attribute("subscriber", public_key))
}

/// Sets a new admin for the contract
pub fn try_set_admin(
    deps: DepsMut,
    info: MessageInfo,
    public_address: String,
) -> StdResult<Response> {
    let mut config = config(deps.storage);
    let mut state = config.load()?;

    // Only current admin can change the admin
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only the current admin can set a new admin"));
    }

    // Validate the new admin address
    let final_address = deps.api.addr_validate(&public_address).map_err(|err| {
        StdError::generic_err(format!("Invalid address: {}", err))
    })?;

    // Update state with new admin address
    state.admin = final_address;
    config.save(&state)?;

    Ok(Response::new()
        .add_attribute("action", "set_admin")
        .add_attribute("new_admin", public_address))
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::SubscriberStatusWithPermit { public_key, permit } => {
            to_binary(&query_subscriber_with_permit(deps, env, public_key, permit)?)
        }
        QueryMsg::GetAdmin {} => to_binary(&get_admin(deps)?),
        QueryMsg::ApiKeysWithPermit { permit } => {
            to_binary(&query_api_keys_with_permit(deps, env, permit)?)
        }
        QueryMsg::ApiKeysByIdentityWithPermit { identity, permit } => {
            to_binary(&query_api_keys_by_identity_with_permit(deps, env, identity, permit)?)
        }
    }
}

/// Returns the current admin address
fn get_admin(deps: Deps) -> StdResult<Addr> {
    let state = config_read(deps.storage).load()?;
    Ok(state.admin)
}

/// Query subscriber status using a permit for authorization
fn query_subscriber_with_permit(
    deps: Deps,
    env: Env,
    public_key: String,
    permit: Permit,
) -> StdResult<SubscriberStatusResponse> {
    let state = config_read(deps.storage).load()?;
    let admin_addr = state.admin;

    // Validate permit name
    if permit.params.permit_name != "query_subscriber_permit" {
        return Err(StdError::generic_err("Invalid permit name"));
    }

    let contract_address = env.contract.address;
    let storage_prefix = "permits_subscriber_status";
    let signer_addr = validate(
        deps,
        storage_prefix,
        &permit,
        contract_address.into_string(),
        Some("secret"),
    )?;

    // Only admin is allowed to query
    if signer_addr != admin_addr {
        return Err(StdError::generic_err("Unauthorized: not the admin"));
    }

    let subscriber = SB_MAP.get(deps.storage, &public_key);
    let active = subscriber.is_some();

    Ok(SubscriberStatusResponse { active })
}

/// Query all API keys (returns hashed API keys) using a permit for authorization
fn query_api_keys_with_permit(
    deps: Deps,
    env: Env,
    permit: Permit,
) -> StdResult<GetApiKeysResponse> {
    let state = config_read(deps.storage).load()?;
    let admin_addr = state.admin;

    // Validate permit name
    if permit.params.permit_name != "api_keys_permit" {
        return Err(StdError::generic_err("Invalid permit name"));
    }

    let contract_address = env.contract.address;
    let storage_prefix = "permits_api_keys";

    let signer_addr = validate(
        deps,
        storage_prefix,
        &permit,
        contract_address.into_string(),
        Some("secret"),
    )?;

    // Only admin is allowed to query
    if signer_addr != admin_addr {
        return Err(StdError::generic_err("Unauthorized: not the admin"));
    }

    // Iterate over all API keys, hash the keys, and return their hashed values
    let api_keys: Vec<ApiKeyResponse> = API_KEY_MAP
        .iter_keys(deps.storage)?
        .filter_map(|key_result| {
            if let Ok(api_key) = key_result {
                let mut hasher = Sha256::new();
                hasher.update(api_key.as_bytes());
                let hashed_key = hex::encode(hasher.finalize());

                Some(ApiKeyResponse { hashed_key })
            } else {
                None
            }
        })
        .collect();

    Ok(GetApiKeysResponse { api_keys })
}

/// Query API keys by identity (returns detailed API key information) using a permit for authorization
fn query_api_keys_by_identity_with_permit(
    deps: Deps,
    env: Env,
    identity: String,
    permit: Permit,
) -> StdResult<ApiKeysByIdentityResponse> {
    let state = config_read(deps.storage).load()?;
    let admin_addr = state.admin;

    // Validate permit name
    if permit.params.permit_name != "api_keys_by_identity_permit" {
        return Err(StdError::generic_err("Invalid permit name"));
    }

    let contract_address = env.contract.address;
    let storage_prefix = "permits_api_keys_by_identity";

    let signer_addr = validate(
        deps,
        storage_prefix,
        &permit,
        contract_address.into_string(),
        Some("secret"),
    )?;

    // Only admin is allowed to query
    if signer_addr != admin_addr {
        return Err(StdError::generic_err("Unauthorized: not the admin"));
    }

    // Iterate over all API keys and filter by the provided identity
    let api_keys: Vec<ApiKeyDetail> = API_KEY_MAP
        .iter(deps.storage)?
        .filter_map(|result| {
            if let Ok((key, data)) = result {
                if let Some(stored_identity) = &data.identity {
                    if stored_identity == &identity {
                        return Some(ApiKeyDetail {
                            api_key: key,
                            name: data.name,
                            created: data.created,
                        });
                    }
                }
            }
            None
        })
        .collect();

    Ok(ApiKeysByIdentityResponse { api_keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        attr, from_binary, BlockInfo, Coin, ContractInfo, Timestamp, TransactionInfo, Uint128,
    };

    /// Mocks an environment for permit tests
    fn mock_env_for_permit() -> Env {
        Env {
            block: BlockInfo {
                height: 12_345,
                time: Timestamp::from_nanos(1_571_797_419_879_305_533),
                chain_id: "pulsar-3".to_string(),
                random: Some(
                    Binary::from_base64("wLsKdf/sYqvSMI0G0aWRjob25mrIB0VQVjTjDXnDafk=").unwrap(),
                ),
            },
            transaction: Some(TransactionInfo {
                index: 3,
                hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            }),
            contract: ContractInfo {
                address: Addr::unchecked("secret1ttm9axv8hqwjv3qxvxseecppsrw4cd68getrvr"),
                code_hash: "".to_string(),
            },
        }
    }

    #[test]
    fn test_migrate_clears_api_key_map() {
        let mut deps = mock_dependencies();

        // Initialize contract with admin address
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        // Add two API keys
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "test_key1".to_string(),
                identity: None,
                name: None,
                created: None,
            },
        )
            .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "test_key2".to_string(),
                identity: None,
                name: None,
                created: None,
            },
        )
            .unwrap();

        // Ensure two keys are added
        let keys: Vec<String> = API_KEY_MAP
            .iter_keys(deps.as_ref().storage)
            .unwrap()
            .filter_map(|key_result| key_result.ok())
            .collect();
        assert_eq!(keys.len(), 2);

        // Migrate (clear) the API key map
        migrate(deps.as_mut(), mock_env(), MigrateMsg::Migrate {}).unwrap();

        // Check that API key map is empty
        let keys_after_migration: Vec<String> = API_KEY_MAP
            .iter_keys(deps.as_ref().storage)
            .unwrap()
            .filter_map(|key_result| key_result.ok())
            .collect();
        assert!(keys_after_migration.is_empty());
    }

    #[test]
    fn test_query_api_keys_with_real_permit() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        // Add a test API key
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "test_key1".to_string(),
                identity: None,
                name: None,
                created: None,
            },
        )
            .unwrap();

        // Read a permit from file "./api_keys_permit.json"
        let json_data = std::fs::read_to_string("./api_keys_permit.json").unwrap();
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::ApiKeysWithPermit { permit };
        let res = query(deps.as_ref(), env.clone(), query_msg);

        match res {
            Ok(bin) => {
                let parsed: GetApiKeysResponse = from_binary(&bin).unwrap();
                assert_eq!(parsed.api_keys.len(), 1);
            }
            Err(e) => panic!("Query failed: {:?}", e),
        }
    }

    #[test]
    fn revoke_api_key_and_query_with_permit() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        // Add an API key
        let add_msg = ExecuteMsg::AddApiKey {
            api_key: "test_api_key".to_string(),
            identity: None,
            name: None,
            created: None,
        };
        execute(deps.as_mut(), env.clone(), info.clone(), add_msg).unwrap();

        // Revoke the API key
        let revoke_msg = ExecuteMsg::RevokeApiKey {
            api_key: "test_api_key".to_string(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), revoke_msg).unwrap();

        let json_data = std::fs::read_to_string("./api_keys_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::ApiKeysWithPermit { permit };
        let res = query(deps.as_ref(), env.clone(), query_msg).expect("Query failed unexpectedly");

        let response: GetApiKeysResponse = from_binary(&res).unwrap();
        assert!(response.api_keys.is_empty());
    }

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

        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn register_subscriber_success() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber1".to_string(),
        };

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
    fn register_subscriber_unauthorized() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        let unauthorized_info = mock_info("not_admin", &[]);
        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber1".to_string(),
        };

        let res = execute(deps.as_mut(), mock_env(), unauthorized_info, register_msg);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            StdError::generic_err("Only admin can register subscribers")
        );
    }

    #[test]
    fn remove_subscriber_success() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber1".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), register_msg).unwrap();

        let remove_msg = ExecuteMsg::RemoveSubscriber {
            public_key: "subscriber1".to_string(),
        };

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
    fn remove_subscriber_not_registered() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let remove_msg = ExecuteMsg::RemoveSubscriber {
            public_key: "subscriber1".to_string(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, remove_msg);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            StdError::generic_err("Subscriber not registered")
        );
    }

    #[test]
    fn set_admin_success() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let set_admin_msg = ExecuteMsg::SetAdmin {
            public_address: "new_admin".to_string(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, set_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "set_admin"),
                attr("new_admin", "new_admin")
            ]
        );

        let config = config_read(&deps.storage).load().unwrap();
        assert_eq!(config.admin, Addr::unchecked("new_admin"));
    }

    #[test]
    fn set_admin_unauthorized() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        let unauthorized_info = mock_info("not_admin", &[]);
        let set_admin_msg = ExecuteMsg::SetAdmin {
            public_address: "new_admin".to_string(),
        };

        let res = execute(deps.as_mut(), mock_env(), unauthorized_info, set_admin_msg);
        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            StdError::generic_err("Only the current admin can set a new admin")
        );
    }

    #[test]
    fn test_get_admin() {
        let mut deps = mock_dependencies();
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        let query_msg = QueryMsg::GetAdmin {};
        let bin = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let response: Addr = from_binary(&bin).unwrap();

        assert_eq!(response, Addr::unchecked("admin"));
    }

    #[test]
    fn query_registered_subscriber() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber_public_key".to_string(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), register_msg).unwrap();

        let json_data = std::fs::read_to_string("./query_subscriber_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::SubscriberStatusWithPermit {
            public_key: "subscriber_public_key".to_string(),
            permit: permit.clone(),
        };
        let bin = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: SubscriberStatusResponse = from_binary(&bin).unwrap();

        assert!(response.active);
    }

    #[test]
    fn query_unregistered_subscriber() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();
        instantiate(deps.as_mut(), env.clone(), info, init_msg).unwrap();

        let json_data = std::fs::read_to_string("./query_subscriber_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::SubscriberStatusWithPermit {
            public_key: "unregistered_public_key".to_string(),
            permit: permit.clone(),
        };
        let bin = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: SubscriberStatusResponse = from_binary(&bin).unwrap();

        assert!(!response.active);
    }

    #[test]
    fn query_subscriber_after_removal() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        let register_msg = ExecuteMsg::RegisterSubscriber {
            public_key: "subscriber_public_key".to_string(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), register_msg).unwrap();

        let remove_msg = ExecuteMsg::RemoveSubscriber {
            public_key: "subscriber_public_key".to_string(),
        };
        execute(deps.as_mut(), env.clone(), info, remove_msg).unwrap();

        let json_data = std::fs::read_to_string("./query_subscriber_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::SubscriberStatusWithPermit {
            public_key: "subscriber_public_key".to_string(),
            permit: permit.clone(),
        };
        let bin = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: SubscriberStatusResponse = from_binary(&bin).unwrap();

        assert!(!response.active);
    }

    #[test]
    fn test_query_api_keys_by_identity_with_permit() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        // Add API keys with additional fields
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_1".to_string(),
                identity: Some("user_123".to_string()),
                name: Some("Test Key 1".to_string()),
                created: Some(1000),
            },
        )
            .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_2".to_string(),
                identity: Some("user_123".to_string()),
                name: Some("Test Key 2".to_string()),
                created: Some(2000),
            },
        )
            .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_3".to_string(),
                identity: Some("user_456".to_string()),
                name: Some("Other Key".to_string()),
                created: Some(3000),
            },
        )
            .unwrap();

        let json_data = std::fs::read_to_string("./api_keys_by_identity_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::ApiKeysByIdentityWithPermit {
            identity: "user_123".to_string(),
            permit,
        };
        let bin = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: ApiKeysByIdentityResponse = from_binary(&bin).unwrap();

        // Verify that only the keys belonging to "user_123" are returned with correct details
        assert_eq!(response.api_keys.len(), 2);
        let key1 = response
            .api_keys
            .iter()
            .find(|x| x.api_key == "api_key_1")
            .expect("Missing api_key_1");
        assert_eq!(key1.name, Some("Test Key 1".to_string()));
        assert_eq!(key1.created, Some(1000));

        let key2 = response
            .api_keys
            .iter()
            .find(|x| x.api_key == "api_key_2")
            .expect("Missing api_key_2");
        assert_eq!(key2.name, Some("Test Key 2".to_string()));
        assert_eq!(key2.created, Some(2000));
    }

    #[test]
    fn test_query_api_keys_by_empty_identity_with_permit() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        // Add API keys with and without identity
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_1".to_string(),
                identity: Some("user_123".to_string()),
                name: Some("Key 1".to_string()),
                created: Some(1000),
            },
        )
            .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_2".to_string(),
                identity: Some("user_456".to_string()),
                name: Some("Key 2".to_string()),
                created: Some(2000),
            },
        )
            .unwrap();

        // API keys without identity
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_3".to_string(),
                identity: None,
                name: None,
                created: None,
            },
        )
            .unwrap();

        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                api_key: "api_key_4".to_string(),
                identity: None,
                name: None,
                created: None,
            },
        )
            .unwrap();

        let json_data = std::fs::read_to_string("./api_keys_by_identity_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        // Query with an empty identity should return an empty result
        let query_msg = QueryMsg::ApiKeysByIdentityWithPermit {
            identity: "".to_string(),
            permit,
        };
        let bin = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: ApiKeysByIdentityResponse = from_binary(&bin).unwrap();

        assert_eq!(response.api_keys.len(), 0);
    }
}
