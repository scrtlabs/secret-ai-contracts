use cosmwasm_std::{entry_point, from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cosmwasm_storage::Bucket;
use schemars::JsonSchema;
use secret_toolkit::permit::{validate, Permit};
use secret_toolkit::storage::Keymap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::msg::{
    ApiKeyDetail, ApiKeyResponse, ApiKeysByIdentityResponse, ExecuteMsg, GetApiKeysResponse,
    InstantiateMsg, MigrateMsg, QueryMsg, SubscriberStatusResponse,
};
use crate::state::{config, config_read, ApiKey, State, Subscriber, API_KEY_MAP, SB_MAP};

/// Generates a pseudo-random API key using env.block.random and the provided identity.
/// Mimics the following JavaScript function:
/// ```js
/// const generateApiKey = (): string => {
///   const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
///   return `sk-${Array.from({ length: 72 }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('')}`;
/// };
/// ```
/// Instead of Math.random(), it uses the available random seed and the identity.
fn generate_api_key(random: &[u8], identity: &str, created: u64) -> String {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut key = String::from("sk-"); // prefix as in the JS example
    // Create an initial seed by hashing the random seed with the identity.
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, random);
    sha2::Digest::update(&mut hasher, identity.as_bytes());
    sha2::Digest::update(&mut hasher, created.to_string().as_bytes());
    let mut seed = hasher.finalize_reset().to_vec();

    // Append characters until key reaches desired length.
    while key.len() < 75 {
        for &byte in seed.iter() {
            if key.len() >= 75 {
                break;
            }
            let idx = (byte as usize) % alphabet.len();
            let ch = alphabet.chars().nth(idx).unwrap();
            key.push(ch);
        }
        // Update the seed by hashing the current seed.
        let mut seed_hasher = Sha256::new();
        sha2::Digest::update(&mut seed_hasher, &seed);
        seed = seed_hasher.finalize().to_vec();
    }
    key
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    // Set the admin as the sender of the instantiate message.
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
        // Note: AddApiKey now generates the key internally.
        ExecuteMsg::AddApiKey {
            identity,
            name,
            created,
        } => try_add_api_key(deps, env, info, identity, name, created),
        ExecuteMsg::RevokeApiKey { api_key } => try_revoke_api_key(deps, info, api_key),
    }
}

/// Adds a new API key for the given identity. The sender must either be the identity owner or the admin.
/// The API key is generated using env.block.random and the identity. The full API key is returned to
/// the caller, but only its hash (SHA‑256) is stored in the contract.
pub fn try_add_api_key(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    identity: String,
    name: Option<String>,
    created: Option<u64>,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;
    // Verify that the sender is either the identity owner or an admin.
    if info.sender != Addr::unchecked(identity.clone()) && info.sender != state.admin {
        return Err(StdError::generic_err(
            "Sender must be admin or match the identity",
        ));
    }

    // Use env.block.random to generate a pseudo-random API key.
    let random = env
        .block
        .random
        .ok_or_else(|| StdError::generic_err("Missing random seed"))?;
    let full_api_key = generate_api_key(random.as_slice(), &identity, created.unwrap_or(0));
    // Compute the string representation: first 10 characters + "..." + last 3 characters.
    let str_representation = if full_api_key.len() >= 13 {
        format!(
            "{}...{}",
            &full_api_key[..10],
            &full_api_key[full_api_key.len() - 3..]
        )
    } else {
        full_api_key.clone()
    };

    // Check if the API key (by its string representation) already exists.
    if API_KEY_MAP.contains(deps.storage, &str_representation) {
        return Err(StdError::generic_err("API key already exists"));
    }

    // Compute the hash of the API key to store in the contract.
    let mut key_hasher = Sha256::new();
    key_hasher.update(full_api_key.as_bytes());
    let key_hash = hex::encode(key_hasher.finalize());

    // Create a new API key entry storing only the hash, along with additional details.
    let api_key_data = ApiKey {
        identity: identity.clone(),
        hash: key_hash,
        name,
        created,
    };

    API_KEY_MAP
        .insert(deps.storage, &str_representation, &api_key_data)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // Return the full API key to the caller.
    Ok(Response::new()
        .add_attribute("action", "add_api_key")
        .add_attribute("api_key", full_api_key))
}

/// Revokes (removes) an existing API key. The parameter is the string representation of the API key.
/// The sender must be either the admin or the owner (matching the stored identity).
pub fn try_revoke_api_key(
    deps: DepsMut,
    info: MessageInfo,
    api_key_str: String,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;

    // Check if the API key exists.
    let api_key_data = API_KEY_MAP
        .get(deps.storage, &api_key_str)
        .ok_or_else(|| StdError::generic_err("API key not found"))?;

    // Verify that the sender is either the admin or the owner of the API key.
    if info.sender != state.admin && info.sender != Addr::unchecked(api_key_data.identity.clone()) {
        return Err(StdError::generic_err(
            "Unauthorized: sender does not own this API key",
        ));
    }

    API_KEY_MAP
        .remove(deps.storage, &api_key_str)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    Ok(Response::new()
        .add_attribute("action", "revoke_api_key")
        .add_attribute("removed_api_key", api_key_str))
}

/// Old API key structure (old format)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct OldApiKey {
    pub identity: Option<String>,
    pub name: Option<String>,
    pub created: Option<u64>,
}

/// Define a keymap for the old API keys using the same prefix as originally used.
pub static OLD_API_KEY_MAP: Keymap<String, OldApiKey> = Keymap::new(b"API_KEY_MAP");

/// Migration function to transfer API keys from the old format to the new format.
///
/// The old data are stored in OLD_API_KEY_MAP (prefix b"API_KEY_MAP") as OldApiKey.
/// The new format uses ApiKey, and the key in storage is the string representation
/// (first 10 characters + "..." + last 3 characters) of the full API key.
/// For each old entry:
///   1. Compute the new key (string representation) from the old key.
///   2. Compute the SHA‑256 hash of the old full API key.
///   3. Create a new ApiKey with:
///      - identity: taken from the old data (or an empty string if missing),
///      - hash: computed hash,
///      - name and created: carried over.
///   4. Insert the new record into NEW_API_KEY_MAP.
///   5. Remove the entry from OLD_API_KEY_MAP.
#[entry_point]
pub fn migrate(deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    match msg {
        MigrateMsg::Migrate {} => {
            // Step 1: Collect all old API key entries from OLD_API_KEY_MAP.
            let mut old_entries: Vec<(String, OldApiKey)> = Vec::new();
            for item in OLD_API_KEY_MAP.iter(deps.storage)? {
                let (raw_key, old_api) = item?;
                old_entries.push((raw_key, old_api));
            }

            // Step 2: For each old entry, convert and insert into NEW_API_KEY_MAP.
            for (old_full_key, old_data) in old_entries.iter() {
                // Compute new key: if old_full_key length is >= 13,
                // then new key = first 10 chars + "..." + last 3 chars;
                // otherwise, use the full key.
                let new_key = if old_full_key.len() >= 13 {
                    format!("{}...{}", &old_full_key[..10], &old_full_key[old_full_key.len()-3..])
                } else {
                    old_full_key.clone()
                };

                // Compute the SHA-256 hash of the old full API key.
                let mut key_hasher = Sha256::new();
                key_hasher.update(old_full_key.as_bytes());
                let new_hash = hex::encode(key_hasher.finalize());

                // Use the old identity if available; otherwise, default to an empty string.
                let new_identity = old_data.identity.clone().unwrap_or_else(|| "".to_string());

                // Create the new ApiKey structure.
                let new_api_key = ApiKey {
                    identity: new_identity,
                    hash: new_hash,
                    name: old_data.name.clone(),
                    created: old_data.created,
                };

                // Insert the new record into NEW_API_KEY_MAP.
                API_KEY_MAP.insert(deps.storage, &new_key, &new_api_key)
                    .map_err(|err| StdError::generic_err(err.to_string()))?;

                // Step 3: Remove the migrated entry from OLD_API_KEY_MAP.
                OLD_API_KEY_MAP.remove(deps.storage, old_full_key)?;
            }

            Ok(Response::new()
                .add_attribute("action", "migrate")
                .add_attribute("status", "migrated from OLD_API_KEY_MAP to NEW_API_KEY_MAP"))
        }
        MigrateMsg::StdError {} => Err(StdError::generic_err("this is an std error")),
    }
}

/// Registers a subscriber using a public key.
pub fn try_register_subscriber(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can register subscribers"));
    }

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

/// Removes a subscriber using a public key.
pub fn try_remove_subscriber(
    deps: DepsMut,
    info: MessageInfo,
    public_key: String,
) -> StdResult<Response> {
    let state = config_read(deps.storage).load()?;
    if info.sender != state.admin {
        return Err(StdError::generic_err("Only admin can remove subscribers"));
    }

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

/// Sets a new admin for the contract.
pub fn try_set_admin(
    deps: DepsMut,
    info: MessageInfo,
    public_address: String,
) -> StdResult<Response> {
    let mut config = config(deps.storage);
    let mut state = config.load()?;

    if info.sender != state.admin {
        return Err(StdError::generic_err(
            "Only the current admin can set a new admin",
        ));
    }

    let final_address = deps.api.addr_validate(&public_address).map_err(|err| {
        StdError::generic_err(format!("Invalid address: {}", err))
    })?;

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

/// Returns the current admin address.
fn get_admin(deps: Deps) -> StdResult<Addr> {
    let state = config_read(deps.storage).load()?;
    Ok(state.admin)
}

/// Queries subscriber status using a permit.
fn query_subscriber_with_permit(
    deps: Deps,
    env: Env,
    public_key: String,
    permit: Permit,
) -> StdResult<SubscriberStatusResponse> {
    let state = config_read(deps.storage).load()?;
    let admin_addr = state.admin;

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

    if signer_addr != admin_addr {
        return Err(StdError::generic_err("Unauthorized: not the admin"));
    }

    let subscriber = SB_MAP.get(deps.storage, &public_key);
    let active = subscriber.is_some();

    Ok(SubscriberStatusResponse { active })
}

/// Queries all API keys using a permit. The stored hash is returned directly.
fn query_api_keys_with_permit(
    deps: Deps,
    env: Env,
    permit: Permit,
) -> StdResult<GetApiKeysResponse> {
    let state = config_read(deps.storage).load()?;
    let admin_addr = state.admin;

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

    if signer_addr != admin_addr {
        return Err(StdError::generic_err("Unauthorized: not the admin"));
    }

    let api_keys: Vec<ApiKeyResponse> = API_KEY_MAP
        .iter(deps.storage)?
        .filter_map(|result| {
            if let Ok((_key, data)) = result {
                Some(ApiKeyResponse { hashed_key: data.hash })
            } else {
                None
            }
        })
        .collect();

    Ok(GetApiKeysResponse { api_keys })
}

/// Queries API keys by identity using a permit.
fn query_api_keys_by_identity_with_permit(
    deps: Deps,
    env: Env,
    identity: String,
    permit: Permit,
) -> StdResult<ApiKeysByIdentityResponse> {
    let state = config_read(deps.storage).load()?;
    let admin_addr = state.admin;

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

    if signer_addr != admin_addr {
        return Err(StdError::generic_err("Unauthorized: not the admin"));
    }

    let api_keys: Vec<ApiKeyDetail> = API_KEY_MAP
        .iter(deps.storage)?
        .filter_map(|result| {
            if let Ok((key, data)) = result {
                if data.identity == identity {
                    return Some(ApiKeyDetail {
                        api_key: key, // string representation
                        name: data.name,
                        created: data.created,
                    });
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
        attr, from_binary, BlockInfo, Coin, ContractInfo, Timestamp, TransactionInfo, Uint128, Addr,
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

        // Initialize contract with admin address.
        let info = mock_info("admin", &[]);
        let init_msg = InstantiateMsg {};
        instantiate(deps.as_mut(), mock_env(), info.clone(), init_msg).unwrap();

        // Add two API keys with different identities.
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                identity: "user1".to_string(),
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
                identity: "user2".to_string(),
                name: None,
                created: None,
            },
        )
            .unwrap();

        // Ensure two keys are added.
        let keys: Vec<String> = API_KEY_MAP
            .iter_keys(deps.as_ref().storage)
            .unwrap()
            .filter_map(|res| res.ok())
            .collect();
        assert_eq!(keys.len(), 2);

        // Migrate (clear) the API key map.
        migrate(deps.as_mut(), mock_env(), MigrateMsg::Migrate {}).unwrap();

        let keys_after: Vec<String> = API_KEY_MAP
            .iter_keys(deps.as_ref().storage)
            .unwrap()
            .filter_map(|res| res.ok())
            .collect();
        assert!(keys_after.is_empty());
    }

    #[test]
    fn test_query_api_keys_with_real_permit() {
        let mut deps = mock_dependencies();
        let info_for_instantiate = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info_for_instantiate.clone(), init_msg).unwrap();

        let info = mock_info("user1", &[]);

        // Add a test API key.
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                identity: "user1".to_string(),
                name: None,
                created: None,
            },
        )
            .unwrap();

        // Read a permit from file "./api_keys_permit.json".
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
        let info_for_instantiate = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info_for_instantiate.clone(), init_msg).unwrap();

        let info = mock_info("user1", &[]);

        // Add an API key.
        let add_res = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                identity: "user1".to_string(),
                name: None,
                created: None,
            },
        )
            .unwrap();

        // Extract the full API key from the response attributes.
        let full_api_key = add_res
            .attributes
            .iter()
            .find(|attr| attr.key == "api_key")
            .expect("Missing api_key attribute")
            .value
            .clone();

        println!("full_api_key: {}", full_api_key);

        // Compute the string representation: first 10 characters + "..." + last 3 characters.
        let str_repr = if full_api_key.len() >= 13 {
            format!(
                "{}...{}",
                &full_api_key[..10],
                &full_api_key[full_api_key.len() - 3..]
            )
        } else {
            full_api_key.clone()
        };

        // Revoke the API key using its string representation.
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::RevokeApiKey {
                api_key: str_repr.clone(),
            },
        )
            .unwrap();

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
        let info = mock_info("user1", &[]);
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

        // Add API keys for different identities.
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                identity: "user_123".to_string(),
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
                identity: "user_123".to_string(),
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
                identity: "user_456".to_string(),
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

        // Verify that only keys belonging to "user_123" are returned.
        assert_eq!(response.api_keys.len(), 2);
        for key_detail in response.api_keys {
            assert!(!key_detail.api_key.is_empty());
            match key_detail.name.as_deref() {
                Some("Test Key 1") => assert_eq!(key_detail.created, Some(1000)),
                Some("Test Key 2") => assert_eq!(key_detail.created, Some(2000)),
                _ => panic!("Unexpected key detail returned"),
            }
        }
    }

    #[test]
    fn test_query_api_keys_by_empty_identity_with_permit() {
        let mut deps = mock_dependencies();
        let info = mock_info("secret1p55wr2n6f63wyap8g9dckkxmf4wvq73ensxrw4", &[]);
        let init_msg = InstantiateMsg {};
        let env = mock_env_for_permit();

        instantiate(deps.as_mut(), env.clone(), info.clone(), init_msg).unwrap();

        // Add API keys for specific identities.
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::AddApiKey {
                identity: "user_123".to_string(),
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
                identity: "user_456".to_string(),
                name: Some("Key 2".to_string()),
                created: Some(2000),
            },
        )
            .unwrap();

        // Query with an empty identity should return an empty result.
        let json_data = std::fs::read_to_string("./api_keys_by_identity_permit.json")
            .expect("Failed to read permit.json");
        let permit: secret_toolkit::permit::Permit =
            serde_json::from_str(&json_data).expect("Could not parse Permit from JSON");

        let query_msg = QueryMsg::ApiKeysByIdentityWithPermit {
            identity: "".to_string(),
            permit,
        };
        let bin = query(deps.as_ref(), env.clone(), query_msg).unwrap();
        let response: ApiKeysByIdentityResponse = from_binary(&bin).unwrap();

        assert_eq!(response.api_keys.len(), 0);
    }
}
