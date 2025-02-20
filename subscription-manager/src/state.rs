use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use secret_toolkit::storage::Keymap;

use cosmwasm_std::{Addr, Storage};
use cosmwasm_storage::{singleton, singleton_read, ReadonlySingleton, Singleton};

/// Storage key for contract configuration
pub static CONFIG_KEY: &[u8] = b"config";

/// Keymap for storing subscribers (keyed by public key)
pub static SB_MAP: Keymap<String, Subscriber> = Keymap::new(b"SB_MAP");

/// Keymap for storing API keys
pub static API_KEY_MAP: Keymap<String, ApiKey> = Keymap::new(b"API_KEY_MAP");

/// Contract state structure containing the admin address
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct State {
    pub admin: Addr,
}

/// Structure representing a subscriber
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct Subscriber {
    pub status: bool,
}

/// Structure representing an API key with additional fields
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct ApiKey {
    pub identity: String, // Associated identity
    pub hash: String,     // Hash of the API key
    pub name: Option<String>,
    pub created: Option<u64>,
}

/// Returns a mutable singleton for contract configuration
pub fn config(storage: &mut dyn Storage) -> Singleton<State> {
    singleton(storage, CONFIG_KEY)
}

/// Returns a read-only singleton for contract configuration
pub fn config_read(storage: &dyn Storage) -> ReadonlySingleton<State> {
    singleton_read(storage, CONFIG_KEY)
}
