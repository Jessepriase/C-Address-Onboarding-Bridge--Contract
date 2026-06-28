#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env, Map, Symbol,
    Val, Vec,
};

#[cfg(target_family = "wasm")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(target_family = "wasm")]
#[alloc_error_handler]
fn alloc_error(_: core::alloc::Layout) -> ! {
    core::arch::wasm32::unreachable()
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BridgeError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    InvalidAmount = 3,
    FeeTooHigh = 4,
    MismatchedArrays = 5,
    ContractPaused = 6,
    AddressBlocked = 7,
    AddressNotAllowlisted = 8,
    InsufficientReclaimable = 9,
    AssetNotWhitelisted = 10,
    DailyLimitExceeded = 11,
    DuplicateNonce = 12,
    TransactionExpired = 13,
    LoyaltyTokenNotSet = 14,
    ReplayedNonce = 15,
    NotRelayer = 16,
    BelowThreshold = 17,
    ThresholdExceedsRelayers = 18,
    TimelockNotFound = 19,
    TimelockNotMatured = 20,
    InvalidReleaseTime = 21,
    Unauthorized = 22,
    // Issue #95: replay protection for Soroban authorization entries
    AuthNonceAlreadyUsed = 23,
    AuthNonceExpired = 24,
}

#[contracttype]
pub enum DataKey {
    Admin,
    FeeCollector,
    FeeBps,
    Initialized,
    Paused,
    Blocked(Address),
    Allowlisted(Address),
    AllowlistMode,
    AccruedFees(Address),
    AssetWhitelist,
    TotalBridged(Address),
    TotalFeesCollected(Address),
    SourceDailyLimit(Address, Address),
    AssetFeeCap(Address),
    Nonce(Address),
    ReferralRate,
    // Extended variants used throughout the contract
    Config,
    AssetStats(Address),
    Relayer(BytesN<32>),
    RelayerCount,
    RelayerThreshold,
    CrossChainNonce(BytesN<32>),
    DailyUsage(Address, Address, u64),
    FeeTiers,
    SourceBridgedVolume(Address),
    LoyaltyToken,
    LoyaltyAmountPerFund,
    TimelockId,
    Timelock(u64),
    UserDeposit(Address, Address),
    MaxInstanceTtl,
    MaxPersistentTtl,
    BridgeConfig,
    // Issue #95: per-address auth nonce counter and used-nonce set
    AuthNonce(Address),
    UsedAuthNonce(Address, u64),
}

const MAX_FEE_BPS: u32 = 1_000;
const FEE_DENOMINATOR: i128 = 10_000;
const MAX_BATCH_SIZE: u32 = 100;
const MAX_ALLOWED_TTL: u32 = 3_110_400; // ~1 year in ledgers (5s/ledger)
const CRITICAL_ENTRY_TTL_THRESHOLD: u32 = 100_000;

// --- Packed BridgeConfig struct (fee_bps + paused + allowlist_mode) ---

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    pub fee_bps: u32,
    pub paused: bool,
    pub allowlist_mode: bool,
}

// BridgeConfigData: admin + fee_collector + fee_bps snapshot (used in initialize)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeConfigData {
    pub admin: Address,
    pub fee_collector: Address,
    pub fee_bps: u32,
}

// --- Asset counters ---

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetCounters {
    pub accrued_fees: i128,
    pub total_bridged: i128,
    pub total_fees_collected: i128,
}

// --- Fee tier ---

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeTier {
    pub min_volume: i128,
    pub max_volume: i128,
    pub fee_bps: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayerSig {
    pub pubkey: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockEntry {
    pub source: Address,
    pub target: Address,
    pub asset: Address,
    pub amount: i128,
    pub release_time: u64,
    pub cliff_time: u64,
    pub claimed: bool,
}

fn read_bridge_config(env: &Env) -> BridgeConfigData {
    env.storage()
        .instance()
        .get(&DataKey::BridgeConfig)
        .unwrap_or(BridgeConfigData {
            admin: read_admin(env),
            fee_collector: read_fee_collector(env),
            fee_bps: read_fee_bps(env),
        })
}

fn save_bridge_config(env: &Env, cfg: &BridgeConfigData) {
    env.storage()
        .instance()
        .set(&DataKey::BridgeConfig, cfg);
}

fn read_max_instance_ttl(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::MaxInstanceTtl)
        .unwrap_or(MAX_ALLOWED_TTL)
}

fn read_max_persistent_ttl(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::MaxPersistentTtl)
        .unwrap_or(MAX_ALLOWED_TTL)
}

fn extend_instance_ttl(env: &Env) {
    let max_ttl = read_max_instance_ttl(env);
    let threshold = max_ttl / 4;
    env.storage().instance().extend_ttl(threshold, max_ttl);
}

fn next_timelock_id(env: &Env) -> u64 {
    let id: u64 = env
        .storage()
        .instance()
        .get(&DataKey::TimelockId)
        .unwrap_or(0u64);
    env.storage()
        .instance()
        .set(&DataKey::TimelockId, &(id + 1));
    id
}

fn save_timelock_entry(env: &Env, id: u64, entry: &TimelockEntry) {
    env.storage()
        .persistent()
        .set(&DataKey::Timelock(id), entry);
}

fn read_timelock_entry(env: &Env, id: u64) -> Option<TimelockEntry> {
    env.storage().persistent().get(&DataKey::Timelock(id))
}

fn increment_user_deposit(env: &Env, source: &Address, asset: &Address, amount: i128) {
    let key = DataKey::UserDeposit(source.clone(), asset.clone());
    let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage()
        .persistent()
        .set(&key, &(current + amount));
}

#[inline(never)]
fn save_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&DataKey::Admin, admin);
}

#[inline(never)]
fn read_admin(env: &Env) -> Address {
    env.storage().instance().get(&DataKey::Admin).unwrap()
}

#[inline(never)]
fn save_fee_collector(env: &Env, addr: &Address) {
    env.storage().instance().set(&DataKey::FeeCollector, addr);
}

#[inline(never)]
fn read_fee_collector(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::FeeCollector)
        .unwrap()
}

// --- Packed BridgeConfig accessors (fee_bps + paused + allowlist_mode in one entry) ---

fn read_config(env: &Env) -> BridgeConfig {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .unwrap_or(BridgeConfig {
            fee_bps: 0,
            paused: false,
            allowlist_mode: false,
        })
}

fn save_config(env: &Env, config: &BridgeConfig) {
    env.storage().instance().set(&DataKey::Config, config);
}

fn save_fee_bps(env: &Env, fee_bps: &u32) {
    let mut config = read_config(env);
    config.fee_bps = *fee_bps;
    save_config(env, &config);
    env.storage().instance().set(&DataKey::FeeBps, fee_bps);
}

fn read_fee_bps(env: &Env) -> u32 {
    read_config(env).fee_bps
}

fn read_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Initialized)
}

fn mark_initialized(env: &Env) {
    env.storage().instance().set(&DataKey::Initialized, &true);
}

#[inline(never)]
fn save_minimum_amount(env: &Env, amount: &i128) {
    let _ = (env, amount);
}

#[inline(never)]
fn read_minimum_amount(env: &Env) -> i128 {
    let _ = env;
    0
}

fn check_initialized(env: &Env) -> Result<(), BridgeError> {
    if !read_initialized(env) {
        return Err(BridgeError::NotInitialized);
    }
    Ok(())
}

fn read_paused(env: &Env) -> bool {
    read_config(env).paused
}

fn set_paused(env: &Env, paused: bool) {
    let mut config = read_config(env);
    config.paused = paused;
    save_config(env, &config);
    env.storage().instance().set(&DataKey::Paused, &paused);
}

fn check_not_paused(env: &Env) -> Result<(), BridgeError> {
    if read_paused(env) {
        return Err(BridgeError::ContractPaused);
    }
    Ok(())
}

#[inline(always)]
fn calculate_fee(amount: i128, fee_bps: u32) -> i128 {
    if fee_bps == 0 {
        return 0;
    }
    let bps = fee_bps as i128;
    // Use checked arithmetic to guard against overflow on very large amounts.
    // If checked_mul overflows i128 (amount > ~1.7e38 / 1000), fall back to
    // dividing first at the cost of minor precision loss.
    match amount.checked_mul(bps) {
        Some(product) => product / FEE_DENOMINATOR,
        None => (amount / FEE_DENOMINATOR) * bps,
    }
}

fn is_blocked(env: &Env, addr: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Blocked(addr.clone()))
        .unwrap_or(false)
}

fn is_allowlisted(env: &Env, addr: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Allowlisted(addr.clone()))
        .unwrap_or(false)
}

fn allowlist_mode(env: &Env) -> bool {
    read_config(env).allowlist_mode
}

fn set_allowlist_mode_flag(env: &Env, enabled: bool) {
    let mut config = read_config(env);
    config.allowlist_mode = enabled;
    save_config(env, &config);
    env.storage()
        .instance()
        .set(&DataKey::AllowlistMode, &enabled);
}

fn check_access(env: &Env, target: &Address) -> Result<(), BridgeError> {
    if is_blocked(env, target) {
        return Err(BridgeError::AddressBlocked);
    }
    if allowlist_mode(env) && !is_allowlisted(env, target) {
        return Err(BridgeError::AddressNotAllowlisted);
    }
    Ok(())
}

#[inline(never)]
fn read_whitelist(env: &Env) -> Map<Address, bool> {
    env.storage()
        .instance()
        .get(&DataKey::AssetWhitelist)
        .unwrap_or_else(|| Map::new(env))
}

#[inline(never)]
fn save_whitelist(env: &Env, whitelist: &Map<Address, bool>) {
    env.storage()
        .instance()
        .set(&DataKey::AssetWhitelist, whitelist);
}

fn check_asset_whitelisted(env: &Env, asset: &Address) -> Result<(), BridgeError> {
    if !read_whitelist(env).get(asset.clone()).unwrap_or(false) {
        return Err(BridgeError::AssetNotWhitelisted);
    }
    Ok(())
}

// --- Packed AssetCounters accessors (3 i128 counters in one persistent entry per asset) ---

fn read_asset_counters(env: &Env, asset: &Address) -> AssetCounters {
    env.storage()
        .persistent()
        .get(&DataKey::AssetStats(asset.clone()))
        .unwrap_or(AssetCounters {
            accrued_fees: 0,
            total_bridged: 0,
            total_fees_collected: 0,
        })
}

fn save_asset_counters(env: &Env, asset: &Address, counters: &AssetCounters) {
    env.storage()
        .persistent()
        .set(&DataKey::AssetStats(asset.clone()), counters);
    env.storage()
        .persistent()
        .set(&DataKey::AccruedFees(asset.clone()), &counters.accrued_fees);
    env.storage()
        .persistent()
        .set(&DataKey::TotalBridged(asset.clone()), &counters.total_bridged);
    env.storage()
        .persistent()
        .set(
            &DataKey::TotalFeesCollected(asset.clone()),
            &counters.total_fees_collected,
        );
}

fn read_accrued_fees(env: &Env, asset: &Address) -> i128 {
    read_asset_counters(env, asset).accrued_fees
}

fn increment_accrued_fees(env: &Env, asset: &Address, amount: i128) {
    let mut c = read_asset_counters(env, asset);
    c.accrued_fees += amount;
    save_asset_counters(env, asset, &c);
}

fn decrement_accrued_fees(env: &Env, asset: &Address, amount: i128) {
    let mut c = read_asset_counters(env, asset);
    c.accrued_fees -= amount;
    save_asset_counters(env, asset, &c);
}

fn read_total_bridged(env: &Env, asset: &Address) -> i128 {
    read_asset_counters(env, asset).total_bridged
}

fn increment_total_bridged(env: &Env, asset: &Address, amount: i128) {
    let mut c = read_asset_counters(env, asset);
    c.total_bridged += amount;
    save_asset_counters(env, asset, &c);
}

fn read_total_fees_collected(env: &Env, asset: &Address) -> i128 {
    read_asset_counters(env, asset).total_fees_collected
}

fn increment_total_fees_collected(env: &Env, asset: &Address, amount: i128) {
    let mut c = read_asset_counters(env, asset);
    c.total_fees_collected += amount;
    save_asset_counters(env, asset, &c);
}

/// Atomically update all three counters in a single storage read+write
fn update_asset_counters(env: &Env, asset: &Address, fees: i128, bridged: i128) {
    let mut c = read_asset_counters(env, asset);
    c.accrued_fees += fees;
    c.total_bridged += bridged;
    c.total_fees_collected += fees;
    save_asset_counters(env, asset, &c);
}

fn read_nonce(env: &Env, caller: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Nonce(caller.clone()))
        .unwrap_or(0)
}

/// If `nonce` is `Some(n)`, verify it equals the caller's current nonce then increment.
/// If `None`, no check is performed (standard Stellar tx path — replay prevented by sequence number).
fn consume_nonce(env: &Env, caller: &Address, nonce: Option<u64>) -> Result<(), BridgeError> {
    if let Some(n) = nonce {
        let stored = read_nonce(env, caller);
        if n != stored {
            return Err(BridgeError::DuplicateNonce);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Nonce(caller.clone()), &(stored + 1));
    }
    Ok(())
}

// --- Issue #95: Replay protection for Soroban authorization entries ---
//
// An "auth nonce" is a monotonically increasing u64 counter per source address.
// A caller commits to a specific nonce **and** a ledger-sequence window
// [valid_after_ledger, valid_before_ledger).  The contract:
//   1. Binds the nonce to the current contract ID (implicitly — stored under this
//      contract's own persistent storage, keyed by source address).
//   2. Checks that the current ledger sequence is within the caller-supplied window.
//   3. Records the (source, nonce) pair as used, preventing replay in any future
//      transaction regardless of ledger sequence.
//   4. Emits `AuthUsed(source, nonce)` so off-chain indexers can track usage.

fn read_auth_nonce(env: &Env, source: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::AuthNonce(source.clone()))
        .unwrap_or(0)
}

fn is_auth_nonce_used(env: &Env, source: &Address, nonce: u64) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::UsedAuthNonce(source.clone(), nonce))
        .unwrap_or(false)
}

fn mark_auth_nonce_used(env: &Env, source: &Address, nonce: u64) {
    env.storage()
        .persistent()
        .set(&DataKey::UsedAuthNonce(source.clone(), nonce), &true);
    // Advance the per-address counter so clients can always discover the next
    // expected nonce without scanning storage.
    let current = read_auth_nonce(env, source);
    if nonce >= current {
        env.storage()
            .persistent()
            .set(&DataKey::AuthNonce(source.clone()), &(nonce + 1));
    }
}

/// Validate and consume a Soroban authorization-entry nonce.
///
/// Parameters
/// - `source`              : address whose auth entry is being validated
/// - `nonce`               : caller-supplied nonce (must not have been used before)
/// - `valid_after_ledger`  : inclusive lower bound on `env.ledger().sequence()`
/// - `valid_before_ledger` : exclusive upper bound on `env.ledger().sequence()`
///
/// On success the nonce is marked used and `AuthUsed(source, nonce)` is emitted.
fn consume_auth_nonce(
    env: &Env,
    source: &Address,
    nonce: u64,
    valid_after_ledger: u32,
    valid_before_ledger: u32,
) -> Result<(), BridgeError> {
    // 1. Ledger-sequence window check (guards against stale / premature replays)
    let seq = env.ledger().sequence();
    if seq < valid_after_ledger || seq >= valid_before_ledger {
        return Err(BridgeError::AuthNonceExpired);
    }

    // 2. Used-nonce check (prevents exact replay of this (source, nonce) pair)
    if is_auth_nonce_used(env, source, nonce) {
        return Err(BridgeError::AuthNonceAlreadyUsed);
    }

    // 3. Mark as used and advance the per-address counter
    mark_auth_nonce_used(env, source, nonce);

    // 4. Emit AuthUsed event for off-chain indexers
    env.events()
        .publish(("AuthUsed", source.clone()), (nonce,));

    Ok(())
}

// --- Referral rate helpers ---

fn save_referral_rate(env: &Env, bps: u32) {
    env.storage().instance().set(&DataKey::ReferralRate, &bps);
}

fn read_referral_rate(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::ReferralRate)
        .unwrap_or(0)
}

// --- Cross-chain relayer registry ---

fn relayer_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::RelayerCount)
        .unwrap_or(0u32)
}

fn is_relayer(env: &Env, pubkey: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Relayer(pubkey.clone()))
        .unwrap_or(false)
}

fn add_relayer(env: &Env, pubkey: &BytesN<32>) {
    if !is_relayer(env, pubkey) {
        env.storage()
            .persistent()
            .set(&DataKey::Relayer(pubkey.clone()), &true);
        env.storage()
            .instance()
            .set(&DataKey::RelayerCount, &(relayer_count(env) + 1));
    }
}

fn remove_relayer(env: &Env, pubkey: &BytesN<32>) {
    if is_relayer(env, pubkey) {
        env.storage()
            .persistent()
            .remove(&DataKey::Relayer(pubkey.clone()));
        let count = relayer_count(env);
        env.storage()
            .instance()
            .set(&DataKey::RelayerCount, &(count.saturating_sub(1)));
    }
}

fn relayer_threshold(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::RelayerThreshold)
        .unwrap_or(1u32)
}

fn save_relayer_threshold(env: &Env, threshold: u32) {
    env.storage()
        .instance()
        .set(&DataKey::RelayerThreshold, &threshold);
}

fn is_nonce_used(env: &Env, nonce: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::CrossChainNonce(nonce.clone()))
        .unwrap_or(false)
}

fn mark_nonce_used(env: &Env, nonce: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&DataKey::CrossChainNonce(nonce.clone()), &true);
}

// --- Daily limit helpers ---

fn save_source_daily_limit(env: &Env, source: &Address, asset: &Address, limit: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::SourceDailyLimit(source.clone(), asset.clone()), &limit);
}

fn read_source_daily_limit(env: &Env, source: &Address, asset: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::SourceDailyLimit(source.clone(), asset.clone()))
        .unwrap_or(0)
}

fn current_day(env: &Env) -> u64 {
    env.ledger().timestamp() / 86_400
}

fn check_daily_limit(env: &Env, source: &Address, asset: &Address, amount: i128) -> Result<(), BridgeError> {
    let limit = read_source_daily_limit(env, source, asset);
    if limit == 0 {
        return Ok(()); // no limit set
    }
    let day = current_day(env);
    let key = DataKey::DailyUsage(source.clone(), asset.clone(), day);
    let used: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    if used + amount > limit {
        return Err(BridgeError::DailyLimitExceeded);
    }
    env.storage().persistent().set(&key, &(used + amount));
    Ok(())
}

// --- Asset fee cap helpers ---

fn save_asset_fee_cap(env: &Env, asset: &Address, max_fee_bps: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::AssetFeeCap(asset.clone()), &max_fee_bps);
}

fn read_asset_fee_cap(env: &Env, asset: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::AssetFeeCap(asset.clone()))
        .unwrap_or(MAX_FEE_BPS)
}

#[inline(always)]
fn get_effective_fee_bps(env: &Env, asset: &Address, global_fee_bps: u32) -> u32 {
    if global_fee_bps == 0 {
        return 0;
    }
    let cap = read_asset_fee_cap(env, asset);
    global_fee_bps.min(cap)
}

// --- Fee tier helpers ---

fn save_fee_tiers(env: &Env, tiers: &Vec<FeeTier>) {
    env.storage().instance().set(&DataKey::FeeTiers, tiers);
}

fn read_fee_tiers(env: &Env) -> Option<Vec<FeeTier>> {
    env.storage().instance().get(&DataKey::FeeTiers)
}

fn read_source_bridged_volume(env: &Env, source: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::SourceBridgedVolume(source.clone()))
        .unwrap_or(0)
}

fn increment_source_bridged_volume(env: &Env, source: &Address, amount: i128) {
    let current = read_source_bridged_volume(env, source);
    env.storage()
        .persistent()
        .set(&DataKey::SourceBridgedVolume(source.clone()), &(current + amount));
}

fn get_tiered_fee_bps(env: &Env, source: &Address, fallback_bps: u32) -> u32 {
    if let Some(tiers) = read_fee_tiers(env) {
        let volume = read_source_bridged_volume(env, source);
        for i in 0..tiers.len() {
            let tier = tiers.get(i).unwrap();
            if volume >= tier.min_volume && volume <= tier.max_volume {
                return tier.fee_bps;
            }
        }
    }
    fallback_bps
}

fn find_current_tier(env: &Env, source: &Address) -> Option<FeeTier> {
    if let Some(tiers) = read_fee_tiers(env) {
        let volume = read_source_bridged_volume(env, source);
        for i in 0..tiers.len() {
            let tier = tiers.get(i).unwrap();
            if volume >= tier.min_volume && volume <= tier.max_volume {
                return Some(tier);
            }
        }
    }
    None
}

// --- Loyalty token helpers ---

fn save_loyalty_token(env: &Env, token: &Address) {
    env.storage().instance().set(&DataKey::LoyaltyToken, token);
}

fn read_loyalty_token(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::LoyaltyToken)
}

fn save_loyalty_amount_per_fund(env: &Env, amount: &i128) {
    env.storage()
        .instance()
        .set(&DataKey::LoyaltyAmountPerFund, amount);
}

fn read_loyalty_amount_per_fund(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::LoyaltyAmountPerFund)
        .unwrap_or(0)
}

fn mint_loyalty_tokens(env: &Env, recipient: &Address) {
    if let Some(loyalty_token) = read_loyalty_token(env) {
        let amount = read_loyalty_amount_per_fund(env);
        if amount > 0 {
            let token_client = token::Client::new(env, &loyalty_token);
            token_client.transfer(&env.current_contract_address(), recipient, &amount);
        }
    }
}

#[contract]
pub struct OnboardingBridge;

#[contractimpl]
impl OnboardingBridge {
    pub fn initialize(
        env: Env,
        admin: Address,
        fee_collector: Address,
        fee_bps: u32,
        nonce: Option<u64>,
    ) -> Result<(), BridgeError> {
        if read_initialized(&env) {
            return Err(BridgeError::AlreadyInitialized);
        }
        if fee_bps > MAX_FEE_BPS {
            return Err(BridgeError::FeeTooHigh);
        }
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        save_admin(&env, &admin);
        save_fee_collector(&env, &fee_collector);
        save_fee_bps(&env, &fee_bps);
        save_bridge_config(&env, &BridgeConfigData {
            admin: admin.clone(),
            fee_collector: fee_collector.clone(),
            fee_bps,
        });
        mark_initialized(&env);
        extend_instance_ttl(&env);
        env.events()
            .publish(("Initialized", admin.clone(), fee_collector.clone()), (fee_bps,));
        Ok(())
    }

    pub fn fund_c_address(
        env: Env,
        source: Address,
        target: Address,
        asset: Address,
        amount: i128,
        nonce: Option<u64>,
        deadline: Option<u64>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if let Some(d) = deadline {
            if env.ledger().timestamp() > d {
                return Err(BridgeError::TransactionExpired);
            }
        }
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        check_access(&env, &target)?;
        check_asset_whitelisted(&env, &asset)?;
        check_daily_limit(&env, &source, &asset, amount)?;
        source.require_auth();
        consume_nonce(&env, &source, nonce)?;

        let token_client = token::Client::new(&env, &asset);
        let contract_addr = env.current_contract_address();
        token_client.transfer(&source, &contract_addr, &amount);

        let global_fee_bps = read_fee_bps(&env);
        let tiered_fee_bps = get_tiered_fee_bps(&env, &source, global_fee_bps);
        let effective_fee_bps = get_effective_fee_bps(&env, &asset, tiered_fee_bps);
        let fee = calculate_fee(amount, effective_fee_bps);
        let net_amount = amount - fee;

        if net_amount > 0 {
            token_client.transfer(&contract_addr, &target, &net_amount);
        }

        increment_user_deposit(&env, &source, &asset, amount);
        increment_accrued_fees(&env, &asset, fee);
        increment_total_bridged(&env, &asset, net_amount);
        increment_total_fees_collected(&env, &asset, fee);
        increment_source_bridged_volume(&env, &source, amount);

        mint_loyalty_tokens(&env, &source);

        env.events()
            .publish(("CAddressFunded", source, target), (amount, fee, asset));
        Ok(())
    }

    pub fn batch_fund_c_address(
        env: Env,
        source: Address,
        targets: Vec<Address>,
        amounts: Vec<i128>,
        asset: Address,
        nonce: Option<u64>,
        deadline: Option<u64>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if let Some(d) = deadline {
            if env.ledger().timestamp() > d {
                return Err(BridgeError::TransactionExpired);
            }
        }
        if targets.len() != amounts.len() {
            return Err(BridgeError::MismatchedArrays);
        }
        if targets.len() == 0 {
            return Ok(());
        }
        check_asset_whitelisted(&env, &asset)?;
        source.require_auth();
        consume_nonce(&env, &source, nonce)?;

        let mut total: i128 = 0;
        for i in 0..targets.len() {
            let amount = amounts.get(i).unwrap();
            if amount <= 0 {
                return Err(BridgeError::InvalidAmount);
            }
            total += amount;
        }

        let token_client = token::Client::new(&env, &asset);
        token_client.transfer(&source, &env.current_contract_address(), &total);

        // Cache effective fee bps once — same asset for entire batch
        let fee_bps = read_fee_bps(&env);
        let effective_fee_bps = get_effective_fee_bps(&env, &asset, fee_bps);
        let contract_addr = env.current_contract_address();
        token_client.transfer(&source, &contract_addr, &total);

        let config = read_bridge_config(&env);
        let effective_fee_bps = get_effective_fee_bps(&env, &asset, config.fee_bps);
        let mut num_success = 0u32;
        let mut num_failures = 0u32;
        let mut refund_amount = 0i128;
        let mut total_fees = 0i128;
        let mut total_bridged = 0i128;

        // Aggregate net amounts per target to combine transfers to the same address
        let mut aggregated: Map<Address, i128> = Map::new(&env);

        for i in 0..targets.len() {
            let target = targets.get(i).unwrap();
            let amount = amounts.get(i).unwrap();

            let fee = calculate_fee(amount, effective_fee_bps);
            let net_amount = amount - fee;

            if check_access(&env, &target).is_err() {
                num_failures += 1;
                refund_amount += amount;
                env.events().publish(
                    ("BatchTransferFailed", source.clone(), target.clone()),
                    (amount, "access_denied"),
                );
                continue;
            }

            num_success += 1;
            total_fees += fee;
            total_bridged += net_amount;

            if net_amount > 0 {
                let existing = aggregated.get(target.clone()).unwrap_or(0);
                aggregated.set(target.clone(), existing + net_amount);
            }

            env.events().publish(
                ("CAddressFunded", source.clone(), target),
                (amount, fee, asset.clone()),
            );
        }

        // Execute one transfer per unique target instead of N
        for target_addr in aggregated.keys() {
            let combined_amount = aggregated.get(target_addr.clone()).unwrap();
            if combined_amount > 0 {
                token_client.transfer(&contract_addr, &target_addr, &combined_amount);
            }
        }

        // Batch-update all counters in a single storage read+write
        if total_fees > 0 || total_bridged > 0 {
            update_asset_counters(&env, &asset, total_fees, total_bridged);
        }

        if refund_amount > 0 {
            token_client.transfer(&contract_addr, &source, &refund_amount);
        }

        env.events().publish(
            ("BatchCompleted", source),
            (num_success, num_failures),
        );
        Ok(())
    }

    pub fn set_fee_bps(env: Env, new_fee_bps: u32, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if new_fee_bps > MAX_FEE_BPS {
            return Err(BridgeError::FeeTooHigh);
        }
        let mut config = read_bridge_config(&env);
        config.admin.require_auth();
        consume_nonce(&env, &config.admin, nonce)?;
        let old_fee_bps = config.fee_bps;
        config.fee_bps = new_fee_bps;
        save_fee_bps(&env, &new_fee_bps);
        save_bridge_config(&env, &config);
        env.events()
            .publish(("FeeBpsChanged", old_fee_bps, new_fee_bps), (config.admin,));
        Ok(())
    }

    pub fn set_source_daily_limit(
        env: Env,
        source: Address,
        asset: Address,
        limit_amount: i128,
        nonce: Option<u64>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        save_source_daily_limit(&env, &source, &asset, limit_amount);
        Ok(())
    }

    pub fn query_source_daily_limit(
        env: Env,
        source: Address,
        asset: Address,
    ) -> Result<i128, BridgeError> {
        check_initialized(&env)?;
        Ok(read_source_daily_limit(&env, &source, &asset))
    }

    pub fn set_asset_fee_cap(
        env: Env,
        asset: Address,
        max_fee_bps: u32,
        nonce: Option<u64>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        if max_fee_bps > MAX_FEE_BPS {
            return Err(BridgeError::FeeTooHigh);
        }
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        save_asset_fee_cap(&env, &asset, max_fee_bps);
        Ok(())
    }

    pub fn query_asset_fee_cap(
        env: Env,
        asset: Address,
    ) -> Result<u32, BridgeError> {
        check_initialized(&env)?;
        Ok(read_asset_fee_cap(&env, &asset))
    }

    pub fn set_fee_collector(env: Env, new_fee_collector: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        let mut config = read_bridge_config(&env);
        config.admin.require_auth();
        consume_nonce(&env, &config.admin, nonce)?;
        let old_collector = config.fee_collector.clone();
        config.fee_collector = new_fee_collector.clone();
        save_fee_collector(&env, &new_fee_collector);
        save_bridge_config(&env, &config);
        env.events()
            .publish(("FeeCollectorChanged", old_collector, new_fee_collector), (config.admin,));
        Ok(())
    }

    pub fn set_admin(env: Env, new_admin: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        let mut config = read_bridge_config(&env);
        let old_admin = config.admin.clone();
        config.admin.require_auth();
        consume_nonce(&env, &config.admin, nonce)?;
        config.admin = new_admin.clone();
        save_admin(&env, &new_admin);
        save_bridge_config(&env, &config);
        env.events()
            .publish(("AdminChanged", old_admin, new_admin.clone()), ());
        Ok(())
    }

    pub fn set_minimum_amount(env: Env, amount: i128, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        if amount < 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        save_minimum_amount(&env, &amount);
        Ok(())
    }

    pub fn query_minimum_amount(env: Env) -> Result<i128, BridgeError> {
        check_initialized(&env)?;
        Ok(read_minimum_amount(&env))
    }

    pub fn withdraw_fees(env: Env, asset: Address, amount: i128, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let fee_collector = read_fee_collector(&env);
        fee_collector.require_auth();
        consume_nonce(&env, &fee_collector, nonce)?;

        let token_client = token::Client::new(&env, &asset);
        token_client.transfer(&env.current_contract_address(), &fee_collector, &amount);

        decrement_accrued_fees(&env, &asset, amount);
        env.events()
            .publish(("FeesWithdrawn", fee_collector), (amount, asset));
        Ok(())
    }

    pub fn query_fee_bps(env: Env) -> Result<u32, BridgeError> {
        check_initialized(&env)?;
        Ok(read_fee_bps(&env))
    }

    pub fn set_referral_rate(env: Env, bps: u32, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        if bps > MAX_FEE_BPS {
            return Err(BridgeError::FeeTooHigh);
        }
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        save_referral_rate(&env, bps);
        env.events().publish(("ReferralRateChanged", bps), ());
        Ok(())
    }

    pub fn query_referral_rate(env: Env) -> Result<u32, BridgeError> {
        check_initialized(&env)?;
        Ok(read_referral_rate(&env))
    }

    pub fn fund_c_address_with_referral(
        env: Env,
        source: Address,
        target: Address,
        asset: Address,
        amount: i128,
        referrer: Option<Address>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        check_access(&env, &target)?;
        check_asset_whitelisted(&env, &asset)?;
        check_daily_limit(&env, &source, &asset, amount)?;
        source.require_auth();

        let token_client = token::Client::new(&env, &asset);
        token_client.transfer(&source, &env.current_contract_address(), &amount);

        let global_fee_bps = read_fee_bps(&env);
        let effective_fee_bps = get_effective_fee_bps(&env, &asset, global_fee_bps);
        let fee = calculate_fee(amount, effective_fee_bps);
        let net_amount = amount - fee;

        if net_amount > 0 {
            token_client.transfer(&env.current_contract_address(), &target, &net_amount);
        }

        // Split fee: referral portion goes directly to referrer
        let referral_fee = if let Some(ref referrer_addr) = referrer {
            let referral_rate = read_referral_rate(&env);
            let rf = (fee * referral_rate as i128) / FEE_DENOMINATOR;
            if rf > 0 {
                token_client.transfer(&env.current_contract_address(), referrer_addr, &rf);
                env.events().publish(
                    ("ReferralPaid", source.clone(), referrer_addr.clone()),
                    (rf, asset.clone()),
                );
            }
            rf
        } else {
            0
        };

        let protocol_fee = fee - referral_fee;
        increment_accrued_fees(&env, &asset, protocol_fee);
        increment_total_bridged(&env, &asset, net_amount);
        increment_total_fees_collected(&env, &asset, fee);

        env.events().publish(
            ("CAddressFunded", source, target),
            (amount, fee, asset),
        );
        Ok(())
    }

    pub fn query_fee_collector(env: Env) -> Result<Address, BridgeError> {
        check_initialized(&env)?;
        Ok(read_fee_collector(&env))
    }

    pub fn query_admin(env: Env) -> Result<Address, BridgeError> {
        check_initialized(&env)?;
        Ok(read_admin(&env))
    }

    pub fn query_balance(env: Env, c_address: Address, asset: Address) -> i128 {
        let token_client = token::Client::new(&env, &asset);
        token_client.balance(&c_address)
    }

    pub fn query_all_balances(env: Env, assets: Vec<Address>) -> Map<Address, i128> {
        let contract = env.current_contract_address();
        let mut result: Map<Address, i128> = Map::new(&env);
        for i in 0..assets.len() {
            let asset = assets.get(i).unwrap();
            let balance = token::Client::new(&env, &asset).balance(&contract);
            result.set(asset, balance);
        }
        result
    }

    pub fn query_fee_balance(env: Env, asset: Address) -> Result<i128, BridgeError> {
        check_initialized(&env)?;
        let token_client = token::Client::new(&env, &asset);
        Ok(token_client.balance(&env.current_contract_address()))
    }

    pub fn query_is_initialized(env: Env) -> bool {
        read_initialized(&env)
    }

    pub fn query_nonce(env: Env, caller: Address) -> u64 {
        read_nonce(&env, &caller)
    }

    pub fn query_calculate_fee(env: Env, gross_amount: i128) -> (i128, i128) {
        let fee_bps = read_fee_bps(&env);
        let fee = calculate_fee(gross_amount, fee_bps);
        let net = gross_amount - fee;
        (fee, net)
    }

    pub fn query_total_bridged(env: Env, asset: Address) -> Result<i128, BridgeError> {
        check_initialized(&env)?;
        Ok(read_total_bridged(&env, &asset))
    }

    pub fn query_total_fees_collected(env: Env, asset: Address) -> Result<i128, BridgeError> {
        check_initialized(&env)?;
        Ok(read_total_fees_collected(&env, &asset))
    }

    pub fn pause(env: Env, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        set_paused(&env, true);
        env.events().publish(("ContractPaused",), (admin,));
        Ok(())
    }

    pub fn unpause(env: Env, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        set_paused(&env, false);
        env.events().publish(("ContractUnpaused",), (admin,));
        Ok(())
    }

    pub fn query_is_paused(env: Env) -> bool {
        read_paused(&env)
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());
        env.events().publish(("Upgraded",), (admin, new_wasm_hash));
        Ok(())
    }

    // --- Blocklist / Allowlist ---

    pub fn add_to_blocklist(env: Env, address: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        env.storage()
            .persistent()
            .set(&DataKey::Blocked(address), &true);
        Ok(())
    }

    pub fn remove_from_blocklist(env: Env, address: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Blocked(address));
        Ok(())
    }

    pub fn add_to_allowlist(env: Env, address: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        env.storage()
            .persistent()
            .set(&DataKey::Allowlisted(address), &true);
        Ok(())
    }

    pub fn remove_from_allowlist(env: Env, address: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        env.storage()
            .persistent()
            .remove(&DataKey::Allowlisted(address));
        Ok(())
    }

    pub fn set_allowlist_mode(env: Env, enabled: bool, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        set_allowlist_mode_flag(&env, enabled);
        Ok(())
    }

    pub fn query_is_blocked(env: Env, address: Address) -> bool {
        is_blocked(&env, &address)
    }

    pub fn query_is_allowlisted(env: Env, address: Address) -> bool {
        is_allowlisted(&env, &address)
    }

    pub fn query_allowlist_mode(env: Env) -> bool {
        allowlist_mode(&env)
    }

    pub fn reclaim_tokens(
        env: Env,
        asset: Address,
        amount: i128,
        destination: Address,
        nonce: Option<u64>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;

        let token_client = token::Client::new(&env, &asset);
        let contract_balance = token_client.balance(&env.current_contract_address());
        let accrued = read_accrued_fees(&env, &asset);
        let reclaimable = contract_balance - accrued;

        if reclaimable < amount {
            return Err(BridgeError::InsufficientReclaimable);
        }

        token_client.transfer(&env.current_contract_address(), &destination, &amount);
        env.events()
            .publish(("TokensReclaimed", admin, asset), (amount, destination));
        Ok(())
    }

    // --- Asset Whitelist ---

    pub fn add_asset(env: Env, asset: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        let mut whitelist = read_whitelist(&env);
        whitelist.set(asset, true);
        save_whitelist(&env, &whitelist);
        Ok(())
    }

    pub fn remove_asset(env: Env, asset: Address, nonce: Option<u64>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        consume_nonce(&env, &admin, nonce)?;
        let mut whitelist = read_whitelist(&env);
        whitelist.remove(asset);
        save_whitelist(&env, &whitelist);
        Ok(())
    }

    pub fn query_is_asset_whitelisted(env: Env, asset: Address) -> Result<bool, BridgeError> {
        check_initialized(&env)?;
        Ok(read_whitelist(&env).get(asset).unwrap_or(false))
    }

    pub fn query_whitelisted_assets(env: Env) -> Result<Vec<Address>, BridgeError> {
        check_initialized(&env)?;
        Ok(read_whitelist(&env).keys())
    }

    // --- Loyalty Token ---

    pub fn set_loyalty_token(
        env: Env,
        token: Address,
        amount_per_fund: i128,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        if amount_per_fund < 0 {
            return Err(BridgeError::InvalidAmount);
        }
        save_loyalty_token(&env, &token);
        save_loyalty_amount_per_fund(&env, &amount_per_fund);
        env.events()
            .publish(("LoyaltyTokenSet", admin), (token, amount_per_fund));
        Ok(())
    }

    pub fn query_loyalty_token(env: Env) -> Result<(Address, i128), BridgeError> {
        check_initialized(&env)?;
        let token = read_loyalty_token(&env).ok_or(BridgeError::LoyaltyTokenNotSet)?;
        let amount = read_loyalty_amount_per_fund(&env);
        Ok((token, amount))
    }

    // --- Tiered Fees ---

    pub fn set_fee_tiers(env: Env, tiers: Vec<FeeTier>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        for i in 0..tiers.len() {
            let tier = tiers.get(i).unwrap();
            if tier.fee_bps > MAX_FEE_BPS {
                return Err(BridgeError::FeeTooHigh);
            }
        }
        save_fee_tiers(&env, &tiers);
        env.events()
            .publish(("FeeTiersSet", admin), (tiers.len(),));
        Ok(())
    }

    pub fn query_fee_tiers(env: Env) -> Result<Vec<FeeTier>, BridgeError> {
        check_initialized(&env)?;
        Ok(read_fee_tiers(&env).unwrap_or_else(|| {
            let mut tiers = Vec::new(&env);
            let fee_bps = read_fee_bps(&env);
            tiers.push_back(FeeTier {
                min_volume: 0,
                max_volume: i128::MAX,
                fee_bps,
            });
            tiers
        }))
    }

    pub fn query_current_tier(env: Env, source: Address) -> Result<FeeTier, BridgeError> {
        check_initialized(&env)?;
        Ok(find_current_tier(&env, &source).unwrap_or_else(|| {
            let fee_bps = read_fee_bps(&env);
            FeeTier {
                min_volume: 0,
                max_volume: i128::MAX,
                fee_bps,
            }
        }))
    }

    // --- Cross-chain Onboarding ---

    /// Fund a C-address from a cross-chain event.
    ///
    /// Parameters:
    /// - `chain_id`  : numeric id of the source chain (e.g. 1 = Ethereum, 101 = Solana)
    /// - `tx_hash`   : 32-byte hash of the source-chain transaction
    /// - `target`    : Soroban C-address to credit
    /// - `asset`     : whitelisted token contract address
    /// - `amount`    : gross amount (fee deducted before crediting target)
    /// - `sigs`      : at least `threshold` distinct relayer Ed25519 signatures over
    ///                 sha256(chain_id_be4 || tx_hash || target_bytes || asset_bytes ||
    ///                        amount_be16 || nonce)
    ///                 where nonce = sha256(chain_id_be4 || tx_hash)
    pub fn fund_c_address_crosschain(
        env: Env,
        chain_id: u32,
        tx_hash: BytesN<32>,
        target: Address,
        asset: Address,
        amount: i128,
        sigs: Vec<RelayerSig>,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        check_access(&env, &target)?;
        check_asset_whitelisted(&env, &asset)?;

        // Derive nonce = sha256(chain_id_be4 || tx_hash)
        let mut nonce_pre: soroban_sdk::Bytes = soroban_sdk::Bytes::new(&env);
        nonce_pre.extend_from_array(&chain_id.to_be_bytes());
        let tx_hash_bytes: soroban_sdk::Bytes = tx_hash.clone().into();
        nonce_pre.append(&tx_hash_bytes);
        let nonce: BytesN<32> = env.crypto().sha256(&nonce_pre).into();

        if is_nonce_used(&env, &nonce) {
            return Err(BridgeError::ReplayedNonce);
        }

        // Build payload hash = sha256(chain_id_be4 || tx_hash || target_bytes ||
        //                              asset_bytes || amount_be16 || nonce)
        // Note: soroban-sdk 22 does not expose Address::to_xdr.
        // We represent each address as a sha256 hash of its strkey bytes so the
        // payload is still domain-separated and collision-resistant.
        let target_strkey = target.clone().to_string();
        let asset_strkey = asset.clone().to_string();
        let mut addr_buf = [0u8; 64];

        let tlen = target_strkey.len() as usize;
        target_strkey.copy_into_slice(&mut addr_buf[..tlen]);
        let target_raw = soroban_sdk::Bytes::from_slice(&env, &addr_buf[..tlen]);
        let target_hash: BytesN<32> = env.crypto().sha256(&target_raw).into();
        let target_bytes: soroban_sdk::Bytes = target_hash.into();

        let alen = asset_strkey.len() as usize;
        asset_strkey.copy_into_slice(&mut addr_buf[..alen]);
        let asset_raw = soroban_sdk::Bytes::from_slice(&env, &addr_buf[..alen]);
        let asset_hash: BytesN<32> = env.crypto().sha256(&asset_raw).into();
        let asset_bytes: soroban_sdk::Bytes = asset_hash.into();
        let nonce_bytes: soroban_sdk::Bytes = nonce.clone().into();

        let mut payload: soroban_sdk::Bytes = soroban_sdk::Bytes::new(&env);
        payload.extend_from_array(&chain_id.to_be_bytes());
        payload.append(&tx_hash_bytes);
        payload.append(&target_bytes);
        payload.append(&asset_bytes);
        payload.extend_from_array(&amount.to_be_bytes());
        payload.append(&nonce_bytes);

        let payload_hash: BytesN<32> = env.crypto().sha256(&payload).into();

        // Verify M-of-N relayer signatures
        let threshold = relayer_threshold(&env);
        let mut valid: u32 = 0;
        for i in 0..sigs.len() {
            let sig = sigs.get(i).unwrap();
            if !is_relayer(&env, &sig.pubkey) {
                return Err(BridgeError::NotRelayer);
            }
            // Panics (traps) on invalid sig — convert to error via try pattern
            env.crypto()
                .ed25519_verify(&sig.pubkey, &payload_hash.clone().into(), &sig.signature);
            valid += 1;
        }
        if valid < threshold {
            return Err(BridgeError::BelowThreshold);
        }

        // Consume nonce, apply fee, credit target
        mark_nonce_used(&env, &nonce);

        let fee_bps = read_fee_bps(&env);
        let effective_fee_bps = get_effective_fee_bps(&env, &asset, fee_bps);
        let fee = calculate_fee(amount, effective_fee_bps);
        let net_amount = amount - fee;

        let token_client = token::Client::new(&env, &asset);
        if net_amount > 0 {
            token_client.transfer(&env.current_contract_address(), &target, &net_amount);
        }
        update_asset_counters(&env, &asset, fee, net_amount);

        env.events().publish(
            ("CrossChainFunded", target),
            (chain_id, tx_hash, amount, fee, asset),
        );
        Ok(())
    }

    pub fn add_relayer(env: Env, pubkey: BytesN<32>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        read_admin(&env).require_auth();
        add_relayer(&env, &pubkey);
        Ok(())
    }

    pub fn remove_relayer(env: Env, pubkey: BytesN<32>) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        read_admin(&env).require_auth();
        // Prevent removing below threshold
        let new_count = relayer_count(&env).saturating_sub(1);
        if new_count < relayer_threshold(&env) {
            return Err(BridgeError::BelowThreshold);
        }
        remove_relayer(&env, &pubkey);
        Ok(())
    }

    pub fn set_relayer_threshold(env: Env, threshold: u32) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        read_admin(&env).require_auth();
        if threshold > relayer_count(&env) {
            return Err(BridgeError::ThresholdExceedsRelayers);
        }
        save_relayer_threshold(&env, threshold);
        Ok(())
    }

    pub fn query_relayer_threshold(env: Env) -> Result<u32, BridgeError> {
        check_initialized(&env)?;
        Ok(relayer_threshold(&env))
    }

    pub fn query_is_relayer(env: Env, pubkey: BytesN<32>) -> Result<bool, BridgeError> {
        check_initialized(&env)?;
        Ok(is_relayer(&env, &pubkey))
    }

    // --- Timelocked Funding ---

    pub fn fund_c_address_timelocked(
        env: Env,
        source: Address,
        target: Address,
        asset: Address,
        amount: i128,
        release_time: u64,
        cliff_time: u64,
    ) -> Result<u64, BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        if amount <= 0 {
            return Err(BridgeError::InvalidAmount);
        }
        let now = env.ledger().timestamp();
        if release_time <= now {
            return Err(BridgeError::InvalidReleaseTime);
        }
        if cliff_time > 0 && cliff_time > release_time {
            return Err(BridgeError::InvalidReleaseTime);
        }
        check_access(&env, &target)?;
        check_asset_whitelisted(&env, &asset)?;
        source.require_auth();

        token::Client::new(&env, &asset)
            .transfer(&source, &env.current_contract_address(), &amount);

        let id = next_timelock_id(&env);
        save_timelock_entry(
            &env,
            id,
            &TimelockEntry {
                source: source.clone(),
                target: target.clone(),
                asset: asset.clone(),
                amount,
                release_time,
                cliff_time,
                claimed: false,
            },
        );

        env.events().publish(
            ("TimelockCreated", source, target),
            (id, amount, asset, release_time, cliff_time),
        );
        Ok(id)
    }

    pub fn claim_timelocked(env: Env, id: u64) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;

        let mut entry = read_timelock_entry(&env, id)
            .ok_or(BridgeError::TimelockNotFound)?;

        entry.target.require_auth();

        if env.ledger().timestamp() < entry.release_time {
            return Err(BridgeError::TimelockNotMatured);
        }
        if entry.claimed {
            return Err(BridgeError::Unauthorized);
        }

        entry.claimed = true;
        save_timelock_entry(&env, id, &entry);

        let fee_bps = read_fee_bps(&env);
        let effective_fee_bps = get_effective_fee_bps(&env, &entry.asset, fee_bps);
        let fee = calculate_fee(entry.amount, effective_fee_bps);
        let net_amount = entry.amount - fee;

        let token_client = token::Client::new(&env, &entry.asset);
        if net_amount > 0 {
            token_client.transfer(&env.current_contract_address(), &entry.target, &net_amount);
        }
        update_asset_counters(&env, &entry.asset, fee, net_amount);

        env.events().publish(
            ("TimelockClaimed", entry.target),
            (id, net_amount, fee, entry.asset),
        );
        Ok(())
    }

    pub fn query_timelocked(env: Env, id: u64) -> Result<TimelockEntry, BridgeError> {
        read_timelock_entry(&env, id).ok_or(BridgeError::TimelockNotFound)
    }

    // --- TTL Management ---

    pub fn extend_instance_ttl(env: Env, ttl: u32) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        let max_ttl = if ttl > MAX_ALLOWED_TTL {
            MAX_ALLOWED_TTL
        } else {
            ttl
        };
        let threshold = max_ttl / 4;
        env.storage().instance().extend_ttl(threshold, max_ttl);
        env.events()
            .publish(("InstanceTtlExtended",), (admin, max_ttl));
        Ok(())
    }

    pub fn extend_persistent_ttl(
        env: Env,
        key_asset: Address,
        ttl: u32,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        let max_ttl = if ttl > MAX_ALLOWED_TTL {
            MAX_ALLOWED_TTL
        } else {
            ttl
        };
        let threshold = max_ttl / 4;
        let keys = [
            DataKey::AccruedFees(key_asset.clone()),
            DataKey::TotalBridged(key_asset.clone()),
            DataKey::TotalFeesCollected(key_asset.clone()),
        ];
        for key in keys.iter() {
            if env.storage().persistent().has(key) {
                env.storage()
                    .persistent()
                    .extend_ttl(key, threshold, max_ttl);
            }
        }
        env.events()
            .publish(("PersistentTtlExtended",), (admin, key_asset, max_ttl));
        Ok(())
    }

    pub fn set_max_instance_ttl(env: Env, ttl: u32) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        let capped = if ttl > MAX_ALLOWED_TTL {
            MAX_ALLOWED_TTL
        } else {
            ttl
        };
        env.storage()
            .instance()
            .set(&DataKey::MaxInstanceTtl, &capped);
        Ok(())
    }

    pub fn set_max_persistent_ttl(env: Env, ttl: u32) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        let admin = read_admin(&env);
        admin.require_auth();
        let capped = if ttl > MAX_ALLOWED_TTL {
            MAX_ALLOWED_TTL
        } else {
            ttl
        };
        env.storage()
            .instance()
            .set(&DataKey::MaxPersistentTtl, &capped);
        Ok(())
    }

    pub fn query_ttl_config(env: Env) -> Result<(u32, u32, u32, u32), BridgeError> {
        check_initialized(&env)?;
        Ok((
            read_max_instance_ttl(&env),
            read_max_persistent_ttl(&env),
            MAX_ALLOWED_TTL,
            CRITICAL_ENTRY_TTL_THRESHOLD,
        ))
    }

    // --- Issue #95: Replay protection for Soroban authorization entries ---

    /// Validate and consume a Soroban authorization-entry nonce.
    ///
    /// This prevents signature / authorization-entry reuse attacks by:
    /// - Binding the nonce to this contract's own storage (contract ID scoping is
    ///   implicit — nonces live in this contract's persistent storage).
    /// - Enforcing a ledger-sequence window so stale entries cannot be replayed.
    /// - Recording the `(source, nonce)` pair as permanently used.
    /// - Emitting an `AuthUsed(source, nonce)` event for off-chain tracking.
    ///
    /// Parameters
    /// - `source`              : the address whose authorization entry is being consumed
    /// - `nonce`               : the caller-supplied nonce (must be unused)
    /// - `valid_after_ledger`  : inclusive lower bound on the current ledger sequence
    /// - `valid_before_ledger` : exclusive upper bound on the current ledger sequence
    pub fn verify_auth_entry(
        env: Env,
        source: Address,
        nonce: u64,
        valid_after_ledger: u32,
        valid_before_ledger: u32,
    ) -> Result<(), BridgeError> {
        check_initialized(&env)?;
        check_not_paused(&env)?;
        source.require_auth();
        consume_auth_nonce(&env, &source, nonce, valid_after_ledger, valid_before_ledger)
    }

    /// Query the next expected auth nonce for `source`.
    ///
    /// Returns the lowest nonce value that has not yet been used for `source`.
    /// Callers should use this value when constructing a new authorization entry.
    pub fn query_auth_nonce(env: Env, source: Address) -> u64 {
        read_auth_nonce(&env, &source)
    }

    /// Query whether a specific auth nonce has already been used for `source`.
    pub fn query_auth_nonce_used(env: Env, source: Address, nonce: u64) -> bool {
        is_auth_nonce_used(&env, &source, nonce)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod benchmarks;

#[cfg(test)]
mod integration_tests;
