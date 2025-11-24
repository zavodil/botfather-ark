//! Bot Father - NEAR Account Manager with derived keys
//!
//! This WASI module allows users to:
//! 1. Create multiple NEAR accounts with AI-generated names
//! 2. List all accounts by scanning derived keys via fastnear API
//! 3. Execute batch contract calls on created accounts
//! 4. Fund accounts with NEAR tokens
//!
//! Key derivation: SHA256(master_key + predecessor + index)
//! - Each user (predecessor/NEAR_SENDER_ID) has their own isolated account list
//! - Master key + different predecessor = completely different account set
//! - Index starts at 0 and increments for each new account
//!
//! Account discovery: Check each derived public key via fastnear API until no account found
//! - Deterministic: same master_key + predecessor always produces same accounts
//! - Stateless: no need to store account list between runs

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read, Write};
use std::time::Duration;
use wasi_http_client::Client;

// Generate bindings for near:rpc/api interface
wit_bindgen::generate!({
    world: "bot-father",
    path: "wit",
});

// ============================================================================
// Input/Output Types
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
enum Input {
    /// Create N new accounts with AI-generated names
    #[serde(rename = "create_accounts")]
    CreateAccounts {
        /// Prompt for AI to generate account names
        prompt: String,
        /// Number of accounts to create
        count: u32,
        /// Deposit per account in yoctoNEAR
        deposit_per_account: String,
    },
    /// Execute contract call for created accounts (batch)
    /// If indices is empty - execute for ALL accounts
    /// If indices has one element - execute for single account
    /// If indices has multiple elements - execute for those accounts
    #[serde(rename = "batch_call")]
    BatchCall {
        contract_id: String,
        method_name: String,
        /// Args template - use {{account_id}} placeholder for current account
        args: serde_json::Value,
        deposit: String,
        gas: String,
        /// Optional list of account indices to execute for (empty = all)
        #[serde(default)]
        indices: Vec<u32>,
    },
    /// List all created accounts by scanning derived keys
    /// If indices is empty - list ALL accounts
    /// If indices has elements - list only those accounts
    #[serde(rename = "list_accounts")]
    ListAccounts {
        /// Optional list of account indices to list (empty = all)
        #[serde(default)]
        indices: Vec<u32>,
    },
    /// Fund accounts with NEAR tokens
    /// Total deposit is split evenly among selected accounts
    #[serde(rename = "fund_accounts")]
    FundAccounts {
        /// Total amount to distribute in yoctoNEAR
        total_amount: String,
        /// Optional list of account indices to fund (empty = all)
        #[serde(default)]
        indices: Vec<u32>,
    },
}

#[derive(Debug, Serialize)]
struct Output {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accounts: Option<Vec<AccountInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transactions: Option<Vec<TxResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AccountInfo {
    index: u32,
    account_id: String,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance_near: Option<String>,
}

#[derive(Debug, Serialize)]
struct TxResult {
    account_id: String,
    tx_hash: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ============================================================================
// Fastnear API Response
// ============================================================================

#[derive(Debug, Deserialize)]
struct PublicKeyApiResponse {
    account_ids: Vec<String>,
    public_key: String,
}

// ============================================================================
// Key Derivation
// ============================================================================

/// Derive a new ed25519 key from master key + predecessor + index using SHA-256
/// Each user (predecessor) gets unique derived keys
fn derive_signing_key(master_key: &SigningKey, predecessor: &str, index: u32) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(master_key.to_bytes());
    hasher.update(predecessor.as_bytes());
    hasher.update(index.to_string().as_bytes());
    let hash = hasher.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);

    SigningKey::from_bytes(&seed)
}

/// Get predecessor account ID from environment
fn get_predecessor() -> Result<String, String> {
    env::var("NEAR_SENDER_ID")
        .map_err(|_| "NEAR_SENDER_ID not found".to_string())
}

/// Parse ed25519 private key from NEAR format (ed25519:base58...)
fn parse_private_key(key_str: &str) -> Result<SigningKey, String> {
    let key_data = if key_str.starts_with("ed25519:") {
        &key_str[8..]
    } else {
        key_str
    };

    let decoded = bs58::decode(key_data)
        .into_vec()
        .map_err(|e| format!("Failed to decode base58: {}", e))?;

    if decoded.len() < 32 {
        return Err(format!("Invalid key length: {}", decoded.len()));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded[..32]);

    Ok(SigningKey::from_bytes(&seed))
}

/// Format public key in NEAR format (ed25519:base58...)
fn format_public_key(verifying_key: &VerifyingKey) -> String {
    format!("ed25519:{}", bs58::encode(verifying_key.as_bytes()).into_string())
}

/// Format private key in NEAR format (ed25519:base58...)
/// NEAR format requires 64 bytes: 32 bytes seed + 32 bytes public key
fn format_private_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let mut full_key = [0u8; 64];
    full_key[..32].copy_from_slice(&signing_key.to_bytes());
    full_key[32..].copy_from_slice(verifying_key.as_bytes());
    format!("ed25519:{}", bs58::encode(&full_key).into_string())
}

// ============================================================================
// Environment
// ============================================================================

/// Get master key from environment (used for derivation only)
fn get_master_key() -> Result<SigningKey, String> {
    let key_str = env::var("BOT_FATHER_MASTER_KEY")
        .map_err(|_| "BOT_FATHER_MASTER_KEY not found")?;

    parse_private_key(&key_str)
}

/// Get NEAR sender account private key from environment (used for signing transactions)
/// This key is passed as a SECRET via OutLayer secrets mechanism in production
fn get_sender_private_key() -> Result<String, String> {
    env::var("NEAR_SENDER_PRIVATE_KEY")
        .map_err(|_| "NEAR_SENDER_PRIVATE_KEY not found (should come from secrets in production)".to_string())
}

/// Get NEAR network (e.g., "testnet" or "near")
fn get_near_network() -> String {
    env::var("NEAR_NETWORK")
        .unwrap_or_else(|_| "testnet".to_string())
}

/// Get fastnear API base URL based on NEAR network
fn get_fastnear_api_url() -> String {
    let network = get_near_network();
    if network == "near" {
        "https://api.fastnear.com".to_string()
    } else {
        "https://test.api.fastnear.com".to_string()
    }
}

/// Format yoctoNEAR balance to NEAR with proper decimal formatting
fn format_balance_near(yocto_balance: &str) -> Option<String> {
    let balance: u128 = yocto_balance.parse().ok()?;
    let near_balance = balance as f64 / 1_000_000_000_000_000_000_000_000.0;
    Some(format!("{:.4}", near_balance))
}

// ============================================================================
// Fastnear API
// ============================================================================

/// Check if public key has an associated account via fastnear API
/// Returns Some(account_id) if found, None if no account
fn get_account_by_public_key(public_key: &str) -> Result<Option<String>, String> {
    let base_url = get_fastnear_api_url();
    let url = format!("{}/v0/public_key/{}", base_url, public_key);

    eprintln!("Checking fastnear: {}", url);

    let response = Client::new()
        .get(&url)
        .connect_timeout(Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    let status = response.status();

    // 404 means no account found
    if status == 404 {
        return Ok(None);
    }

    if status < 200 || status >= 300 {
        let body = response.body().unwrap_or_default();
        let error_text = String::from_utf8_lossy(&body);
        return Err(format!("Fastnear API error {}: {}", status, error_text));
    }

    let response_body = response.body()
        .map_err(|e| format!("Failed to read response: {:?}", e))?;

    let data: PublicKeyApiResponse = serde_json::from_slice(&response_body)
        .map_err(|e| format!("Failed to parse fastnear response: {}", e))?;

    // Return first account if exists
    Ok(data.account_ids.into_iter().next())
}

/// Check if account exists by account_id via fastnear API
fn is_account_exists(account_id: &str) -> bool {
    let base_url = get_fastnear_api_url();
    let url = format!("{}/v1/account/{}/full", base_url, account_id);

    eprintln!("Checking account exists: {}", url);

    let response = match Client::new()
        .get(&url)
        .connect_timeout(Duration::from_secs(10))
        .send() {
            Ok(r) => r,
            Err(_) => return false,
        };

    let status = response.status();
    if status != 200 {
        return false;
    }

    // Check if account has storage
    if let Ok(body) = response.body() {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&body) {
            if let Some(state) = parsed.get("state") {
                if let Some(storage) = state.get("storage_bytes") {
                    return storage.as_u64().unwrap_or(0) > 0;
                }
            }
        }
    }
    false
}

// ============================================================================
// AI Name Generation
// ============================================================================

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<Message>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: MessageContent,
}

#[derive(Deserialize)]
struct MessageContent {
    content: Option<String>,
}

#[derive(Deserialize)]
struct AiAccountsResponse {
    status: bool,
    accounts: Vec<String>,
}

/// Extract JSON from AI response, handling markdown code blocks
fn extract_json_from_response(response: &str) -> String {
    let response = response.trim();

    // Try direct JSON parse first
    if response.starts_with('{') {
        return response.to_string();
    }

    // Try ```json {...} ```
    if let Some(start) = response.find("```json") {
        if let Some(end) = response[start + 7..].find("```") {
            return response[start + 7..start + 7 + end].trim().to_string();
        }
    }

    // Try ``` {...} ```
    if let Some(start) = response.find("```") {
        if let Some(end) = response[start + 3..].find("```") {
            let inner = response[start + 3..start + 3 + end].trim();
            if inner.starts_with('{') {
                return inner.to_string();
            }
        }
    }

    // Try to find any JSON object {...}
    if let Some(start) = response.find('{') {
        if let Some(end) = response.rfind('}') {
            if end > start {
                return response[start..=end].to_string();
            }
        }
    }

    response.to_string()
}

/// Generate account names using AI
fn generate_account_names(prompt: &str, count: u32) -> Result<Vec<String>, String> {
    let api_key = env::var("OPENAI_API_KEY")
        .map_err(|_| "OPENAI_API_KEY not found in environment")?;

    let endpoint = env::var("OPENAI_ENDPOINT")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());

    let model = env::var("OPENAI_MODEL")
        .unwrap_or_else(|_| "gpt-3.5-turbo".to_string());

    let network = get_near_network();
    let suffix_str = if network == "near" { ".near" } else { ".testnet" };

    let system_prompt = r#"You are an agent that generates NEAR account names.

Rules:
- Use only lowercase letters (a-z), digits (0-9), and separators _ or -
- No "@" or "." characters in the name part
- Must be at least 2 characters and no longer than 64 characters (including suffix)
- Names must be unique and contextually relevant to the prompt

Return JSON: {"status": true, "accounts": ["name1.near", "name2.near", ...]}
If invalid request: {"status": false, "accounts": []}"#;

    let user_prompt = format!(
        "Create {} NEAR accounts with {} suffix, themed: \"{}\". Return 5x more names than requested to account for duplicates. Be creative, never repeat names.",
        count, suffix_str, prompt
    );

    let request_body = OpenAIRequest {
        model,
        messages: vec![
            Message { role: "system".to_string(), content: system_prompt.to_string() },
            Message { role: "user".to_string(), content: user_prompt },
        ],
        max_tokens: 16000,
        temperature: 1.2,
    };

    let request_json = serde_json::to_string(&request_body)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    eprintln!("Calling AI for name generation...");

    let response = Client::new()
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", api_key))
        .connect_timeout(Duration::from_secs(60))
        .body(request_json.as_bytes())
        .send()
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    let status = response.status();
    if status < 200 || status >= 300 {
        let body = response.body().unwrap_or_default();
        let error_text = String::from_utf8_lossy(&body);
        return Err(format!("AI API error {}: {}", status, error_text));
    }

    let response_body = response.body()
        .map_err(|e| format!("Failed to read response: {:?}", e))?;

    let ai_response: OpenAIResponse = serde_json::from_slice(&response_body)
        .map_err(|e| format!("Failed to parse AI response: {}", e))?;

    let content = ai_response.choices
        .first()
        .and_then(|c| c.message.content.clone())
        .ok_or("No response from AI")?;

    eprintln!("AI response: {}", content);

    // Parse JSON from AI response (handle markdown code blocks)
    let json_content = extract_json_from_response(&content);
    eprintln!("Extracted JSON: {}", json_content);

    let accounts_response: AiAccountsResponse = serde_json::from_str(&json_content)
        .map_err(|e| format!("Failed to parse AI accounts JSON: {} (content: {})", e, json_content))?;

    if !accounts_response.status {
        return Err("AI returned status: false".to_string());
    }

    // Filter valid accounts that don't exist yet
    let valid_accounts: Vec<String> = accounts_response.accounts
        .into_iter()
        .map(|a| a.to_lowercase())
        .filter(|a| {
            let valid_suffix = a.ends_with(suffix_str);
            let not_exists = !is_account_exists(a);
            eprintln!("Account {}: valid_suffix={}, not_exists={}", a, valid_suffix, not_exists);
            valid_suffix && not_exists
        })
        .take(count as usize)
        .collect();

    if valid_accounts.len() < count as usize {
        return Err(format!(
            "AI generated only {} valid available accounts, requested {}",
            valid_accounts.len(), count
        ));
    }

    Ok(valid_accounts)
}

// ============================================================================
// Account Discovery
// ============================================================================

/// Scan derived keys to find all existing accounts for a specific predecessor
/// Returns list of accounts and the next available index
fn discover_accounts(master_key: &SigningKey, predecessor: &str) -> Result<(Vec<AccountInfo>, u32), String> {
    let mut accounts = Vec::new();
    let mut index = 0u32;

    eprintln!("Discovering accounts for predecessor: {}", predecessor);

    loop {
        let derived_key = derive_signing_key(master_key, predecessor, index);
        let public_key = format_public_key(&VerifyingKey::from(&derived_key));

        eprintln!("Checking index {} -> {}", index, public_key);

        match get_account_by_public_key(&public_key)? {
            Some(account_id) => {
                eprintln!("Found account: {}", account_id);
                accounts.push(AccountInfo {
                    index,
                    account_id,
                    public_key,
                    balance: None,
                    balance_near: None,
                });
                index += 1;
            }
            None => {
                eprintln!("No account at index {}, stopping", index);
                break;
            }
        }

        // Safety limit
        if index > 1000 {
            eprintln!("Reached safety limit of 1000 accounts");
            break;
        }
    }

    Ok((accounts, index))
}

// ============================================================================
// NEAR Operations
// ============================================================================

/// Create a new NEAR account using the "near" contract
fn create_account(
    signer_id: &str,
    signer_key: &str,
    account_id: &str,
    public_key: &str,
    deposit: &str,
) -> Result<String, String> {
    let network = get_near_network();
    let registrar = if network == "near" { "near" } else { "testnet" };

    let args = serde_json::json!({
        "new_account_id": account_id,
        "new_public_key": public_key,
    });

    let (tx_hash, error) = near::rpc::api::call(
        signer_id,
        signer_key,
        registrar,
        "create_account",
        &args.to_string(),
        deposit,
        "300000000000000", // 300 TGas
    );

    if !error.is_empty() {
        return Err(error);
    }

    Ok(tx_hash)
}


// ============================================================================
// Action Handlers
// ============================================================================

fn handle_create_accounts(prompt: String, count: u32, deposit_per_account: String) -> Output {
    eprintln!("Creating {} accounts with prompt: {}", count, prompt);

    let master_key = match get_master_key() {
        Ok(k) => k,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    let predecessor = match get_predecessor() {
        Ok(p) => p,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    // Use predecessor as signer (the account that pays for creation)
    let signer_id = predecessor.clone();

    // Get private key from environment (comes from secrets in production)
    let signer_private_key = match get_sender_private_key() {
        Ok(k) => k,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    // Find next available index
    let (existing_accounts, mut next_index) = match discover_accounts(&master_key, &predecessor) {
        Ok(r) => r,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(format!("Failed to discover accounts: {}", e)),
        },
    };

    eprintln!("Found {} existing accounts, next index: {}", existing_accounts.len(), next_index);

    // Generate account names using AI
    let account_names = match generate_account_names(&prompt, count) {
        Ok(names) => names,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some(format!("Failed to generate names: {}", e)),
        },
    };

    eprintln!("AI generated names: {:?}", account_names);

    let mut new_accounts = Vec::new();
    let mut transactions = Vec::new();

    for (i, account_id) in account_names.iter().enumerate() {
        let index = next_index + i as u32;
        let derived_key = derive_signing_key(&master_key, &predecessor, index);
        let public_key = format_public_key(&VerifyingKey::from(&derived_key));

        eprintln!("Creating account {} with key {}", account_id, public_key);

        match create_account(&signer_id, &signer_private_key, account_id, &public_key, &deposit_per_account) {
            Ok(tx_hash) => {
                new_accounts.push(AccountInfo {
                    index,
                    account_id: account_id.clone(),
                    public_key: public_key.clone(),
                    balance: Some(deposit_per_account.clone()),
                    balance_near: None,
                });
                transactions.push(TxResult {
                    account_id: account_id.clone(),
                    tx_hash,
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                transactions.push(TxResult {
                    account_id: account_id.clone(),
                    tx_hash: String::new(),
                    success: false,
                    error: Some(e),
                });
            }
        }
    }

    let success = transactions.iter().any(|t| t.success);
    next_index += count;

    Output {
        success,
        accounts: Some(new_accounts),
        transactions: Some(transactions),
        next_index: Some(next_index),
        error: None,
    }
}

fn handle_list_accounts(indices: Vec<u32>) -> Output {
    let master_key = match get_master_key() {
        Ok(k) => k,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    let predecessor = match get_predecessor() {
        Ok(p) => p,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    let (all_accounts, next_index) = match discover_accounts(&master_key, &predecessor) {
        Ok(r) => r,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(format!("Failed to discover accounts: {}", e)),
        },
    };

    // Filter accounts by indices if provided
    let accounts: Vec<AccountInfo> = if indices.is_empty() {
        all_accounts
    } else {
        all_accounts.into_iter().filter(|a| indices.contains(&a.index)).collect()
    };

    if accounts.is_empty() && !indices.is_empty() {
        return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some(format!("No accounts found for indices {:?}", indices)),
        };
    }

    // Fetch balances for each account
    let accounts_with_balances: Vec<AccountInfo> = accounts
        .into_iter()
        .map(|mut acc| {
            let (result, _) = near::rpc::api::view_account(&acc.account_id);
            if !result.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&result) {
                    if let Some(amount) = parsed.get("result").and_then(|r| r.get("amount")) {
                        let balance_yocto = amount.to_string().trim_matches('"').to_string();
                        acc.balance_near = format_balance_near(&balance_yocto);
                        acc.balance = Some(balance_yocto);
                    }
                }
            }
            acc
        })
        .collect();

    Output {
        success: true,
        accounts: Some(accounts_with_balances),
        transactions: None,
        next_index: Some(next_index),
        error: None,
    }
}

fn handle_batch_call(
    contract_id: String,
    method_name: String,
    args: serde_json::Value,
    deposit: String,
    gas: String,
    indices: Vec<u32>,
) -> Output {
    let master_key = match get_master_key() {
        Ok(k) => k,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    let predecessor = match get_predecessor() {
        Ok(p) => p,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    // Discover all accounts
    let (all_accounts, next_index) = match discover_accounts(&master_key, &predecessor) {
        Ok(r) => r,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(format!("Failed to discover accounts: {}", e)),
        },
    };

    if all_accounts.is_empty() {
        return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some("No accounts found".to_string()),
        };
    }

    // Filter accounts by indices if provided
    let accounts: Vec<&AccountInfo> = if indices.is_empty() {
        all_accounts.iter().collect()
    } else {
        all_accounts.iter().filter(|a| indices.contains(&a.index)).collect()
    };

    if accounts.is_empty() {
        return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some(format!("No accounts found for indices {:?}", indices)),
        };
    }

    eprintln!("Executing batch call for {} accounts (indices: {:?})", accounts.len(),
        if indices.is_empty() { "all".to_string() } else { format!("{:?}", indices) });

    let args_template = args.to_string();
    let mut transactions = Vec::new();
    let mut processed_accounts = Vec::new();

    for account in &accounts {
        // Replace {{account_id}} placeholder in args
        let account_args = args_template.replace("{{account_id}}", &account.account_id);

        eprintln!("Calling {} on {} for account {}", method_name, contract_id, account.account_id);

        // Derive key for this account
        let derived_key = derive_signing_key(&master_key, &predecessor, account.index);
        let private_key = format_private_key(&derived_key);

        eprintln!("About to call RPC: signer={}, receiver={}, method={}, deposit={}, gas={}",
            account.account_id, contract_id, method_name, deposit, gas);

        // Call with derived key
        let (tx_hash, error) = near::rpc::api::call(
            &account.account_id,
            &private_key,
            &contract_id,
            &method_name,
            &account_args,
            &deposit,
            &gas,
        );

        eprintln!("RPC call returned: tx_hash='{}', error='{}'", tx_hash, error);

        processed_accounts.push((*account).clone());

        if error.is_empty() {
            eprintln!("✓ Transaction succeeded for {}: {}", account.account_id, tx_hash);
            transactions.push(TxResult {
                account_id: account.account_id.clone(),
                tx_hash,
                success: true,
                error: None,
            });
        } else {
            eprintln!("✗ Transaction failed for {}: {}", account.account_id, error);
            transactions.push(TxResult {
                account_id: account.account_id.clone(),
                tx_hash: String::new(),
                success: false,
                error: Some(error),
            });
        }
    }

    let success = transactions.iter().any(|t| t.success);

    Output {
        success,
        accounts: Some(processed_accounts),
        transactions: Some(transactions),
        next_index: Some(next_index),
        error: None,
    }
}

fn handle_fund_accounts(total_amount: String, indices: Vec<u32>) -> Output {
    let master_key = match get_master_key() {
        Ok(k) => k,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    let predecessor = match get_predecessor() {
        Ok(p) => p,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    // Parse total amount
    let total_amount_u128: u128 = match total_amount.parse() {
        Ok(a) => a,
        Err(_) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(format!("Invalid total_amount: {}", total_amount)),
        },
    };

    // Get sender account private key for signing transfers (comes from secrets, provided by user)
    let signer_private_key = match get_sender_private_key() {
        Ok(k) => k,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(e),
        },
    };

    // Discover all accounts
    let (all_accounts, next_index) = match discover_accounts(&master_key, &predecessor) {
        Ok(r) => r,
        Err(e) => return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: None,
            error: Some(format!("Failed to discover accounts: {}", e)),
        },
    };

    if all_accounts.is_empty() {
        return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some("No accounts found".to_string()),
        };
    }

    // Filter accounts by indices if provided
    let accounts: Vec<&AccountInfo> = if indices.is_empty() {
        all_accounts.iter().collect()
    } else {
        all_accounts.iter().filter(|a| indices.contains(&a.index)).collect()
    };

    if accounts.is_empty() {
        return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some(format!("No accounts found for indices {:?}", indices)),
        };
    }

    // Calculate amount per account
    let num_accounts = accounts.len() as u128;
    let amount_per_account = total_amount_u128 / num_accounts;

    if amount_per_account == 0 {
        return Output {
            success: false,
            accounts: None,
            transactions: None,
            next_index: Some(next_index),
            error: Some(format!("Total amount {} is too small to split among {} accounts", total_amount, num_accounts)),
        };
    }

    eprintln!("Funding {} accounts with {} yoctoNEAR each (total: {})",
        accounts.len(), amount_per_account, total_amount_u128);

    let mut transactions = Vec::new();
    let mut processed_accounts = Vec::new();

    for account in &accounts {
        eprintln!("Transferring {} yoctoNEAR from {} to {}",
            amount_per_account, predecessor, account.account_id);

        // Transfer from predecessor to account
        let (tx_hash, error) = near::rpc::api::transfer(
            &predecessor,
            &signer_private_key,
            &account.account_id,
            &amount_per_account.to_string(),
        );

        eprintln!("Transfer returned: tx_hash='{}', error='{}'", tx_hash, error);

        processed_accounts.push((*account).clone());

        if error.is_empty() {
            eprintln!("✓ Transfer succeeded for {}: {}", account.account_id, tx_hash);
            transactions.push(TxResult {
                account_id: account.account_id.clone(),
                tx_hash,
                success: true,
                error: None,
            });
        } else {
            eprintln!("✗ Transfer failed for {}: {}", account.account_id, error);
            transactions.push(TxResult {
                account_id: account.account_id.clone(),
                tx_hash: String::new(),
                success: false,
                error: Some(error),
            });
        }
    }

    let success = transactions.iter().any(|t| t.success);

    Output {
        success,
        accounts: Some(processed_accounts),
        transactions: Some(transactions),
        next_index: Some(next_index),
        error: None,
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input_string = String::new();
    io::stdin().read_to_string(&mut input_string)?;

    eprintln!("Bot Father received input: {}", input_string);

    let input: Input = serde_json::from_str(&input_string)?;

    let output = match input {
        Input::CreateAccounts { prompt, count, deposit_per_account } => {
            handle_create_accounts(prompt, count, deposit_per_account)
        }
        Input::BatchCall { contract_id, method_name, args, deposit, gas, indices } => {
            handle_batch_call(contract_id, method_name, args, deposit, gas, indices)
        }
        Input::ListAccounts { indices } => {
            handle_list_accounts(indices)
        }
        Input::FundAccounts { total_amount, indices } => {
            handle_fund_accounts(total_amount, indices)
        }
    };

    let output_json = serde_json::to_string(&output)?;
    print!("{}", output_json);
    io::stdout().flush()?;

    Ok(())
}
