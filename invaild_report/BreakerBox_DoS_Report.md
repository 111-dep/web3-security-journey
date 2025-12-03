# BreakerBox: Unbounded loop in removeBreaker leads to permanent administrative DoS via Block Gas Limit

**Severity**: Medium
**Likelihood**: Low
**Impact**: High

## Summary
The `removeBreaker` function in `BreakerBox.sol` contains an unbounded loop that iterates over all registered `rateFeedIDs`. If the number of rate feeds grows significantly, the gas cost to remove a breaker can exceed the block gas limit, making it impossible to remove a breaker. This creates a permanent configuration lock-in and potential DoS for administrative actions.

## Finding Description
The `BreakerBox` contract manages trading breakers for various rate feeds. When removing a breaker via `removeBreaker`, the contract iterates through **all** registered rate feeds to disable the breaker for each one.

**File:** `contracts/oracles/BreakerBox.sol`

```solidity
  function removeBreaker(address breaker) external onlyOwner {
    // ... (find breaker index)

    // VULNERABILITY: Unbounded loop over all rate feeds
    // slither-disable-next-line cache-array-length
    for (uint256 i = 0; i < rateFeedIDs.length; i++) {
      if (rateFeedBreakerStatus[rateFeedIDs[i]][breaker].enabled) {
        // slither-disable-start reentrancy-no-eth
        // slither-disable-start reentrancy-events
        toggleBreaker(breaker, rateFeedIDs[i], false);
        // slither-disable-end reentrancy-no-eth
        // slither-disable-end reentrancy-events
      }
    }

    // ... (remove from breakers array)
  }
```

The `toggleBreaker` function itself performs storage writes (SSTORE) and emits events, which are gas-expensive operations.

The complexity is **O(N)** where N is the number of rate feeds. If `rateFeedIDs` contains thousands of entries (e.g., if the protocol scales to support many pairs), the cumulative gas cost of this loop will scale linearly. Once it exceeds the block gas limit, the transaction will always revert.

## Impact Explanation
**Impact: High**
1.  **Permanent Administrative Lock-out**: If a breaker becomes malicious, buggy, or obsolete, administrators will be unable to remove it globally. They would be forced to manually disable it for each rate feed individually (if separate functions allow) or upgrade the entire `BreakerBox` contract.
2.  **Emergency Response Failure**: In an emergency where a specific breaker is malfunctioning (e.g., incorrectly halting trading), the inability to quickly remove it could prolong market downtime.
3.  **Operational Risk**: While primarily an administrative DoS, if a breaker logic interferes with critical system functions (like price updates or withdrawals) and cannot be removed, it could indirectly lead to stuck funds.

## Likelihood Explanation
**Likelihood: Low**
It requires a large number of rate feeds to be added to the system. However, this is a realistic long-term scenario for a DeFi protocol aiming to support many assets.

**Crucially, a review of the codebase and documentation reveals no explicit hard cap on the number of rate feeds.** The system appears designed to support an arbitrary number of assets, making this "time bomb" vulnerability valid as the protocol scales.

## Proof of Concept
A test case has been created to demonstrate the high gas usage.

**Test Results:**
In the test, adding **1500 rate feeds** resulted in a gas cost of approximately **13.2 Million Gas** to remove a breaker.

```text
[PASS] testRemoveBreakerGasUsage() (gas: 109579520)
Logs:
  Gas used to remove breaker with 1500 rate feeds: 13219829
```

**Gas Analysis:**
*   **Ethereum Mainnet**: The block gas limit is 30M. Since 1500 feeds consume ~13.2M gas, reaching approximately **3000-3500 feeds** would make the function strictly impossible to execute (exceeding 30M gas).
*   **Celo / L2s**: While some chains have higher theoretical throughput, single-transaction execution limits (often around 30M or dependent on node propagation limits) still apply. The linear growth ensures the limit will eventually be hit.


**Reproduction Code:**
You can run the following test file to verify the finding.
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import { ISortedOracles } from "../../../contracts/interfaces/ISortedOracles.sol";
import { IBreaker } from "../../../contracts/interfaces/IBreaker.sol";
import { IBreakerBox } from "../../../contracts/interfaces/IBreakerBox.sol";

// Define an interface for BreakerBox that includes the functions we need
// This avoids importing the 0.5.13 source code directly
interface IBreakerBoxExtended is IBreakerBox {
    function addBreaker(address breaker, uint8 tradingMode) external;
    function removeBreaker(address breaker) external;
    function addRateFeed(address rateFeedID) external;
    function toggleBreaker(address breakerAddress, address rateFeedID, bool enable) external;
}

contract MockSortedOracles {
    function getOracles(address) external pure returns (address[] memory) {
        address[] memory oracles = new address[](1);
        oracles[0] = address(0x123);
        return oracles;
    }
}

contract MockBreaker is IBreaker {
    function getCooldown(address) external pure returns (uint256) { return 0; }
    function shouldReset(address) external pure returns (bool) { return true; }
    function shouldTrigger(address) external pure returns (bool) { return false; }
}

contract BreakerBoxDoSTest is Test {
    IBreakerBoxExtended breakerBox;
    MockSortedOracles sortedOracles;
    MockBreaker breaker;
    
    function setUp() public {
        sortedOracles = new MockSortedOracles();
        breaker = new MockBreaker();
        
        // Deploy BreakerBox using deployCode to bypass version constraints
        address[] memory rateFeeds = new address[](0);
        bytes memory args = abi.encode(rateFeeds, address(sortedOracles), address(this));
        address deployed = deployCode("BreakerBox.sol", args);
        breakerBox = IBreakerBoxExtended(deployed);
    }
    
    function testRemoveBreakerGasUsage() public {
        // Add the breaker first
        breakerBox.addBreaker(address(breaker), 1);
        
        // Add a large number of rate feeds
        // Note: In a real scenario, 1000 might not be enough to hit the block gas limit depending on the chain,
        // but it demonstrates the linear growth.
        // Celo block gas limit is typically around 10M-30M.
        uint256 numRateFeeds = 1500; 
        
        for (uint256 i = 0; i < numRateFeeds; i++) {
            address rateFeed = address(uint160(i + 1));
            breakerBox.addRateFeed(rateFeed);
            // Enable the breaker for this rate feed to force the loop to do work
            breakerBox.toggleBreaker(address(breaker), rateFeed, true);
        }
        
        uint256 gasStart = gasleft();
        breakerBox.removeBreaker(address(breaker));
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("Gas used to remove breaker with %s rate feeds: %s", numRateFeeds, gasUsed);
        
        // Assert that it consumes a significant amount of gas per item
        // Base cost ~30k + ~5k per item. 1500 items => ~7.5M gas.
        // If we had 5000 items, it would likely revert.
        assertTrue(gasUsed > 1000000, "Gas usage should be significant");
    }
}

```



## Recommendation
Avoid iterating over all rate feeds in a single transaction.

**Option 1: Reverse Mapping (Recommended)**
Maintain a mapping of `breaker => rateFeedIDs[]` to track which rate feeds actually use a specific breaker. Only iterate over this subset.

**Option 2: Pagination / Two-Step Removal**
1.  Disable the breaker globally or mark it as "pending removal".
2.  Allow `removeBreaker` to process a batch of rate feeds (e.g., `removeBreaker(breaker, startIndex, count)`).
3.  Only fully remove the breaker from the `breakers` list when all associations are cleared.

**Option 3: Lazy Cleanup**
When `removeBreaker` is called, simply remove it from the global `breakers` list. In `checkAndSetBreakers`, add a check to ignore or cleanup breakers that are no longer in the global list, rather than eagerly updating all storage slots at once.
