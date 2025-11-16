+++
title = "Blockchain Interoperability Part-1 : Interoperability Problem And Bridges"

date = "2025-11-16"

[taxonomies]
tags=["blockchain", "interoperability", "bridges", "cross-chain", "web3"]

[extra]

+++


Blockchains are isolated distributed computer networks where each node runs a deterministic program that produces consistent, predictable outputs. To maintain this deterministic nature, blockchain networks cannot access external information such as real-world temperature, weather conditions, or async API calls. While this isolation provides strong security guarantees and consensus properties, it also creates significant limitations. One critical drawback is that two blockchains cannot natively communicate with each other, this is known as the **interoperability problem**.

As the blockchain ecosystem has grown to include hundreds of networks (each with unique features, assets, and communities), the inability to transfer value and data across chains has become a major bottleneck. Solving blockchain interoperability is essential for creating a truly connected decentralized ecosystem where users can seamlessly interact with applications and assets regardless of which chain they're on.

# Cross-Chain Communication Use Cases

Bridges solve practical problems that arise from blockchain fragmentation. Users hold assets on one chain but need them on another to access specific applications, lower fees, or tap into different liquidity pools.

**Accessing DeFi protocols on different chains**

A user holds USDC on Ethereum but wants to use a lending protocol on Solana that offers higher yields. Without a bridge, they would need to sell their USDC for fiat, buy SOL, then rebuy USDC on Solana, paying exchange fees and slippage twice. With a bridge like [Wormhole](https://docs.wormhole.com/) or [deBridge](https://docs.debridge.finance/), they transfer USDC directly from Ethereum to Solana in one transaction, paying only the bridge fee and gas costs.

**Gas fee optimization through Layer 2 migration**

Ethereum mainnet gas fees can reach \\$50-100 per transaction during network congestion. Users bridge ETH or ERC-20 tokens to Layer 2 networks like [Arbitrum](https://docs.arbitrum.io/) or [Optimism](https://docs.optimism.io/) where transaction costs drop to \\$0.10-1.00. Bridges like Hop Protocol and [Stargate](https://stargatefi.gitbook.io/) specialize in moving assets between Ethereum and its rollups, letting users keep the same assets while cutting costs by 99%.

**Cross-chain yield farming and liquidity provision**

DeFi users chase yields across different chains. A liquidity provider might deposit USDC-ETH liquidity on Uniswap (Ethereum), then bridge those LP tokens or underlying assets to provide liquidity on Trader Joe (Avalanche) when incentives shift. This requires bridges that support not just simple tokens but also wrapped assets and synthetic representations.

**NFT transfers between ecosystems**

NFT collectors and traders bridge NFTs between chains to access different marketplaces or avoid high gas fees. An NFT minted on Ethereum might get bridged to Polygon to sell on a marketplace with lower fees, or moved to Solana to participate in a chain-specific game or metaverse project. Bridges like Wormhole Portal support NFT bridging alongside fungible tokens.

**Multi-chain dApp interactions**

Some applications operate across multiple chains simultaneously. A user might deposit collateral on Ethereum, take out a loan on Arbitrum, and use those funds to trade on a Solana DEX, all within the same protocol. This requires messaging bridges that can pass not just tokens but also arbitrary data and contract calls between chains.

**Liquidity unification and arbitrage**

Traders use bridges to exploit price differences across chains. If ETH trades at \\$3000 on Ethereum but \\$3020 on Avalanche, an arbitrageur bridges ETH to Avalanche, sells it, bridges the proceeds back, and pockets the difference minus fees. This arbitrage activity helps unify prices across fragmented liquidity pools.

**Accessing chain-specific features**

Different blockchains have unique capabilities. Solana offers high throughput for DEX trading. Ethereum has the deepest DeFi ecosystem. Polygon provides cheap NFT minting. Users bridge assets to whichever chain offers the specific feature they need at that moment, then bridge back when done.

--- 

# The Interoperability Problem

Blockchains cannot natively read the state of other blockchains. This isolation stems from the fundamental requirement that every node in a blockchain network must independently verify all state transitions by executing the same deterministic program. When a node processes a transaction, it must produce identical results to every other honest node. This is how consensus works.

Consider what happens when a smart contract on Ethereum needs to verify that a transaction occurred on Solana. The Ethereum Virtual Machine has no mechanism to query Solana's state. Even if it could make such a query, different Ethereum nodes might receive different responses at different times due to network delays, Solana chain reorganizations, or node availability. This non-determinism would break consensus. Nodes would disagree about the contract's state, making the blockchain unusable.

The problem resembles the oracle problem. Just as blockchains cannot directly access off-chain data like stock prices or weather information, they cannot access the state of other chains. Both require external systems to bring information on-chain in a way that preserves determinism and security.

## Why State Isolation is Fundamental

Blockchain consensus depends on state isolation. When Ethereum validators process block N, they execute every transaction in sequence against state N-1 to produce state N. This computation must be deterministic. Given the same input state and transactions, every validator must compute the same output state.

Introducing dependencies on external blockchain state breaks this model. If a smart contract could call `getCurrentBlockHashOnSolana()`, different validators might get different answers. Validators running at slightly different times would see different Solana blocks. Validators with poor network connectivity to Solana nodes might get stale data or timeouts. The resulting state divergence would prevent validators from agreeing on the canonical chain.

This constraint applies even to reading historical state from other chains. While historical data is immutable, blockchains don't inherently trust each other. Ethereum nodes don't run Solana clients and cannot verify Solana's consensus rules. Accepting cross-chain state requires either trusting external claims about that state or implementing verification logic that can validate cryptographic proofs of the other chain's state.

## The Trust Problem

Solving interoperability means solving a trust problem. When a user locks 100 USDC on Ethereum and expects to receive wrapped USDC on Solana, the Solana contract must somehow verify that the Ethereum lock actually happened. This verification cannot rely on Solana nodes querying Ethereum directly. That would create the non-determinism problem described above.

Instead, interoperability solutions introduce intermediaries that observe one chain and relay information to another. These intermediaries might be:
- A centralized server that monitors both chains
- A committee of validators who sign attestations about cross-chain events
- Light clients implemented as smart contracts that verify proofs of the other chain's state

Each approach involves trust assumptions. Centralized relayers can steal funds by lying about cross-chain events. Validator committees can collude. Light client implementations can have bugs or might not verify the full security of the source chain.

The core challenge is that Chain A cannot verify Chain B's state with the same security guarantees as it verifies its own state. This fundamental limitation means all bridge designs trade off between trust assumptions, capital efficiency, and latency. 

--- 

# General Architecture of Blockchain Bridges

Blockchain bridges consist of three components that work together to relay state and transfer assets across chains: smart contracts on the source chain, smart contracts on the destination chain, and off-chain infrastructure that connects them.

![General Architecture of Bridges](/assets/img/blog_img/bridge-interop-1/general_architecture.png)

## Source Chain Smart Contracts

The source chain contract handles the initial action that triggers a cross-chain operation. For token bridges, this typically means locking or burning tokens. For messaging bridges, it means emitting events that encode cross-chain messages.


**Lock-and-mint bridges** use a vault contract on the source chain that holds deposited tokens. When a user deposits 100 USDC, the contract locks these tokens and emits an event containing:
- The user's address
- The destination chain identifier
- The recipient address on the destination chain
- The token type and amount
- A unique transaction nonce

The lock contract must prevent double-spending. Once tokens are locked for cross-chain transfer, they cannot be withdrawn on the source chain until a reverse bridge operation releases them. This requires tracking which deposits have been processed and preventing replay attacks where the same deposit event gets processed multiple times.

**Burn-and-mint bridges** destroy tokens on the source chain instead of locking them. This approach works for wrapped assets (tokens that were originally minted by the bridge itself). When bridging wrapped Ethereum (WETH) from Polygon back to Ethereum, the Polygon contract burns the WETH tokens since they're synthetic representations. The destination chain then releases native ETH or mints equivalent tokens.

**Message-passing bridges** emit events containing arbitrary calldata rather than just token transfer information. These bridges enable cross-chain contract calls. A user might trigger a function on Chain A that encodes parameters for a function call on Chain B. The source contract validates the message format and emits an event that off-chain relayers will observe.

## Destination Chain Smart Contracts

The destination chain contract receives proof that an event occurred on the source chain and executes the corresponding action: minting tokens, releasing locked funds, or executing a contract call.

**Verification logic** forms the core of destination contracts. They must answer: did this event actually occur on the source chain? The verification method depends on the bridge's security model.

Light client bridges implement verification by maintaining a view of the source chain's block headers. When a relayer submits a deposit proof, the contract checks that:
1. The block header is part of the source chain's canonical history
2. The event is included in that block's transaction receipts
3. The Merkle proof correctly links the event to the block's receipt root

This requires the destination contract to track source chain block headers and verify consensus rules. For Ethereum, this means verifying signatures from the validator set. For proof-of-work chains, it means checking that block headers form a valid chain with sufficient cumulative difficulty.

Multisig bridges such as [Wormhole](https://docs.wormhole.com/) uses a simpler verification model. A set of off-chain bridge validator nodes observe source chain events and sign attestations. The destination contract checks that enough bridge validators (a quorum threshold like 2/3) have signed the attestation. This trades decentralization for simplicity, the contract doesn't need to understand source chain consensus, but security depends entirely on the validator committee's honesty. And verification of these multisig bridges are cheaper than consensus based bridges.

**Token minting and release** happens after verification succeeds. Lock-and-mint bridges mint wrapped tokens representing the locked source chain assets. These wrapped tokens track 1:1 with locked funds. The total supply of wrapped tokens on all destination chains should never exceed locked funds on the source chain. The destination contract maintains this invariant by only minting when it receives valid proofs of locked deposits.

## Off-Chain Components

Off-chain infrastructure connects source and destination chains by observing events on one chain and submitting proofs to another. This includes relayers, validators, watchers, and supporting systems.

**Relayers** monitor source chain events and submit proofs to destination chains. A relayer runs full nodes (or connect to RPC) for both chains, watches for bridge-related events, constructs validity proofs, and broadcasts destination chain transactions containing those proofs.

For light client bridges, relayers submit block headers from the source chain to keep the destination contract's view up to date. They also submit Merkle proofs of specific events when users initiate transfers. The relayer doesn't need to be trusted because the destination contract verifies all proofs cryptographically. Relayers earn fees for successfully submitting proofs, incentivizing them to maintain infrastructure.

For validator committee bridges, relayers are typically also validators. They observe source chain events, sign attestations, collect signatures from other validators, and submit aggregated signatures to the destination chain. Unlike light client relayers, these validators must be trusted since the destination chain doesn't verify source chain consensus.

**Validators** in committee-based bridges stake capital as collateral. If they sign fraudulent attestations (claiming an event occurred that didn't), they can be slashed. This requires a challenge mechanism where anyone can submit fraud proofs showing that a validator signed an invalid attestation. The challenge period introduces latency. Transfers aren't final until the challenge window closes, typically 10 minutes to several hours.

**Watchers** monitor for invalid cross-chain messages and submit fraud proofs. In optimistic bridge designs, relayers can submit proofs without immediate verification, but watchers can challenge them during a dispute window. If the challenge succeeds, the relayer loses their bond and the invalid message doesn't execute. This pattern reduces on-chain verification costs by only checking proofs when disputes arise.

**APIs and indexers** provide infrastructure for users and applications to track transfer status. When a user bridges tokens, they need to know when the transfer completes. Indexers watch both chains, track the lifecycle of bridge transactions (initiated, validated, executed, finalized), and provide status via REST APIs or websockets. These are convenience services. Users could monitor chains directly, but indexers aggregate data and provide better UX.

In general, above three are the only components present in most of the bridge protocols they might be called with a different name but ultimately the source smart contracts will emit an event whenever a user initiated a bridge request, the off-chain components will get the event information and the required proofs to prove that this event actually does exists on source chain then relay this information to the destination chain smart contracts. The destination smart contracts will verify these proofs and perform the subsequent action based on the verification status. 

--- 

# Types of Blockchain Bridges

The interoperability problem is solved by bridges, but how a bridge is solving this problems brings us to types of bridges. There are multiple types of bridges each of them addressing the same problem but in a different approach, in different security models, with different architectures. Every type of bridging have its own advantages and disadvantages. For example if a bridge is trying to complete the bridge request within seconds, the limitation of it might be an optimistic security model. This section is going to explain the notable bridge types, core principle of each and how the three generalized components discuessed above changes for each type.

## Trustless Bridges

Trustless bridges (also called consensus-based or light client bridges) verify cross-chain messages by recomputing the source chain's consensus protocol on the destination chain. Instead of trusting external validators or oracles, the destination chain smart contract directly validates cryptographic proofs that a specific event occurred on the source chain according to that chain's consensus rules. The security assumptions match those of the underlying chains. No additional trust is required beyond trusting the source and destination chain consensus mechanisms. Examples include [HyperBridge](https://docs.hyperbridge.network/), [SupraNova](https://docs.supra.com/supranova), [Rainbow Bridge](https://doc.aurora.dev/bridge/introduction/), and various zkBridge implementations.

![Trustless Bridge Architecture](/assets/img/blog_img/bridge-interop-1/trustless_bridge_arch.png)

Consider a trustless bridge doing cross-chain message transfers between Ethereum and Binance. Bridge workflow will start whenever a user initiates the bridge request by calling a bridge function (Ex, `sendMessageToBinance()`) on the source bridge smartc contract. The successful source bridge transaction will emit an event `BridgeEvent()` with the message that user wants to send, necessary information like recipient address and other information required for the bridge relayers to filter out the bridge events and destination information like destination chain id. 

```solidity
event BridgeEvent(
    address indexed bridgeContract, 
    uint256 indexed toChainId, 
    uint256 indexed id, 
    address sender, 
    address recipient, 
    bytes memory message
);
function sendMessageToBinance(address recipient, bytes memory message) public {
    // Basic require checks
    emit BridgeEvent(
        address(this),
        BNB_CHAIN_ID,
        id++,
        msg.sender,
        recipient,
        message
    );
}
```

Now, the source bridge event got emitted, before looking at relayer operations, try understanding how can we say the bridge event is actually emitted on Ethereum chain? To prove this we have to understand how the Ethereum blockchain consensus works and how events are stored on Ethereum blocks.

### Event Verification and State Proofs 

Bridges need to verify that the transaction which emitted the bidge event is actually present in the source blockchain. To prove that a transaction is present in the blockchain we need to get the transaction proof, this is typically a merkle proof where the bridge transaction is the leaf of the transaction merkle tree and merkle root of the tree will be the final transaction root of the block. In general this transaction root will be present in the block header of a block which is ultimately signed by the chain validators. In particular to Ethereumm we don't need to verify this transaction proof because the etheruem block header will also contains the receipt root which is a merkle root constructed from the successful trransaction output receipts. Which means by verifying the receipt proof of the bridge transaction we can say that the bridge transaction is exists in the source blockchain. But we may need to verify the transaction proof as well for many other chains which doesn't contains the receipts in their block headers(Ex, Aptos, Supra). 

Bridges need to verify not just that a transaction exists, but that specific events were emitted or state changes occurred. Ethereum achieves this through receipt tries. Each block header contains a receipts root committing to all transaction receipts, which include emitted events.

To prove a bridge event occurred in Ethereum:

1. **Transaction receipt proof**: Merkle patricia trie proof showing the transaction receipt exists in the block's receipt trie
2. **Log inclusion proof**: The receipt contains logs (events) with specific topics and data
3. **Block finality proof**: The block header is part of the finalized chain (e.g., beyond Ethereum's 64-slot finalization)

The destination contract verifies the Merkle proof structure:
```solidity
verify(receiptTrieRoot, receiptProof, transactionIndex) → receipt
require(receipt.status == 1) // transaction succeeded
require(receipt.logs[i].address == SOURCE_BRIDGE_CONTRACT)
require(receipt.logs[i].topics[0] == BRIDGE_EVENT_SIGNATURE)
require(receipt.logs[i].topics[1] == SOURCE_BRIDGE_CONTRACT)
require(receipt.logs[i].topics[2] == BNB_CHAIN_ID)
decode(receipt.logs[i].data) → (sender, recipient, message)
```

Some protocols, verifies the state proofs which works similarly but prove account storage values rather than events. To verify that an account has a specific storage slot value:

1. **Account proof**: Merkle patricia proof from state root to account state
2. **Storage proof**: Merkle patricia proof from account's storage root to the specific storage slot

This allows verifying arbitrary contract state (like locked token balances) without trusting external attestations.

### Consensus Verification & Ethereum Sync Committee

Transaction and event proofs alone are insufficient without block header verification. A Merkle proof only proves that a receipt hashes to a given root, an attacker can fabricate a fake receipt, compute its Merkle root, and generate a valid proof for this fabricated data. The proof verifies correctly because Merkle proof verification is just hash computation: given a receipt and sibling hashes, anyone can compute `hash(receipt) + hash(siblings) = root`. Without verifying that the root appears in a legitimate block, the destination contract cannot distinguish real receipts from fabricated ones.

Block header verification prevents this attack. The verification logic must confirm that the receipt root (or transaction root) exists in a block header signed by the source chain's validators. This requires validating the block header signatures according to the source chain's consensus rules.

For the block header verification the destination smart contract should have all the validators public keys who signed the source chain block header. And perform a consenus quorum number of correct signatures for a successful block header verification. Storing all the validator for each block header on the destination chain is difficult when the source is a chain like ethereum where the total number of validators are ~1M. Fortunately, Ethereum addressed this problem and introduced a secondary consensus sync committee in [altair fork upgrade](https://github.com/ethereum/annotated-spec/blob/master/altair/sync-protocol.md). Sync commitee is randomly chooses 512 validators for every 256 epochs (~27 hours) who attests the ethereum block headers along with the major validator sets. But sync committee consensus doesn't implement any slashing mechanism to slash the sync committee participants when they refuse to sign the block header which introduces a security issue (more details in security model section of this post). So, when verifying block headers instead of verifying the full validators signatures (expensive) we can verify the sync committee signatures (cheaper). 

The destination bridge contract stores the current sync committee set (or a commitment to it) and verifies block signatures. Ethereum's sync committee design allows light clients to track a rotating subset of 512 validators who sign block headers every 12 seconds. When a relayer submits block header, event proofs, the contract verifies:

1. **BLS signature aggregation**: At least 2/3 of the sync committee signed the header
2. **Necessary header values validity**: The header values check like slot number falls within the current sync period
3. **Event proof**: The Merkle proof correctly links the event to the header's receipt root

Additionally, relayer has to submit the sync committee validator set handover changes, because the current sync-committee validator set will only be valid for the current period (256 epochs) and for the next period there will be a new set of 512 validators selected. Which means all the events emitted in the next period can only be verified with the new sync committee public keys. So, relayer should also check for the sync committee handovers and update the validator set on the destination bridge smart contract with necessary handover proofs. There is a necessity to generate the proofs for sync committee handover as well. These proofs are just singature verifications in case of ethereum, because the new sync committee for the next period will be signed by the current sync committee set. So verifying this signature helps us to update the new sync committee.

This verification chain (Event merkle proof -> receipt root in block header -> sync committee signatures on header -> sync committee rotation proofs) establishes cryptographic certainty that the event occurred on the source chain. Different consensus mechanisms use different proof types, signature schemes, and validator set sizes, but the verification logic follows the same pattern: prove the event exists in a transaction, prove the transaction exists in a block, prove the block was signed by the consensus validators.

### Relayer Operations and Incentives

In trustless bridges the relayers job is complex as relayers have to generate block and state proofs. Relayer have to listen for the events and get/generate the necessary proofs according to source consensus rules and construct a destination transaction and complete the transaction.

Relayers performs two main functions:

1. **Validator set updates**: Continuously submit source chain validator set updates to keep the destination contract state synchronized. For Ethereum, this means submitting sync committee updates and signed headers.

2. **Event/Transaction proof**: When a user initiates a bridge transfer, the relayer waits for finality on the source chain, fetches the merkle proof for the event, and submits it to the destination contract along with relevant header data.

Relayers are permissionless, anyone can run one since the destination contract verifies all proofs cryptographically. This eliminates relayer trust assumptions but requires incentive mechanisms to ensure relayers actually submit proofs. To incentive relayer, protocols implements different kinds of fee models. Fee model design is completely subject to the protocol designers but ultimately the fee model works to collects the fee from user for providing the bridging service and uses this fee to reward the relayer.

Example fee models :
- **User-paid fees**: The source chain event encodes a fee the user commits to pay. The destination contract sends this fee to the relayer who successfully submits the proof.
- **Protocol subsidies**: The bridge protocol subsidizes relayer costs from a treasury, treating relay as a public good.

The challenge is ensuring timely relay without overpaying. If fees are too low, no relayer will submit the proof. If too high, users overpay. Dynamic fee markets let users set their own fees, but risk delays when users underestimate costs.

### Latency and Cost Trade-offs

Trustless bridges face trade-offs between security, latency, and cost. Security divides into two categories: full node verification and light client verification.

**Full node security** verifies block headers against the complete validator set. For Ethereum, this means verifying signatures from all ~1M validators rather than just the 512-validator sync committee. This approach costs millions of gas per day regardless of finality choices. Even with optimistic verification or shorter finality windows, the signature verification overhead remains prohibitively expensive for chains with large validator sets. Only chains with small validator counts or alternative consensus mechanisms that reduce per-block attestations can achieve full node verification economically.

**Light client security** verifies headers against a validator subset. The security and latency characteristics depend on finality requirements:

**Light client + full finality = high security, high latency, moderate cost**: Verifying sync committee signatures (512 validators for Ethereum) with full finality guarantees provides strong security at ~300-400k gas per verification. Ethereum's finality requires 64 slots (~13 minutes), adding latency but preventing reorg attacks. This configuration matches the security assumptions of the underlying chains without the cost burden of full node verification.

**Light client + optimistic finality = lower security, low latency, moderate cost**: Accepting headers before full finality reduces latency to seconds or minutes but introduces reorg risk. If the source chain reorganizes, previously verified events might disappear from the canonical chain. Protocols using optimistic finality typically implement dispute periods or rely on economic incentives to penalize relayers who submit headers from orphaned chains.

Most production trustless bridges prioritize security over latency, using light client verification with full finality. This accepts high latency (~13 minutes for Ethereum) to avoid additional trust assumptions. zkBridge designs attempt to break this trade-off by compressing full node verification costs through cryptographic proofs, potentially enabling full node security with light client costs.

### ZK Bridges

**zkBridges**: Proof systems like zkSNARKs can compress consensus verification. Instead of verifying hundreds of signatures on-chain, a prover generates a SNARK proving "I verified N signatures correctly and they satisfy the consensus rule." The on-chain verifier checks the SNARK proof in constant time (~300k gas) regardless of N. This dramatically reduces costs for chains with many validators.

## Trusted/Multisig Bridges

Trusted bridges (also called validator committee or multisig bridges) verify cross-chain messages through attestations from a trusted set of validators rather than cryptographic consensus proofs. Instead of verifying the source chain's consensus on-chain, the destination contract trusts a committee of bridge validators to observe source chain events and sign attestations confirming those events occurred. The security model depends on the honesty of the validator committee, users must trust that a threshold majority (typically 2/3 or higher) will not collude to sign fraudulent attestations.

![Multisig Bridge Architecture](/assets/img/blog_img/bridge-interop-1/multisig_bridge_arch.png)

Consider a trusted bridge transferring messages between Ethereum and Binance. The user initiates a bridge request by calling the source bridge contract, which emits the same `BridgeEvent()` as in trustless bridges:

```solidity
event BridgeEvent(
    address indexed bridgeContract,
    uint256 indexed toChainId,
    uint256 indexed id,
    address sender,
    address recipient,
    bytes memory message
);

function sendMessageToBinance(address recipient, bytes memory message) public {
    emit BridgeEvent(
        address(this),
        BNB_CHAIN_ID,
        id++,
        msg.sender,
        recipient,
        message
    );
}
```

The architectural difference emerges in how this event gets verified on the destination chain.

### Attestation and Signature Verification

Bridge validators run full nodes(or connect to RPCs) for both source and destination chains. When a `BridgeEvent()` is emitted on Ethereum, each validator observes the event, waits for sufficient confirmations (to avoid reorg issues), and signs an attestation message containing:

```
attestation = {
    sourceChainId: 1,  // Ethereum
    destChainId: 56,   // Binance
    eventId: 12345,
    sourceContract: 0x...,
    sender: 0x...,
    recipient: 0x...,
    message: 0x...,
    blockNumber: 18500000,
    blockHash: 0x...
}
```

Each validator signs this attestation with their private key: `signature = sign(hash(attestation), validatorPrivateKey)`. Validators share signatures through a peer-to-peer gossip network or submit them directly to the destination chain.

The destination bridge contract maintains the current validator set and their public keys. When sufficient signatures are collected (meeting the threshold like 2/3 or 13/19 validators), any party can submit the attestation bundle to the destination contract:

```solidity
struct Attestation {
    uint256 sourceChainId;
    uint256 destChainId;
    uint256 eventId;
    address sourceContract;
    address sender;
    address recipient;
    bytes message;
    uint256 blockNumber;
    bytes32 blockHash;
}

function submitAttestation(
    Attestation calldata att,
    bytes[] calldata signatures
) external {
    require(signatures.length >= threshold, "Insufficient signatures");
    require(!processedEvents[att.eventId], "Already processed");

    bytes32 attHash = keccak256(abi.encode(att));
    uint256 validSigs = 0;

    for (uint i = 0; i < signatures.length; i++) {
        address signer = recoverSigner(attHash, signatures[i]);
        if (isValidator(signer) && !seenSigners[signer]) {
            validSigs++;
            seenSigners[signer] = true;
        }
    }

    require(validSigs >= threshold, "Threshold not met");

    processedEvents[att.eventId] = true;
    // Execute the cross-chain message
    executeMessage(att.recipient, att.message);
}
```

The verification process costs significantly less gas than trustless bridges. Recovering ECDSA signatures costs ~3,000 gas per signature. For a 13-validator set with 2/3 threshold (9 signatures required), verification costs ~27,000 gas plus storage operations. This compares to 300-400k gas for sync committee BLS verification in trustless bridges.

### Validator Set Management

The bridge protocol defines a validator set that operators trust to attest honestly. Validator selection and management varies by protocol:

**Permissioned validators**: The bridge protocol selects validators based on reputation, stake, or governance votes. Wormhole uses 19 "Guardians" selected by the Wormhole DAO. Multichain (formerly Anyswap) uses a federated set of validators operated by known entities.

**Staked validators**: Validators must stake collateral (in the bridge token or native chain tokens) to participate. [Axelar](https://docs.axelar.dev/) requires validators to stake AXL tokens. If validators sign fraudulent attestations, their stake can be slashed through a challenge mechanism.

**Rotating validator sets**: Some protocols rotate validators periodically to reduce centralization risk. The destination contract must handle validator set updates by verifying that the current validator set signed an attestation approving the new set:

```solidity
function updateValidatorSet(
    address[] calldata newValidators,
    bytes[] calldata signatures
) external {
    require(signatures.length >= currentThreshold, "Insufficient signatures");

    bytes32 updateHash = keccak256(abi.encode(newValidators, nextEpoch));
    uint256 validSigs = verifySignatures(updateHash, signatures);

    require(validSigs >= currentThreshold, "Threshold not met");

    // Update validator set
    validators = newValidators;
    epoch = nextEpoch;
}
```

Threshold configuration balances security and liveness. A 2/3 threshold (Byzantine fault tolerance standard) allows the system to tolerate up to 1/3 malicious or offline validators. Higher thresholds like 3/4 or 13/19 increase security but reduce liveness. More validators must remain online and honest.

### Bridge Validator Operations

Bridge validators perform simpler operations than trustless bridge relayers since they don't generate consensus proofs:

**Event monitoring**: Validators run full nodes or connect to RPC endpoints for both chains. They subscribe to bridge contract events on the source chain and monitor for new `BridgeEvent()` emissions.

**Confirmation waiting**: After detecting an event, validators wait for a confirmation threshold (e.g., 64 blocks on Ethereum for finality) to avoid signing events from reorged blocks. This adds latency but prevents signing invalid events.

**Attestation signing**: Once sufficient confirmations pass, validators sign the attestation message and broadcast it to other validators via a P2P gossip network or submit it directly to the destination chain. 

**Relay submission**: Either validators themselves or third-party relayers aggregate signatures and submit the attestation bundle to the destination contract. Some protocols incentivize this by paying gas refunds or small fees to the submitter.

The validator's trust model differs fundamentally from trustless relayers. Bridge validators can steal funds by signing fraudulent attestations (claiming events occurred that didn't). Preventing this requires:

**Slashing mechanisms**: Validators stake collateral that gets slashed if they sign provably fraudulent attestations. Anyone can submit a fraud proof showing a validator signed an attestation for a non-existent event.

**Economic security**: The total value locked (TVL) in the bridge should not exceed the total staked collateral multiplied by a safety factor. If TVL > total_stake, validators have economic incentive to collude and steal funds.

**Reputation and legal agreements**: Some bridges rely on validators' reputation or legal contracts rather than pure cryptoeconomic security. This works for federated bridges where validators are known entities with legal accountability.

The **Attestation signing** and **Relay submission** steps are subject to change for different bridge designs. An interactive multisig bridge setup will use a P2P gossip channel to collect and aggregate all the attestations and relay them as a single transaction. But in a non-interactive setting of bridge nodes, each node will sign their attestation and submit immediately to the destination contract.

### Latency and Cost Advantages

Trusted bridges achieve significantly lower latency and costs compared to trustless bridges:

**Latency**: After the source chain confirmation period (e.g., 13 minutes for Ethereum finality), validators can sign and submit attestations within seconds. Total latency ranges from 13-15 minutes for Ethereum sources, compared to the same finality wait plus additional time for consensus proof generation in trustless bridges.

**Gas costs**: Destination chain verification costs ~3,000 gas per signature. For a 13-validator set requiring 9 signatures: ~27,000 gas for signature verification plus ~50,000 gas for execution overhead = ~77,000 gas total. This compares to 300-400k gas for trustless bridges using sync committees, or millions of gas for full validator set verification.

**Operational costs**: Validators don't need to generate complex Merkle proofs or consensus proofs. Running a bridge validator requires full nodes for both chains and basic signing infrastructure, costing $100-500/month compared to more expensive proof generation infrastructure for trustless bridges.

**Note**: Game-theoretic designs like [Hyperloop](https://supra.com/documents/Supra-Hyperloop-Whitepaper.pdf) attempt to make multisig bridges trustless by introducing a sliding window limit on total value being transferred in one window of time is not more than validators stake. This creates no economic incentive for the bridge nodes to collude and perform malicious activity.


## Intent Based Bridges

Intent-based bridges separate user goals from execution paths. Users express their desired outcome (receive token X on chain B) rather than specifying how to achieve it. Solvers(third-party liquidity providers) compete to fulfill these intents by providing capital upfront on the destination chain, then claiming reimbursement on the source chain after verification. This architecture inverts the traditional bridge flow: instead of locking funds and waiting for cross-chain proofs, users receive funds immediately while solvers handle the settlement asynchronously.

![Intent Based Bridge Architecture](/assets/img/blog_img/bridge-interop-1/intent_bridge_arch.png)
*Source: [Intent-based bridge between L2s and Ethereum powered by multi-proof storage proofs](https://ethresear.ch/t/intent-based-bridge-between-l2s-and-ethereum-powered-by-multi-proof-storage-proofs/18563)*

### Architecture and Workflow

The user deposits tokens into a source chain escrow contract and specifies their intent:

```solidity
struct Intent {
    address sender;
    address recipient;
    uint256 sourceChainId;
    uint256 destChainId;
    address inputToken;
    address outputToken;
    uint256 inputAmount;
    uint256 minOutputAmount;
    uint256 deadline;
    bytes32 intentId;
}

function submitIntent(Intent calldata intent) external {
    require(msg.sender == intent.sender, "Invalid sender");
    require(block.timestamp <= intent.deadline, "Expired");

    // Lock user funds in escrow
    IERC20(intent.inputToken).transferFrom(
        intent.sender,
        address(this),
        intent.inputAmount
    );

    emit IntentCreated(intent.intentId, intent);
}
```

### Solver Fulfillment and Settlement

Solvers monitor intent events across chains. When a solver identifies a profitable intent, they execute the transfer on the destination chain using their own capital:

```solidity
// On destination chain
function fulfillIntent(
    bytes32 intentId,
    address recipient,
    address token,
    uint256 amount
) external {
    require(msg.sender == registeredSolver, "Unauthorized solver");

    // Solver sends funds to user immediately
    IERC20(token).transferFrom(msg.sender, recipient, amount);

    emit IntentFulfilled(intentId, msg.sender, recipient, amount);
}
```

After fulfilling the intent on the destination chain, the solver must prove fulfillment to claim the escrowed funds on the source chain. Verification mechanisms vary by protocol:

**Storage proof verification**: The solver submits a zero-knowledge or validity proof showing that the destination chain contract emitted an `IntentFulfilled` event. Protocols like Herodotus or Axiom generate proofs of storage state changes, allowing the source chain contract to verify that the fulfillment transaction occurred without running a full light client.

**Optimistic verification**: The solver claims they fulfilled the intent and submits evidence (transaction hash, block number). The claim enters a challenge period (typically 10-30 minutes). Any watcher can dispute by proving the fulfillment didn't occur or didn't meet the intent specifications. If no dispute arises, the solver receives the escrowed funds.

**Native messaging**: For L2-to-L1 bridges, solvers can use the L2's native message passing to prove fulfillment. This inherits the L2's security assumptions but adds latency (7 days for Optimistic Rollups).

The source chain settlement contract verifies the proof and releases funds:

```solidity
function claimEscrow(
    Intent calldata intent,
    bytes calldata proof
) external {
    require(!claimed[intent.intentId], "Already claimed");

    // Verify solver fulfilled the intent on destination chain
    require(verifyFulfillment(intent, proof), "Invalid proof");

    claimed[intent.intentId] = true;

    // Release funds to solver
    IERC20(intent.inputToken).transfer(msg.sender, intent.inputAmount);
}
```

### Latency and User Experience Advantages

Intent-based bridges optimize for user-facing speed at the cost of solver capital efficiency:

**Instant settlement for users**: Users receive funds on the destination chain within seconds to minutes (as fast as solvers can execute transactions). This eliminates the 13-minute Ethereum finality wait that trustless bridges require. Users don't wait for consensus proofs or validator attestations.

**Delayed settlement for solvers**: Solvers wait for proof generation and verification before claiming escrowed funds. With storage proofs, this takes 5-15 minutes. With optimistic verification, challenge periods add 10-30 minutes. With native L2 messaging, it can take days. This capital lockup means solvers must have deep liquidity or charge higher fees to compensate for opportunity cost.

**Gas cost efficiency**: Users pay gas only on the source chain (for depositing into escrow). Solvers pay destination chain gas and source chain claiming gas, but can batch multiple claims to amortize costs. Total gas costs are similar to or lower than trustless bridges since verification happens once per claim rather than per user transaction.

**MEV protection**: Solvers take on MEV risk. Since users specify minimum output amounts and solvers compete to fulfill intents, users are protected from sandwich attacks and frontrunning that would affect direct swaps. Solvers with better MEV extraction capabilities can offer better rates, creating competitive pressure.

Intent-based bridges represent a different point in the design space: optimizing user experience and speed by shifting capital and operational complexity to specialized solvers. This makes them suitable for applications requiring fast cross-chain execution (DEX aggregators, cross-chain swaps, gaming) but less suitable for high-value transfers where users prefer not to trust solver liquidity and verification mechanisms.

**Learn more**: This post provides an overview of intent-based bridging. Part 3 of this series will cover intent-based bridges in depth, including detailed protocol comparisons, solver economics, proof mechanisms, and security considerations. See also: .

## L2 Bridges

L2 bridges enable transfers between different Layer 2 networks (Arbitrum to Polygon, Optimism to zkSync) by using the shared Ethereum L1 as a message passing layer. A transfer from L2-A to L2-B requires the source L2 to finalize a message on L1, which the destination L2 then consumes. This L2→L1→L2 path introduces significant latency: Optimistic Rollups like Arbitrum and Optimism impose 7-day challenge periods before L1 withdrawal finality, while zkRollups require proof generation and submission delays ranging from minutes to hours.

The latency compounds because each L2 has independent finality requirements. Even zkRollups with faster L1 settlement still require waiting for L1 block finality (13 minutes on Ethereum) plus the destination L2 to process the incoming message. Total user-facing latency for native L2→L1→L2 transfers ranges from 20 minutes (zkRollup to zkRollup) to 7+ days (Optimistic Rollup to any L2).

![L2 Bridge Architecture](/assets/img/blog_img/bridge-interop-1/l2_bridge_arch.png)

Protocols like [Hop](https://docs.hop.exchange/basics/a-short-explainer) solve this through liquidity providers called Bonders. When a user initiates a transfer, Bonders front liquidity on the destination L2 immediately by minting hTokens (intermediate wrapped tokens) that users can swap for native tokens via an automated market maker. The Bonder locks collateral (110% of transfer value) and waits for the canonical L2→L1→L2 message to settle. After the challenge period passes without fraud proofs, the Bonder unlocks their collateral and claims the original user funds. This provides instant settlement for users while Bonders absorb the capital lockup cost.

Security relies on both cryptographic proofs and economic stakes. The L1 message path guarantees that transfers will eventually complete correctly. If Bonders fail or act maliciously, users can still use the native bridge after waiting for L1 finality. Bonders must lock collateral that gets slashed if they bond fake transfers. The more capital Bonders stake, the more security the system has. This design gives users fast transfers (under a minute) while maintaining the same security as the underlying L1.

## Sidechain Bridges

Sidechains are independent blockchains that run their own consensus mechanisms separate from Ethereum mainnet. Unlike Layer 2 rollups that post state data to L1 for security, sidechains like Polygon PoS, Gnosis Chain, and Skale maintain their own validator sets and block production rules. This independence allows sidechains to optimize for different performance characteristics such as faster block times, lower fees, alternative consensus algorithms. This also means they don't inherit Ethereum's security.

Sidechain bridges use a two-way peg mechanism to transfer assets between mainnet and the sidechain. When a user bridges tokens from Ethereum to a sidechain, the bridge contract locks those tokens on mainnet and mints equivalent tokens on the sidechain. Reversing the process burns sidechain tokens and unlocks the original mainnet tokens. The bridge maintains a 1:1 peg between locked mainnet assets and circulating sidechain tokens.

--- 

# Types of Blockchain Bridges - By Usecases

The bridge types discussed above categorize protocols by their technical architecture and security models. Users typically encounter bridges organized by use case: what the bridge enables rather than how it works.

## Message Passing Bridges

Message passing bridges enable arbitrary cross-chain communication beyond simple token transfers. They allow smart contracts on one chain to invoke functions on another chain, passing data and execution instructions. This enables cross-chain governance, cross-chain NFT operations, and multi-chain application logic.

Examples: [LayerZero](https://layerzero.network/), [Axelar](https://docs.axelar.dev/), [Wormhole](https://docs.wormhole.com/), [IBC (Cosmos)](https://ibc.cosmos.network/), [Chainlink CCIP](https://docs.chain.link/ccip), [Hyperlane](https://docs.hyperlane.xyz/), [HyperBridge](https://docs.hyperbridge.network/), [SupraNova](https://docs.supra.com/supranova).

## Asset Transfer Bridges

Asset transfer bridges specialize in moving tokens between chains. They optimize for speed, cost, and liquidity when transferring fungible tokens or wrapped assets. Many implement liquidity pools on both sides to enable instant swaps rather than waiting for cross-chain verification.

Examples: [Hop Protocol](https://docs.hop.exchange/), [Stargate](https://stargatefi.gitbook.io/), [Synapse](https://docs.synapseprotocol.com/), [Across Protocol](https://docs.across.to/), [Connext](https://docs.connext.network/), [Celer cBridge](https://cbridge-docs.celer.network/).

## Application Specific Bridges

Application specific bridges serve a single blockchain or application ecosystem. They optimize for that specific environment rather than providing general-purpose bridging. L2 canonical bridges fall into this category, as do bridges built for specific blockchain migrations or ecosystem integrations.

Examples: [Polygon PoS Bridge](https://wiki.polygon.technology/docs/pos/how-to/bridging/ethereum-polygon/), [Arbitrum Bridge](https://docs.arbitrum.io/), [Optimism Bridge](https://docs.optimism.io/), [Avalanche Bridge](https://docs.avax.network/), [zkSync Bridge](https://docs.zksync.io/), [Base Bridge](https://docs.base.org/).

--- 

# Security Considerations

Bridges represent the most exploited attack surface in blockchain systems. The largest cryptocurrency hacks have targeted bridge protocols (Ronin: \\$624M, Poly Network: \\$611M, Wormhole: \\$326M). Off-chain components create this vulnerability regardless of whether they're permissioned or permissionless. These components become the weakest link in the security model.

Even trustless bridges, which claim not to add trust assumptions beyond the underlying chains, face fundamental security limitations. A trustless Ethereum bridge should inherit only Ethereum's existing security assumptions. Consider a 51% attack on Ethereum. Many assume this breaks everything, but blockchains often maintain certain properties even under majority attacks. Ethereum can potentially roll back to a correct state after such an attack, preserving some security guarantees.

If trustless bridges truly add no additional assumptions, they should survive or recover from a 51% attack on the source chain. This is not the case. When the source chain experiences a consensus failure, bridges built on that chain's consensus proofs also fail. The bridge cannot distinguish between legitimate consensus and attacker-controlled consensus. Vitalik Buterin explains this limitation in detail [here](https://old.reddit.com/r/ethereum/comments/rwojtk/ama_we_are_the_efs_research_team_pt_7_07_january/hrngyk8/).

### Security Model and Trust Assumptions

#### Trustless bridges
Trustless bridges inherit the security properties of both chains:

**Honest majority assumption**: The source chain's consensus must be secure. If 51% of Bitcoin miners collude or 2/3 of Ethereum validators collude, they can create fraudulent proofs of events that never happened.

**Finality requirements**: The destination contract must only accept events from finalized blocks. For Ethereum, this means waiting for finality (64 slots, ~13 minutes). For probabilistic finality chains like Bitcoin, this means waiting for sufficient confirmations (e.g., 100 blocks).

**Liveness**: Relayers in trustless bridges cant commit for any malicious activity and break security of the bridge. But relayers can cause a liveness attack where all the relayers goes offline on refuses to submit transactions on destination, since relayers are permissionless this attack is possible. But with a good incentive mechanism of bridge design where multiple relayer compete together to get reward for each bridge request, this can be solved.

The key advantage over trusted bridges is that these assumptions already exist. Users already trust the source and destination chains. The bridge adds no additional trust requirements beyond believing the smart contract code correctly implements verification.

**Security of ethereum sync committee**: Sync committees lack slashing mechanisms. Validators who fail to sign block headers as sync committee members face no penalties beyond missing attestation rewards. This creates a liveness assumption: the bridge relies on at least 2/3 of the sync committee being honest and online. A byzantine majority in the sync committee can sign invalid block headers without risking stake slashing, unlike consensus layer validators who face slashing for equivocation or invalid attestations. Read more about the sync committee security is analysis in the [Polkadot forum](https://forum.polkadot.network/t/snowforks-analysis-of-sync-committee-security/2712). The summary of is that, *Sync committee colusions are all exceedingly low probabilities. Even with 50% of the full Ethereum validator set being dishonest, attempting a takeover every day (epoch) for 5 years, ie, ~1825 attempts at a takeover, it is almost impossible for a takeover to occur.*

#### Trusted bridges

Trusted bridges introduce trust assumptions beyond the underlying chains:

**Honest majority of validators**: The bridge assumes at least threshold validators (e.g., 2/3) will not collude to sign fraudulent attestations. If this assumption breaks, funds can be stolen without recourse beyond slashing (which only works if the fraud is provable on-chain).

**Validator liveness**: If too many validators go offline, the bridge halts. With a 2/3 threshold, if more than 1/3 of validators are offline or refuse to sign, no new cross-chain messages can be processed.

**Validator set trust**: Users must trust the mechanism that selects and rotates validators. If the selection process is centralized or captured, malicious validators can be added.

**Slashing effectiveness**: For staked validator bridges, slashing only works if fraudulent attestations are provably fraudulent on-chain. If validators simply refuse to sign legitimate events (censorship), they typically cannot be slashed.

The key risk is that the validator set is a smaller attack surface than the full source and destination chains. Compromising 2/3 of 13-19 validators is easier than attacking Ethereum's consensus. This makes trusted bridges suitable for lower-value transfers or scenarios where validators have strong off-chain accountability, but risky for securing billions in TVL.

Some protocols attempt to reduce trust through hybrid approaches. **Axelar** combines a validator set with quadratic voting and slashing. **Synapse** uses optimistic verification where validators attest immediately but watchers can challenge within a dispute period. These designs trade some of the latency/cost advantages for improved security.

#### Intent based bridging

Intent-based bridges introduce different trust assumptions than consensus-based or multisig bridges:

**Solver liquidity risk**: Solvers provide capital before receiving reimbursement. If the verification system fails or the source chain experiences extended downtime, solvers' capital remains locked. This creates a capital efficiency problem. Solvers must maintain liquidity across multiple chains and cannot reuse capital instantly.

**Verification mechanism trust**: The security depends on how fulfillment is verified. Storage proof systems inherit the source chain's security (anyone can verify proofs on-chain). Optimistic systems assume at least one honest watcher monitors for fraud. Native messaging inherits the L2's trust assumptions.

**Censorship and liveness**: If solvers refuse to fulfill intents (censorship) or all solvers go offline, the bridge halts for new transfers. Some protocols implement fallback mechanisms allowing users to withdraw their escrowed funds after a timeout period, but this adds latency for legitimate transfers.

**Solver centralization**: High capital requirements and infrastructure complexity create barriers to entry. If few solvers dominate, they can collude to extract MEV, censor transactions, or demand unfair fees. Protocols address this through solver reputation systems, slashing for misbehavior, or auction mechanisms that drive competitive pricing.

#### Sidechains

The security model depends entirely on the sidechain's consensus and the bridge validators. If the sidechain's validator set is compromised or the bridge contract has vulnerabilities, funds can be stolen without recourse to Ethereum's security. Users trust the sidechain's independent consensus rather than relying on Ethereum validators or cryptographic proofs of Ethereum state. This makes sidechains suitable for applications prioritizing throughput and low costs over maximum security, but risky for high-value asset storage.

## What Makes a Bridge Good?

No single bridge design works best for all scenarios. The optimal choice depends on the specific chains being bridged and the application requirements.

Trustless bridges provide the strongest security by inheriting the security of the underlying chains without additional trust assumptions. They work best when the source chain has fast finality (zkRollups with minutes, not Optimistic Rollups with 7 days), consensus proofs are simple to verify (512 validators in sync committees vs. 1M full validator set), destination chain gas costs are low enough to make proof verification economical, and permissionless relayers can operate profitably with reasonable fee structures. Trustless bridges become impractical when verification costs are too high or finality takes too long. Verifying full consensus proofs on expensive chains can cost millions of gas per day. Waiting 7 days for Optimistic Rollup finality makes poor user experience.

Trusted or intent-based bridges offer better latency and lower costs when source chain finality is slow or verification is expensive, users prioritize speed over maximum security, the application handles lower-value transfers where trust tradeoffs are acceptable, and strong monitoring and dispute systems exist to catch misbehavior. Trusted bridges require good incentive design to remain secure. Slashing mechanisms should punish validators who sign fraudulent attestations. The total value locked should not exceed validator collateral. Economic incentives must make collusion unprofitable. For multisig bridges, limiting the value transferred within a time window to less than total validator stake removes the profit motive for collusion.

Good bridge design balances security, speed, and cost for the specific use case. High-value asset transfers justify the cost and latency of trustless bridges. Fast cross-chain swaps and gaming applications benefit from intent-based bridges with instant settlement. Application-specific L2 bridges can optimize for their specific chains and use cases. The best bridge is the one that matches your security requirements with acceptable cost and latency tradeoffs. 



--- 
