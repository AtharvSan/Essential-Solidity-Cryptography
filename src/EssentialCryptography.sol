// --- part 3 of a 5 part series on essentials for solidity devs ---
// - Essential-Solidity  (https://github.com/AtharvSan/Essential-Solidity)
// - Essential-EVM-Assembly  (https://github.com/AtharvSan/Essential-EVM-Assembly)
// - Essential-Solidity-Cryptography  (https://github.com/AtharvSan/Essential-Solidity-Cryptography)
// - Essential-Solidity-Design-Patterns
// - Essential-Solidity-Security


/* table of contents -------------------*/
// --- trivia ---
// - properties: computation environment
// - properties: cryptography
// - cryptographic terms and definitions

// --- concepts ---
// - Hash functions
// - Encryption
// - Elliptic Curves and keys
// - Signatures
// - EIP191 signed_data standard
// - EIP712 typed structured data hashing and signing
// - Signature verification
// - EIP2612 signed approvals for erc20 tokens
// - EIP1271: ecrecover for multi-account signatures
// - commit reveal mechanism
// - merkle proofs
// - Randomness generation


/* trivia --------------------------------------*/
// --- properties in computation environment  ---
// - onchain
//      - immutable
//      - transparent
// - offchain
//      - cheap to compute
//      - excellent privacy
// notes: use cryptographic proofs to bridge off-chain to on-chain

// --- properties in cryptography ---
// - data 
//      - easy reference to data: hash is an easy reference to data thats easy to deal with than the actual data
//      - Collision Resistance(uniqueness): No two different inputs should produce the same output
//      - Preimage Resistance(non reversibility): Given a output, it should be infeasible to find the original input.
//      - Avalanche Effect: A small change in input should result in a completely different output
//      - deterministic system: getting outputs from fixed processes (same output for same input)
//      - randomness: no predictability in output
//      - encryption: locking
//      - decryption: unlocking
//      - Integrity(tamper proof): Guarantees that data has not been altered or tampered with.
//      - Semantic Security: Ciphertext leaks no partial information about plaintext.
//      - Zero-Knowledge Proofs: Prove knowledge of a secret without revealing it.
// - participants
//      - trust: you will have to know character of the participant before you can interact with them
//      - trustless: you can interact with anyone without knowing their character
//      - Confidentiality: only authorized parties can access the information.
//      - Authentication: Verifies the identity of communicating parties.
//      - non-repudiation: non deniability of action
//      - anonymity: no one knows who is interacting
//      - signatures(proof of order)
// - general
//      - verifiability: proof of correctness

// --- cryptographic terms and definitions ---
// - seed: a crucial input value 
//      - use : to initialize cryptographic algorithms, particularly those involving randomness.
// - key: a special value derived from a seed using key derivation functions (KDFs)
//      - use : encryption(public key), decryption(pvt key)
// - encryption decryption: locking unlocking
//      - use : secure communications
// - plain text: human readable text, this is the data that we want to protect from interception
// - cypher text: cryptic text output that we get after plain text is encrypted
// - hash: a fixed-size of bytes that uniquely represents a certain data. 
//      - use : data integrity, data representation
// - salt: A random value added to input data before hashing, ensures that same inputs produce different hash outputs.
//      - use : protecting against precomputed attacks like rainbow tables.
// - nonce: a 'n'umber used 'once' intended to create uniqueness.
//      - use : to prevent replay attacks.
// - signature: proof of origin
//      - use : identify who initiated the txn
// - signed data: the data on which signature is being created
// - signed order: the order to be executed along with the signature
//      - use : delegating orders to third party


// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";


/// @author AtharvSan
/// @dev part 3 : essential cryptography for solidity devs
contract EssentialCryptography {
    
    constructor(bytes32 _merkleRoot) {
        // 8. eip2612 signed approval (signed orders)
        alice = address(0x2);
        bob = address(0x3);

        // 11. merkelRoot (represents the allowlist)
        merkleRoot = _merkleRoot;
    }

    // 1. Hash functions ----------------------------//
    // - the problem : big data has the risk is sometimes too big its hard to point out the exact data(if the data gets corrupted)
    // - the solution : the data is shortened down to few bytes, now its way easier to give reference to exact data
    // - implementation : keccak256(bytes data) --> bytes32
    // - properties (specially engineered features) :
    //      - collision resistance : unique and short output
    //      - fast to compute
    //      - deterministic : same input will always give same output
    //      - avalanche effect : small change in input will result in completely different output
    //      - pre-image resistance : given output, very hard to find input that gives that output
    //      - fixed output size : always gives same size output
    bytes32 public ATHARVSAN = keccak256("atharvsan"); 

    bytes32 salt = bytes32(uint256(0x12345678));
    bytes32 public ATHARVSAN_SALTED = keccak256(abi.encodePacked("atharvsan",salt)); 


    // 2. Encryption ---------------------------------//
    // - the problem : communications can be intercepted
    // - the solution : develop a 'lock and key' system to protect the communication from interception
    // - implementation : OFFCHAIN encryption by wallets


    // 3. Elliptic Curves and keys -------------------//
    // - the problem : strangers not able to open the encrypted lock
    // - the solution : seperation of keys for locking and opening. Anyone can lock but only the reciever can open.
    // - implementation : OFFCHAIN key computation using the secp256k1 curve
    // - properties : 
    //      - pvt key: 
    //          - opens the encrypted lock
    //          - creates a signature
    //      - public key:
    //          - closes the encryption lock
    // - trivia :
    //      - each account has its own lock, use the account's public key to use it.
    //      - pvt key :
    //          - randomly generated 256-bit key using random number generator from the OS
    //      - pub key :
    //          - generated by doing elliptic curve multiplication on the pvt key


    // 4. Signatures ---------------------------------//
    // - the problem : secure communication with strangers became possible, but no info on who sent the message
    // - the solution : sender sends his signature along with the data
    // - implementation : 
    //      - signatures are created OFFCHAIN using ECDSA, but verification can be done onchain with ecrecover
    //          - signatures generated by wallets: standard transactions <RLPdata,r,s,v>
    //          - generated by offchain scripts: signed orders <signed_data,r,s,v>
    //              - create signed_data according to eip191
    //              - ECDSA(signed_data,pvt_key) --> v,r,s
    // - trivia :
    //      - signatures are created offchain, so this is a gasless process.
    //      - signature(bytes32 r, bytes32 s, uint8 v) is a 65-byte data created by ECDSA using data and pvt key


    // 5. EIP191 signed_data standard -----------------//
    // - the problem: 
    //      - presigned txns getting confused with standard txns as there was no standard to differentiate in 'signed_data' and 'RLPdata'
    //      - the signed_data was not standardized, caused confusion in verification
    // - the solution: 
    //      - setting a standard for differentiating 'signed_data' from 'RLPdata' (initiate with 0x19)
    //      - creating a standard scheme for 'signed_data', to avoid confusion while verifying
    // - implementation :
    //      - signed_data = hash(encodePacked( 0x19 | version | version_data | data_to_sign ))
    //      *************************************************************************************************
    //      eth_sign              -->  0x19 | 0x00   | intended validator | data to sign
    //      eth_signTypedData_v4  -->  0x19 | 0x01   | domainSeperator    | hashStruct(message)
    //      personal_sign         -->  0x19 | 0x45(E)| thereum Signed Message:\n"+len(message) | data to sign
    //      *************************************************************************************************
    // - trivia :
    //      - signed_data : the data on which the signature is created
    //      - signed order : a chunk of binary 'signed_data', along with the signature(r,s,v)
    //      - standard txn : RLP<nonce, gasPrice, startGas, to, valve, data>, r, s, v
    //      - helps in verification of off-chain signatures in ethereum ecosystem
    //      - RPC calls like eth_sign, eth_signTypedData_v4, personal_sign are executed offchain
    //      - E is 0x45 in ASCII
    MultiSig multisig = new MultiSig();
    function Signed_data00() view public returns(bytes32 signed_data00) { 
        bytes memory data00 = "yo multisig, how are you..";
        // signed_data00 = 0x19 || 0x00 || validator address || data00
        signed_data00 = keccak256(abi.encodePacked(hex"1900",address(multisig), data00));
    }
    function Signed_data45() pure public returns(bytes32 signed_data45) { 
        bytes memory data45 = "hello, its me.";
        // signed_data45 = 0x19 || 0x45 || "thereum Signed Message:\nlen(data)" || data45
        signed_data45 = keccak256(abi.encodePacked(hex"1945","thereum Signed Message:\n14",data45));
    }


    // 6. EIP712 typed structured data hashing and signing --------------//
    // - the problem : users are shown cryptic messages when they create signatures in wallets
    // - the solution : 
    //      - create a standard for hashing and signing typed structured data
    //      - this brings clarity to the end user when he signs via his wallet
    // - implementation :
    //      - the start of eip712 is mainly offchain when users sign the message using eth_signTypedData
    //      - the other part is in contracts where they have to reconstruct the signed_data to recover the signer
    //          - contract has a struct for EIP712Domain and structured data(sturct or function)
    //          - create a hashStruct of EIP712Domain and structured data
    //              - typehash: notice that no space after the comma
    //              - encodeData: each encoded member value is exactly 32-byte long, thats why abi.encode is used at encodeData step
    //                  - atomic values are encoded directly
    //                  - The array values are encoded as the keccak256 hash of the concatenated encodeData of their contents 
    //                    (i.e. the encoding of SomeType[5] is identical to that of a struct containing five members of type SomeType).
    //                  - hash values for dynamic types
    //          - create signed_data01 as in eip191
    // - properties
    //      - domainSeperator should be unique to the contract and chain to prevent replay attacks from other domains, and satisfy 
    //        the requirements of EIP-712, but is otherwise unconstrained.
    // - use cases :
    //      - give a better user experience when signing via wallets
    // - trivia :
    //      - the typed structured data can be anything like a struct or a function
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        bytes32 salt;
    }
    struct Mail { 
        string subject;
        address to;
        address from;
        uint256 nonce;
        bytes4 magicValue;
        bytes data;
        bool result;
        string[3] message;
    }
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    function Signed_data01() view public returns(bytes32 signed_data01) {
        bytes32 typeHash_eip712domain = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
        bytes32 hashStruct_EIP712Domain = keccak256(abi.encode(
            typeHash_eip712domain, 
            keccak256("name"),
            keccak256("version"),
            1,
            address(this),
            0x1234
            )
        );

        bytes32 typeHash_mail = keccak256("Mail(string subject,address to,address from,uint256 nonce,bytes4 magicValue,bytes data,bool result,string[3] message)");
        bytes32 hashStruct_mail = keccak256(abi.encode(
            typeHash_mail,
            keccak256("practice"),
            alice,
            bob,
            0,
            0x12345678,
            keccak256("data"),
            true,
            keccak256(abi.encodePacked(
                keccak256("hey"),
                keccak256("hello"),
                keccak256("hi")
            ))
        ));
        // signed_data01 = 0x19 || 0x01 || domainSeperator || hashStruct
        signed_data01 = keccak256(abi.encodePacked(hex"1901", hashStruct_EIP712Domain, hashStruct_mail));
    }


    // 7. Signature verification -------------------------//
    // - the problem : signatures are handled at infrasturcture level, but if you choose to do it yourself you will need to do handle
    //   both signature creation(offchain) and signature verification(onchain) independently
    // - the solution : create offchain signatures using ECDSA, and include a function in smart contracts that verifies the signature using ecrecover
    // - implementation : 
    //      - arrange: recreate the signed_data
    //      - extraction: ecrecover(signed_data, v, r, s)
    //      - verification: recovered address == the 'owner' that was included in signed_data
    // - use cases:
    //      - no need to transact yourself, create signed orders that can be submitted via 3rd party(relayers) as the process is not depending
    //        on msg.sender for proof of authentication.
    function verify(address owner, bytes calldata data, uint8 v, bytes32 r, bytes32 s) public view returns (bool success) {
        bytes32 signed_data = keccak256(abi.encodePacked(hex"1900", address(this), data));
        address signer = ecrecover(signed_data, v, r, s);
        require(signer == owner, "unauthorized");
        return true;
    }

    // @audit what is passed in functions? (signed_data, vrs), (order params, vrs), or just (vrs)

    // 8. EIP2612 signed approvals for erc20 tokens //
    // - the problem : ERC20 operation is attached to msg.sender for its builtin signature handling
    // - the solution : we decouple ERC20 from msg.sender by implementing signature handling independently 
    //      - offchain signature creation (v, r, s): eth_signTypedData_v4
    //      - submit the order(owner, spender, value, deadline) and the signature (v, r, s) to relayer that will inititate the permit method on token
    //      - create signed_data that will be used in signer extraction: 191, 712, 2612
    //      - extract signer: ecrecover(signed_data, v, r, s)
    //      - verify if the signature is of owner from the order : require(signer == owner, "don't touch someone else's money")
    //      - perform the approve action i.e update allowance for the given order
    // - implementation : Compliant contracts must implement 3 new functions in addition to EIP-20:
    //      - function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external{
    //            // 1. signer recovery 
    //            // 2. verification
    //            // 3. allowance update 
    //        }
    //      - function nonces(address owner) external view returns (uint)
    //      - function DOMAIN_SEPARATOR() external view returns (bytes32)
    // - use cases :
    //      - Gasless approves
    //          - Users can approve token transfers without paying gas fees upfront.
    //          - instead of calling approve(), users sign a message off-chain, which is later submitted by the relayer.
    //      - Uniswap and Aave use EIP-2612 to streamline token approvals
    //          - No need for two transactions (approve() + transferFrom()), improving user experience.
    //          - Ideal for onboarding new users without requiring ETH for gas.
    // - Security notes
    //      - reducing frontrunning risks
    //      - Uses eip712 domainSeperator, preventing signature malleability issues.
    //      - deadline param prevents issues like "stuck approvals" 
    //      - nonces gives replay protection
    //      - Since the ecrecover precompile fails silently and just returns the zero address as signer when given malformed messages, 
    //        it is important to ensure owner != address(0) to avoid permit from creating an approval to spend “zombie funds” belong 
    //        to the zero address.
    //      - The standard EIP-20 race condition for approvals (SWC-114) applies to permit as well
    //      - If the DOMAIN_SEPARATOR contains the chainId and is defined at contract deployment instead of reconstructed for every signature, 
    //        there is a risk of possible replay attacks between chains in the event of a future chain split.
    // - trivia
    //      - a practical application of independent signature handling (offchain signature creation and onchain signature verification)
    //      - it de-couples ERC20 from msg.sender(builtin signature handling) by handling signatures independently
    //      - A common use case of permit design pattern has a relayer submit a permit order on behalf of the owner.
    address public alice;
    address public bob;
    function permit(
        address owner, // this owner is the one who owns tokens
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");

        // Unchecked because the only math done is incrementing
        // the owner's nonce which cannot realistically overflow.
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)" //@audit why not the entire permit function, whats going on?
                                ),
                                owner,
                                spender,
                                value,
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );

            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");

            allowance[recoveredAddress][spender] = value;
        }

        emit Approval(owner, spender, value);
    }
    
    uint256 internal immutable INITIAL_CHAIN_ID = block.chainid;
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();//in case the chain bifurgates, chainids may differ
    }
    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("MockERC20"),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }


    // 9. EIP1271: ecrecover for multi-account signatures //
    // - the problem : no native support to handle(generate and verify) multi account signatures
    // - the solution :
    //      - create signatures(anywhere onchain offchain) without ECDSA (cuz contracts dont have pvt keys) using EOA signatures as base components 
    //        (Notice that signatures can be anything as long as it gives proof of origin)
    //      - now you need to write the logic for how to veify the signature that your contract has just created(cuz ecrecover is for single
    //        account signatures)
    // - implementation :
    //      - signature creation
    //          - a custom sign function: uses EOA owner signatures to generate something that represents joint multi account signature.
    //      - signature verification
    //          - a custom isValidSignature function: 
    //              - uses the same logic from sign function to verify if the given signature was really from your contract.
    //              - must not modify state
    //              - must return the bytes4 magic value 0x1626ba7e when function passes.
    //      - in standard single account signature verification, the receiving contract of (signed order, signature) uses builtin 
    //        recovery logic(ecrecover). But in our case the receiving contract of (signed order, signature) uses custom logic(isValidSignature)
    // - use cases :
    //      - multiSig wallets
    //      - advanced signed orders
    // - trivia :
    //      - ethereum's native signatures originate from single point of source(pvt key of user account), but if you need joint partnership
    //        accounts you will need to create signatures that represent multiple accounts involved in the parthnership.
    //      - signature is basically a proof of origin, it doesnt necessarily be just the (v, r, s), it can be anything as long as
    //        the proof of origin(the signature) is verifyable. The verification logic can be anything, as long as it can correctly identify 
    //        the origin from the signature
    //      - multi account signatures must contain each account's individual vrs components as produced from ECDSA, as these components 
    //        can't be fabricated by third party.
    //      - standardizes verification, not creation.
    function validate_contractSigner(bytes32 signed_data, bytes calldata jointSignature, address multiSig_wallet) external view { //@audit about the params?
        // acutally signed_data is never given, its in the form of order(the params to function). signed_data is meant to be reconstructed.
        // - cheatsheet calls multisig wallet to verify the signature
        bytes4 result = IERC1271Wallet(multiSig_wallet).isValidSignature(signed_data, jointSignature);
        require(result == 0x1626ba7e, "INVALID_SIGNATURE");
    }
    

    // 10. commit reveal mechanism -------------------------//
    // - the problem :
    //      - in coordinated efforts like voting or auctions, notorious users can change submissions as and when they feel.
    //      - mempool is transparent and plain text data in txns is easy to intercept, bots can read the txns and frontrun as they suit. 
    // - the solution : 
    //      - commit reveal mechanism, commit the hash of secret onchain and reveal the secret at the right time.
    // - implementation : 
    //      - commit: save the hash of your secret onchain
    //      - reveal: reveal your secret at the appropriate time, so that anyone can cross verify with the hash.
    // - use cases :
    //      - fairness in participation (voting, auctions, games)
    struct Commitment {
        bytes32 commitHash;
        bool revealed;
    }
    mapping(address => Commitment) public commitments;
    mapping(address => string) public secrets;

    function commit(bytes32 _commitHash/* keccak256(abi.encodePacked(_secret, _salt)) */) external {
        require(commitments[msg.sender].commitHash == bytes32(0), "Already committed");
        commitments[msg.sender] = Commitment(_commitHash, false);
    }

    function reveal(string memory _secret, uint256 _salt) external {
        // 1. sanity checks
        Commitment storage userCommitment = commitments[msg.sender];
        require(userCommitment.commitHash != bytes32(0), "No commitment found");
        require(!userCommitment.revealed, "Already revealed");
        // 2. Verify the hash
        require(userCommitment.commitHash == keccak256(abi.encodePacked(_secret, _salt)), "Invalid reveal");
        userCommitment.revealed = true;
        // 3. Process revealed value (e.g., store or use it)
        secrets[msg.sender] = _secret;
    }


    // 11. merkleRoot: an advanced hash, now you can interact with it --------------------//
    // - objective :
    //     - verify membership of an element in a set
    // - the problem : 
    //      - you can't store big list of users onchain, thats expensive. Hashes are small bytes32 values, but you can not interact with them.
    //      - if you store some small value like hash, how do you prove membership of an element that made up the hash. 
    // - the solution : 
    //      - you use merkle root that are small cuz its a hash at the end, but its special that you can interact with it.
    // - implementation :
    //      - 1. create a merkelRoot offchain (in ethers.js or Python) out of the set of elements and store it onchain
    //      - 2. to verify membership, you will need the merkleProof and the leaf ready for that particular element. You need to generate 
    //        the merkleProof offchain (in ethers.js or Python) before sending it to Solidity.
    //      - 3. just call the verifyMember function with the leaf and merkleProof, it verifies the proof and tells if the element was included in
    //        the calculation of the root hash.
    // - properties : 
    //      - small size of merkle root
    //      - interactable: you can verify if an element was included in calculation of the root hash
    //      - minimal computation: 
    //          - building the merkleTree : O(N)
    //          - everything else: O(logN)
    // - use cases : 
    //      - save gas on verifing a user's membership
    //      - Prove a file’s integrity without storing it fully on-chain
    // - trivia :
    //      - merkleRoot: the final single hash at the top of the tree.
    //          - Leaf nodes contain the hashes of individual data elements.
    //          - Each parent node is the hash of its two child nodes.
    //          - The merkle root is the final single hash at the top of the tree.
    //      - merkleProof: all the brothers in the pairs upto root to prove the membership of an element
    //          - A path of hashes in the tree needed to recompute the Merkle root.
    //      - leaf: hash of an element in the set
    // - scenario :
    //      - verify if the caller is a member of allowlist
    bytes32 public merkleRoot; 
    function verifyMember(bytes32[] memory merkleProof) view public {
        // prepare the leaf for the element
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        
        // recreating merkleRoot using leaf and Proof, to match if its indeed the root. That tells if leaf was included in calculation of merkelRoot.
        require(MerkleProof.verify(merkleProof, merkleRoot, leaf),"invalid proof");
    }


    // 12. Randomness generation : Chainlink VRF 
    // - the problem : 
    //      - Computers are deterministic (outputs are generated via a fixed process). So there remains a chance of predicting outputs, if the 
    //        computation process is known. The issue is how do you get randomness in deterministic environments.
    // - the solution :
    //      - generate randomness outside of the system and just import it
    // - implementation of chainlink vrf :
    //      - integrate chinklink vrf into your randomness consumer contract
    //      - to import randomness consumer contract calls chainlink coordinator
    // - properties :
    //      - generates randomness outside of your system
    //      - Verifiable: Proof is validated on-chain to ensure no manipulation.
    //      - Decentralized: Combines oracle secrets, user input, and blockchain state.
    // - use cases : 
    //      - fairness in distribution (lottery, in-game mechanisms)

    
    // 13. ERC 7683 : Cross Chain Intents
}

/// @dev 2/3 multisig account
contract MultiSig { 
    address public alice = address(0x01);
    address public bob = address(0x02);
    address public codi = address(0x03);
    mapping(address => bool) public owner_multisig;

    constructor () {
        owner_multisig[alice] = true;
        owner_multisig[bob] = true;
        owner_multisig[codi] = true;
    }

    // - This function should be implemented by contracts which desire to sign messages (multisignature wallets, DAOs) 
    // - Applications wanting to support contract signatures should call this method if the signer is a contract.
    function isValidSignature(bytes32 _signed_data, bytes calldata _jointSignature) external view returns (bytes4 magicValue) {
        magicValue = 0xffffffff;
        require(_jointSignature.length == 130, "invalid packing");

        uint8 v1 = uint8(_jointSignature[64]);
        bytes32 r1 = bytes32(_jointSignature[0:32]);
        bytes32 s1 = bytes32(_jointSignature[32:64]);
        address signer1 = ecrecover(_signed_data, v1, r1, s1);

        uint8 v2 = uint8(_jointSignature[129]);
        bytes32 r2 = bytes32(_jointSignature[65:97]);
        bytes32 s2 = bytes32(_jointSignature[97:129]);
        address signer2 = ecrecover(_signed_data, v2, r2, s2);

        require(owner_multisig[signer1] && owner_multisig[signer2], "invalid jointSignature");

        return 0x1626ba7e;
    }
}

interface IERC1271Wallet { 
    // bytes4 constant internal MAGICVALUE = bytes4(keccak256("isValidSignature(bytes32,bytes)");
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view returns (bytes4 magicValue);
}
