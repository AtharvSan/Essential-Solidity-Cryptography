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
// - foundational tools

// --- concepts ---
// - Hash functions
// - salting
// - commit reveal mechanism
// - merkle proofs
// - Encryption
// - Elliptic Curves and keys
// - Signatures
// - EIP191 signed_data standard
// - EIP712 typed structured data hashing and signing
// - Signature verification
// - EIP2612 signed approvals for erc20 tokens
// - EIP1271: ecrecover for multi-account signatures
// - Randomness onchain

// --- roadmap ---
// - ERC 7683 Cross Chain Intents
// - Zero Knowledge Proofs


/* trivia --------------------------------------*/
// --- properties in computation environment  ---
// - onchain
//      - sovereign transactions (cencorship resistant)
//      - transparent
// - offchain
//      - cheap to compute
//      - excellent privacy
// notes: use cryptographic proofs to bridge off-chain and on-chain states.

// --- properties in cryptography ---
// - data 
//      - easy reference to data: hash is an easy reference to data thats easy to deal with than the actual data
//      - Collision Resistance: No two different inputs produce the same output
//      - Preimage Resistance(non reversibility): Given a output, it is infeasible to find the original input.
//      - Avalanche Effect: A small change in input results in a completely different output
//      - deterministic: getting outputs from fixed processes (same output for same input)
//      - randomness: no predictability in output
//      - uniqueness: data is different from all others
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
// - secret : a data that is meant to be known only to the owner
//      - use : commit reveal scheme, voting, auctions
// - hash: a fixed-size of bytes that uniquely represents a certain data. 
//      - use : data integrity, data representation
// - salt: A random value added to input data before hashing
//      - use : protecting against brute force attacks like rainbow tables.
// - nonce: a 'n'umber used 'once' intended to create uniqueness.
//      - use : to prevent replay attacks.
// - signature: proof of origin
//      - use : identify who initiated the txn
// - signed data: the data on which signature is being created
// - signed order: the order to be executed along with the signature
//      - use : delegating orders to third party

// --- foundational tools ---
// - secp256k1: ethereum's elliptic curve that is foundational to keys, encryption and signatures
// - ECDSA: create signatures using secp256k1
// - ecrecover: recover the signer from the signature using secp256k1
// - keccak256: ethereum's hash function


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

    /* hash functions -----------------------*/
    // - the problem:
    //      - referencing crucial data directly is prone to silly errors (like function signatures)
    //      - Working with large data directly is error-prone and inefficient.
    //      - plain text secrets can be accessed by attackers and extracted from contract state.
    // - the solution:
    //      - create compact fingerprint of the data. It helps in both, data integrity and covering up of secrets.
    //      -------------------------------------------------------------------------------------------------------------------------------------
    //      |  . . . . . . . . . . . . . . . . . . . . . . . . . .                                                                              |
    //      |  . . . . . . . . . . . . . . . . . . . . . . . . . .                                                                              |
    //      |  . . . . . . . . . . . . . . . . . . . . . . . . . .     -->    **************                                                    |
    //      |  . . . . . . . . . . . . . . . . . . . . . . . . . .                                                                              |
    //      |  . . . . . . . . . . . . . . . . . . . . . . . . . .                    `--> short hash output only 32 bytes                      |
    //      |  . . . . . . . . . . . . . . . . . . . . . . . . . .                         (no correlation to input, good for keeping secrets)  |
    //      |                                                                                                                                   |
    //      |                           |                                                                                                       |
    //      |                           `--> plain text data                                                                                    |
    //      -------------------------------------------------------------------------------------------------------------------------------------
    // - Implementation: 
    //      - keccak256(bytes memory)  →  bytes32
    // - properties (specially engineered features) :
    //     *1  avalanche effect : small change in input will result in drastically different output
    //      2  short hash
    //     *3  obfuscation : output is very different to the input, no correlation
    //     *4  pre-image resistance : given output, very hard to find input that generates that output
    //      -  collision resistance : unique hash
    //      -  deterministic : same input will always give same output
    //      -  fixed output size of 32 bytes
    //      -  fast to compute
    // - use cases: 
    //      - data integrity: reference to the exact data with pin point accuracy (1. avalanche effect)
    //      - commiting secrets: covering up the secrets (3. obfuscation and  4. pre-image resistance)
    // - example:
    // hashes are great at dealing with data with pin point accuracy. Even a slight change in data is easily evident when hash values are used.
    bytes32 public real_name = keccak256("AtharvSan"); //0x930b8dfd2e331b73a97ba6d9de99459d54f4a44fe1380b014c78a10cc68a0f20
    bytes32 public small_mistake_in_name = keccak256("atharvsan"); //0xbbefe4dfe80e6a074139e9cd958be264dfb3ed25b010865e1181c9b97683da88


    /* salted hashing --------------------------*/
    // - the problem:
    //      - some systems demand uniqueness for each hash value
    //      - it is very easy to brute force the hash generated from smaller size secrets 
    // - the solution: add a salt value 
    //      - add an additional value(called salt) to the data and make the input to hash function quite bigger
    // - Implementation:
    //     bytes32 salted_hash = keccak256(abi.encode("data", salt));
    // - properties: 
    //      - salting makes input to hash functions a lot bigger
    //      - salting makes the hash values unique even for the same primary data
    //      - when salting is intended for uniqueness of hash 
    //          - salt is generated from a deterministic process
    //          - unique salt value for each instance of primary data
    //      - when salting is intended for covering up of secrets
    //          - salt is a random value
    //          - salt is a secret
    // - use cases :
    //      - creates uniqueness where needed like 
    //          - create2 addresses, cross chain messages, eip712 
    //      - risk free use of smaller secrets for generating hash values


    // commit reveal mechanism -------------------------//
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


    // merkleRoot: an advanced hash, now you can interact with it --------------------//
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


    /* Simple Encryption ----------------------------*/
    // - the problem : 
    //      - communications can be intercepted
    // - the solution : 
    //      - a 'lock and key' system to protect the communication from interception
    // - use cases : 
    //      - used in secure communications


    /* Elliptic Curves, keys and Asymetric Encryption ---------------*/
    // - the problem : 
    //      - to use locks you need to have the keys with you and thats why establishing communication with strangers becomes a problem.
    // - the solution : 
    //      - seperation of keys for locking and opening. 
    //      - Locking key is made public, so anyone can lock but only the reciever can open.
    //      - now its possible to communicate with strangers cuz they have made their locking system public (opening key is private to recipient)
    // - implementation : 
    //      - key generation: implemented by wallets using the secp256k1 curve. 
    //      - asymetric encryption: is done offchain, communication is locked using public key of recipient and opened using private key of recipient
    // - properties : 
    //      - pvt key: 
    //          - opens the encrypted lock
    //          - creates a signature
    //      - public key:
    //          - closes the encryption lock
    // - trivia :
    //      - tx to smart contract is not encrypted, just signed with pvt key of eoa.
    //      - each account has its own lock, use the account's public key to access the locking system.
    //      - pvt key :
    //          - randomly generated 256-bit key (subject to constraints from secp256k1)
    //      - pub key :
    //          - generated by doing elliptic curve multiplication on the pvt key
    //      - signature verification is the only elliptic curve computation that is done onchain, everything else is offchain


    // Signatures ---------------------------------//
    // --- intro ---
    // - the problem: 
    //      - strangers could receive communication messages but couldn't figure out who sent the message
    // - the solution: 
    //      - sender sends his signature along with the data
    //      - signature is a proof of origin, so the receiver can identify the real sender
    // - trivia:
    //      - participants: user, wallet, dapp frontend, dapp backend, ethereum node, contract
    //      - signable objects
    //          - transactions (𝕋)
    //          - bytestrings (𝔹⁸ⁿ)
    //          - structured data (𝕊)
    //      - all signatures are created offchain usually by the wallets
    //      - pvt key never leaves the wallet (ethereum node directly gets the signature from the wallet)
    //      - ethereum uses ECDSA as its signature creation algorithm which uses secp256k1 under the hood
    //      - default ECDSA libraries like OpenSSL give seperate 32-byte r and s as output
    //      - but Ethereum wallets and ethereum clients combine them into the 65-byte package because that's the format used in ethereum signatures
    //          - v is the recovery id, r and s are the signature values
    //          - it is packed as a single 65-byte value in the order --> r s v

    // --- standard trnansactions ---
    // - use case:
    //      - standard transactions are meant for immidiate onchain actions with all strings attached to msg.sender
    // - signature creation
    //      - signature for standard transactions is automatically handled by wallets when user signs the transaction
    //          - wallet serializes the transaction object using RLP encoding
    //          - wallet creates a signature on RLP encoded data then sends the tx to ethereum node using eth_sendRawTransaction
    // - signer recovery
    //      - signer recovery is builtin, evm makes the msg.signer available globally (ecrecover used under the hood)
    // - trivia:
    //      - Wallet sends signed transactions on-chain. Dapp frontend backend do not interfere.

    // --- signed messages ---
    // - use case:
    //      - signed messages provide flexibility in authorization designs
    // - trivia
    //      - wallets create the signature by signing the signed_data with methods like personal_sign, eth_signTypedData_v4, eth_sign
    //      - dapp frontend provides the messgaes to sign for and also decides which signing method to call on the wallet
    //      - signed_data is the data on which signature is created, this data is packed according to eip191 format
    //      - signed message is a chunk of binary 'signed_data', along with the signature(r,s,v)
    //      - Signed messages are returned to you — the dApp — to handle however you want.
    
    // --- eip191 signed_data format ---
    // - the problem: 
    //      - the signed_data was not standardized, it lead to confusion in signer recovery logic
    // - the solution: 
    //      - creating a standard scheme for 'signed_data', to avoid confusion while signer recovery
    // - implementation :
    //      - signed_data = hash(encodePacked( 0x19 | version | version_data | data_to_sign ))
    //      ***
    //      personal_sign (auto arrangement)         -->  0x19 | 0x45(E)| "thereum Signed Message:\n"+len(message) | data to sign
    //      eth_signTypedData_v4 (auto arrangement)  -->  0x19 | 0x01   |  domainSeperator    | hashStruct(message)
    //      eth_sign (manual arrangement)            -->  0x19 | 0x00   |  intended validator | data to sign

    // --- personal_sign (signed message) ---
    // - use case:
    //      - when you just want to issue authorization and no onchain action
    // - signature creation
    //      - the 'message' to be signed is given by the dapp frontend itself
    //      - personal_sign auto arranges the message as : "0x19Ethereum Signed Message:\n" + length of message + message
    //      - adding a prefix is like adding a salt to the message, it makes sure the signature from message cant be used as signature for a transaction
    // - signer recovery
    //      - onchain or offchain recovery of signer depending on where the signature is sent: ecrecover(signed_data, v, r, s)
    
    // --- eth_signTypedData_v4 (signed message) ---
    // - use case:
    //      - when you want to issue authorization that can perform onchain actions
    // - signature creation
    //      - the 'message' is generally a typed structured data (struct or function)
    //      - dapp frontend provides all the message data to the wallet
    //      - eth_signTypedData_v4 auto arranges the message as : 0x19 | 0x01 | domainSeperator | hashStruct(message)
    // - signer recovery
    //      - onchain or offchain recovery of signer depending on where the signature is sent: ecrecover(signed_data, v, r, s)
    // - trivia: 
    //      - when passing onchain, (order params, v, r, s) is passed to the contract

    // --- eth_sign (signed message) ---
    // - use case:
    //      - legacy contracts, low level protocols
    // - signature creation
    //      - the 'message' to be signed is given by the dapp frontend itself
    //      - eth_sign needs manual arrangement of the message as : 0x19 | 0x00 | intended validator | data to sign
    // - signer recovery
    //      - onchain or offchain recovery of signer depending on where the signature is sent: ecrecover(signed_data, v, r, s)
    // - trivia
    //      - no prefixes, it just signs anything that you throw at it
    //      - eth_sign makes phishing attacks easy
    //      - when passing onchain, (order params, v, r, s) is passed to the contract
    function verify(address owner, bytes calldata data, uint8 v, bytes32 r, bytes32 s) public view returns (bool success) {
        bytes32 signed_data = keccak256(abi.encodePacked(hex"1900", address(this), data));
        address signer = ecrecover(signed_data, v, r, s);
        require(signer == owner, "unauthorized");
        return true;
    }
    
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

    // EIP712 typed structured data signing ------------------------//
    // - used for anything involving onchain actions
    // - the problem : 
    //      - users are shown cryptic messages when they create signatures in wallets
    // - the solution : 
    //      - create a standard for signing structured data
    //      - this brings clarity to the end user when he signs via his wallet
    // - implementation :
    //      - wallet does all the heavy lifting and creates the signature with eth_signTypedData_v4
    //      - the other part is done inside the contract where signed_data is reconstructed to recover the signer
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
    //      - gives a better user experience when signing via wallets
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


    // EIP2612 signed approvals for erc20 tokens ---------------//
    // - the problem : 
    //      - ERC20 operations are attached to builtin msg.sender for signer identification, that means you can't use someone else 
    //        to submit tx on your behalf
    // - the solution : 
    //      - we decouple ERC20 from msg.sender by handling signature creation and signer recovery independently 
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
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
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


    // EIP1271: ecrecover for multi-account signatures -------------------//
    // - the problem : 
    //      - no native support to handle(generate and verify) multi account signatures
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
    function validate_contractSigner(bytes32 signed_data, bytes calldata jointSignature, address multiSig_wallet) external view {
        // acutally signed_data is never given, its in the form of order(the params to function). signed_data is meant to be reconstructed.
        // - cheatsheet calls multisig wallet to verify the signature
        bytes4 result = IERC1271Wallet(multiSig_wallet).isValidSignature(signed_data, jointSignature);
        require(result == 0x1626ba7e, "INVALID_SIGNATURE");
    }


    // Randomness onchain : Chainlink VRF 
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
