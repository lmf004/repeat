pub struct BlockMetadata {
    id: HashValue,
    round: u64,
    timestamp_usecs: u64,
    // The vector has to be sorted to ensure consistent result among all nodes
    previous_block_votes: Vec<AccountAddress>,
    proposer: AccountAddress,
}

pub struct BlockInfo {
    /// Epoch number corresponds to the set of validators that are active for this block.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
}

pub struct Vote {
    vote_data: VoteData,
    author: Author,
    ledger_info: LedgerInfo,
    signature: Ed25519Signature,
    timeout_signature: Option<Ed25519Signature>,
}

pub struct VoteData {
    proposed: BlockInfo,
    parent: BlockInfo,
}

pub struct VoteMsg {
    vote: Vote,
    sync_info: SyncInfo,
}

pub struct VoteProposal<T> {
    accumulator_extension_proof: AccumulatorExtensionProof<TransactionAccumulatorHasher>,
    block: Block<T>,
    next_epoch_info: Option<EpochInfo>,
}

pub struct QuorumCert {
    vote_data: VoteData,
    signed_ledger_info: LedgerInfoWithSignatures,
}

pub struct LedgerInfo {
    commit_info: BlockInfo,
    consensus_data_hash: HashValue,
}

pub struct LedgerInfoWithSignatures {
    ledger_info: LedgerInfo,
    signatures: BTreeMap<AccountAddress, Ed25519Signature>,
}

pub struct SyncInfo {
    highest_quorum_cert: QuorumCert,
    highest_commit_cert: QuorumCert,
    highest_timeout_cert: Option<TimeoutCertificate>,
}

pub struct Timeout {
    epoch: u64,
    round: Round,
}

pub struct Block<T> {
    id: HashValue,
    block_data: BlockData<T>,
    signature: Option<Ed25519Signature>,
}

pub enum BlockType<T> {
    Proposal {
        payload: T,
        author: Author,
    },
    NilBlock,
    Genesis,
}

pub struct BlockData<T> {
    epoch: u64,
    round: Round,
    timestamp_usecs: u64,
    quorum_cert: QuorumCert,
    block_type: BlockType<T>,
}

pub struct TransactionInfo {
    /// The hash of this transaction.
    transaction_hash: HashValue,
    /// The root hash of Sparse Merkle Tree describing the world state at the end of this
    /// transaction.
    state_root_hash: HashValue,
    event_root_hash: HashValue,
    gas_used: u64,
    status: KeptVMStatus,
}

pub enum BlockType {
    Proposal {
        payload: Payload,
        author: Author,
    },
    NilBlock,
    /// A genesis block is the first committed block in any epoch that is identically constructed on
    /// all validators by any (potentially different) LedgerInfo that justifies the epoch change
    /// from the previous epoch.  The genesis block is used as the the first root block of the
    /// BlockTree for all epochs.
    Genesis,
}
impl Block {
    /// Construct new genesis block for next epoch deterministically from the end-epoch LedgerInfo
    /// We carry over most fields except round and block id
    pub fn make_genesis_block_from_ledger_info(ledger_info: &LedgerInfo) -> Self {
        let block_data = BlockData::new_genesis_from_ledger_info(ledger_info);
        Block {
            id: block_data.hash(),
            block_data,
            signature: None,
        }
    }
}
impl BlockData {
    pub fn new_genesis_from_ledger_info(ledger_info: &LedgerInfo) -> Self {
        assert!(ledger_info.ends_epoch());
        let ancestor = BlockInfo::new(
            ledger_info.epoch(),
            0,                 /* round */
            HashValue::zero(), /* parent block id */
            ledger_info.transaction_accumulator_hash(),
            ledger_info.version(),
            ledger_info.timestamp_usecs(),
            None,
        );

        // Genesis carries a placeholder quorum certificate to its parent id with LedgerInfo
        // carrying information about version from the last LedgerInfo of previous epoch.
        let genesis_quorum_cert = QuorumCert::new(
            VoteData::new(ancestor.clone(), ancestor.clone()),
            LedgerInfoWithSignatures::new(
                LedgerInfo::new(ancestor, HashValue::zero()),
                BTreeMap::new(),
            ),
        );

        BlockData::new_genesis(ledger_info.timestamp_usecs(), genesis_quorum_cert)
    }
    pub fn new_genesis(timestamp_usecs: u64, quorum_cert: QuorumCert) -> Self {
        assume!(quorum_cert.certified_block().epoch() < u64::max_value()); // unlikely to be false in this universe
        Self {
            epoch: quorum_cert.certified_block().epoch() + 1,
            round: 0,
            timestamp_usecs,
            quorum_cert,
            block_type: BlockType::Genesis,
        }
    }
    
}
