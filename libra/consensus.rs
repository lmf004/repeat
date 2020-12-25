pub struct BlockInfo {
    epoch: u64,
    round: Round,
    id: HashValue,
    executed_state_id: HashValue,
    version: Version,
    timestamp_usecs: u64,
    next_epoch_info: Option<EpochInfo>,
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

pub struct EpochManager<T> {
    author: Author,
    config: ConsensusConfig,
    time_service: Arc<ClockTimeService>,
    self_sender: channel::Sender<anyhow::Result<Event<ConsensusMsg<T>>>>,
    network_sender: ConsensusNetworkSender<T>,
    timeout_sender: channel::Sender<Round>,
    txn_manager: Box<dyn TxnManager<Payload = T>>,
    state_computer: Arc<dyn StateComputer<Payload = T>>,
    storage: Arc<dyn PersistentLivenessStorage<T>>,
    safety_rules_manager: SafetyRulesManager<T>,
    processor: Option<Processor<T>>,
}

impl<T: Payload> EpochManager<T> {
    async fn start_event_processor(
        &mut self,
        recovery_data: RecoveryData<T>,
        epoch_info: EpochInfo,
    ) {
        // Release the previous EventProcessor, especially the SafetyRule client
        self.processor = None;
        let last_vote = recovery_data.last_vote();
        let block_store = Arc::new(BlockStore::new(
            Arc::clone(&self.storage),
            recovery_data,
            Arc::clone(&self.state_computer),
            self.config.max_pruned_blocks_in_mem,
        ));

        let mut safety_rules = self.safety_rules_manager.client();
        let consensus_state = safety_rules
            .consensus_state();
        let sr_waypoint = consensus_state.waypoint();
        let proofs = self
            .storage
            .retrieve_epoch_change_proof(sr_waypoint.version());

        safety_rules
            .initialize(&proofs);

        let proposal_generator = ProposalGenerator::new(
            self.author,
            block_store.clone(),
            self.txn_manager.clone(),
            self.time_service.clone(),
            self.config.max_block_size,
        );

        let pacemaker =
            self.create_pacemaker(self.time_service.clone(), self.timeout_sender.clone());

        let proposer_election = self.create_proposer_election(&epoch_info);
        let network_sender = NetworkSender::new(
            self.author,
            self.network_sender.clone(),
            self.self_sender.clone(),
            epoch_info.verifier.clone(),
        );

        let mut processor = EventProcessor::new(
            epoch_info,
            block_store,
            last_vote,
            pacemaker,
            proposer_election,
            proposal_generator,
            safety_rules,
            network_sender,
            self.txn_manager.clone(),
            self.storage.clone(),
            self.time_service.clone(),
        );
        processor.start().await;
        self.processor = Some(Processor::EventProcessor(processor));
    }

    pub async fn start(
        mut self,
        mut pacemaker_timeout_sender_rx: channel::Receiver<Round>,
        mut network_receivers: NetworkReceivers<T>,
        mut reconfig_events: libra_channel::Receiver<(), OnChainConfigPayload>,
    ) {
        if let Some(payload) = reconfig_events.next().await {
            self.start_processor(payload).await;
        }
        loop {
            select! {
                payload = reconfig_events.select_next_some() => {
                    self.start_processor(payload).await
                }
                msg = network_receivers.consensus_messages.select_next_some() => {
                    self.process_message(msg.0, msg.1).await
                }
                block_retrieval = network_receivers.block_retrieval.select_next_some() => {
                    self.process_block_retrieval(block_retrieval).await
                }
                round = pacemaker_timeout_sender_rx.select_next_some() => {
                    self.process_local_timeout(round).await
                }
            }
        }
    }

    pub async fn process_message(
        &mut self,
        peer_id: AccountAddress,
        consensus_msg: ConsensusMsg<T>,
    ) {
        if let Some(event) = self.process_epoch(peer_id, consensus_msg).await {
            match event.verify(&self.epoch_info().verifier) {
                Ok(event) => self.process_event(peer_id, event).await,
            }
        }
    }

    async fn process_epoch(
        &mut self,
        peer_id: AccountAddress,
        msg: ConsensusMsg<T>,
    ) -> Option<UnverifiedEvent<T>> {
        match msg {
            ConsensusMsg::ProposalMsg(_) | ConsensusMsg::SyncInfo(_) | ConsensusMsg::VoteMsg(_) => {
                let event: UnverifiedEvent<T> = msg.into();
                if event.epoch() == self.epoch() {
                    return Some(event);
                } else {
                    self.process_different_epoch(event.epoch(), peer_id).await;
                }
            }
            ConsensusMsg::EpochChangeProof(proof) => {
                let msg_epoch = proof.epoch().map_err(|e| warn!("{:?}", e)).ok()?;
                if msg_epoch == self.epoch() {
                    self.start_new_epoch(*proof).await
                } else {
                    self.process_different_epoch(msg_epoch, peer_id).await
                }
            }
            ConsensusMsg::EpochRetrievalRequest(request) => {
                if request.end_epoch <= self.epoch() {
                    self.process_epoch_retrieval(*request, peer_id).await
                } 
            }
        }
    }

    async fn process_epoch_retrieval(
        &mut self,
        request: EpochRetrievalRequest,
        peer_id: AccountAddress,
    ) {
        let proof = match self
            .state_computer
            .get_epoch_proof(request.start_epoch, request.end_epoch)
            .await
        {
            Ok(proof) => proof,
        };
        let msg = ConsensusMsg::EpochChangeProof::<T>(Box::new(proof));
        self.network_sender.send_to(peer_id, msg);
    }
    
    async fn start_new_epoch(&mut self, proof: EpochChangeProof) {
        let verifier = VerifierType::TrustedVerifier(self.epoch_info().clone());
        let ledger_info = match proof.verify(&verifier) {
            Ok(ledger_info) => ledger_info,
        };
        self.state_computer.sync_to(ledger_info.clone());
    }
    
    async fn process_event(&mut self, peer_id: AccountAddress, event: VerifiedEvent<T>) {
        match self.processor_mut() {
            Processor::SyncProcessor(p) => {
                //...
            }
            Processor::EventProcessor(p) => match event {
                VerifiedEvent::ProposalMsg(proposal)
                    => p.process_proposal_msg(*proposal).await,
                VerifiedEvent::VoteMsg(vote)
                    => p.process_vote(*vote).await,
                VerifiedEvent::SyncInfo(sync_info)
                    => {
                        p.process_sync_info_msg(*sync_info, peer_id).await
                    }
            },
        }
    }

    pub async fn process_block_retrieval(&mut self, request: IncomingBlockRetrievalRequest) {
        match self.processor_mut() {
            Processor::EventProcessor(p) => p.process_block_retrieval(request).await,
        }
    }

    pub async fn process_local_timeout(&mut self, round: u64) {
        match self.processor_mut() {
            Processor::EventProcessor(p) => p.process_local_timeout(round).await,
        }
    }    
}

pub struct EventProcessor<T> {
    epoch_info: EpochInfo,
    block_store: Arc<BlockStore<T>>,
    pending_votes: PendingVotes,
    pacemaker: Pacemaker,
    proposer_election: Box<dyn ProposerElection<T> + Send + Sync>,
    proposal_generator: ProposalGenerator<T>,
    safety_rules: Box<dyn TSafetyRules<T> + Send + Sync>,
    network: NetworkSender<T>,
    txn_manager: Box<dyn TxnManager<Payload = T>>,
    storage: Arc<dyn PersistentLivenessStorage<T>>,
    time_service: Arc<dyn TimeService>,
    // Cache of the last sent vote message.
    last_vote_sent: Option<(Vote, Round)>,
}

impl<T: Payload> EventProcessor<T> {
    
}

