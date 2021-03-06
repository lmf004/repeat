// consensus/src/state_computer.rs
pub struct ExecutionProxy {
    execution_correctness_client: Mutex<Box<dyn ExecutionCorrectness + Send + Sync>>,
    synchronizer: Arc<StateSyncClient>,
}

impl StateComputer for ExecutionProxy {
    fn compute(
        &self,
        block: &Block,
        parent_block_id: HashValue,
    ) -> Result<StateComputeResult, Error> {
        self.execution_correctness_client
            .execute_block(block.clone(), parent_block_id);
    }
    async fn commit(
        &self,
        block_ids: Vec<HashValue>,
        finality_proof: LedgerInfoWithSignatures,
    ) -> Result<()> {
        let (committed_txns, reconfig_events) =
            self.execution_correctness_client.commit_blocks(block_ids, finality_proof)?
        self.synchronizer.commit(committed_txns, reconfig_events).await
    }
    async fn sync_to(&self, target: LedgerInfoWithSignatures) -> Result<()> {
        self.synchronizer.sync_to(target).await;
        self.execution_correctness_client.reset()?;    
    }
}

// epoch_manager.rs
async fn start_new_epoch(&mut self, proof: EpochChangeProof) -> anyhow::Result<()> {
    let ledger_info = proof.verify(self.epoch_state());
    self.state_computer.sync_to(ledger_info.clone());
}
async fn start_round_manager(&mut self, recovery_data: RecoveryData, epoch_state: EpochState) {
    let last_vote = recovery_data.last_vote();
    let block_store = Arc::new(BlockStore::new(
        Arc::clone(&self.storage),
        recovery_data,
        Arc::clone(&self.state_computer), // lmf
        self.config.max_pruned_blocks_in_mem,
        Arc::clone(&self.time_service),
    ));
    let mut safety_rules =
        MetricsSafetyRules::new(self.safety_rules_manager.client(), self.storage.clone());
    safety_rules
        .perform_initialize();

    let proposal_generator = ProposalGenerator::new(
        self.author,
        block_store.clone(),
        self.txn_manager.clone(),
        self.time_service.clone(),
        self.config.max_block_size,
    );

    let round_state =
        self.create_round_state(self.time_service.clone(), self.timeout_sender.clone());

    let proposer_election = self.create_proposer_election(&epoch_state);
    let network_sender = NetworkSender::new(
        self.author,
        self.network_sender.clone(),
        self.self_sender.clone(),
        epoch_state.verifier.clone(),
    );

    let mut processor = RoundManager::new(
        epoch_state,
        block_store,
        round_state,
        proposer_election,
        proposal_generator,
        safety_rules,
        network_sender,
        self.txn_manager.clone(),
        self.storage.clone(),
        self.config.sync_only,
    );
    processor.start(last_vote).await;
    self.processor = Some(RoundProcessor::Normal(processor));
}

// block_store.rs
pub struct BlockStore {
    inner: Arc<RwLock<BlockTree>>,
    state_computer: Arc<dyn StateComputer>,
    storage: Arc<dyn PersistentLivenessStorage>,
    time_service: Arc<dyn TimeService>,
}
fn execute_block(&self, block: Block) -> anyhow::Result<ExecutedBlock, Error> {
    let state_compute_result = self.state_computer.compute(&block, block.parent_id())?; // lmf
    Ok(ExecutedBlock::new(block, state_compute_result))
}
/// Commit the given block id with the proof, returns () on success or error
pub async fn commit(&self, finality_proof: LedgerInfoWithSignatures) -> anyhow::Result<()> {
    let block_id_to_commit = finality_proof.ledger_info().consensus_block_id();
    let block_to_commit = self.get_block(block_id_to_commit);

    ensure!(block_to_commit.round() > self.root().round());

    let blocks_to_commit = self.path_from_root(block_id_to_commit);

    self.state_computer.commit( // lmf
        blocks_to_commit.iter().map(|b| b.id()).collect(),
        finality_proof,
    );
    self.prune_tree(block_to_commit.id());
    Ok(())
}
pub fn insert_single_quorum_cert(&self, qc: QuorumCert) -> anyhow::Result<()> {
    match self.get_block(qc.certified_block().id()) {
        Some(executed_block) => {
            ensure!(
                executed_block.block_info() == *qc.certified_block(),
                "QC for block {} has different {:?} than local {:?}",
                qc.certified_block().id(),
                qc.certified_block(),
                executed_block.block_info()
            );
        }
        None => bail!("Insert {} without having the block in store first", qc),
    }

    self.storage.save_tree(vec![], vec![qc.clone()]);
    self.inner.write().unwrap().insert_quorum_cert(qc)
}
pub fn insert_timeout_certificate(&self, tc: Arc<TimeoutCertificate>) -> anyhow::Result<()> {
    let cur_tc_round = self.highest_timeout_cert().map_or(0, |tc| tc.round());
    if tc.round() <= cur_tc_round {
        return Ok(());
    }
    self.storage.save_highest_timeout_cert(tc.as_ref().clone());
    self.inner.write().unwrap().replace_timeout_cert(tc);
}
pub fn execute_and_insert_block(&self, block: Block) -> anyhow::Result<Arc<ExecutedBlock>> {
    if let Some(existing_block) = self.get_block(block.id()) {
        return Ok(existing_block);
    }
    ensure!(self.inner.read().unwrap().root().round() < block.round(), "Block with old round");

    let executed_block = match self.execute_block(block.clone()) {
        Ok(res) => Ok(res),
        Err(Error::BlockNotFound(parent_block_id)) => {
            // recover the block tree in executor
            let blocks_to_reexecute = self
                .path_from_root(parent_block_id)
                .unwrap_or_else(Vec::new);

            for block in blocks_to_reexecute {
                self.execute_block(block.block().clone())?;
            }
            self.execute_block(block)
        }
        err => err,
    }?;

    // ensure local time past the block time
    let block_time = Duration::from_micros(executed_block.timestamp_usecs());
    self.time_service.wait_until(block_time);
    self.storage.save_tree(vec![executed_block.block().clone()], vec![]);
    self.inner.write().unwrap().insert_block(executed_block)
}

// round_manager.rs
async fn execute_and_vote(&mut self, proposed_block: Block) -> anyhow::Result<Vote> {
    let executed_block = self.block_store.execute_and_insert_block(proposed_block); // lmf
    // notify mempool about failed txn
    let compute_result = executed_block.compute_result();
    self.txn_manager.notify(executed_block.block(), compute_result);
    // Short circuit if already voted.
    ensure!(self.round_state.vote_sent().is_none());
    ensure!(!self.sync_only,"[RoundManager] sync_only flag is set, stop voting");
    
    let maybe_signed_vote_proposal = executed_block.maybe_signed_vote_proposal();
    let vote = self
        .safety_rules
        .construct_and_sign_vote(&maybe_signed_vote_proposal)?;

    self.storage.save_vote(&vote)?;
    Ok(vote)
}




pub fn start_consensus(
    node_config: &NodeConfig,
    network_sender: ConsensusNetworkSender,
    network_events: ConsensusNetworkEvents,
    state_sync_client: Arc<StateSyncClient>,
    consensus_to_mempool_sender: mpsc::Sender<ConsensusRequest>,
    libra_db: Arc<dyn DbReader>,
    reconfig_events: libra_channel::Receiver<(), OnChainConfigPayload>,
) -> Runtime {
    let runtime = runtime::Builder::new()
        .thread_name("consensus-")
        .threaded_scheduler()
        .enable_all()
        .build();
    let storage = Arc::new(StorageWriteProxy::new(node_config, libra_db));
    let txn_manager = Arc::new(MempoolProxy::new(consensus_to_mempool_sender));
    let execution_correctness_manager = ExecutionCorrectnessManager::new(node_config); // lmf
    let state_computer = Arc::new(ExecutionProxy::new( // lmf
        execution_correctness_manager.client(),
        state_sync_client,
    ));
    let time_service = Arc::new(ClockTimeService::new(runtime.handle().clone()));

    let (timeout_sender, timeout_receiver) = channel::new(1_024, &counters::PENDING_ROUND_TIMEOUTS);
    let (self_sender, self_receiver) = channel::new(1_024, &counters::PENDING_SELF_MESSAGES);

    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        self_sender,
        network_sender,
        timeout_sender,
        txn_manager,
        state_computer, // lmf
        storage,
    );

    let (network_task, network_receiver) = NetworkTask::new(network_events, self_receiver);

    runtime.spawn(network_task.start());
    runtime.spawn(epoch_mgr.start(timeout_receiver, network_receiver, reconfig_events));
}

pub fn setup_environment(node_config: &NodeConfig) -> LibraHandle {
    rayon::ThreadPoolBuilder::new()
        .thread_name(|index| format!("rayon-global-{}", index))
        .build_global();

    let (libra_db, db_rw) = DbReaderWriter::wrap(
        LibraDB::open(
            &node_config.storage.dir(),
            false, /* readonly */
            node_config.storage.prune_window,
        );
    );
    let _simple_storage_service =
        start_storage_service_with_db(&node_config, Arc::clone(&libra_db));
    let backup_service = start_backup_service(
        node_config.storage.backup_service_port,
        Arc::clone(&libra_db),
    );

    bootstrap_db_if_empty::<LibraVM>(&db_rw, get_genesis_txn(&node_config).unwrap());

    let chunk_executor = setup_chunk_executor(db_rw.clone());

    let chain_id = fetch_chain_id(&db_rw);
    let mut network_runtimes = vec![];
    let mut state_sync_network_handles = vec![];
    let mut mempool_network_handles = vec![];
    let mut consensus_network_handles = None;
    let mut reconfig_subscriptions = vec![];

    let (mempool_reconfig_subscription, mempool_reconfig_events) =
        gen_mempool_reconfig_subscription();
    reconfig_subscriptions.push(mempool_reconfig_subscription);
    let (consensus_reconfig_subscription, consensus_reconfig_events) =
        gen_consensus_reconfig_subscription();
    reconfig_subscriptions.push(consensus_reconfig_subscription);

    let waypoint = node_config.base.waypoint.waypoint();

    let mut network_configs: Vec<(RoleType, &NetworkConfig)> = node_config
        .full_node_networks
        .iter()
        .map(|network_config| (RoleType::FullNode, network_config))
        .collect();
    if let Some(network_config) = node_config.validator_network.as_ref() {
        network_configs.push((RoleType::Validator, network_config));
    }

    let mut network_builders = Vec::new();

    // Instantiate every network and collect the requisite endpoints for state_sync, mempool, and consensus.
    for (idx, (role, network_config)) in network_configs.into_iter().enumerate() {
        // Perform common instantiation steps
        let mut network_builder = NetworkBuilder::create(chain_id, role, network_config);
        let network_id = network_config.network_id.clone();

        // Create the endpoints to connect the Network to StateSynchronizer.
        let (state_sync_sender, state_sync_events) = network_builder
            .add_protocol_handler(state_synchronizer::network::network_endpoint_config());
        state_sync_network_handles.push((
            NodeNetworkId::new(network_id.clone(), idx),
            state_sync_sender,
            state_sync_events,
        ));

        // Create the endpoints to connect the Network to mempool.
        let (mempool_sender, mempool_events) =
            network_builder.add_protocol_handler(libra_mempool::network::network_endpoint_config(
                // TODO:  Make this configuration option more clear.
                node_config.mempool.max_broadcasts_per_peer,
            ));
        mempool_network_handles.push((
            NodeNetworkId::new(network_id, idx),
            mempool_sender,
            mempool_events,
        ));

        match role {
            RoleType::Validator => {
                consensus_network_handles =
                    Some(network_builder.add_protocol_handler(
                        consensus::network_interface::network_endpoint_config(),
                    ));
            }
            RoleType::FullNode => (),
        }

        reconfig_subscriptions.append(network_builder.reconfig_subscriptions());
        network_builders.push(network_builder);
    }

    for network_builder in &mut network_builders {
        let runtime = Builder::new().thread_name("network-").threaded_scheduler().enable_all().build();
        network_builder.build(runtime.handle().clone());
        network_runtimes.push(runtime);
    }
    for network_builder in &mut network_builders {
        network_builder.start();
    }

    let (state_sync_to_mempool_sender, state_sync_requests) =
        channel(INTRA_NODE_CHANNEL_BUFFER_SIZE);
    let state_synchronizer = StateSynchronizer::bootstrap(
        state_sync_network_handles,
        state_sync_to_mempool_sender,
        Arc::clone(&db_rw.reader),
        chunk_executor,
        &node_config,
        waypoint,
        reconfig_subscriptions,
    );
    let (mp_client_sender, mp_client_events) = channel(AC_SMP_CHANNEL_BUFFER_SIZE);

    let rpc_runtime = bootstrap_rpc(&node_config, chain_id, libra_db.clone(), mp_client_sender);

    let (consensus_to_mempool_sender, consensus_requests) = channel(INTRA_NODE_CHANNEL_BUFFER_SIZE);

    let mempool = libra_mempool::bootstrap(
        node_config,
        Arc::clone(&db_rw.reader),
        mempool_network_handles,
        mp_client_events,
        consensus_requests,
        state_sync_requests,
        mempool_reconfig_events,
    );

    if let Some((consensus_network_sender, consensus_network_events)) = consensus_network_handles {
        block_on(state_synchronizer.wait_until_initialized());
        consensus_runtime = Some(start_consensus( // lmf
            node_config,
            consensus_network_sender,
            consensus_network_events,
            state_synchronizer.create_client(),
            consensus_to_mempool_sender,
            libra_db,
            consensus_reconfig_events,
        ));
    }

     LibraHandle {
        _network_runtimes: network_runtimes,
        _rpc: rpc_runtime,
        _mempool: mempool,
        _state_synchronizer: state_synchronizer,
        _consensus_runtime: consensus_runtime,
        _debug: debug_if,
        _backup: backup_service,
    }
}


