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
            // Perform steps relevant specifically to Validator networks.
            RoleType::Validator => {
                // A valid config is allowed to have at most one ValidatorNetwork
                // TODO:  `expect_none` would be perfect here, once it is stable.
                if consensus_network_handles.is_some() {
                    panic!("There can be at most one validator network!");
                }

                consensus_network_handles =
                    Some(network_builder.add_protocol_handler(
                        consensus::network_interface::network_endpoint_config(),
                    ));
            }
            // Currently no FullNode network specific steps.
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
        consensus_runtime = Some(start_consensus(
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
