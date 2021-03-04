// network/src/protocols/wire/handshake/v1/mod.rs

pub enum ProtocolId {
    ConsensusRpc = 0,
    ConsensusDirectSend = 1,
    MempoolDirectSend = 2,
    StateSynchronizerDirectSend = 3,
    DiscoveryDirectSend = 4,
    HealthCheckerRpc = 5,
}

pub struct SupportedProtocols(bitvec::BitVec);

impl TryInto<Vec<ProtocolId>> for SupportedProtocols {}

pub enum MessagingProtocolVersion {
    V1 = 0,
}

pub struct HandshakeMsg {
    pub supported_protocols: BTreeMap<MessagingProtocolVersion, SupportedProtocols>,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
}

pub enum HandshakeError {
    InvalidChainId(ChainId, ChainId),
    InvalidNetworkId(NetworkId, NetworkId),
    NoCommonProtocols,
}

/// 1. verifies that both HandshakeMsg are compatible and
/// 2. finds out the intersection of protocols that is supported
pub fn perform_handshake(
    &self,
    other: &HandshakeMsg,
) -> Result<(MessagingProtocolVersion, SupportedProtocols), HandshakeError> {}


// network/src/protocols/wire/messaging/v1/mod.rs

pub enum NetworkMessage {
    Error(ErrorCode),
    RpcRequest(RpcRequest),
    RpcResponse(RpcResponse),
    DirectSendMsg(DirectSendMsg),
}

pub type RequestId = u32;
pub type Priority = u8;

pub struct RpcRequest {
    pub protocol_id: ProtocolId,
    pub request_id: RequestId,
    pub priority: Priority,
    pub raw_request: Vec<u8>,
}

pub struct RpcResponse {
    pub request_id: RequestId,
    pub priority: Priority,
    pub raw_response: Vec<u8>,
}

pub struct DirectSendMsg {
    pub protocol_id: ProtocolId,
    pub priority: Priority,
    pub raw_msg: Vec<u8>,
}

pub struct NetworkMessageStream<TReadSocket: AsyncRead> {
    framed_read: FramedRead<IoCompat<TReadSocket>, LengthDelimitedCodec>,
}
impl<TReadSocket: AsyncRead> Stream for NetworkMessageStream<TReadSocket> {
    type Item = Result<NetworkMessage, ReadError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().framed_read.poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let frame = frame.freeze();
                match bcs::from_bytes(&frame) {
                    Ok(message) => Poll::Ready(Some(Ok(message))),
                    Err(err) => {
                        let mut frame = frame;
                        let frame_len = frame.len();
                        frame.truncate(8);
                        let err = ReadError::DeserializeError(err, frame_len, frame);
                        Poll::Ready(Some(Err(err)))
                    }
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(ReadError::IoError(err)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct NetworkMessageSink<TWriteSocket: AsyncWrite> {
    framed_write: FramedWrite<IoCompat<TWriteSocket>, LengthDelimitedCodec>,
}
impl<TWriteSocket: AsyncWrite> Sink<&NetworkMessage> for NetworkMessageSink<TWriteSocket> {
    type Error = WriteError;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed_write.poll_ready(cx).map_err(WriteError::IoError)
    }
    fn start_send(self: Pin<&mut Self>, message: &NetworkMessage) -> Result<(), Self::Error> {
        let frame = bcs::to_bytes(message).map_err(WriteError::SerializeError)?;
        let frame = Bytes::from(frame);
        self.project().framed_write.start_send(frame).map_err(WriteError::IoError)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed_write.poll_flush(cx).map_err(WriteError::IoError)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().framed_write.poll_close(cx).map_err(WriteError::IoError)
    }
}

// network/src/protocols/rpc/mod.rs

pub struct InboundRpcRequest {
    pub protocol_id: ProtocolId,
    pub data: Bytes,
    pub res_tx: oneshot::Sender<Result<Bytes, RpcError>>,
}

pub struct OutboundRpcRequest {
    pub protocol_id: ProtocolId,
    pub data: Bytes,
    pub res_tx: oneshot::Sender<Result<Bytes, RpcError>>,
    pub timeout: Duration,
}

pub struct InboundRpcs {
    network_context: Arc<NetworkContext>,
    remote_peer_id: PeerId,
    inbound_rpc_tasks: FuturesUnordered<BoxFuture<'static, Result<RpcResponse, RpcError>>>,
    inbound_rpc_timeout: Duration,
    max_concurrent_inbound_rpcs: u32,
}

impl InboundRpcs {
    pub async fn handle_inbound_request(
        &mut self,
        peer_notifs_tx: &mut channel::Sender<PeerNotification>,
        request: RpcRequest,
    ) -> Result<(), RpcError> {
        let network_context = &self.network_context;
        let protocol_id = request.protocol_id;
        let request_id = request.request_id;
        let priority = request.priority;
        let req_len = request.raw_request.len() as u64;

        // Foward request to PeerManager for handling.
        let (res_tx, res_rx) = oneshot::channel();
        let notif = PeerNotification::RecvRpc(InboundRpcRequest {
            protocol_id,
            data: Bytes::from(request.raw_request),
            res_tx,
        });
        peer_notifs_tx.send(notif).await;

        // Create a new task that waits for a response from the upper layer with a timeout.
        let inbound_rpc_task = tokio::time::timeout(self.inbound_rpc_timeout, res_rx)
            .map(move |result| {
                // Flatten the errors
                let maybe_response = match result {
                    Ok(Ok(Ok(response_bytes))) => Ok(RpcResponse {
                        request_id,
                        priority,
                        raw_response: Vec::from(response_bytes.as_ref()),
                    }),
                    Ok(Ok(Err(err))) => Err(err),
                    Ok(Err(oneshot::Canceled)) => Err(RpcError::UnexpectedResponseChannelCancel),
                    Err(_elapsed) => Err(RpcError::TimedOut),
                };
                // Only record latency of successful requests
                match maybe_response {
                    Ok(_) => timer.stop_and_record(),
                    Err(_) => timer.stop_and_discard(),
                };
                maybe_response
            })
            .boxed();

        // Add that task to the inbound completion queue. These tasks are driven
        // forward by `Peer` awaiting `self.next_completed_response()`.
        self.inbound_rpc_tasks.push(inbound_rpc_task);

        Ok(())
    }
    pub fn next_completed_response<'a>(
        &'a mut self,
    ) -> impl Future<Output = Result<RpcResponse, RpcError>> + FusedFuture + 'a {
        self.inbound_rpc_tasks.select_next_some()
    }

    pub async fn send_outbound_response(
        &mut self,
        write_reqs_tx: &mut channel::Sender<(
            NetworkMessage,
            oneshot::Sender<Result<(), PeerManagerError>>,
        )>,
        maybe_response: Result<RpcResponse, RpcError>,
    ) -> Result<(), RpcError> {
        let network_context = &self.network_context;
        let response = match maybe_response {
            Ok(response) => response,
            Err(err) => { return Err(err); }
        };
        let res_len = response.raw_response.len() as u64;

        let message = NetworkMessage::RpcResponse(response);
        let (ack_tx, _) = oneshot::channel();
        write_reqs_tx.send((message, ack_tx)).await?;
        Ok(())
    }
}

pub struct Rpc {
    network_context: Arc<NetworkContext>,
    peer_handle: PeerHandle,
    requests_rx: channel::Receiver<OutboundRpcRequest>,
    peer_notifs_rx: channel::Receiver<PeerNotification>,
    pending_outbound_rpcs: HashMap<RequestId, (ProtocolId, oneshot::Sender<RpcResponse>)>,
    request_id_gen: RequestIdGenerator,
}

impl Rpc {
    pub async fn start(mut self) {
        let peer_id = self.peer_handle.peer_id();
        let mut outbound_rpc_tasks = OutboundRpcTasks::new();

        loop {
            ::futures::select! {
                notif = self.peer_notifs_rx.select_next_some() => {
                    self.handle_inbound_message(notif);
                },
                maybe_req = self.requests_rx.next() => {
                    if let Some(req) = maybe_req {
                        self.handle_outbound_rpc(req, &mut outbound_rpc_tasks).await;
                    } else {
                        break;
                    }
                },
                request_id = outbound_rpc_tasks.select_next_some() => {
                    let _ = self.pending_outbound_rpcs.remove(&request_id);
                }
            }
        }
    }

    
}
