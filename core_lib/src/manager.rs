use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;

use crate::channel::{self, ChannelMessage, MessageClient, TransferKind};
use crate::errors::AppError;
use crate::hdl::{InboundRequest, OutboundPayload, OutboundRequest, TransferState};
use crate::utils::RemoteDeviceInfo;

const INNER_NAME: &str = "TcpServer";

/// Where and how to reach a device for an outbound transfer.
///
/// Nearby Connections defines several mediums and uses the same frame format on
/// all of them, so the only medium-specific thing about a transfer is how the
/// byte pipe is obtained. Naming that as a variant keeps `connect` honest about
/// which ones actually exist, rather than implying any address string will do.
#[derive(Debug, Clone)]
pub enum Target {
    /// `Medium::WifiLan`: an `"ip:port"` to open a TCP connection to.
    WifiLan { addr: String },
}

#[derive(Debug, Clone)]
pub struct SendInfo {
    /// How the caller identifies this device. Opaque here, and echoed back as
    /// the id on every event for this transfer.
    pub id: String,
    pub name: String,
    pub target: Target,
    pub ob: OutboundPayload,
}

pub struct TcpServer {
    endpoint_id: [u8; 4],
    tcp_listener: TcpListener,
    sender: Sender<ChannelMessage>,
    connect_receiver: Receiver<SendInfo>,
}

impl TcpServer {
    pub fn new(
        endpoint_id: [u8; 4],
        tcp_listener: TcpListener,
        sender: Sender<ChannelMessage>,
        connect_receiver: Receiver<SendInfo>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            endpoint_id,
            tcp_listener,
            sender,
            connect_receiver,
        })
    }

    pub async fn run(&mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");

        loop {
            let cctk = ctk.clone();

            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                Some(i) = self.connect_receiver.recv() => {
                    info!("{INNER_NAME}: connect_receiver: got {:?}", i);
                    if let Err(e) = self.connect(cctk, i).await {
                        error!("{INNER_NAME}: error sending: {}", e.to_string());
                    }
                }
                r = self.tcp_listener.accept() => {
                    match r {
                        Ok((socket, remote_addr)) => {
                            trace!("{INNER_NAME}: new client: {remote_addr}");
                            let esender = self.sender.clone();
                            let csender = self.sender.clone();

                            tokio::spawn(async move {
                                let mut ir = InboundRequest::new(socket, remote_addr.to_string(), csender);

                                loop {
                                    match ir.handle().await {
                                        Ok(_) => {},
                                        Err(e) => match e.downcast_ref() {
                                            Some(AppError::NotAnError) => break,
                                            None => {
                                                if ir.state.state == TransferState::Initial {
                                                    break;
                                                }

                                                if ir.state.state != TransferState::Finished {
                                                    let _ = esender.send(ChannelMessage {
                                                        id: remote_addr.to_string(),
                                                        msg: channel::Message::Client(MessageClient {
                                                            kind: TransferKind::Inbound,
                                                            state: Some(TransferState::Disconnected),
                                                            metadata: Default::default()
                                                        }),
                                                    });
                                                }

                                                // Once the transfer has finished, the peer
                                                // hanging up is how it ends -- typically
                                                // surfacing here as "early eof". Logging that at
                                                // ERROR puts an alarming line in the journal
                                                // after every successful transfer.
                                                if ir.state.state == TransferState::Finished {
                                                    debug!("{INNER_NAME}: client closed the connection after finishing: {e}");
                                                } else {
                                                    error!("{INNER_NAME}: error while handling client: {e} ({:?})", ir.state.state);
                                                }
                                                break;
                                            }
                                        },
                                    }
                                }
                            });
                        },
                        Err(err) => {
                            error!("{INNER_NAME}: error accepting: {}", err);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// To be called inside a separate task if we want to handle concurrency
    pub async fn connect(&self, ctk: CancellationToken, si: SendInfo) -> Result<(), anyhow::Error> {
        let transfer_id = si.id.clone();

        let socket = match &si.target {
            Target::WifiLan { addr } => {
                debug!("{INNER_NAME}: connecting over Wi-Fi LAN to: {addr}");
                TcpStream::connect(addr.clone()).await?
            }
        };

        let mut or = OutboundRequest::new(
            self.endpoint_id,
            socket,
            si.id,
            self.sender.clone(),
            si.ob,
            RemoteDeviceInfo {
                device_type: crate::DeviceType::Unknown,
                name: si.name,
            },
        );

        // Send connection request
        or.send_connection_request().await?;
        // Send UKEY init
        or.send_ukey2_client_init().await?;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                },
                r = or.handle() => {
                    if let Err(e) = r {
                        match e.downcast_ref() {
                            Some(AppError::NotAnError) => break,
                            None => {
                                if or.state.state == TransferState::Initial {
                                    break;
                                }

                                if or.state.state != TransferState::Finished && or.state.state != TransferState::Cancelled {
                                    let _ = self.sender.clone().send(ChannelMessage {
                                        // The caller's id, matching every other
                                        // event for this transfer. This used to
                                        // report the address, which was the same
                                        // string only while identity and address
                                        // were the same thing -- a client would
                                        // otherwise get a failure for an id it
                                        // had never been given.
                                        id: transfer_id,
                                        msg: channel::Message::Client(MessageClient {
                                            kind: TransferKind::Outbound,
                                            state: Some(TransferState::Disconnected),
                                            metadata: Default::default()
                                        }),
                                    });
                                }
                                // See the matching note on the inbound path: a
                                // peer hanging up after a finished transfer is
                                // not an error.
                                if or.state.state == TransferState::Finished {
                                    debug!("{INNER_NAME}: peer closed the connection after finishing: {e}");
                                } else {
                                    error!("{INNER_NAME}: error while handling client: {e} ({:?})", or.state.state);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
