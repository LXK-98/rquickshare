//! What a Quick Share connection needs from the thing underneath it.
//!
//! Nearby Connections defines several mediums — `WIFI_LAN`, `BLUETOOTH`,
//! `WIFI_HOTSPOT`, `WIFI_DIRECT`, `WIFI_AWARE`, `WEB_RTC` — and the frame format
//! is identical on all of them. Only the byte pipe differs.
//!
//! The handshake used to be written against `TcpStream` directly, which pinned
//! the library to `WIFI_LAN`: two devices with no network in common could not
//! talk at all. Naming the requirement here instead keeps that choice in one
//! place, and it turns out to be a low bar — length-prefixed frames over an
//! ordered, reliable stream.

use tokio::io::{AsyncRead, AsyncWrite};

/// A byte pipe a Quick Share connection can run over.
///
/// `Send` is required because `manager` drives each connection in its own task.
/// Nothing here assumes sockets, addresses or a particular medium, so
/// `tokio::net::TcpStream` and `bluer::rfcomm::Stream` both qualify, as does
/// anything used in tests.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}

/// Blanket impl: implementing the three standard traits is the whole contract,
/// so a transport never has to opt in.
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast;

    use crate::hdl::{InboundRequest, OutboundRequest};
    use crate::utils::RemoteDeviceInfo;

    /// The point of the abstraction: a connection over something that is not a
    /// socket at all.
    ///
    /// `tokio::io::duplex` is an in-memory pipe, so this compiling is what says
    /// the handshake no longer depends on TCP. It is also what will let the
    /// protocol be exercised in tests without a network, and what lets
    /// `bluer::rfcomm::Stream` be passed in once a Bluetooth medium exists.
    #[tokio::test]
    async fn a_connection_can_run_over_an_in_memory_pipe() {
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (sender, _) = broadcast::channel(4);

        let request = InboundRequest::new(ours, "in-memory".to_owned(), sender);
        assert_eq!(request.state.id, "in-memory");
    }

    #[tokio::test]
    async fn an_outbound_connection_can_too() {
        let (ours, _theirs) = tokio::io::duplex(1024);
        let (sender, _) = broadcast::channel(4);

        let request = OutboundRequest::new(
            [1, 2, 3, 4],
            ours,
            "in-memory".to_owned(),
            sender,
            crate::hdl::OutboundPayload::Files(vec![]),
            RemoteDeviceInfo {
                name: "test".to_owned(),
                device_type: crate::DeviceType::Unknown,
            },
        );
        assert_eq!(request.state.id, "in-memory");
    }
}
