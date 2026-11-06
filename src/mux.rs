use anyhow::{anyhow, Result};
use futures::future::poll_fn;
use std::collections::VecDeque;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config as YamuxConfig, Connection, Mode, Stream as YamuxStream};

pub type CompatYamuxStream = Compat<YamuxStream>;

/// Clonable handle allowing multiple concurrent tasks to open outbound multiplexed streams
/// over a single `yamux::Connection`.
#[derive(Clone)]
pub struct MuxHandle {
    open_tx: mpsc::Sender<oneshot::Sender<Result<CompatYamuxStream>>>,
}

impl MuxHandle {
    /// Opens a new bidirectional stream over the multiplexed tunnel.
    pub async fn open_stream(&self) -> Result<CompatYamuxStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx
            .send(reply_tx)
            .await
            .map_err(|_| anyhow!("Tunnel session is closed"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("Tunnel session closed while opening stream"))?
    }

    pub fn is_closed(&self) -> bool {
        self.open_tx.is_closed()
    }
}

/// Spawns a background task that drives a `yamux::Connection` in both directions:
/// - Accepts inbound streams and forwards them to `inbound_rx`
/// - Fulfils outbound stream requests from `MuxHandle::open_stream()`
pub fn spawn_mux_session<S>(
    io: S,
    mode: Mode,
    max_num_streams: usize,
) -> (MuxHandle, mpsc::Receiver<CompatYamuxStream>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut cfg = YamuxConfig::default();
    cfg.set_max_num_streams(max_num_streams);
    cfg.set_max_connection_receive_window(Some(256 * 1024 * max_num_streams));

    let compat_io = io.compat();
    let mut conn = Connection::new(compat_io, cfg, mode);

    let (open_tx, mut open_rx) =
        mpsc::channel::<oneshot::Sender<Result<CompatYamuxStream>>>(128);
    let (inbound_tx, inbound_rx) = mpsc::channel::<CompatYamuxStream>(128);

    tokio::spawn(async move {
        let mut pending_outbound: VecDeque<oneshot::Sender<Result<CompatYamuxStream>>> =
            VecDeque::new();
        let mut open_rx_done = false;

        let res: Result<()> = poll_fn(|cx| {
            if inbound_tx.is_closed() {
                let _ = conn.poll_close(cx);
                return Poll::Ready(Ok(()));
            }

            // 1. Drain any new outbound stream requests from the channel
            if !open_rx_done {
                loop {
                    match open_rx.poll_recv(cx) {
                        Poll::Ready(Some(req)) => {
                            if !req.is_closed() {
                                pending_outbound.push_back(req);
                            }
                        }
                        Poll::Ready(None) => {
                            open_rx_done = true;
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
            }

            // 2. Fulfill pending outbound stream requests via yamux
            while let Some(reply_tx) = pending_outbound.front() {
                if reply_tx.is_closed() {
                    pending_outbound.pop_front();
                    continue;
                }
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        let tx = pending_outbound.pop_front().unwrap();
                        let _ = tx.send(Ok(stream.compat()));
                    }
                    Poll::Ready(Err(e)) => {
                        let tx = pending_outbound.pop_front().unwrap();
                        let _ = tx.send(Err(anyhow!("Yamux outbound error: {}", e)));
                        return Poll::Ready(Err(anyhow!("Yamux connection error: {}", e)));
                    }
                    Poll::Pending => break,
                }
            }

            // 3. Always poll inbound streams to drive the underlying Yamux connection
            loop {
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        if inbound_tx.try_send(stream.compat()).is_err() {
                            // Receiver dropped or full
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(anyhow!("Yamux inbound error: {}", e)));
                    }
                    Poll::Ready(None) => {
                        // Clean EOF from peer
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => break,
                }
            }

            Poll::Pending
        })
        .await;

        for tx in pending_outbound.drain(..) {
            let _ = tx.send(Err(anyhow!("Tunnel connection closed")));
        }
        let _ = res;
    });

    (MuxHandle { open_tx }, inbound_rx)
}
