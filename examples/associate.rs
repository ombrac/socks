use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use socks_lib::io::{self, AsyncRead, AsyncWrite};
use socks_lib::net::{TcpListener, TcpStream, UdpSocket};
use socks_lib::v5::server::auth::NoAuthentication;
use socks_lib::v5::server::{Config, Handler, Server};
use socks_lib::v5::{Address, Request, Response, Stream, UdpPacket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:1081").await.unwrap();
    println!(
        "SOCKS server listening on {}",
        listener.local_addr().unwrap()
    );

    let config = Config::new(NoAuthentication, CommandHandler);

    Server::run(listener, config.into(), async {
        tokio::signal::ctrl_c().await.unwrap();
    })
    .await
    .unwrap();
}

pub struct CommandHandler;

impl Handler for CommandHandler {
    async fn handle<T>(&self, stream: &mut Stream<T>, request: Request) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        println!("Request: {request:?}");

        match request {
            Request::Connect(addr) => {
                stream.write_response_unspecified().await?;

                let mut target = TcpStream::connect(addr.to_string()).await?;
                let copy = io::copy_bidirectional(stream, &mut target).await?;

                println!(
                    "[TCP] {} -> {} | Sent: {}, Received: {}",
                    stream.peer_addr(),
                    addr,
                    copy.0,
                    copy.1
                );
            }
            Request::Associate(_) => {
                let server_ip = stream.local_addr().ip();

                let inbound = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                let udp_port = inbound.local_addr().unwrap().port();

                let reply_addr = SocketAddr::new(server_ip, udp_port);
                let bind_addr = Address::from(reply_addr);
                stream
                    .write_response(&Response::Success(&bind_addr))
                    .await?;

                println!(
                    "[UDP] Association created for {}. Client should send UDP to {}.",
                    stream.peer_addr(),
                    bind_addr
                );

                udp_session_run(inbound, Duration::from_secs(180)).await?;

                println!("[UDP] Association for {} ended.", stream.peer_addr());
            }
            _ => {
                stream.write_response_unsupported().await?;
            }
        }

        Ok(())
    }
}

/// Represents a NAT entry for a single target address.
/// It contains the dedicated outbound socket, a task to handle replies,
/// and a timestamp for idle cleanup.
struct OutboundEntry {
    socket: Arc<UdpSocket>,
    last_active: Instant,
    recv_task: JoinHandle<()>,
}

/// Manages a single SOCKS5 UDP ASSOCIATE session.
/// It implements a NAT-like mechanism to correctly handle multiple concurrent UDP "connections"
/// from one client to various destinations.
async fn udp_session_run(inbound: Arc<UdpSocket>, idle_timeout: Duration) -> io::Result<()> {
    // A buffer large enough for most UDP packets.
    let mut buf = vec![0u8; 65535];

    // The server must learn the client's address from the first packet.
    // We wait for this first packet with a timeout.
    let (n, client_addr) = tokio::time::timeout(idle_timeout, inbound.recv_from(&mut buf))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Client did not send any UDP packet",
            )
        })??;

    // The NAT table: maps a target address (String) to its dedicated outbound entry.
    let nat: Arc<Mutex<HashMap<String, OutboundEntry>>> = Arc::new(Mutex::new(HashMap::new()));

    // --- Periodic sweeper to clean up idle NAT entries ---
    let nat_for_sweep = nat.clone();
    let sweep_handle = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(30)); // Check every 30s
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let mut map = nat_for_sweep.lock().await;

            // Collect keys of expired entries
            let dead_keys: Vec<String> = map
                .iter()
                .filter(|(_, v)| v.last_active.elapsed() > idle_timeout)
                .map(|(k, v)| {
                    // Abort the associated receiver task before removing.
                    v.recv_task.abort();
                    k.clone()
                })
                .collect();

            // Remove them from the map
            for k in dead_keys {
                if map.remove(&k).is_some() {
                    println!("[UDP] NAT entry for {} timed out and was removed.", k);
                }
            }
        }
    });

    // Handle the very first packet we received before the loop.
    handle_client_packet(&inbound, client_addr, &nat, &buf[..n]).await?;

    // --- Main inbound loop ---
    // This loop continuously receives packets from the SOCKS client and forwards them.
    let main_loop_result = loop {
        match tokio::time::timeout(idle_timeout, inbound.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                // Security: Only process packets from the original client.
                if src != client_addr {
                    continue;
                }

                // Process the packet (find/create NAT entry, forward data).
                if let Err(e) = handle_client_packet(&inbound, client_addr, &nat, &buf[..n]).await {
                    eprintln!("[UDP] Error handling client packet: {}", e);
                    break Err(e);
                }
            }
            Ok(Err(e)) => {
                // Error on the main inbound socket.
                break Err(e);
            }
            Err(_) => {
                // Timeout: The client has been idle for too long. End the session.
                break Ok(());
            }
        }
    };

    // --- Cleanup ---
    // The main loop has exited, so we must clean up all resources.
    sweep_handle.abort(); // Stop the periodic cleanup task.

    // Abort all remaining per-target receiver tasks.
    let mut guard = nat.lock().await;
    for (_, entry) in guard.drain() {
        entry.recv_task.abort();
    }

    main_loop_result
}

/// Parses a packet from the client, manages the NAT table entry for its destination,
/// and forwards the data.
async fn handle_client_packet(
    inbound: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    nat: &Arc<Mutex<HashMap<String, OutboundEntry>>>,
    raw: &[u8],
) -> io::Result<()> {
    // 1. Parse the SOCKS5 UDP request header.
    let pkt = UdpPacket::from_bytes(&mut &raw[..]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse UDP packet: {e}"),
        )
    })?;

    // 2. Resolve the destination address to a concrete SocketAddr.
    // This is crucial for using a consistent key in our NAT map and for async operation.
    let target_sock_addr: SocketAddr = match pkt.address {
        Address::IPv4(v4) => SocketAddr::V4(v4),
        Address::IPv6(v6) => SocketAddr::V6(v6),
        Address::Domain(ref domain, port) => {
            let full_addr = format!("{}:{}", domain.format_as_str(), port);
            tokio::net::lookup_host(full_addr)
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "Domain resolution failed")
                })?
        }
    };

    let target_key = target_sock_addr.to_string();

    // 3. Lock the NAT table and find or create an entry for this target.
    let mut map = nat.lock().await;

    // If an entry for this target doesn't exist, create it.
    if !map.contains_key(&target_key) {
        // Create a new dedicated outbound socket.
        let outbound = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        // Spawn a dedicated receiver task that listens on the new outbound socket
        // and forwards any replies back to the client via the main inbound socket.
        let recv_task = {
            let outbound_rx = outbound.clone();
            let inbound_tx = inbound.clone();
            let original_target_key = target_key.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match outbound_rx.recv_from(&mut buf).await {
                        Ok((n, src_addr)) => {
                            // When a reply comes, wrap it in a SOCKS5 UDP header.
                            // The address field MUST be the actual source of the packet.
                            let data = Bytes::copy_from_slice(&buf[..n]);
                            let response_packet = UdpPacket::un_frag(Address::from(src_addr), data);

                            // Send the SOCKS5-wrapped reply back to the client.
                            if let Err(e) = inbound_tx
                                .send_to(&response_packet.to_bytes(), client_addr)
                                .await
                            {
                                eprintln!(
                                    "[UDP] Failed to send reply to client for target {}: {}",
                                    original_target_key, e
                                );
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[UDP] Error on outbound socket for target {}: {}",
                                original_target_key, e
                            );
                            break;
                        }
                    }
                }
            })
        };

        println!("[UDP] New NAT entry created for target: {}", target_key);
        let entry = OutboundEntry {
            socket: outbound,
            last_active: Instant::now(),
            recv_task,
        };
        map.insert(target_key.clone(), entry);
    }

    // 4. Get the entry, update its activity time, and forward the data.
    if let Some(entry) = map.get_mut(&target_key) {
        entry.last_active = Instant::now();
        let data = pkt.data;
        // Send the client's payload to the target using the dedicated socket.
        entry.socket.send_to(&data, target_sock_addr).await?;
    } else {
        // This case should be unreachable due to the logic above.
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to get or create NAT entry",
        ));
    }

    Ok(())
}
