// Copyright 2023 RobustMQ Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use common_config::mqtt::broker_mqtt_conf;
use delay_message::DelayMessageManager;
use futures::io;
use grpc_clients::pool::ClientPool;
use pem::{encode, Pem};
use quiche::{
    accept, Config, Connection, ConnectionId, Header, RecvInfo, MAX_CONN_ID_LEN, PROTOCOL_VERSION,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use schema_register::schema::SchemaRegisterManager;
use std::{
    collections::HashMap,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use storage_adapter::storage::ArcStorageAdapter;
use tempfile::Builder;
use tokio::{
    net::UdpSocket,
    sync::{broadcast, Mutex},
    time::sleep,
};
use tracing::{error, info, warn};

use crate::{
    handler::{cache::CacheManager, command::Command},
    security::AuthDriver,
    server::common::connection_manager::ConnectionManager,
    subscribe::manager::SubscribeManager,
};

pub fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![cert_der.clone()], priv_key.into())
}

pub async fn start_quic_server(
    subscribe_manager: Arc<SubscribeManager>,
    cache_manager: Arc<CacheManager>,
    connection_manager: Arc<ConnectionManager>,
    message_storage_adapter: ArcStorageAdapter,
    delay_message_manager: Arc<DelayMessageManager>,
    client_pool: Arc<ClientPool>,
    stop_sx: broadcast::Sender<bool>,
    auth_driver: Arc<AuthDriver>,
    schema_register_manager: Arc<SchemaRegisterManager>,
) {
    let conf = broker_mqtt_conf();
    let command = Command::new(
        cache_manager.clone(),
        message_storage_adapter.clone(),
        delay_message_manager.clone(),
        subscribe_manager.clone(),
        client_pool.clone(),
        connection_manager.clone(),
        schema_register_manager.clone(),
        auth_driver.clone(),
    );

    let mut server = QuicServer::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        conf.network_port.quic_port as u16,
    ));

    if let Err(e) = server.start().await {
        error!("QUIC server failed to start: {}", e);
    }
}

pub struct QuicServerConfig {
    server_config: Arc<Mutex<Config>>,
    bind_addr: SocketAddr,
}

impl QuicServerConfig {
    pub fn bind_addr(&mut self, addr: SocketAddr) {
        self.bind_addr = addr;
    }
    fn server_config(&self) -> &Arc<Mutex<Config>> {
        &self.server_config
    }
    fn server_config_mut(&mut self) -> &mut Arc<Mutex<Config>> {
        &mut self.server_config
    }

    fn get_bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

impl Default for QuicServerConfig {
    fn default() -> Self {
        let (cert_chain_der, priv_key) = generate_self_signed_cert();

        let mut server_config =
            Config::new(PROTOCOL_VERSION).expect("Failed to create quic server config in default");

        let mut cert_file = Builder::new()
            .suffix(".pem")
            .tempfile()
            .expect("Failed to create cert chain tempfile");

        for cert in cert_chain_der {
            let pem = Pem::new("CERTIFICATE", cert.to_vec());
            cert_file
                .write_all(encode(&pem).as_bytes())
                .expect("Failed to write cert to tempfile");
        }

        let mut key_file = Builder::new()
            .suffix(".key")
            .tempfile()
            .expect("Failed to create cert private key file");

        let key_pem = Pem::new("PRIVATE KEY", priv_key.secret_der().to_vec());
        key_file
            .write_all(encode(&key_pem).as_bytes())
            .expect("Failed to write private key to tempfile");

        server_config
            .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
            .expect("Failed to load cert chain file");

        server_config
            .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
            .expect("Failed to load private key file");

        server_config.set_initial_max_data(10_000_000);
        server_config.set_initial_max_stream_data_bidi_local(1_000_000);
        server_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        server_config.set_initial_max_streams_bidi(100);
        server_config.set_initial_max_streams_uni(100);

        QuicServerConfig {
            server_config: Arc::new(Mutex::new(server_config)),
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }
}

struct QuicServer {
    quic_server_config: QuicServerConfig,
}

struct Client {
    conn: Connection,
}

impl QuicServer {
    pub fn new(addr: SocketAddr) -> Self {
        let mut quic_server_config = QuicServerConfig::default();
        quic_server_config.bind_addr(addr);

        QuicServer { quic_server_config }
    }

    pub async fn start(&mut self) -> io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(self.quic_server_config.get_bind_addr()).await?);
        info!("QUIC server listening on {}", socket.local_addr()?);

        let clients = Arc::new(Mutex::new(HashMap::<ConnectionId, Client>::new()));

        let socket_clone = socket.clone();
        let clients_clone = clients.clone();

        tokio::spawn(async move {
            handle_timeout(socket_clone, clients_clone).await;
        });

        loop {
            let mut buf = [0; 65535];
            let (len, from) = socket.recv_from(&mut buf).await?;
            let packet = buf[..len].to_vec();

            let socket_clone = socket.clone();
            let clients_clone = clients.clone();
            let config_clone = self.quic_server_config.server_config().clone();

            tokio::spawn(async move {
                handle_packet(socket_clone, clients_clone, from, packet, config_clone).await;
            });
        }
    }
}

async fn handle_packet(
    socket: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<ConnectionId<'static>, Client>>>,
    from: SocketAddr,
    mut packet: Vec<u8>,
    config: Arc<Mutex<Config>>,
) {
    let hdr = match Header::from_slice(&mut packet, MAX_CONN_ID_LEN) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to parse QUIC header: {}", e);
            return;
        }
    };

    let conn_id = hdr.dcid;
    let mut clients_map = clients.lock().await;

    let client: &mut Client;

    if !clients_map.contains_key(&conn_id) {
        let mut config_guard = config.lock().await;

        let new_conn = match accept(
            &hdr.scid,
            None,
            socket.local_addr().unwrap(),
            from,
            &mut config_guard,
        ) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to accept new QUIC connection {}", e);
                return;
            }
        };

        clients_map.insert(conn_id.clone(), Client { conn: new_conn });
        info!("New QUIC connection from: {}", from);
        client = clients_map.get_mut(&conn_id).unwrap();
    } else {
        client = clients_map.get_mut(&conn_id).unwrap();
    };

    let recv_info = RecvInfo {
        to: socket.local_addr().unwrap(),
        from,
    };
    if let Err(e) = client.conn.recv(&mut packet, recv_info) {
        warn!(
            "Failed to process incoming packet for conn {}: {}",
            client.conn.trace_id(),
            e
        );
    }

    // TODO: process streams

    let mut out = [0; 65535];
    loop {
        let (write, send_info) = match client.conn.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => break,
            Err(e) => {
                error!("QUIC send failed: {}", e);
                client.conn.close(false, 0x1, b"fail").ok();
                break;
            }
        };

        if let Err(e) = socket.send_to(&out[..write], send_info.to).await {
            error!("UDP send_to failed: {}", e);
        }
    }
}

async fn handle_timeout(
    socket: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<ConnectionId<'static>, Client>>>,
) {
    loop {
        sleep(Duration::from_millis(20)).await;
        let mut clients_map = clients.lock().await;

        for client in clients_map.values_mut() {
            client.conn.on_timeout();
        }

        let mut out = [0; 65535];
        for client in clients_map.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("QUIC send failed on timeout: {}", e);
                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to).await {
                    error!("UDP send_to failed: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {}
