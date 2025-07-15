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

use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use pem::{encode, Pem};
use quiche::{Config, PROTOCOL_VERSION};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::Builder;

pub fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![cert_der.clone()], priv_key.into())
}

pub struct QuicServerConfig {
    server_config: Config,
    bind_addr: SocketAddr,
}

impl QuicServerConfig {
    pub fn bind_addr(&mut self, addr: SocketAddr) {
        self.bind_addr = addr;
    }
    fn server_config(&self) -> &Config {
        &self.server_config
    }
    fn server_config_mut(&mut self) -> &mut Config {
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

        QuicServerConfig {
            server_config,
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }
}

struct QuicServer {
    quic_server_config: QuicServerConfig,
}
