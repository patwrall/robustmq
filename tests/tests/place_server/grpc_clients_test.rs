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

#[cfg(test)]
mod tests {
    use common_base::error::common::CommonError;
    use common_base::tools::now_second;
    use metadata_struct::journal::shard::JournalShardConfig;
    use metadata_struct::placement::node::BrokerNode;
    use protocol::placement_center::placement_center_inner::placement_center_service_client::PlacementCenterServiceClient;
    use protocol::placement_center::placement_center_inner::{
        ClusterType, HeartbeatRequest, RegisterNodeRequest, SetIdempotentDataRequest,
        UnRegisterNodeRequest,
    };
    use protocol::placement_center::placement_center_journal::engine_service_client::EngineServiceClient;
    use protocol::placement_center::placement_center_journal::{
        CreateNextSegmentRequest, CreateShardRequest, DeleteSegmentRequest, DeleteShardRequest,
    };
    use tonic::{Code, Status};

    use crate::place_server::common::{
        cluster_name, cluster_type, extend_info, namespace, node_id, node_ip, pc_addr, producer_id,
        seq_num, shard_name,
    };

    #[tokio::test]
    async fn test_register_node_method_is_ok() {
        let mut client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .unwrap();
        let node = BrokerNode {
            cluster_name: cluster_name(),
            cluster_type: cluster_type(),
            node_ip: node_ip(),
            node_id: node_id(),
            node_inner_addr: node_ip(),
            extend: extend_info(),
            register_time: now_second(),
            start_time: now_second(),
        };
        let valid_request = RegisterNodeRequest {
            node: node.encode(),
        };
        let response = client
            .register_node(tonic::Request::new(valid_request.clone()))
            .await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_register_node_method_param_type_string_is_empty() {
        let client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .unwrap();

        let mut node = BrokerNode {
            cluster_name: cluster_name(),
            cluster_type: cluster_type(),
            node_ip: node_ip(),
            node_id: node_id(),
            node_inner_addr: node_ip(),
            extend: extend_info(),
            register_time: now_second(),
            start_time: now_second(),
        };
        let valid_request = RegisterNodeRequest {
            node: node.encode(),
        };

        let valid_field = ["cluster_name", "node_ip", "node_inner_addr"];

        for field in valid_field {
            let test_request = valid_request.clone();
            let mut test_client = client.clone();
            match field {
                "cluster_name" => node.cluster_name = String::new(),
                "node_ip" => node.node_ip = String::new(),
                "node_inner_addr" => node.node_inner_addr = String::new(),
                _ => unreachable!(),
            }
            {
                println!("{test_request:?}");
                let response = test_client
                    .register_node(tonic::Request::new(test_request))
                    .await;

                assert!(response.is_err());
                let status = response.unwrap_err();
                assert_eq!(
                    status.code(),
                    Status::invalid_argument(
                        CommonError::ParameterCannotBeNull(field.to_string()).to_string()
                    )
                    .code()
                );

                assert_eq!(status.code(), Code::InvalidArgument);
            }
        }
    }

    #[tokio::test]
    async fn test_register_node_method_param_ip_is_correct() {
        let client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .expect("Failed to connect to PlacementCenterService");

        let mut node = BrokerNode {
            cluster_name: cluster_name(),
            cluster_type: cluster_type(),
            node_ip: node_ip(),
            node_id: node_id(),
            node_inner_addr: node_ip(),
            extend: extend_info(),
            start_time: now_second(),
            register_time: now_second(),
        };
        let valid_request = RegisterNodeRequest {
            node: node.encode(),
        };

        let valid_ip = [
            "192.168.1.1",
            "1.1.1.1",
            "255.255.255.255",
            "0.0.0.0",
            "123.112.154.123",
            "172.192.140.21",
            "192.168.1.1:8080",
            "1.1.1.1:2020",
            "255.255.255.255:9999",
            "0.0.0.0:10009",
            "123.112.154.123:10000",
            "172.192.140.21:32145",
        ];

        let field = ["node_ip", "node_inner_addr"];

        let mut field_ip: Vec<(&str, &str)> = Vec::new();

        for field in field {
            for ip in valid_ip {
                field_ip.push((field, ip))
            }
        }

        for (field, ip) in field_ip {
            let mut test_client = client.clone();
            match field {
                "node_ip" => node.node_ip = ip.parse().unwrap(),
                "node_inner_addr" => node.node_inner_addr = ip.parse().unwrap(),
                _ => unreachable!(),
            }

            {
                let response = test_client
                    .register_node(tonic::Request::new(valid_request.clone()))
                    .await;
                assert!(response.is_ok());
            }
        }
    }

    #[tokio::test]
    async fn test_register_node_method_param_ip_is_err() {
        let client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .unwrap();

        let mut node = BrokerNode {
            cluster_name: cluster_name(),
            cluster_type: cluster_type(),
            node_ip: node_ip(),
            node_id: node_id(),
            node_inner_addr: node_ip(),
            extend: extend_info(),
            start_time: now_second(),
            register_time: now_second(),
        };
        let valid_request = RegisterNodeRequest {
            node: node.encode(),
        };

        let valid_ip = [
            "255",
            "255.255",
            "255.255.255",
            "256.256.256.256",
            "256.111.111.111",
            "111.256.111.111",
            "111.111.256.111",
            "111.111.111.256",
        ];

        let field = ["node_ip"];

        let mut field_ip: Vec<(&str, &str)> = Vec::new();

        for field in field {
            for ip in valid_ip {
                field_ip.push((field, ip))
            }
        }

        for (field, ip) in field_ip {
            let test_request = valid_request.clone();
            let mut test_client = client.clone();
            match field {
                "node_ip" => node.node_ip = ip.parse().unwrap(),
                _ => unreachable!(),
            }
            {
                let response = test_client
                    .register_node(tonic::Request::new(test_request.clone()))
                    .await;

                assert!(response.is_err());
                if let Err(ref e) = response {
                    assert_eq!(e.code(), Code::InvalidArgument);
                    assert_eq!(e.code(), Code::InvalidArgument);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let mut client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .unwrap();

        let request = HeartbeatRequest {
            cluster_type: ClusterType::JournalServer.into(),
            cluster_name: cluster_name(),
            node_id: node_id(),
        };
        let res = client.heartbeat(tonic::Request::new(request)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_unregister_node() {
        let mut client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .unwrap();

        let request = UnRegisterNodeRequest {
            cluster_type: ClusterType::JournalServer.into(),
            cluster_name: cluster_name(),
            node_id: node_id(),
        };
        client
            .un_register_node(tonic::Request::new(request))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_set_idempotent_data() {
        let mut client = PlacementCenterServiceClient::connect(pc_addr())
            .await
            .unwrap();

        let valid_request = SetIdempotentDataRequest {
            cluster_name: cluster_name(),
            producer_id: producer_id(),
            seq_num: seq_num(),
        };

        let response = client
            .set_idempotent_data(tonic::Request::new(valid_request.clone()))
            .await;

        assert!(response.is_ok());

        let invalid_fields = vec![
            ("cluster_name", String::new()),
            ("producer_id", String::new()),
        ];

        for (field, value) in invalid_fields {
            let mut invalid_request = valid_request.clone();
            match field {
                "cluster_name" => invalid_request.cluster_name = value,
                "producer_id" => invalid_request.producer_id = value,
                _ => unreachable!(),
            }

            let response = client
                .set_idempotent_data(tonic::Request::new(invalid_request))
                .await;

            assert!(response.is_err());
        }
    }

    #[tokio::test]
    async fn test_create_shard() {
        let mut client = EngineServiceClient::connect(pc_addr()).await.unwrap();

        let config = JournalShardConfig {
            max_segment_size: 1024 * 1024 * 10,
            replica_num: 1,
        };

        let request = CreateShardRequest {
            cluster_name: cluster_name(),
            namespace: namespace(),
            shard_name: shard_name(),
            shard_config: serde_json::to_vec(&config).unwrap(),
        };

        match client.create_shard(tonic::Request::new(request)).await {
            Ok(_) => {}
            Err(e) => {
                println!("{e}");
            }
        }
    }

    #[tokio::test]
    async fn test_delete_shard() {
        let mut client = EngineServiceClient::connect(pc_addr()).await.unwrap();

        let request = DeleteShardRequest {
            cluster_name: cluster_name(),
            namespace: namespace(),
            shard_name: shard_name(),
        };
        match client.delete_shard(tonic::Request::new(request)).await {
            Ok(_) => {}
            Err(e) => {
                println!("{e}");
            }
        }
    }

    #[tokio::test]
    async fn test_create_segment() {
        let mut client = EngineServiceClient::connect(pc_addr()).await.unwrap();

        let request = CreateNextSegmentRequest {
            cluster_name: cluster_name(),
            namespace: namespace(),
            shard_name: shard_name(),
        };
        match client
            .create_next_segment(tonic::Request::new(request))
            .await
        {
            Ok(_) => {}
            Err(e) => {
                println!("{e}");
            }
        }
    }

    #[tokio::test]
    async fn test_delete_segment() {
        let mut client = EngineServiceClient::connect(pc_addr()).await.unwrap();

        let request = DeleteSegmentRequest {
            cluster_name: cluster_name(),
            namespace: namespace(),
            shard_name: shard_name(),
            segment_seq: 1,
        };
        match client.delete_segment(tonic::Request::new(request)).await {
            Ok(_) => {}
            Err(e) => {
                println!("{e}");
            }
        }
    }
}
