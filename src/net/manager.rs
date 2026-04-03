use std::collections::HashMap;
use log::debug;
use thiserror::Error;
use crate::net::ip_cmd::{IpCmd, IpCmdError};
use crate::spec::NodeId;

#[derive(Debug, Error)]
pub enum ClusterNetworkError {
    #[error("ip command failed: {0}")]
    IpCmdError(String, #[source] IpCmdError),
}

/// Cluster network net is responsible for setting up network namespaces for running nodes and managing topologies
/// between nodes via veth pairs.
pub struct ClusterNetworkManager {
    namespaces: HashMap<NodeId, NetworkNamespace>,
    bridge_name: String,
    bridge_up: bool,
}

impl ClusterNetworkManager {
    pub fn new() -> ClusterNetworkManager {
        ClusterNetworkManager {
            namespaces: HashMap::new(),
            bridge_name: String::from("kh-bridge"),
            bridge_up: false,
        }
    }

    pub fn setup_bridge(&mut self) -> Result<(), ClusterNetworkError> {
        let (exists, up) = IpCmd::get_if_status(&self.bridge_name).map_err(|e| ClusterNetworkError::IpCmdError(
            "failed to get bridge status".to_string(), e
        ))?;

        if !exists {
            debug!("creating bridge veth {}", self.bridge_name);
            IpCmd::add_bridge_veth(&self.bridge_name)
                .map_err(|e| ClusterNetworkError::IpCmdError("failed to create bridge".to_string(), e))?;
        }

        if !up {
            debug!("brining up bridge veth {}", self.bridge_name);
            IpCmd::bring_veth_up(&self.bridge_name)
                .map_err(|e| ClusterNetworkError::IpCmdError("failed to bring bridge up".to_string(), e))?;
        }

        self.bridge_up = true;
        Ok(())
    }

    pub fn setup_node_namespace(&mut self, node_id: &NodeId) -> Result<(), ClusterNetworkError> {
        let name = format!("kh-{}", node_id.0);
        debug!("creating network namespace, ns={}, node_id={}", name, node_id);

        IpCmd::add_ns(&name)
            .map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to add network namespace {}", name), e)
            )?;

        debug!("namespace is up, ns={}, node_id={}", name, node_id);

        // Bring loopback up
        IpCmd::bring_ns_veth_up(&name, "lo").map_err(|e| ClusterNetworkError::IpCmdError(
            format!("failed to bring loopback up in namespace {}", name), e
        ))?;

        debug!("loopback interface is up, ns={}, node_id={}", name, node_id);

        self.namespaces.insert(
            node_id.clone(),
            NetworkNamespace {
                name: name.clone(),
                path: format!("/run/netns/{}", name),
                ..Default::default()
            }
        );
        Ok(())
    }

    pub fn get_node_namespace(&self, node_name: &NodeId) -> Option<&NetworkNamespace> {
        self.namespaces.get(node_name)
    }

    pub fn setup_node_network(&mut self) -> Result<(), ClusterNetworkError> {
        for (node_id, nn) in self.namespaces.iter_mut() {
            // TODO: Generate random IDs instead, because veth names are limited to 15chars and relying on user input here
            //  will cause errors
            let veth = format!("kh-veth-{}", node_id.0);
            let br_veth = format!("kh-br-{}", node_id.0);

            debug!("setting up ns veth pair between {} and {}, ns={}, node_id={}", veth, br_veth, nn.name, node_id);

            // Create veth pair itself
            IpCmd::add_veth_peer(&veth, &br_veth).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to add peer {} to network namespace {}", veth, br_veth), e
            ))?;

            // Move veth to it's workspace
            IpCmd::move_veth_to_ns(&veth, &nn.name).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to move node {} to network namespace {}", nn.name, veth), e
            ))?;

            // Setup connection to the bridge
            IpCmd::set_veth_master(&br_veth, &self.bridge_name).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to set {} as master for {}", self.bridge_name, br_veth), e
            ))?;

            // Bring both veths up
            IpCmd::bring_ns_veth_up(&nn.name, &veth).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to set node {} veth up in namespace {}", veth, nn.name), e
            ))?;

            IpCmd::bring_veth_up(&br_veth).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to set {} up", br_veth), e
            ))?;

            nn.iface = Some(veth);
            nn.bridge_pair = Some(br_veth);

            // TODO: allocate IP
        }
        Ok(())
    }

    pub fn teardown_all(&mut self) -> Result<(), ClusterNetworkError> {
        debug!("tearing down all network namespaces");
        for (_, ns) in self.namespaces.drain() {
            debug!("deleting network namespace, ns={}", &ns.name);
            IpCmd::del_ns(&ns.name).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to delete namespace {}", &ns.name), e
            ))?;
        }
        // TODO: Delete/down bridge interface
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkNamespace {
    pub name: String,
    path: String,
    iface: Option<String>,
    bridge_pair: Option<String>,
}
