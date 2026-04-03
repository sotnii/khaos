use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, info_span};
use crate::net::ip_alloc::{IpAllocError, LanIpAllocator};
use crate::net::ip_cmd::{IpCmd, IpCmdError};
use crate::spec::NodeId;

#[derive(Debug, Error)]
pub enum ClusterNetworkError {
    #[error("ip command failed: {0}")]
    IpCmdError(String, #[source] IpCmdError),
    #[error("ip allocation failed: {0}")]
    IpAllocationError(String, #[source] IpAllocError),
}

/// Cluster network net is responsible for setting up network namespaces for running nodes and managing topologies
/// between nodes via veth pairs.
pub struct ClusterNetworkManager {
    namespaces: HashMap<NodeId, NetworkNamespace>,
    bridge_name: String,
    bridge_up: bool,
    ip_alloc: LanIpAllocator
}

const DEFAULT_IP_SUBNET: &'static str = "10.0.0.0";
const DEFAULT_IP_RANGE: u8 = 24;

impl ClusterNetworkManager {
    pub fn new() -> ClusterNetworkManager {
        ClusterNetworkManager {
            namespaces: HashMap::new(),
            bridge_name: String::from("kh-bridge"),
            bridge_up: false,
            ip_alloc: LanIpAllocator::new(
                Ipv4Addr::from_str(DEFAULT_IP_SUBNET).unwrap(),
                DEFAULT_IP_RANGE
            ).unwrap()
        }
    }

    pub fn setup_bridge(&mut self) -> Result<(), ClusterNetworkError> {
        let _span = info_span!("network.setup_bridge", bridge = %self.bridge_name).entered();
        let (exists, up) = IpCmd::get_if_status(&self.bridge_name).map_err(|e| ClusterNetworkError::IpCmdError(
            "failed to get bridge status".to_string(), e
        ))?;

        if !exists {
            debug!(bridge = %self.bridge_name, "creating bridge interface");
            IpCmd::add_bridge_veth(&self.bridge_name)
                .map_err(|e| ClusterNetworkError::IpCmdError("failed to create bridge".to_string(), e))?;
        }

        if !up {
            debug!(bridge = %self.bridge_name, "bringing bridge interface up");
            IpCmd::bring_veth_up(&self.bridge_name)
                .map_err(|e| ClusterNetworkError::IpCmdError("failed to bring bridge up".to_string(), e))?;
        }

        self.bridge_up = true;
        Ok(())
    }

    pub fn setup_node_namespace(&mut self, node_id: &NodeId) -> Result<(), ClusterNetworkError> {
        let name = format!("kh-{}", node_id.0);
        let _span = info_span!("network.setup_node_namespace", ns = %name, node_id = %node_id).entered();
        debug!("creating network namespace");

        IpCmd::add_ns(&name)
            .map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to add network namespace {}", name), e)
            )?;

        debug!("network namespace created");

        // Bring loopback up
        IpCmd::bring_ns_veth_up(&name, "lo").map_err(|e| ClusterNetworkError::IpCmdError(
            format!("failed to bring loopback up in namespace {}", name), e
        ))?;

        debug!(iface = "lo", "namespace interface is up");

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
        let _span = info_span!("network.setup_node_network", bridge = %self.bridge_name).entered();
        for (node_id, nn) in self.namespaces.iter_mut() {
            // TODO: Generate random IDs instead, because veth names are limited to 15chars and relying on user input here
            //  will cause errors
            let veth = format!("kh-veth-{}", node_id.0);
            let br_veth = format!("kh-br-{}", node_id.0);
            let _span = info_span!(
                "network.attach_namespace",
                node_id = %node_id,
                ns = %nn.name,
                veth = %veth,
                bridge_veth = %br_veth,
                bridge = %self.bridge_name
            ).entered();

            debug!("setting up namespace veth pair");

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

            let addr = self.ip_alloc.allocate_ip().map_err(|e| ClusterNetworkError::IpAllocationError(
                format!("failed to allocate ip address for {}", veth), e
            ))?;
            IpCmd::attach_addr_to_veth(&nn.name, &veth, &addr, self.ip_alloc.subnet()).map_err(|e| ClusterNetworkError::IpCmdError(
                format!("failed to attach new ip address for {}", veth), e
            ))?;

            nn.iface = Some(veth);
            nn.bridge_pair = Some(br_veth);
            nn.allocated_lan_ip = Some(addr);

            debug!("namespace network is ready");
        }
        Ok(())
    }

    pub fn teardown_all(&mut self) -> Result<(), ClusterNetworkError> {
        let _span = info_span!("network.teardown_all", namespace_count = self.namespaces.len()).entered();
        debug!("tearing down all network namespaces");
        for (_, ns) in self.namespaces.drain() {
            let _span = info_span!("network.delete_namespace", ns = %ns.name).entered();
            debug!("deleting network namespace");
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
    allocated_lan_ip: Option<Ipv4Addr>,
}
