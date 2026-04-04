use crate::net::ip_alloc::{IpAllocError, LanIpAllocator};
use crate::net::ip_cmd::{IpCmd, IpCmdError};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, info, info_span};

#[derive(Debug, Error)]
pub enum ClusterNetworkError {
    #[error("ip command failed: {0}")]
    IpCmdError(String, #[source] IpCmdError),
    #[error("ip allocation failed: {0}")]
    IpAllocationError(String, #[source] IpAllocError),
}

/// Cluster network net is responsible for setting up network namespaces for running nodes and managing topologies
/// between nodes via veth pairs.
#[derive(Debug)]
pub struct ClusterNetworkManager {
    namespaces: HashMap<String, NetworkNamespace>,
    bridge_name: String,
    bridge_up: bool,
    ip_alloc: LanIpAllocator,
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
                DEFAULT_IP_RANGE,
            )
            .unwrap(),
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn setup_bridge(&mut self) -> Result<(), ClusterNetworkError> {
        let (exists, up) = IpCmd::get_if_status(&self.bridge_name).map_err(|e| {
            ClusterNetworkError::IpCmdError("failed to get bridge status".to_string(), e)
        })?;

        if !exists {
            debug!(bridge = %self.bridge_name, "creating bridge interface");
            IpCmd::add_bridge_veth(&self.bridge_name).map_err(|e| {
                ClusterNetworkError::IpCmdError("failed to create bridge".to_string(), e)
            })?;
        }

        if !up {
            debug!(bridge = %self.bridge_name, "bringing bridge interface up");
            IpCmd::bring_iface_up(&self.bridge_name).map_err(|e| {
                ClusterNetworkError::IpCmdError("failed to bring bridge up".to_string(), e)
            })?;
        }

        self.bridge_up = true;
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn setup_namespace(&mut self, key: String) -> Result<(), ClusterNetworkError> {
        let namespace_name = format!("kh-{}", key);
        let path = format!("/run/netns/{}", key);

        if Path::new(&path).exists() {
            info!("namespace already exists, tearing it down before recreating");
            IpCmd::del_ns(&namespace_name).map_err(|e| {
                ClusterNetworkError::IpCmdError(
                    format!("failed to delete existing network namespace {}", key),
                    e,
                )
            })?;
        }

        debug!("creating network namespace");

        IpCmd::add_ns(&namespace_name).map_err(|e| {
            ClusterNetworkError::IpCmdError(format!("failed to add network namespace {}", key), e)
        })?;

        // Bring loopback up
        if let Err(e) = IpCmd::bring_ns_iface_up(&namespace_name, "lo") {
            let _ = IpCmd::del_ns(&namespace_name);
            return Err(ClusterNetworkError::IpCmdError(
                format!("failed to bring loopback up in namespace {}", key),
                e,
            ));
        }

        debug!(iface = "lo", "namespace interface is up");

        self.namespaces.insert(
            key,
            NetworkNamespace {
                name: namespace_name,
                path,
                ..Default::default()
            },
        );
        Ok(())
    }

    pub fn get_namespace(&self, name: &String) -> Option<&NetworkNamespace> {
        self.namespaces.get(name)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn setup_node_network(&mut self) -> Result<(), ClusterNetworkError> {
        for (name, nn) in self.namespaces.iter_mut() {
            // TODO: Generate random IDs instead, because veth names are limited to 15chars and relying on user input here
            //  will cause errors
            let veth = format!("kh-veth-{}", name);
            let br_veth = format!("kh-br-{}", name);
            let _span = info_span!(
                "attach_namespace",
                name = %name,
                ns = %nn.name,
                veth = %veth,
                bridge_veth = %br_veth,
                bridge = %self.bridge_name
            )
            .entered();

            debug!("setting up namespace veth pair");

            // Create veth pair itself
            IpCmd::add_iface_peer(&veth, &br_veth).map_err(|e| {
                ClusterNetworkError::IpCmdError(
                    format!(
                        "failed to add peer {} to network namespace {}",
                        veth, br_veth
                    ),
                    e,
                )
            })?;

            // Move veth to it's workspace
            IpCmd::move_iface_to_ns(&veth, &nn.name).map_err(|e| {
                ClusterNetworkError::IpCmdError(
                    format!(
                        "failed to move node {} to network namespace {}",
                        nn.name, veth
                    ),
                    e,
                )
            })?;

            // Setup connection to the bridge
            IpCmd::set_iface_master(&br_veth, &self.bridge_name).map_err(|e| {
                ClusterNetworkError::IpCmdError(
                    format!(
                        "failed to set {} as master for {}",
                        self.bridge_name, br_veth
                    ),
                    e,
                )
            })?;

            // Bring both veths up
            IpCmd::bring_ns_iface_up(&nn.name, &veth).map_err(|e| {
                ClusterNetworkError::IpCmdError(
                    format!(
                        "failed to set node {} veth up in namespace {}",
                        veth, nn.name
                    ),
                    e,
                )
            })?;

            IpCmd::bring_iface_up(&br_veth).map_err(|e| {
                ClusterNetworkError::IpCmdError(format!("failed to set {} up", br_veth), e)
            })?;

            let addr = self.ip_alloc.allocate_ip().map_err(|e| {
                ClusterNetworkError::IpAllocationError(
                    format!("failed to allocate ip address for {}", veth),
                    e,
                )
            })?;
            IpCmd::attach_addr_to_iface(&nn.name, &veth, &addr, self.ip_alloc.subnet()).map_err(
                |e| {
                    ClusterNetworkError::IpCmdError(
                        format!("failed to attach new ip address for {}", veth),
                        e,
                    )
                },
            )?;

            nn.iface = Some(veth);
            nn.bridge_pair = Some(br_veth);
            nn.allocated_lan_ip = Some(addr);

            debug!("namespace network is ready");
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn teardown_all(&mut self) -> Result<(), ClusterNetworkError> {
        debug!("tearing down all network namespaces");
        for (_, ns) in self.namespaces.drain() {
            let _span = info_span!("delete_namespace", ns = %ns.name).entered();
            debug!("deleting network namespace");
            IpCmd::del_ns(&ns.name).map_err(|e| {
                ClusterNetworkError::IpCmdError(
                    format!("failed to delete namespace {}", &ns.name),
                    e,
                )
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkNamespace {
    pub name: String,
    pub path: String,
    iface: Option<String>,
    bridge_pair: Option<String>,
    allocated_lan_ip: Option<Ipv4Addr>,
}
