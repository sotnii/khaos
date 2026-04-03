use crate::spec::{ClusterSpec, NodeId, NodeSpec};
use anyhow::Result;
use thiserror::Error;
use crate::net::manager::ClusterNetworkManager;
use tracing::{debug, info, info_span};


pub struct Node {
    node_id: NodeId,
    spec: NodeSpec,
}

pub struct Test {
    name: &'static str,
    cluster_spec: ClusterSpec,
    network: ClusterNetworkManager,
    nodes: Vec<Node>,
}

#[derive(Debug, Error)]
pub enum TestError {
    #[error("failed to create namespace")]
    SetupFailed(#[source] std::io::Error),
}

pub struct TestContext {
}

// TODO: Using anyhow here is kind of weak for troubleshooting
impl Test {
    pub fn new(name: &'static str, cluster_spec: ClusterSpec) -> Test {
        Test {
            name,
            cluster_spec,
            network: ClusterNetworkManager::new(),
            nodes: Vec::new(),
        }
    }

    pub fn run<F>(&mut self, tester: F) -> Result<()>
    where
        F: Fn(TestContext) -> (),
    {
        let _span = info_span!("test.run", test = self.name).entered();
        info!("running test");
        debug!(cluster_spec = ?self.cluster_spec, "loaded cluster spec");

        // TODO: Set everything up
        self.setup()?;

        // TODO: Wait for liveliness probes as stuff
        // TODO: Setup test context
        // TODO: Give execution to the test function
        // TODO: After everything is tested (regardless of the outcome) - clean everything up
        tester(TestContext {
        });

        self.teardown()?;

        Ok(())
    }

    fn setup(&mut self) -> Result<()> {
        let _span = info_span!(
            "test.setup",
            test = self.name,
            node_count = self.cluster_spec.nodes.len(),
            az_count = self.cluster_spec.az.len()
        ).entered();
        info!("running cluster setup");

        self.network.setup_bridge()?;

        for (node_id, node_spec) in self.cluster_spec.nodes.iter() {
            let _span = info_span!("test.setup_node", node_id = %node_id).entered();
            self.network.setup_node_namespace(&node_id)?;
            self.nodes.push(Node{
                node_id: node_id.clone(),
                spec: node_spec.clone(),
            });
        }

        debug!(node_count = self.nodes.len(), "setting up node network");
        self.network.setup_node_network()?;

        debug!(
            namespace = ?self.network.get_node_namespace(&self.nodes.first().unwrap().node_id).unwrap(),
            "first node namespace ready"
        );

        // TODO:
        //  +1. Setup namespaces
        //  +2. Setup full mesh network between nodes
        //  3. Spawn containers with containerd
        //  4. Wait for availability for containers
        //  5. HOORAY!

        Ok(())
    }

    fn teardown(&mut self) -> Result<()> {
        let _span = info_span!("test.teardown", test = self.name, node_count = self.nodes.len()).entered();
        info!("running cluster teardown");

        // TODO:
        //  1. Teardown container processes
        //  2. Tear down mesh network (disable, delete veth)
        //  +3. Teardown namespaces

        self.network.teardown_all()?;

        Ok(())
    }
}
