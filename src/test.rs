use std::panic::{self, AssertUnwindSafe};
use std::thread;
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;
use crate::net::manager::{ClusterNetworkError, ClusterNetworkManager};
use crate::spec::{ClusterSpec, NodeId, NodeSpec};
use tracing::{debug, error, info, info_span};
use thiserror::Error;
use crate::test::TestRunnerError::{TestFailed, TestPanic};

#[derive(Error, Debug)]
pub enum TestSetupError {
    #[error("network setup failed")]
    ClusterNetworkSetupFailed(#[from] ClusterNetworkError),
}

#[derive(Error, Debug)]
pub enum TestTeardownError {
    #[error("network teardown failed")]
    ClusterNetworkTeardownFailed(#[from] ClusterNetworkError),
}

#[derive(Error, Debug)]
pub enum TestRunnerError {
    #[error("test run failed on setup stage")]
    TestFailedOnSetup(#[from] TestSetupError),

    #[error("failed to tear down test environment")]
    TestTeardownFailed(#[from] TestTeardownError),

    #[error("test failed")]
    TestFailed(#[from] TestFailure),

    #[error("test panic: {0}")]
    TestPanic(String)
}

#[derive(Error, Debug)]
pub enum TestFailure {
    #[error("assertion in test failed: {0}")]
    AssertionFailed(String),
}

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

    pub fn run<F>(&mut self, tester: F) -> Result<(), TestRunnerError>
    where
        F: FnOnce(TestContext) -> Result<(), TestFailure>,
    {
        let _span = info_span!("test.run", test = self.name).entered();
        info!("running test");
        debug!(cluster_spec = ?self.cluster_spec, "loaded cluster spec");

        if let Err(setup_err) = self.setup() {
            if let Err(teardown_err) = self.teardown() {
                error!(teardown_err = ?teardown_err, "failed to tear down after failed setup");
            }

            return Err(TestRunnerError::TestFailedOnSetup(setup_err))
        }

        let test_result = panic::catch_unwind(AssertUnwindSafe(|| {
            // TODO: Wait for liveliness probes as stuff
            // TODO: Setup test context
            // TODO: Give execution to the test function
            tester(TestContext {})
        }));

        let teardown_result = self.teardown().map_err(|e| TestRunnerError::TestTeardownFailed(e));
        if let Err(teardown_err) = teardown_result {
            error!(teardown_err = ?teardown_err, "failed to tear down after test");
        }

        match test_result {
            Ok(r) => {
                if let Err(test_err) = r {
                    return Err(TestFailed(test_err))
                }
                Ok(())
            }
            Err(e) => {
                if let Some(msg) = e.downcast_ref::<&'static str>() {
                    return Err(TestPanic(msg.to_string()))
                } else if let Some(msg) = e.downcast_ref::<String>() {
                    return Err(TestPanic(msg.to_string()))
                }
                panic!("unable to recover test run panic")
            }
        }
    }

    fn setup(&mut self) -> Result<(), TestSetupError> {
        let _span = info_span!(
            "test.setup",
            test = self.name,
            node_count = self.cluster_spec.nodes.len(),
            az_count = self.cluster_spec.az.len()
        ).entered();
        info!("running cluster setup");

        self.network_setup()?;

        // TODO:
        //  +1. Setup namespaces
        //  +2. Setup full mesh network between nodes
        //  3. Spawn containers with containerd
        //  4. Wait for availability for containers
        //  5. HOORAY!

        Ok(())
    }

    fn network_setup(&mut self) -> Result<(), TestSetupError> {
        let _span = info_span!("test.setup.network").entered();

        self.network.setup_bridge().map_err(|e| TestSetupError::ClusterNetworkSetupFailed(e))?;

        for (node_id, node_spec) in self.cluster_spec.nodes.iter() {
            let _span = info_span!("test.setup_node", node_id = %node_id).entered();
            self.network.setup_node_namespace(&node_id).map_err(|e| TestSetupError::ClusterNetworkSetupFailed(e))?;
            self.nodes.push(Node{
                node_id: node_id.clone(),
                spec: node_spec.clone(),
            });
        }

        debug!(node_count = self.nodes.len(), "setting up node network");
        self.network.setup_node_network().map_err(|e| TestSetupError::ClusterNetworkSetupFailed(e))?;

        debug!(
            namespace = ?self.network.get_node_namespace(&self.nodes.first().unwrap().node_id).unwrap(),
            "first node namespace ready"
        );

        Ok(())
    }

    fn teardown(&mut self) -> Result<(), TestTeardownError> {
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