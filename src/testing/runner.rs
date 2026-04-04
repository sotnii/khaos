use crate::containers::manager::{ContainerManager, ContainerManagerError};
use crate::net::manager::{ClusterNetworkError, ClusterNetworkManager};
use crate::spec::{ClusterSpec, NodeId, NodeSpec};
use crate::testing::ctx::TestContext;
use nanoid::nanoid;
use std::collections::HashMap;
use std::panic;
use thiserror::Error;
use tokio::select;
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, info, info_span, instrument};

#[derive(Error, Debug)]
pub enum TestSetupError {
    #[error("network setup failed")]
    ClusterNetworkSetupFailed(#[from] ClusterNetworkError),

    #[error("containers setup failed")]
    ContainerSetupFailed(#[from] ContainerManagerError),
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

    #[error("unexpected error")]
    TestRunFailed(#[from] JoinError),

    #[error("test cancelled")]
    TestCancelled,
}

#[derive(Error, Debug)]
pub enum TestFailure {
    #[error("assertion in test failed: {0}")]
    AssertionFailed(String),
}

pub struct Node {
    node_id: NodeId,
    resource_id: String,
    spec: NodeSpec,
}

pub struct Test {
    id: String,
    name: &'static str,
    cluster_spec: ClusterSpec,
    network: ClusterNetworkManager,
    nodes: HashMap<NodeId, Node>,
    cancellation_token: CancellationToken,
    containerd: ContainerManager,
}

impl Test {
    pub fn new(name: &'static str, cluster_spec: ClusterSpec) -> Test {
        Test {
            id: nanoid!(),
            name,
            cluster_spec,
            network: ClusterNetworkManager::new(),
            nodes: HashMap::new(),
            cancellation_token: CancellationToken::new(),
            containerd: ContainerManager::new(None),
        }
    }

    pub async fn run<F, Fut>(&mut self, test: F) -> Result<(), TestRunnerError>
    where
        F: FnOnce(TestContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TestFailure>> + Send,
    {
        let _span = info_span!("test.run", test = self.name).entered();
        info!("running test");
        debug!(cluster_spec = ?self.cluster_spec, "loaded cluster spec");

        if let Err(setup_err) = self.setup().await {
            if let Err(teardown_err) = self.teardown() {
                error!(teardown_err = ?teardown_err, "failed to tear down after failed setup");
            }

            return Err(TestRunnerError::TestFailedOnSetup(setup_err));
        }

        // TODO: Setup test context
        let ctx = TestContext {
            cancellation_token: self.cancellation_token.clone(),
        };
        let test_task = tokio::spawn(async move { test(ctx).await });

        let res: Result<(), TestRunnerError> = select! {
            join_res = test_task => {
                match join_res {
                    Ok(_) => Ok(()),
                    Err(join_err) if join_err.is_panic() => {
                        if let Err(e) = self.teardown() {
                            error!(teardown_err = ?e, "failed to tear down when caught panic in test");
                        }
                        panic::resume_unwind(join_err.into_panic())
                    }
                    Err(e) => Err(TestRunnerError::TestRunFailed(e)),
                }
            }
            _ = wait_for_ctrl_c() => {
                info!("received sigint signal");
                self.cancellation_token.cancel();
                Err(TestRunnerError::TestCancelled)
            }
        };

        self.teardown()
            .map_err(|e| TestRunnerError::TestTeardownFailed(e))?;

        res
    }

    #[instrument(level = "info", skip(self))]
    async fn setup(&mut self) -> Result<(), TestSetupError> {
        info!("running cluster setup");

        self.network_setup()?;

        self.container_setup().await?;
        // TODO:
        //  +1. Setup namespaces
        //  +2. Setup full mesh network between nodes
        //  3. Spawn containers with containerd
        //  4. Wait for availability for containers
        //  5. HOORAY!

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    async fn container_setup(&mut self) -> Result<(), TestSetupError> {
        self.containerd.connect().await?;

        for (node_id, node) in self.nodes.iter_mut() {
            let ns = self
                .network
                .get_namespace(node_id.raw())
                .expect("node namespace expected to be setup before running containers");
            for spec in node.spec.container_specs.clone() {
                self.containerd
                    .run_container(self.id.clone(), node_id.clone(), spec, ns.clone())
                    .await?;
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    fn network_setup(&mut self) -> Result<(), TestSetupError> {
        self.network
            .setup_bridge()
            .map_err(|e| TestSetupError::ClusterNetworkSetupFailed(e))?;

        for (node_id, node_spec) in self.cluster_spec.nodes.iter() {
            let _span = info_span!("setup_node", node_id = %node_id).entered();
            self.network
                .setup_namespace(node_id.raw().clone())
                .map_err(|e| TestSetupError::ClusterNetworkSetupFailed(e))?;
            self.nodes.insert(
                node_id.clone(),
                Node {
                    node_id: node_id.clone(),
                    resource_id: nanoid!(),
                    spec: node_spec.clone(),
                },
            );
        }

        debug!(node_count = self.nodes.len(), "setting up node network");
        self.network
            .setup_node_network()
            .map_err(|e| TestSetupError::ClusterNetworkSetupFailed(e))?;

        Ok(())
    }

    #[instrument(level = "debug", skip(self))]
    fn teardown(&mut self) -> Result<(), TestTeardownError> {
        info!("running cluster teardown");

        // TODO:
        //  1. Teardown container processes
        //  2. Tear down mesh network (disable, delete veth)
        //  +3. Teardown namespaces

        debug_span!("network_teardown").in_scope(|| self.network.teardown_all())?;

        Ok(())
    }
}

async fn wait_for_ctrl_c() {
    // TODO: Subscribe to other signals like sigquit and sigterm
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install SIGINT handler");
}
