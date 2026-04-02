use crate::net::NamespaceManager;
use crate::spec::ClusterSpec;
use anyhow::Result;
use log::info;
use thiserror::Error;

pub struct Test {
    name: &'static str,
    cluster_spec: ClusterSpec,
    namespace_manager: NamespaceManager,
}

#[derive(Debug, Error)]
pub enum TestError {
    #[error("failed to create namespace")]
    SetupFailed(#[source] std::io::Error),
}

pub struct TestContext {
    pub spec: ClusterSpec,
}

impl Test {
    pub fn new(name: &'static str, cluster_spec: ClusterSpec) -> Test {
        Test {
            name,
            cluster_spec,
            namespace_manager: NamespaceManager::new(),
        }
    }

    pub fn run<F>(&mut self, tester: F) -> Result<()>
    where
        F: Fn(TestContext) -> (),
    {
        info!("Running {}", self.name);

        // TODO: Set everything up
        self.setup()?;

        // TODO: Wait for liveliness probes as stuff
        // TODO: Setup test context
        // TODO: Give execution to the test function
        // TODO: After everything is tested (regardless of the outcome) - clean everything up
        tester(TestContext {
            spec: self.cluster_spec.clone(),
        });

        self.teardown()?;

        Ok(())
    }

    fn setup(&mut self) -> Result<()> {
        info!("running cluster setup");

        let node_names: Vec<_> = self.cluster_spec.nodes.iter().map(|x| x.name()).collect();
        for name in node_names {
            self.namespace_manager.create(format!("kh-{}", name))?;
        }

        // TODO:
        //  +1. Setup namespaces
        //  2. Setup full mesh network between nodes
        //  3. Spawn containers with containerd
        //  4. Wait for availability for containers
        //  5. HOORAY!

        Ok(())
    }

    fn teardown(&mut self) -> Result<()> {
        info!("running cluster teardown");

        // TODO:
        //  1. Teardown container processes
        //  2. Tear down mesh network (disable, delete veth)
        //  +3. Teardown namespaces

        self.namespace_manager.teardown()?;

        Ok(())
    }
}
