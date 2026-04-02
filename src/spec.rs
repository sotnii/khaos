pub mod common;

use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct ClusterSpec {
    pub name: &'static str,
    pub nodes: Vec<NodeSpec>,
    pub az: Vec<AZSpec>,
}

#[derive(Debug)]
struct NodeSpecData {
    name: &'static str,
    container_specs: Vec<ContainerSpec>,
}

#[derive(Clone, Debug)]
pub struct NodeSpec {
    inner: Rc<RefCell<NodeSpecData>>,
}

#[derive(Clone, Debug)]
pub struct ContainerSpec {
    pub image: &'static str,
}

#[derive(Debug, Clone)]
pub struct AZSpec {
    pub name: &'static str,
    pub nodes: Vec<NodeSpec>,
}

impl ClusterSpec {
    pub fn new(name: &'static str) -> ClusterSpec {
        ClusterSpec {
            name,
            nodes: vec![],
            az: vec![],
        }
    }

    pub fn node(&mut self, name: &'static str) -> NodeSpec {
        let node = NodeSpec::new(name);
        self.nodes.push(node.clone());
        node
    }

    pub fn get_node(&self, name: &'static str) -> Option<&NodeSpec> {
        self.nodes.iter().find(|x| x.name() == name)
    }

    pub fn az(&mut self, name: &'static str) -> &mut AZSpec {
        self.az.push(AZSpec {
            name,
            nodes: vec![],
        });
        self.az.last_mut().unwrap()
    }
}

impl NodeSpec {
    fn new(name: &'static str) -> NodeSpec {
        NodeSpec {
            inner: Rc::new(RefCell::new(NodeSpecData {
                name,
                container_specs: vec![],
            })),
        }
    }

    pub fn with(self, container_spec: ContainerSpec) -> NodeSpec {
        self.inner.borrow_mut().container_specs.push(container_spec);
        self
    }

    pub fn name(&self) -> &'static str {
        self.inner.borrow().name
    }

    pub fn container_specs(&self) -> Vec<ContainerSpec> {
        self.inner.borrow().container_specs.clone()
    }
}

impl AZSpec {
    pub fn with(&mut self, node: NodeSpec) -> &mut AZSpec {
        self.nodes.push(node);
        self
    }
}
