use std::collections::HashMap;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct ClusterSpec {
    pub name: String,
    pub nodes: HashMap<NodeId, NodeSpec>,
    pub az: HashMap<AzId, AZSpec>,
}

impl ClusterSpec {
    pub fn new(name: impl Into<String>) -> ClusterSpec {
        ClusterSpec {
            name: name.into(),
            nodes: HashMap::new(),
            az: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, name: impl Into<String>, spec: NodeSpec) -> NodeId {
        let key = NodeId(name.into());
        if self.nodes.contains_key(&key) {
            panic!("Node {key:?} already exists");
        }
        self.nodes.insert(key.clone(), spec);
        key
    }

    pub fn add_az(&mut self, name: impl Into<String>, az: AZSpec) -> AzId {
        let key = AzId(name.into());
        if self.az.contains_key(&key) {
            panic!("AZ {key:?} already exists");
        }
        self.az.insert(key.clone(), az);
        key
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NodeId(pub String);

impl Display for NodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl NodeId {
    pub fn raw(&self) -> &String {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct NodeSpec {
    pub container_specs: Vec<ContainerSpec>,
}

impl NodeSpec {
    pub fn new() -> NodeSpec {
        NodeSpec {
            container_specs: vec![],
        }
    }

    pub fn runs(self, container_spec: &ContainerSpec) -> NodeSpec {
        let mut v = self.clone();
        v.container_specs.push(container_spec.clone());
        v
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AzId(pub String);

#[derive(Debug, Clone)]
pub struct AZSpec {
    pub nodes: Vec<NodeId>,
}

impl AZSpec {
    pub fn new() -> AZSpec {
        AZSpec { nodes: vec![] }
    }
    pub fn contains(self, node: &NodeId) -> AZSpec {
        let mut v = self.clone();
        v.nodes.push(node.clone());
        v
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContainerSpec {
    pub image_ref: String,
    name: Option<String>,
}

impl ContainerSpec {
    // TODO: Normalize image refs
    pub fn new(image_ref: impl Into<String>) -> ContainerSpec {
        ContainerSpec {
            image_ref: image_ref.into(),
            ..Default::default()
        }
    }

    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }

    pub fn named(&self, name: impl Into<String>) -> ContainerSpec {
        let mut s = self.clone();
        s.name = Some(name.into());
        s
    }

    // TODO: awful and will likely break, but good for now
    pub fn image_basename(&self) -> String {
        self.image_ref
            .split('/')
            .last()
            .unwrap()
            .split(':')
            .collect::<Vec<&str>>()
            .first()
            .unwrap()
            .to_string()
    }
}
