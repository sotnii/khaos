use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NamespaceError {
    #[error("failed to create namespace")]
    NamespaceCreateFailed(#[source] std::io::Error),
    #[error("failed to delete namespace")]
    NamespaceDeleteFailed(#[source] std::io::Error),
}

pub struct NamespaceManager {
    pub namespaces: Vec<Namespace>,
}

/// Manages Linux namespaces
impl NamespaceManager {
    pub fn new() -> NamespaceManager {
        NamespaceManager {
            namespaces: Vec::new(),
        }
    }

    /// Create a netns Linux namespace
    pub fn create(&mut self, name: String) -> Result<(), NamespaceError> {
        let res = Command::new("ip")
            .arg("netns")
            .arg("add")
            .arg(&name)
            .output();
        match res {
            Ok(_) => {
                self.namespaces.push(
                    Namespace {
                        name: name.clone(),
                        path: format!("/run/netns/{}", name),
                    }
                );
                Ok(())
            } ,
            Err(e) => Err(NamespaceError::NamespaceCreateFailed(e)),
        }
    }
    
    /// Deletes all registered namespace
    pub fn teardown(&mut self) -> Result<(), NamespaceError> {
        while let Some(ns) = self.namespaces.pop() {
            self.delete(ns.name)?;
        }
        Ok(())
    }

    fn delete(&mut self, name: String) -> Result<(), NamespaceError> {
        let res = Command::new("ip").arg("del").arg(name).output();
        if let Err(e) = res {
            return Err(NamespaceError::NamespaceDeleteFailed(e));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Namespace {
    pub name: String,
    path: String,
}

impl Namespace {
}

pub struct VethLink {
    if_name: String,
}
