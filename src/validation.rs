use std::fmt::Display;
use std::path::Path;

use crate::config::{
    Config, HttpProbe, HttpProbeOptions, IdentifyBy, MethodAction, MethodActionType, NodeConfig,
    PartitionMethod, PartitionOptions, Probe, ProbeVerifyAction, ProbeVerifyOptions, ScriptAction,
    ScriptMethod, ScriptOptions, ScriptProbe, ScriptVerifyAction, SetupAction, SetupActionsEnum,
    SteadyStateCheck, VerifyAction, VerifyActionType, WaitProbesAction, WaitProbesOptions,
};

/// Trait for validating configuration structures
pub trait Validate {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError>;
}

/// Context for validation that contains references to the config and other data
pub struct ValidationContext<'a> {
    pub config: &'a Config,
    pub current_path: String,
    pub config_file_path: String,
}

impl<'a> ValidationContext<'a> {
    pub fn new(config: &'a Config, file_path: &str) -> Self {
        Self {
            config,
            current_path: String::new(),
            config_file_path: file_path.to_string(),
        }
    }

    pub fn with_path(&self, segment: &str) -> ValidationContext<'_> {
        let mut new_path = self.current_path.clone();
        if !new_path.is_empty() {
            new_path.push('.');
        }
        new_path.push_str(segment);

        ValidationContext {
            config: self.config,
            current_path: new_path,
            config_file_path: self.config_file_path.clone(),
        }
    }
}

/// Error type for validation errors
#[derive(Debug)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

impl ValidationError {
    pub fn new(path: &str, message: &str) -> Self {
        Self {
            path: path.to_string(),
            message: message.to_string(),
        }
    }
}

impl Validate for Config {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Validate nodes - check that all referenced groups exist
        let mut groups = std::collections::HashSet::new();
        for (node_name, node_config) in &self.nodes {
            let node_ctx = ctx.with_path(&format!("nodes.{}", node_name));

            // Add the group to our set of known groups
            groups.insert(&node_config.group);

            // Validate the node config itself
            node_config.validate(&node_ctx)?;
        }

        // Validate probes
        for (probe_name, probe) in &self.probes {
            let probe_ctx = ctx.with_path(&format!("probes.{}", probe_name));
            probe.validate(&probe_ctx)?;
        }

        // Validate setup actions
        if let Some(setup) = &self.setup {
            for (action_name, action) in setup {
                let action_ctx = ctx.with_path(&format!("setup.{}", action_name));
                action.validate(&action_ctx)?;
            }
        }

        // Validate method actions
        for (method_name, method) in &self.method {
            let method_ctx = ctx.with_path(&format!("method.{}", method_name));
            method.validate(&method_ctx)?;
        }

        // Validate steady state checks
        if let Some(steady_state) = &self.steady_state {
            for (check_name, check) in steady_state {
                let check_ctx = ctx.with_path(&format!("steady_state.{}", check_name));
                check.validate(&check_ctx)?;
            }
        }

        // Validate verify actions
        for (verify_name, verify_action) in &self.verify {
            let verify_ctx = ctx.with_path(&format!("verify.{}", verify_name));
            verify_action.validate(&verify_ctx)?;
        }

        Ok(())
    }
}

impl Validate for NodeConfig {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.identify_by.validate(ctx)
    }
}

impl Validate for IdentifyBy {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Check that exactly one of docker or host is set
        let mut count = 0;
        if self.docker.is_some() {
            count += 1;
        }
        if self.host.is_some() {
            count += 1;
            // Validate hostname format (<host>:<port>)
            if let Some(host_value) = &self.host {
                if let Some(colon_pos) = host_value.rfind(':') {
                    let _host_part = &host_value[..colon_pos]; // Keep for future use if needed
                    let port_part = &host_value[colon_pos + 1..];

                    // Validate port is numeric
                    if port_part.parse::<u16>().is_err() {
                        return Err(ValidationError::new(
                            &ctx.current_path,
                            &format!(
                                "Invalid port in host '{}'. Port must be a number between 1 and 65535",
                                host_value
                            ),
                        ));
                    }
                }
            }
        }

        if count != 1 {
            return Err(ValidationError::new(
                &ctx.current_path,
                "Exactly one of docker or host must be specified in identify_by",
            ));
        }

        Ok(())
    }
}

impl Validate for Probe {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        match self {
            Probe::Http(http_probe) => http_probe.validate(ctx),
            Probe::Script(script_probe) => script_probe.validate(ctx),
        }
    }
}

impl Validate for HttpProbe {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for HttpProbeOptions {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Validate that all nodes in the nodes list are valid
        for (i, node_spec) in self.nodes.iter().enumerate() {
            let node_ctx = ctx.with_path(&format!("options.nodes[{}]", i));

            // Extract node name (before optional :port)
            let node_name = if let Some(pos) = node_spec.find(':') {
                let host_part = &node_spec[..pos];
                let port_part = &node_spec[pos + 1..];

                // Validate that the port is valid (numeric)
                if port_part.parse::<u16>().is_err() {
                    return Err(ValidationError::new(
                        &node_ctx.current_path,
                        &format!(
                            "Invalid port '{}' in node specification '{}'. Port must be a number between 1 and 65535",
                            port_part, node_spec
                        ),
                    ));
                }

                host_part
            } else {
                node_spec
            };

            // Check if the node exists in the config
            if !ctx.config.nodes.contains_key(node_name) {
                return Err(ValidationError::new(
                    &node_ctx.current_path,
                    &format!("Node '{}' does not exist in the nodes section", node_name),
                ));
            }
        }

        // Validate the script check if present
        if let Some(check) = &self.check {
            let check_ctx = ctx.with_path("options.check");
            check.validate(&check_ctx)?;
        }

        Ok(())
    }
}

impl Validate for ScriptProbe {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for ScriptOptions {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        if self.file.is_none() && self.lua.is_none() {
            return Err(ValidationError::new(
                &ctx.current_path,
                "Either a `file` or `lua` option should be present",
            ));
        }
        if self.file.is_some() && self.lua.is_some() {
            return Err(ValidationError::new(
                &ctx.current_path,
                "Cannot have both `file` and `lua` options set.",
            ));
        }

        // If a file is specified, validate that it exists (relative to config file)
        if let Some(file) = &self.file {
            // First check if it's an absolute path
            let path = Path::new(file);
            if path.is_absolute() {
                if !path.exists() {
                    return Err(ValidationError::new(
                        &ctx.current_path,
                        &format!("Script file '{}' does not exist", file),
                    ));
                }
            } else {
                // It's a relative path, so we need to resolve it relative to the config file
                // Get the directory of the config file
                let config_dir = Path::new(&ctx.config_file_path)
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| Path::new(".").to_path_buf());

                // Join the config directory with the relative file path
                let full_path = config_dir.join(file);

                if !full_path.exists() {
                    return Err(ValidationError::new(
                        &ctx.current_path,
                        &format!(
                            "Script file '{}' does not exist (resolved relative to config file as '{}')",
                            file,
                            full_path.display()
                        ),
                    ));
                }
            }
        }

        // TODO: Check that the specified function actually exists in the script

        Ok(())
    }
}

impl Validate for SetupAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.action.validate(ctx)
    }
}

impl Validate for SetupActionsEnum {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        match self {
            SetupActionsEnum::WaitProbes(wait_probes) => wait_probes.validate(ctx),
            SetupActionsEnum::Script(script_action) => script_action.validate(ctx),
        }
    }
}

impl Validate for WaitProbesAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for WaitProbesOptions {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Validate that all probe names in the probes list exist in the config
        for (i, probe_name) in self.probes.iter().enumerate() {
            let probe_ctx = ctx.with_path(&format!("options.probes[{}]", i));

            if !ctx.config.probes.contains_key(probe_name) {
                return Err(ValidationError::new(
                    &probe_ctx.current_path,
                    &format!(
                        "Probe '{}' does not exist in the probes section",
                        probe_name
                    ),
                ));
            }
        }

        Ok(())
    }
}

impl Validate for ScriptAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for MethodAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.action.validate(ctx)
    }
}

impl Validate for MethodActionType {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        match self {
            MethodActionType::Partition(partition_method) => partition_method.validate(ctx),
            MethodActionType::Script(script_method) => script_method.validate(ctx),
        }
    }
}

impl Validate for PartitionMethod {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for PartitionOptions {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Validate partition loss is between 1 and 100
        if self.loss < 1 || self.loss > 100 {
            return Err(ValidationError::new(
                &ctx.with_path("options.loss").current_path,
                "Partition loss must be between 1 and 100",
            ));
        }

        // Validate that all partitions contain valid node names or group names
        for (i, partition) in self.partitions.iter().enumerate() {
            for (j, item) in partition.iter().enumerate() {
                let item_ctx = ctx.with_path(&format!("options.partitions[{}][{}]", i, j));

                // Check if it's a node name
                if ctx.config.nodes.contains_key(item) {
                    continue; // Valid node name
                }

                // Check if it's a group name (a group exists if at least one node has that group name)
                let group_exists = ctx.config.nodes.values().any(|node| node.group == *item);

                if !group_exists {
                    return Err(ValidationError::new(
                        &item_ctx.current_path,
                        &format!(
                            "Item '{}' in partition is neither a valid node name nor a group name",
                            item
                        ),
                    ));
                }
            }
        }

        Ok(())
    }
}

impl Validate for ScriptMethod {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for SteadyStateCheck {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Validate that the probe exists in the config
        if !ctx.config.probes.contains_key(&self.probe) {
            return Err(ValidationError::new(
                &ctx.with_path("probe").current_path,
                &format!(
                    "Probe '{}' does not exist in the probes section",
                    self.probe
                ),
            ));
        }

        Ok(())
    }
}

impl Validate for VerifyAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.action.validate(ctx)
    }
}

impl Validate for VerifyActionType {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        match self {
            VerifyActionType::Probe(probe_verify) => probe_verify.validate(ctx),
            VerifyActionType::Script(script_verify) => script_verify.validate(ctx),
        }
    }
}

impl Validate for ProbeVerifyAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}

impl Validate for ProbeVerifyOptions {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        // Validate that the probe exists in the config
        if !ctx.config.probes.contains_key(&self.probe) {
            return Err(ValidationError::new(
                &ctx.with_path("options.probe").current_path,
                &format!(
                    "Probe '{}' does not exist in the probes section",
                    self.probe
                ),
            ));
        }

        Ok(())
    }
}

impl Validate for ScriptVerifyAction {
    fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
        self.options.validate(ctx)
    }
}
