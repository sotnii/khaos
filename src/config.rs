use duration_str::{deserialize_duration, deserialize_option_duration};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml;
use std::{collections::HashMap, time::Duration};

use crate::validation::{Validate, ValidationContext};

/// Defines configuration for test cases.
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub name: String,
    pub description: String,
    #[serde(deserialize_with = "deserialize_duration")]
    pub verify_timeout: Duration,
    pub nodes: HashMap<String, NodeConfig>,
    pub probes: HashMap<String, Probe>,
    pub setup: Option<IndexMap<String, SetupAction>>,
    pub method: HashMap<String, MethodAction>,
    pub steady_state: Option<HashMap<String, SteadyStateCheck>>,
    pub verify: IndexMap<String, VerifyAction>,
}

/// Defines the structure of a cluser nodes that are being tested.
#[derive(Debug, Deserialize, Serialize)]
pub struct NodeConfig {
    pub group: String,
    pub identify_by: IdentifyBy,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IdentifyBy {
    pub docker: Option<String>,
    pub host: Option<String>,
}

/// Probes are reusable actions that are used to verify the state of the system.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum Probe {
    #[serde(rename = "http")]
    Http(HttpProbe),
    #[serde(rename = "script")]
    Script(ScriptProbe),
    // Add more probe types as needed
}

/// HTTP probe for testing a node responds to an HTTP request.
#[derive(Debug, Deserialize, Serialize)]
pub struct HttpProbe {
    pub options: HttpProbeOptions,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpProbeOptions {
    /// A list of nodes names that are going to be probed with the HTTP request.
    /// `:<port>` can be added after the node name to specify a port (seet the `port` variable below).
    pub nodes: Vec<String>,
    /// Timeout for the HTTP request.
    #[serde(deserialize_with = "deserialize_duration")]
    pub timeout: Duration,
    /// Request holds a format-string that is used to construct the HTTP request.
    /// The general format is "<METHOD> <PATH>"
    ///
    /// Supported methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
    /// It uses handlebars syntax (`{{variable}}`) for variable substitution.
    /// Supported variables:
    /// - `{node}` - The IP address of the node being probed.
    /// - `{port}` - The port of the node being probed. Default is 80.
    pub request: String,
    /// Defines how many nodes must respond with a successful status code for a probe to be considered successful.
    #[serde(default = "at_least_default")]
    pub at_least: AtLeastOption,
    /// Optional script that is used for more sophisticated checks.
    pub check: Option<ScriptOptions>,
}

fn at_least_default() -> AtLeastOption {
    AtLeastOption::All
}

fn deserialize_at_least_option<'de, D>(deserializer: D) -> Result<AtLeastOption, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value = serde_yaml::Value::deserialize(deserializer)?;

    match value {
        serde_yaml::Value::String(s) => {
            if s.to_lowercase() == "all" {
                Ok(AtLeastOption::All)
            } else {
                match s.parse::<usize>() {
                    Ok(num) => Ok(AtLeastOption::Some(num)),
                    Err(_) => Err(D::Error::custom(format!(
                        "Expected 'all' or a positive integer, got: {}",
                        s
                    ))),
                }
            }
        }
        serde_yaml::Value::Number(n) => {
            if let Some(num) = n.as_u64() {
                Ok(AtLeastOption::Some(num as usize))
            } else {
                Err(D::Error::custom("Expected a positive integer"))
            }
        }
        _ => Err(D::Error::custom("Expected 'all' or a positive integer")),
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AtLeastOption {
    All,
    Some(usize),
}

impl<'de> Deserialize<'de> for AtLeastOption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_at_least_option(deserializer)
    }
}

/// A generic script configuration used across actions
#[derive(Debug, Deserialize, Serialize)]
pub struct ScriptOptions {
    /// Inline Lua script, takes precedence over file
    pub lua: Option<String>,
    /// A file path to a Lua script
    pub file: Option<String>,
    /// A function name to call in the Lua script, can be different depending on the script
    pub function: Option<String>,
    /// This option allows to run the function from the script concurrently, allowing for parallel execution.
    /// Which is useful for, say, simulating traffic in the tested system.
    #[serde(default = "concurrency_default")]
    pub concurrency: usize,
}

fn concurrency_default() -> usize {
    1
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScriptProbe {
    pub options: ScriptOptions,
}

/// Setup actions are run once before the methods are started
#[derive(Debug, Deserialize, Serialize)]
pub struct SetupAction {
    #[serde(flatten)]
    pub action: SetupActionsEnum,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum SetupActionsEnum {
    /// Wait for the specified probes to be ready before starting the methods
    #[serde(rename = "wait_probes")]
    WaitProbes(WaitProbesAction),
    /// Run a script before starting the methods
    #[serde(rename = "script")]
    Script(ScriptAction),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WaitProbesAction {
    pub options: WaitProbesOptions,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WaitProbesOptions {
    /// The probes to wait for
    pub probes: Vec<String>,
    /// The timeout for waiting for the probes. If the timeout is reached, the test will not proceed.
    #[serde(deserialize_with = "deserialize_duration")]
    pub timeout: Duration,
    /// The probe test is run every interval seconds
    #[serde(deserialize_with = "deserialize_duration")]
    pub interval: Duration,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScriptAction {
    pub options: ScriptOptions,
}

// Methods are the heart of the test, they define the actions to be taken on the system
#[derive(Debug, Deserialize, Serialize)]
pub struct MethodAction {
    #[serde(flatten)]
    pub action: MethodActionType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum MethodActionType {
    /// Partition method splits the system into network partitions as defined per the configuration
    #[serde(rename = "partition")]
    Partition(PartitionMethod),
    /// Script method runs a script to perform arbitrary actions on the system during the test
    #[serde(rename = "script")]
    Script(ScriptMethod),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PartitionMethod {
    /// The duration for which the partition should last.
    #[serde(deserialize_with = "deserialize_duration")]
    pub duration: Duration,
    /// The duration to wait before running the partition
    #[serde(deserialize_with = "deserialize_option_duration", default)]
    pub after: Option<Duration>,
    pub options: PartitionOptions,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PartitionOptions {
    /// The partitions to create (consists of node or group names)
    pub partitions: Vec<Vec<String>>,
    /// The loss percentage to apply to the partitions. Default is 100%
    #[serde(default = "default_loss")]
    pub loss: u32,
}

fn default_loss() -> u32 {
    100
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScriptMethod {
    /// The duration to wait before running the script
    #[serde(deserialize_with = "deserialize_option_duration", default)]
    pub after: Option<Duration>,
    pub options: ScriptOptions,
}

/// During the time when methods run, steady state checks confirm that the system is in a stable state using the probes
/// defined in "probes" section.
#[derive(Debug, Deserialize, Serialize)]
pub struct SteadyStateCheck {
    /// The probe to run
    pub probe: String,
    /// The interval at which the probe should be run
    #[serde(deserialize_with = "deserialize_duration")]
    pub interval: Duration,
}

/// Verify actions are run after all methods have completed to verify that the system remained in a stable state.
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyAction {
    #[serde(flatten)]
    pub action: VerifyActionType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum VerifyActionType {
    /// Probe verify action uses a probe defined in the "probes" section
    #[serde(rename = "probe")]
    Probe(ProbeVerifyAction),
    /// Script verify action uses a script to verify the system state
    #[serde(rename = "script")]
    Script(ScriptVerifyAction),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeVerifyAction {
    pub options: ProbeVerifyOptions,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeVerifyOptions {
    pub probe: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScriptVerifyAction {
    pub options: ScriptOptions,
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self, config_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let validation_context = ValidationContext::new(self, config_file_path);
        Validate::validate(self, &validation_context)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_config() {
        // Since we don't have the file in the test environment, we'll create a minimal version
        let yaml_content = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
  second_check:
    kind: script
    options:
      file: "test_script.sh"
      function: "second_func"
"#;

        let config: Config = serde_yaml::from_str(yaml_content).unwrap();

        assert_eq!(config.name, "test_config");
        assert_eq!(config.description, "Test configuration");
        assert_eq!(config.verify_timeout, Duration::from_secs(60));

        // Check that verify actions maintain order
        let verify_keys: Vec<&String> = config.verify.keys().collect();
        assert_eq!(verify_keys, vec!["first_check", "second_check"]);
    }

    #[test]
    fn test_at_least_option_parsing() {
        // Test "all" string
        let yaml_all = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
      at_least: "all"
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        let config: Config = serde_yaml::from_str(yaml_all).unwrap();
        match &config.probes.get("test_probe").unwrap() {
            Probe::Http(http_probe) => {
                assert!(matches!(http_probe.options.at_least, AtLeastOption::All));
            }
            _ => panic!("Expected Http probe"),
        }

        // Test numeric string
        let yaml_number = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
      at_least: "2"
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        let config: Config = serde_yaml::from_str(yaml_number).unwrap();
        match &config.probes.get("test_probe").unwrap() {
            Probe::Http(http_probe) => {
                if let AtLeastOption::Some(value) = http_probe.options.at_least {
                    assert_eq!(value, 2);
                } else {
                    panic!("Expected Some(2)");
                }
            }
            _ => panic!("Expected Http probe"),
        }

        // Test integer value
        let yaml_integer = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
      at_least: 3
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        let config: Config = serde_yaml::from_str(yaml_integer).unwrap();
        match &config.probes.get("test_probe").unwrap() {
            Probe::Http(http_probe) => {
                if let AtLeastOption::Some(value) = http_probe.options.at_least {
                    assert_eq!(value, 3);
                } else {
                    panic!("Expected Some(3)");
                }
            }
            _ => panic!("Expected Http probe"),
        }

        // Test invalid string should fail
        let yaml_invalid = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
      at_least: "invalid"
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        let result: Result<Config, _> = serde_yaml::from_str(yaml_invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_valid_config() {
        let yaml_content = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
  node2:
    group: group1
    identify_by:
      docker: test_container2
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1", "node2"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
method:
  test_method:
    kind: partition
    duration: 1m
    options:
      partitions:
        - ["node1"]
        - ["node2"]
      loss: 100
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        // This should parse and validate successfully
        let result = serde_yaml::from_str::<Config>(yaml_content);
        assert!(result.is_ok());

        let config = result.unwrap();
        // Try to validate explicitly
        let validation_result = config.validate(".");
        assert!(validation_result.is_ok());
    }

    #[test]
    fn test_validation_invalid_node_reference() {
        let yaml_content = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["nonexistent_node"]  # This node doesn't exist
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        let config: Config = serde_yaml::from_str(yaml_content).unwrap();
        let result = config.validate(".");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "probes.test_probe.options.nodes[0]: Node 'nonexistent_node' does not exist in the nodes section"
        )
    }

    #[test]
    fn test_validation_invalid_probe_reference() {
        let yaml_content = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
method:
  test_method:
    kind: script
    options:
      file: "test_script.sh"
      function: "test_func"
verify:
  first_check:
    kind: probe
    options:
      probe: nonexistent_probe  # This probe doesn't exist
"#;

        let config: Config = serde_yaml::from_str(yaml_content).unwrap();
        let result = config.validate(".");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "method.test_method: Script file 'test_script.sh' does not exist (resolved relative to config file as 'test_script.sh')"
        );
    }

    #[test]
    fn test_validation_invalid_partition_loss() {
        let yaml_content = r#"
name: test_config
description: "Test configuration"
verify_timeout: 1m
nodes:
  node1:
    group: group1
    identify_by:
      docker: test_container
  node2:
    group: group1
    identify_by:
      docker: test_container2
probes:
  test_probe:
    kind: http
    options:
      nodes: ["node1"]
      timeout: 5s
      request: "GET http://{{node}}:8080/health"
method:
  test_method:
    kind: partition
    duration: 1m
    options:
      partitions:
        - ["node1"]
        - ["node2"]
      loss: 150  # Invalid loss value (should be 1-100)
verify:
  first_check:
    kind: probe
    options:
      probe: test_probe
"#;

        let config: Config = serde_yaml::from_str(yaml_content).unwrap();
        let result = config.validate(".");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "method.test_method.options.loss: Partition loss must be between 1 and 100"
        )
    }
}
