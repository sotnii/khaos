mod config;

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <config_file>", args[0]);
        process::exit(1);
    }

    let config_path = &args[1];

    match config::Config::load_from_file(config_path) {
        Ok(config) => {
            println!("Configuration loaded successfully!");
            println!("Name: {}", config.name);
            println!("Description: {}", config.description);

            println!("Verify timeout: {:?}", config.verify_timeout);

            println!("\nNodes:");
            for (name, node_config) in &config.nodes {
                println!(
                    "  {}: group={}, identify_by={:?}",
                    name, node_config.group, node_config.identify_by
                );
            }

            println!("\nProbes:");
            for (name, probe) in &config.probes {
                println!("{}: {:?}", name, probe);
            }

            if let Some(setup) = &config.setup {
                println!("\nSetup actions:");
                for (name, action) in setup {
                    println!("  {}: {:?}", name, action);
                }
            }

            println!("\nMethod actions:");
            for (name, action) in &config.method {
                println!("  {}: {:?}", name, action);
            }

            if let Some(steady_state) = &config.steady_state {
                println!("\nSteady state checks:");
                for (name, check) in steady_state {
                    println!("  {}: {:?}", name, check);
                }
            }

            println!("\nVerify actions (in order):");
            for (name, action) in &config.verify {
                println!("  {}: {:?}", name, action);
            }

            println!("\nConfiguration parsed successfully!");
        }
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            process::exit(1);
        }
    }
}
