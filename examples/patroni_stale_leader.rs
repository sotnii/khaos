use std::io;
use anyhow::Result;
use khaos::spec::common::postgres;
use khaos::spec::{AZSpec, ClusterSpec, NodeSpec};
use khaos::test::Test;
use simple_logger::SimpleLogger;

fn main() -> Result<()> {
    // You're free to use any logging implementation
    SimpleLogger::new().init()?;

    let mut s = ClusterSpec::new("patroni_stale_leader");

    // TODO: reuse node specs with NodeSpec::from(name, other_spec)

    let pg = postgres("postgres:latest");
    let db1 = s.add_node(
        "db1",
        NodeSpec::new()
            .runs(&pg)
    );
    let db2 = s.add_node(
        "db2",
        NodeSpec::new()
            .runs(&pg)
    );

    let _az1 = s.add_az(
        "az1",
        AZSpec::new()
            .contains(&db1)
            .contains(&db2)
    );

    Test::new("patroni_stale_leader", s).run(move |_ctx| {
        let mut input = String::new();
        println!("Stopped for debug, press enter to end the test and run teardown...");
        io::stdin().read_line(&mut input).unwrap();
    })?;

    Ok(())
}
