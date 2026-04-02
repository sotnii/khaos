use anyhow::Result;
use khaos::spec::common::postgres;
use khaos::spec::ClusterSpec;
use khaos::test::Test;
use simple_logger::SimpleLogger;

fn main() -> Result<()> {
    // You're free to use any logging implementation
    SimpleLogger::new().init()?;

    let mut s = ClusterSpec::new("patroni_stale_leader");

    let db1 = s.node("db1").with(postgres("postgres:latest"));
    let db2 = s.node("db2").with(postgres("postgres:latest"));

    s.az("az1").with(db1).with(db2);

    Test::new("patroni_stale_leader", s).run(move |ctx| {
        println!("{:#?}", ctx.spec.get_node("db1").unwrap());
    })?;

    Ok(())
}
