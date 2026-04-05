use anyhow::Result;
use khaos::spec::common::postgres;
use khaos::spec::{AZSpec, ClusterSpec, NodeSpec};
use khaos::testing::Test;
use std::time::Duration;
use tokio;
use tokio::time::sleep;
use tracing::Level;

#[tokio::main]
async fn main() -> Result<()> {
    // The library emits tracing events; callers choose how to format and display them.
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let mut s = ClusterSpec::new("patroni_stale_leader");

    // TODO: reuse node specs with NodeSpec::from(name, other_spec)

    let pg = postgres("docker.io/library/postgres:latest");
    let db1 = s.add_node("db1", NodeSpec::new().runs(&pg.named("pg1")));
    let db2 = s.add_node("db2", NodeSpec::new().runs(&pg));

    let _az1 = s.add_az("az1", AZSpec::new().contains(&db1).contains(&db2));

    Test::new("patroni_stale_leader", s)
        .run(async move |_ctx| {
            sleep(Duration::from_secs(1000)).await;
            Ok(())
        })
        .await?;

    Ok(())
}
