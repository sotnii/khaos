use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct TestContext {
    pub(crate) cancellation_token: CancellationToken,
}
