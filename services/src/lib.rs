pub mod input;
pub mod postgres;
pub mod types;

pub use timeout::Timeout;

mod timeout {
    use std::future::Future;
    use std::time::Duration;
    use tokio::time::{timeout, Timeout as TimeoutFuture};

    pub trait Timeout: Sized {
        fn timeout(self, duration: Duration) -> TimeoutFuture<Self>;
    }

    impl<T: Future> Timeout for T {
        fn timeout(self, duration: Duration) -> TimeoutFuture<Self> {
            timeout(duration, self)
        }
    }
}
