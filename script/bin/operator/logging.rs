//! The log writer that keeps URL paths and the configured secret values out of the log.

use std::io::Write;
use std::sync::OnceLock;

use services::redact::{redact_urls, Redactor};

/// The configured secret values. `main` sets it once the chain config is loaded.
pub(crate) static LOG_REDACTOR: OnceLock<Redactor> = OnceLock::new();

/// Writes log lines with the path and query of every URL redacted. RPC URLs carry API keys, and
/// errors from the HTTP and RPC libraries print the URL that failed. Once `LOG_REDACTOR` is set,
/// the configured secret values are removed as well.
///
/// The `tracing` fmt layer passes each event in one `write` call, so a URL is never split.
pub(crate) struct RedactingWriter<W>(pub(crate) W);

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let line = match LOG_REDACTOR.get() {
            Some(redactor) => redactor.redact(&text),
            None => redact_urls(&text),
        };
        self.0.write_all(line.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::RedactingWriter;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An error with a key-bearing URL, logged the way the operator logs errors, must reach the
    /// output without the key. The JSON layer is the one `main` installs.
    #[test]
    fn log_lines_have_no_url_path() {
        let buffer = SharedBuffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(move || RedactingWriter(writer.clone())),
        );

        tracing::subscriber::with_default(subscriber, || {
            let error = anyhow::anyhow!(
                r#"reqwest::Error {{ kind: Request, url: "https://rpc.example/v2/SECRET_KEY" }}"#
            )
            .context("error sending request for url (https://rpc.example/v2/SECRET_KEY)");
            tracing::error!("Error during `handle_rotate`: {:?}", error);
        });

        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        // The redacted line is still one valid JSON object.
        serde_json::from_str::<serde_json::Value>(&output).expect("log line is not valid JSON");
        assert!(output.contains("handle_rotate"), "{output}");
        assert!(
            output.contains("https://rpc.example/<redacted>"),
            "{output}"
        );
        assert!(!output.contains("SECRET_KEY"), "{output}");
    }
}
