//! Remove secrets from text before it is logged.
//!
//! RPC provider URLs carry the API key in the path or in the query string, and library errors
//! (`reqwest`, alloy transports, the Avail client) print the URL they failed on.

/// Replace the path, the query string and the userinfo of every URL in `text` with `<redacted>`.
/// The scheme and the host stay, so the log still shows which endpoint failed.
///
/// Limits: a key inside the host name stays, and a password that contains a quote, a backslash
/// or a slash is cut at that character. Register such values with [`Redactor::add_secret`].
pub fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(pos) = rest.find("://") {
        let after_scheme = &rest[pos + 3..];
        let url_end = after_scheme.find(is_url_end).unwrap_or(after_scheme.len());
        let url = &after_scheme[..url_end];

        let authority_end = url.find(['/', '?', '#']).unwrap_or(url.len());
        let (authority, tail) = url.split_at(authority_end);
        let host = match authority.rsplit_once('@') {
            Some((_userinfo, host)) => host,
            None => authority,
        };

        out.push_str(&rest[..pos + 3]);
        out.push_str(host);
        if tail == "/" {
            out.push('/');
        } else if !tail.is_empty() {
            out.push_str("/<redacted>");
        }

        rest = &after_scheme[url_end..];
    }

    out.push_str(rest);
    out
}

/// A URL in a log line ends at whitespace, at a double quote, or at the backslash of an escaped
/// quote. Other characters stay part of the URL: redacting too much is harmless, too little is a
/// leak.
fn is_url_end(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\\')
}

/// Secret values shorter than this are not registered, because replacing a short string would
/// remove unrelated text from the log.
const MIN_SECRET_LENGTH: usize = 8;

/// Redacts URLs by pattern, and also every occurrence of the secret values it was given. It is
/// made for JSON log lines: the values are matched in their JSON-escaped form.
///
/// The pattern alone misses a secret that is printed without its URL, for example the `Debug`
/// output of a parsed URL (`Url { path: "/<key>" }`) or a bare API key. The known values close
/// that gap.
/// One path segment or query value is registered alone only from this length. A shorter part is
/// more likely a common word, such as a network name, than a key.
const MIN_URL_PART_LENGTH: usize = 16;

#[derive(Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// Register a secret value, such as an API key or a private key.
    pub fn add_secret(&mut self, value: &str) {
        self.add_secret_of_length(value, MIN_SECRET_LENGTH);
    }

    fn add_secret_of_length(&mut self, value: &str, min_length: usize) {
        for secret in [value, value.trim_start_matches("0x")] {
            // A value of digits only could equal a JSON number, such as a chain id. Replacing a
            // number would make the log line invalid JSON, so such a value is not registered.
            if secret.len() < min_length || secret.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            // The log line is JSON, so the value appears there in its JSON-escaped form.
            let quoted = serde_json::Value::from(secret).to_string();
            let escaped = &quoted[1..quoted.len() - 1];
            if !self.secrets.iter().any(|s| s == escaped) {
                self.secrets.push(escaped.to_string());
            }
        }
    }

    /// Register the parts of a URL that can carry a key: the userinfo, the path and the query.
    pub fn add_url(&mut self, url: &str) {
        let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
        let authority_end = after_scheme
            .find(['/', '?', '#'])
            .unwrap_or(after_scheme.len());
        let (authority, tail) = after_scheme.split_at(authority_end);
        if let Some((userinfo, _host)) = authority.rsplit_once('@') {
            self.add_secret(userinfo);
            // The password can also be printed alone, for example in an error body.
            for part in userinfo.split(':') {
                self.add_secret(part);
            }
        }
        let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
        self.add_secret(path);
        self.add_secret(query);
        // A key can also be printed alone, without the rest of the path or the query.
        for part in path.split('/').chain(query.split(['&', '='])) {
            self.add_secret_of_length(part, MIN_URL_PART_LENGTH);
        }
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = redact_urls(text);
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), "<redacted>");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_urls, Redactor};

    #[test]
    fn redacts_key_in_path() {
        assert_eq!(
            redact_urls("error for url (https://lb.drpc.live/ethereum/SECRET): timeout"),
            "error for url (https://lb.drpc.live/<redacted> timeout"
        );
    }

    #[test]
    fn redacts_key_in_query_and_userinfo() {
        assert_eq!(
            redact_urls("GET https://api.example.com?key=SECRET failed"),
            "GET https://api.example.com/<redacted> failed"
        );
        assert_eq!(
            redact_urls("postgres://user:SECRET@db.example.com:5432/name"),
            "postgres://db.example.com:5432/<redacted>"
        );
    }

    #[test]
    fn redacts_debug_and_json_escaped_output() {
        assert_eq!(
            redact_urls(r#"reqwest::Error { url: "wss://rpc.example/ws/SECRET", kind: Request }"#),
            r#"reqwest::Error { url: "wss://rpc.example/<redacted>", kind: Request }"#
        );
        assert_eq!(
            redact_urls(r#"{"message":"url: \"http://127.0.0.1:9/SECRET\" refused"}"#),
            r#"{"message":"url: \"http://127.0.0.1:9/<redacted>\" refused"}"#
        );
    }

    #[test]
    fn single_quote_does_not_end_a_url() {
        assert_eq!(
            redact_urls("https://h/a'SECRET next"),
            "https://h/<redacted> next"
        );
    }

    #[test]
    fn redactor_removes_known_values_without_a_url() {
        let mut redactor = Redactor::default();
        redactor.add_url("https://lb.drpc.live/ethereum/SECRETKEY0123456?token=QUERYSECRET012345");
        redactor.add_secret("0xPRIVATEKEY123");
        redactor.add_secret("short");

        // The `Debug` output of a parsed URL prints the path without the scheme.
        assert_eq!(
            redactor.redact(r#"Url { host: "lb.drpc.live", path: "/ethereum/SECRETKEY0123456", query: Some("token=QUERYSECRET012345") }"#),
            r#"Url { host: "lb.drpc.live", path: "<redacted>", query: Some("<redacted>") }"#
        );
        assert_eq!(
            redactor.redact("key PRIVATEKEY123 here"),
            "key <redacted> here"
        );
        assert_eq!(redactor.redact("a short word"), "a short word");
        assert_eq!(redactor.redact("chain ethereum"), "chain ethereum");
        assert_eq!(
            redactor.redact("key SECRETKEY0123456 alone"),
            "key <redacted> alone"
        );
        assert_eq!(
            redactor.redact("token QUERYSECRET012345 alone"),
            "token <redacted> alone"
        );
        assert_eq!(
            redactor.redact("GET https://other.example/v1/OTHERKEY"),
            "GET https://other.example/<redacted>"
        );
    }

    #[test]
    fn redactor_handles_passwords_escapes_and_numbers() {
        let mut redactor = Redactor::default();
        redactor.add_url("https://alice:SUPERSECRET@rpc.example");
        redactor.add_secret(r#"LONG"SECRET"#);
        redactor.add_secret("12345678");

        assert_eq!(
            redactor.redact("invalid password SUPERSECRET"),
            "invalid password <redacted>"
        );
        // In a JSON log line the quote inside the secret is escaped.
        assert_eq!(
            redactor.redact(r#"{"message":"key LONG\"SECRET"}"#),
            r#"{"message":"key <redacted>"}"#
        );
        // A numeric value is left alone, so a JSON number stays a number.
        assert_eq!(
            redactor.redact(r#"{"chain_id":12345678}"#),
            r#"{"chain_id":12345678}"#
        );
    }

    #[test]
    fn redacts_every_url_and_keeps_other_text() {
        assert_eq!(
            redact_urls("a http://h1/K1 b http://h2/K2 c"),
            "a http://h1/<redacted> b http://h2/<redacted> c"
        );
        assert_eq!(redact_urls("no url here: 0xabc"), "no url here: 0xabc");
        assert_eq!(
            redact_urls("http://localhost:9944/"),
            "http://localhost:9944/"
        );
        assert_eq!(
            redact_urls("http://localhost:9944"),
            "http://localhost:9944"
        );
    }
}
