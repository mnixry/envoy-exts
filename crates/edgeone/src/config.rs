use anyhow::{Context as _, Result};
use serde::Deserialize;
use std::{env::VarError, time::Duration};

const DEFAULT_API_ENDPOINT: &str = "teo.tencentcloudapi.com";

#[derive(Clone, Debug)]
pub(crate) struct ConfigRuntime {
    pub(crate) secret_id: String,
    pub(crate) secret_key: String,
    pub(crate) api_host: String,
    pub(crate) api_cluster: Option<String>,
    pub(crate) cache_ttl: Duration,
    pub(crate) timeout: Duration,
    pub(crate) region: Option<String>,
}

/// Plugin configuration JSON.
#[derive(Debug, Deserialize)]
pub(crate) struct EdgeOneConfig {
    pub(crate) secret_id: String,
    pub(crate) secret_key: String,
    #[serde(default = "default_api_endpoint")]
    pub(crate) api_endpoint: String,
    #[serde(default)]
    pub(crate) api_cluster: Option<String>,
    #[serde(default = "default_cache_size")]
    pub(crate) cache_size: usize,
    #[serde(default = "default_cache_ttl")]
    pub(crate) cache_ttl: u64,
    #[serde(default = "default_timeout")]
    pub(crate) timeout: u64,
    #[serde(default)]
    pub(crate) region: Option<String>,
}

fn default_api_endpoint() -> String {
    DEFAULT_API_ENDPOINT.to_string()
}

fn default_cache_size() -> usize {
    1000
}

fn default_cache_ttl() -> u64 {
    60 * 60
}

fn default_timeout() -> u64 {
    5
}

pub(crate) fn load_config<R: AsRef<[u8]>>(raw: R) -> Result<(ConfigRuntime, usize)> {
    let EdgeOneConfig {
        secret_id,
        secret_key,
        api_endpoint,
        api_cluster,
        cache_size,
        cache_ttl,
        timeout,
        region,
    } = serde_json::from_slice(raw.as_ref())
        .context("failed to parse plugin configuration JSON")?;

    let env_mapper = |name: &str| match std::env::var(name) {
        Ok(v) => Ok(v),
        Err(VarError::NotPresent) => Ok(String::new()),
        Err(e) => anyhow::bail!("failed to get environment variable {name}: {e}"),
    };

    Ok((
        ConfigRuntime {
            secret_id: expand_env(&secret_id, env_mapper)?,
            secret_key: expand_env(&secret_key, env_mapper)?,
            api_host: expand_env(&api_endpoint, env_mapper)?,
            api_cluster: api_cluster
                .map(|v| expand_env(&v, env_mapper))
                .transpose()?,
            cache_ttl: Duration::from_secs(cache_ttl),
            timeout: Duration::from_secs(timeout),
            region,
        },
        cache_size,
    ))
}

fn expand_env(s: &str, mapping: impl Fn(&str) -> Result<String>) -> Result<String> {
    // Mirrors Go's os.Expand/os.ExpandEnv parsing semantics.
    // See: $GOROOT/src/os/env.go (Expand, getShellName).
    let bytes = s.as_bytes();
    let mut buf: Option<Vec<u8>> = None;

    // ${} is all ASCII, so bytes are fine for this operation.
    let mut i = 0usize;
    let mut j = 0usize;
    while j < bytes.len() {
        if bytes[j] == b'$' && j + 1 < bytes.len() {
            if buf.is_none() {
                buf = Some(Vec::with_capacity(2 * bytes.len()));
            }
            let out = buf.as_mut().expect("buf is always Some here");
            out.extend_from_slice(&bytes[i..j]);

            let (name_bytes, w) = get_shell_name(&bytes[j + 1..]);
            if name_bytes.is_empty() && w > 0 {
                // Encountered invalid syntax; eat the characters.
            } else if name_bytes.is_empty() {
                // Valid syntax, but $ was not followed by a name. Leave the dollar untouched.
                out.push(b'$');
            } else {
                // `name_bytes` is a slice of the original UTF-8 string, so it's valid UTF-8.
                let name = std::str::from_utf8(name_bytes)
                    .expect("env var name bytes are always valid UTF-8");
                let value = mapping(name)?;
                out.extend_from_slice(value.as_bytes());
            }

            j = j + 1 + w;
            i = j;
            continue;
        }
        j += 1;
    }

    match buf {
        None => Ok(s.to_string()),
        Some(mut out) => {
            out.extend_from_slice(&bytes[i..]);
            Ok(String::from_utf8(out).expect("output is valid UTF-8"))
        }
    }
}

fn is_shell_special_var(c: u8) -> bool {
    matches!(
        c,
        b'*' | b'#'
            | b'$'
            | b'@'
            | b'!'
            | b'?'
            | b'-'
            | b'0'
            | b'1'
            | b'2'
            | b'3'
            | b'4'
            | b'5'
            | b'6'
            | b'7'
            | b'8'
            | b'9'
    )
}

fn is_alpha_num(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

fn get_shell_name(s: &[u8]) -> (&[u8], usize) {
    match () {
        _ if s[0] == b'{' => {
            if s.len() > 2 && is_shell_special_var(s[1]) && s[2] == b'}' {
                return (&s[1..2], 3);
            }
            // Scan to closing brace
            for i in 1..s.len() {
                if s[i] == b'}' {
                    if i == 1 {
                        return (&[], 2); // Bad syntax; eat "${}"
                    }
                    return (&s[1..i], i + 1);
                }
            }
            (&[], 1) // Bad syntax; eat "${"
        }
        _ if is_shell_special_var(s[0]) => (&s[0..1], 1),
        _ => {
            // Scan alphanumerics.
            let mut i = 0usize;
            while i < s.len() && is_alpha_num(s[i]) {
                i += 1;
            }
            (&s[..i], i)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::expand_env;
    use anyhow::Result;

    fn mapper(name: &str) -> Result<String> {
        Ok(match name {
            "FOO" => "foo",
            "FOO_BAR" => "foo_bar",
            "X" => "x",
            "_" => "underscore",
            _ => "",
        }
        .to_string())
    }

    #[test]
    fn expand_env_matches_go_os_expandenv_examples() -> Result<()> {
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("no vars", "no vars"),
            ("$", "$"),
            ("$$", ""),
            ("$$$", "$"),
            ("$$FOO", "FOO"),
            ("$FOO", "foo"),
            ("${FOO}", "foo"),
            ("${FOO_BAR}", "foo_bar"),
            ("$FOO_BAR", "foo_bar"),
            ("$FOO-BAR", "foo-BAR"),
            ("${FOO-BAR}", ""),
            ("${FOO", "FOO"),
            ("${}", ""),
            ("$1", ""),
            ("$9abc", "abc"),
            ("$FOO1", ""),
            ("${FOO}1", "foo1"),
            ("a$FOOb", "a"),
            ("a${FOO}b", "afoob"),
            ("a$FOO_barb", "a"),
            ("a$FOO_BARb", "a"),
            ("a$_b", "a"),
            ("a${_}b", "aunderscoreb"),
            ("${X}${X}", "xx"),
            ("$X$X", "xx"),
            ("${X}$X", "xx"),
            ("${X}${}", "x"),
            ("${X}${X", "xX"),
            ("$-", ""),
            ("$*", ""),
            ("${-}", ""),
            ("${*}", ""),
            ("${1}", ""),
            ("${9abc}", ""),
            ("${FOO}$$${FOO}", "foofoo"),
            ("prefix ${FOO} suffix", "prefix foo suffix"),
        ];

        for (input, expected) in cases {
            assert_eq!(expand_env(input, mapper)?, *expected, "input={input:?}");
        }
        Ok(())
    }

    #[test]
    fn expand_env_propagates_mapping_errors() {
        let err_mapper = |name: &str| -> Result<String> {
            if name == "FOO" {
                anyhow::bail!("boom");
            }
            Ok(String::new())
        };
        let err = expand_env("$FOO", err_mapper).unwrap_err();
        assert!(err.to_string().contains("boom"));
    }
}
