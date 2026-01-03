use anyhow::{Context as _, Result};
use regex::Regex;
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
    let re = Regex::new(r"\$(?P<name>\{\w+\}|\w+)")?;
    let mut buf = String::new();
    let mut i = 0;
    for caps in re.captures_iter(s) {
        buf.push_str(&s[i..caps.get_match().start()]);
        if let Some(name) = caps.name("name").map(|m| m.as_str()) {
            if name.starts_with('{') && name.ends_with('}') {
                let name = &name[1..name.len() - 1];
                let value = mapping(name).context("failed to map variable")?;
                buf.push_str(&value);
            } else {
                let value = mapping(name).context("failed to map variable")?;
                buf.push_str(&value);
            }
        }
        i = caps.get_match().end();
    }
    buf.push_str(&s[i..]);
    Ok(buf)
}
