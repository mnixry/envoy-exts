use anyhow::{Context as _, Result};
use log::{debug, error, info};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

mod tencent_api;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(EdgeOneRoot::default()) });
}}

const ENV_SECRET_ID: &str = "TENCENTCLOUD_SECRET_ID";
const ENV_SECRET_KEY: &str = "TENCENTCLOUD_SECRET_KEY";
const DEFAULT_API_ENDPOINT: &str = "teo.tencentcloudapi.com";

const HEADER_TRUSTED: &str = "x-forwarded-from-edgeone";
const HEADER_DOWNSTREAM_IP: &str = "eo-connecting-ip";
const HEADER_XFF: &str = "x-forwarded-for";
const HEADER_X_REAL_IP: &str = "x-real-ip";

#[derive(Debug, Default, Deserialize)]
struct EdgeOneConfig {
    /// Optional. If omitted, we try to read it from an env var property (e.g. `TENCENTCLOUD_SECRET_ID`).
    secret_id: Option<String>,
    /// Optional. If omitted, we try to read it from an env var property (e.g. `TENCENTCLOUD_SECRET_KEY`).
    secret_key: Option<String>,
    /// API hostname used for signing + `:authority`/`host` headers.
    /// Defaults to `teo.tencentcloudapi.com`.
    api_endpoint: Option<String>,
    /// Envoy cluster name used by `dispatch_http_call`.
    /// Defaults to `api_endpoint` (so you can name the cluster `teo.tencentcloudapi.com`).
    api_cluster: Option<String>,
    /// Cache size for per-IP validation results (LRU).
    cache_size: Option<usize>,
    /// Cache TTL in seconds.
    cache_ttl: Option<u64>,
    /// Outbound call timeout in seconds.
    timeout: Option<u64>,
    /// Optional Tencent region header (`X-TC-Region`).
    region: Option<String>,
}

#[derive(Clone, Debug)]
struct ConfigRuntime {
    secret_id: String,
    secret_key: String,
    api_host: String,
    api_cluster: String,
    cache_ttl: Duration,
    timeout: Duration,
    region: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct CacheEntry {
    is_edgeone: bool,
    expires_at: SystemTime,
}

struct SharedState {
    config: Option<Rc<ConfigRuntime>>,
    cache: lru::LruCache<String, CacheEntry>,
}

impl SharedState {
    fn new(cache_size: usize) -> Self {
        let cap = NonZeroUsize::new(cache_size.max(1)).unwrap();
        Self {
            config: None,
            cache: lru::LruCache::new(cap),
        }
    }

    fn reset_cache(&mut self, cache_size: usize) {
        let cap = NonZeroUsize::new(cache_size.max(1)).unwrap();
        self.cache = lru::LruCache::new(cap);
    }

    fn cache_get(&mut self, key: &str, now: SystemTime) -> Option<bool> {
        let entry = self.cache.get(key).copied()?;
        if now <= entry.expires_at {
            return Some(entry.is_edgeone);
        }
        self.cache.pop(key);
        None
    }

    fn cache_put(&mut self, key: String, is_edgeone: bool, now: SystemTime, ttl: Duration) {
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        self.cache.put(
            key,
            CacheEntry {
                is_edgeone,
                expires_at,
            },
        );
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new(1000)
    }
}

struct EdgeOneRoot {
    shared: Rc<RefCell<SharedState>>,
}

impl Default for EdgeOneRoot {
    fn default() -> Self {
        Self {
            shared: Rc::new(RefCell::new(SharedState::default())),
        }
    }
}

impl Context for EdgeOneRoot {}

impl RootContext for EdgeOneRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _: usize) -> bool {
        match self.try_configure() {
            Ok((runtime, cache_size)) => {
                let mut shared = self.shared.borrow_mut();
                shared.config = Some(Rc::new(runtime));
                shared.reset_cache(cache_size);

                let cfg = shared.config.as_ref().unwrap();
                info!(
                    "edgeone event=configured api_cluster={} api_host={} cache_size={} cache_ttl_s={} timeout_s={} region={}",
                    cfg.api_cluster,
                    cfg.api_host,
                    cache_size.max(1),
                    cfg.cache_ttl.as_secs(),
                    cfg.timeout.as_secs(),
                    cfg.region.as_deref().unwrap_or("")
                );
                true
            }
            Err(err) => {
                error!("edgeone event=configure_failed err={:#}", err);
                self.shared.borrow_mut().config = None;
                false
            }
        }
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(EdgeOneHttp {
            context_id,
            shared: self.shared.clone(),
            pending: None,
            did_check: false,
        }))
    }
}

impl EdgeOneRoot {
    fn try_configure(&self) -> Result<(ConfigRuntime, usize)> {
        let raw = self.get_plugin_configuration().unwrap_or_default();
        let cfg_str = String::from_utf8(raw).context("plugin configuration is not valid UTF-8")?;

        let cfg_str = if cfg_str.trim().is_empty() {
            "{}"
        } else {
            cfg_str.trim()
        };
        let cfg: EdgeOneConfig =
            serde_json::from_str(cfg_str).context("failed to parse plugin configuration JSON")?;

        let EdgeOneConfig {
            secret_id: secret_id_cfg,
            secret_key: secret_key_cfg,
            api_endpoint,
            api_cluster,
            cache_size,
            cache_ttl,
            timeout,
            region,
        } = cfg;

        let api_host = api_endpoint.unwrap_or_else(|| DEFAULT_API_ENDPOINT.to_string());
        let api_cluster = api_cluster.unwrap_or_else(|| api_host.clone());

        let cache_size = cache_size.unwrap_or(1000);
        let cache_ttl = Duration::from_secs(cache_ttl.unwrap_or(60 * 60));
        let timeout = Duration::from_secs(timeout.unwrap_or(5));

        let secret_id = secret_id_cfg.or(std::env::var(ENV_SECRET_ID).ok());
        let secret_key = secret_key_cfg.or(std::env::var(ENV_SECRET_KEY).ok());
        if let (Some(secret_id), Some(secret_key)) = (secret_id, secret_key) {
            let region = region.and_then(|s| trim_non_empty(s.as_str()));
            Ok((
                ConfigRuntime {
                    secret_id,
                    secret_key,
                    api_host,
                    api_cluster,
                    cache_ttl,
                    timeout,
                    region,
                },
                cache_size,
            ))
        } else {
            error!("missing credentials: expected {ENV_SECRET_ID} (env) or secret_id (config)");
            Err(anyhow::anyhow!("missing credentials"))
        }
    }
}

struct PendingCall {
    token_id: u32,
    remote_ip: String,
}

struct EdgeOneHttp {
    context_id: u32,
    shared: Rc<RefCell<SharedState>>,
    pending: Option<PendingCall>,
    did_check: bool,
}

impl Context for EdgeOneHttp {
    fn on_http_call_response(
        &mut self,
        token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if pending.token_id != token_id {
            self.pending = Some(pending);
            return;
        }

        let config = { self.shared.borrow().config.clone() };
        let Some(config) = config else {
            self.resume_http_request();
            return;
        };

        let status_code = self
            .get_http_call_response_header(":status")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let body = self
            .get_http_call_response_body(0, body_size)
            .unwrap_or_default();

        let now = self.get_current_time();

        let mut should_cache = false;
        let is_edgeone = if status_code != 200 {
            error!(
                "edgeone event=tencent_http_error ctx={} status={} ip={}",
                self.context_id, status_code, pending.remote_ip
            );
            false
        } else {
            match tencent_api::parse_describe_ip_region_response(
                body.as_slice(),
                pending.remote_ip.as_str(),
            )
            .with_context(|| format!("ip={}", pending.remote_ip))
            {
                Ok(v) => {
                    should_cache = true;
                    v
                }
                Err(e) => {
                    error!(
                        "edgeone event=tencent_parse_error ctx={} ip={} err={:#}",
                        self.context_id, pending.remote_ip, e
                    );
                    false
                }
            }
        };

        if should_cache {
            self.shared.borrow_mut().cache_put(
                pending.remote_ip.clone(),
                is_edgeone,
                now,
                config.cache_ttl,
            );
        }

        self.apply_result(is_edgeone, &pending.remote_ip);
        self.resume_http_request();
    }
}

impl HttpContext for EdgeOneHttp {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        if self.did_check {
            return Action::Continue;
        }

        let config = { self.shared.borrow().config.clone() };
        let Some(config) = config else {
            self.set_http_request_header(HEADER_TRUSTED, Some("no"));
            self.did_check = true;
            return Action::Continue;
        };

        let Some(remote_ip) = self.downstream_remote_ip() else {
            debug!("edgeone event=missing_remote_addr ctx={}", self.context_id);
            self.set_http_request_header(HEADER_TRUSTED, Some("no"));
            return Action::Continue;
        };

        let now = self.get_current_time();
        let cached = { self.shared.borrow_mut().cache_get(remote_ip.as_str(), now) };
        if let Some(is_edgeone) = cached {
            self.apply_result(is_edgeone, &remote_ip);
            self.did_check = true;
            return Action::Continue;
        }

        match self.dispatch_validate_ip_call(&config, remote_ip.as_str(), now) {
            Ok(token_id) => {
                self.pending = Some(PendingCall {
                    token_id,
                    remote_ip: remote_ip.clone(),
                });
                self.did_check = true;
                Action::Pause
            }
            Err(err) => {
                error!(
                    "edgeone event=dispatch_failed ctx={} ip={} api_cluster={} api_host={} err={:#}",
                    self.context_id, remote_ip, config.api_cluster, config.api_host, err
                );
                self.apply_result(false, &remote_ip);
                self.did_check = true;
                Action::Continue
            }
        }
    }
}

impl EdgeOneHttp {
    fn downstream_remote_ip(&self) -> Option<String> {
        let addr = self
            .get_property(vec!["source", "address"])
            .and_then(|b| String::from_utf8(b).ok())?;

        parse_ip_from_address(addr.trim())
    }

    fn apply_result(&self, is_edgeone: bool, remote_ip: &str) {
        self.set_http_request_header(HEADER_TRUSTED, Some(if is_edgeone { "yes" } else { "no" }));
        if is_edgeone
            && let Some(downstream_real_ip) = self.get_http_request_header(HEADER_DOWNSTREAM_IP)
        {
            self.set_http_request_header(
                HEADER_XFF,
                Some(&format!("{downstream_real_ip}, {remote_ip}")),
            );
            self.set_http_request_header(HEADER_X_REAL_IP, Some(&downstream_real_ip));
        } else if !is_edgeone {
            self.set_http_request_header(HEADER_XFF, Some(remote_ip));
            self.set_http_request_header(HEADER_X_REAL_IP, Some(remote_ip));
        }
    }

    fn dispatch_validate_ip_call(
        &self,
        config: &ConfigRuntime,
        ip: &str,
        now: SystemTime,
    ) -> Result<u32> {
        debug!(
            "edgeone event=validate_begin ctx={} ip={} api_cluster={} api_host={}",
            self.context_id, ip, config.api_cluster, config.api_host
        );

        tencent_api::dispatch_describe_ip_region(
            self,
            &tencent_api::DescribeIpRegionCall {
                api_cluster: config.api_cluster.as_str(),
                api_host: config.api_host.as_str(),
                secret_id: config.secret_id.as_str(),
                secret_key: config.secret_key.as_str(),
                region: config.region.as_deref(),
                timeout: config.timeout,
            },
            now,
            ip,
        )
    }
}

fn trim_non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn parse_ip_from_address(addr: &str) -> Option<String> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa.ip().to_string());
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    None
}
