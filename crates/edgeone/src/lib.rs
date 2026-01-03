use anyhow::{Context as _, Result};
use log::warn;
use log::{debug, error, info};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

mod config;
mod tencent_api;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(EdgeOneRoot::default()) });
}}

const HEADER_TRUSTED: &str = "x-forwarded-from-edgeone";
const HEADER_DOWNSTREAM_IP: &str = "eo-connecting-ip";
const HEADER_XFF: &str = "x-forwarded-for";
const HEADER_X_REAL_IP: &str = "x-real-ip";

#[derive(Clone, Copy, Debug)]
struct CacheEntry {
    is_edgeone: bool,
    expires_at: SystemTime,
}

#[derive(Debug)]
struct SharedState {
    config: Option<Rc<config::ConfigRuntime>>,
    cache: lru::LruCache<String, CacheEntry>,
}

impl SharedState {
    fn new(cache_size: usize) -> Self {
        let cap = match NonZeroUsize::new(cache_size.max(1)) {
            Some(v) => v,
            None => NonZeroUsize::MIN,
        };
        Self {
            config: None,
            cache: lru::LruCache::new(cap),
        }
    }

    fn reset_cache(&mut self, cache_size: usize) {
        let cap = match NonZeroUsize::new(cache_size.max(1)) {
            Some(v) => v,
            None => NonZeroUsize::MIN,
        };
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
        let expires_at = match now.checked_add(ttl) {
            Some(v) => v,
            None => now,
        };
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
        match self.get_plugin_configuration().map(config::load_config) {
            Some(Ok((runtime, cache_size))) => {
                let mut shared = self.shared.borrow_mut();
                let runtime = Rc::new(runtime);
                shared.config = Some(runtime.clone());
                shared.reset_cache(cache_size);

                let cfg = runtime;
                info!(
                    "edgeone event=configured api_cluster={:?} api_host={} cache_size={} cache_ttl_s={:?} timeout_s={:?} region={:?}",
                    cfg.api_cluster,
                    cfg.api_host,
                    cache_size,
                    cfg.cache_ttl,
                    cfg.timeout.as_secs(),
                    cfg.region
                );
                true
            }
            Some(Err(err)) => {
                error!("edgeone event=configure_failed err={:#}", err);
                self.shared.borrow_mut().config = None;
                false
            }
            None => {
                error!("edgeone event=missing_configuration");
                false
            }
        }
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(EdgeOneHttp {
            context_id,
            shared: self.shared.clone(),
            pending: None,
        }))
    }
}

#[derive(Clone, Debug)]
struct PendingCall {
    token_id: u32,
    remote_ip: String,
}

#[derive(Clone, Debug)]
struct EdgeOneHttp {
    context_id: u32,
    shared: Rc<RefCell<SharedState>>,
    pending: Option<PendingCall>,
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
            .map_or(0, |v| v);

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
        let config = { self.shared.borrow().config.clone() };

        let Some(config) = config else {
            self.set_http_request_header(HEADER_TRUSTED, Some("no"));
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
            return Action::Continue;
        }

        match self.dispatch_validate_ip_call(&config, remote_ip.as_str(), now) {
            Ok(token_id) => {
                self.pending = Some(PendingCall {
                    token_id,
                    remote_ip: remote_ip.clone(),
                });
                Action::Pause
            }
            Err(err) => {
                error!(
                    "edgeone api_cluster={:?} api_host={} ip={} err={:#}",
                    config.api_cluster, config.api_host, remote_ip, err
                );
                self.apply_result(false, &remote_ip);
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
        if !is_edgeone {
            self.set_http_request_headers(vec![
                (HEADER_TRUSTED, "no"),
                (HEADER_XFF, remote_ip),
                (HEADER_X_REAL_IP, remote_ip),
            ]);
        } else if let Some(downstream_real_ip) = self
            .get_http_request_header(HEADER_DOWNSTREAM_IP)
            .and_then(|s| parse_ip_from_address(&s))
        {
            self.set_http_request_headers(vec![
                (HEADER_TRUSTED, "yes"),
                (HEADER_XFF, &format!("{downstream_real_ip}, {remote_ip}")),
                (HEADER_X_REAL_IP, &downstream_real_ip),
            ]);
        } else {
            warn!(
                "edgeone event=missing_downstream_real_ip ctx={} ip={}",
                self.context_id, remote_ip
            );
            self.set_http_request_headers(vec![
                (HEADER_TRUSTED, "yes"),
                (HEADER_XFF, remote_ip),
                (HEADER_X_REAL_IP, remote_ip),
            ]);
        }
    }

    fn dispatch_validate_ip_call(
        &self,
        config: &config::ConfigRuntime,
        ip: &str,
        now: SystemTime,
    ) -> Result<u32> {
        debug!(
            "edgeone event=validate_begin ctx={} ip={} api_cluster={:?} api_host={}",
            self.context_id, ip, config.api_cluster, config.api_host
        );

        tencent_api::dispatch_describe_ip_region(
            self,
            &tencent_api::DescribeIpRegionCall {
                api_cluster: config.api_cluster.as_deref().unwrap_or(&config.api_host),
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

fn parse_ip_from_address(addr: &str) -> Option<String> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa.ip().to_string());
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    None
}
