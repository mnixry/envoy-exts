use anyhow::{Context as _, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use proxy_wasm::traits::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SERVICE: &str = "teo";
const VERSION: &str = "2022-09-01";
const ACTION: &str = "DescribeIPRegion";
const ALGORITHM: &str = "TC3-HMAC-SHA256";
const CONTENT_TYPE: &str = "application/json; charset=utf-8";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug)]
pub struct DescribeIpRegionCall<'a> {
    pub api_cluster: &'a str,
    pub api_host: &'a str,
    pub secret_id: &'a str,
    pub secret_key: &'a str,
    pub region: Option<&'a str>,
    pub timeout: Duration,
}

#[derive(Debug, Serialize)]
struct DescribeIpRegionRequest<'a> {
    #[serde(rename = "IPs")]
    ips: [&'a str; 1],
}

pub fn dispatch_describe_ip_region<C: Context>(
    ctx: &C,
    call: &DescribeIpRegionCall<'_>,
    now: SystemTime,
    ip: &str,
) -> Result<u32> {
    let payload = DescribeIpRegionRequest { ips: [ip] };
    let payload_bytes = serde_json::to_vec(&payload).context("serialize request payload")?;
    let timestamp = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();

    let authorization = tc3_authorization(
        call.secret_id,
        call.secret_key,
        call.api_host,
        timestamp,
        payload_bytes.as_slice(),
    );

    // NOTE: `dispatch_http_call` copies headers immediately; references only need to live until the
    // call returns.
    let mut headers_owned: Vec<(String, String)> = vec![
        (":method".to_string(), "POST".to_string()),
        (":path".to_string(), "/".to_string()),
        (":authority".to_string(), call.api_host.to_string()),
        ("host".to_string(), call.api_host.to_string()),
        ("content-type".to_string(), CONTENT_TYPE.to_string()),
        ("x-tc-action".to_string(), ACTION.to_string()),
        ("x-tc-version".to_string(), VERSION.to_string()),
        ("x-tc-timestamp".to_string(), timestamp.to_string()),
        ("authorization".to_string(), authorization),
    ];

    if let Some(region) = call.region {
        headers_owned.push(("x-tc-region".to_string(), region.to_string()));
    }
    let headers: Vec<(&str, &str)> = headers_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    ctx.dispatch_http_call(
        call.api_cluster,
        headers,
        Some(payload_bytes.as_slice()),
        vec![],
        call.timeout,
    )
    .map_err(|status| anyhow!("dispatch_http_call failed: {status:?}"))
    .with_context(|| {
        format!(
            "api_cluster={} api_host={} ip={ip}",
            call.api_cluster, call.api_host
        )
    })
}

pub fn parse_describe_ip_region_response(body: &[u8], expected_ip: &str) -> Result<bool> {
    let resp: DescribeIPRegionOuter =
        serde_json::from_slice(body).context("invalid JSON response")?;

    if let Some(err) = resp.response.error {
        let code = err.code.unwrap_or_else(|| "UnknownError".to_string());
        let msg = err.message.unwrap_or_else(|| "<no message>".to_string());
        bail!("{code}: {msg}");
    }

    let list = resp.response.ip_region_info.unwrap_or_default();
    for info in list {
        let Some(is_edgeone) = info.is_edgeone_ip.as_deref() else {
            continue;
        };
        if !is_edgeone.eq_ignore_ascii_case("yes") {
            continue;
        }
        let Some(ip) = info.ip.as_deref() else {
            continue;
        };
        if ip == expected_ip {
            return Ok(true);
        }
    }

    Ok(false)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn tc3_authorization(
    secret_id: &str,
    secret_key: &str,
    host: &str,
    timestamp: u64,
    payload: &[u8],
) -> String {
    // ************* Step 1: canonical request *************
    let canonical_headers = format!(
        "content-type:{CONTENT_TYPE}\nhost:{host}\nx-tc-action:{}\n",
        ACTION.to_ascii_lowercase()
    );
    let signed_headers = "content-type;host;x-tc-action";
    let hashed_request_payload = sha256_hex(payload);

    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_request_payload}");

    // ************* Step 2: string to sign *************
    let date = tencent_date_utc(timestamp);
    let credential_scope = format!("{}/{SERVICE}/tc3_request", date);
    let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());

    let string_to_sign =
        format!("{ALGORITHM}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}");

    // ************* Step 3: signature *************
    let secret_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let secret_service = hmac_sha256(secret_date.as_slice(), SERVICE.as_bytes());
    let secret_signing = hmac_sha256(secret_service.as_slice(), b"tc3_request");
    let signature = hex::encode(hmac_sha256(
        secret_signing.as_slice(),
        string_to_sign.as_bytes(),
    ));

    // ************* Step 4: authorization *************
    format!(
        "{ALGORITHM} Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

fn tencent_date_utc(timestamp: u64) -> String {
    let ts = i64::try_from(timestamp).unwrap_or(0);
    let dt =
        time::OffsetDateTime::from_unix_timestamp(ts).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let year = dt.year();
    let month = dt.month() as u8;
    let day = dt.day();
    format!("{year:04}-{month:02}-{day:02}")
}

#[derive(Debug, Deserialize)]
struct DescribeIPRegionOuter {
    #[serde(rename = "Response")]
    response: DescribeIPRegionInner,
}

#[derive(Debug, Deserialize)]
struct DescribeIPRegionInner {
    #[serde(rename = "IPRegionInfo")]
    ip_region_info: Option<Vec<IpRegionInfo>>,
    #[serde(rename = "Error")]
    error: Option<TencentError>,
}

#[derive(Debug, Deserialize)]
struct IpRegionInfo {
    #[serde(rename = "IP")]
    ip: Option<String>,
    #[serde(rename = "IsEdgeOneIP")]
    is_edgeone_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TencentError {
    #[serde(rename = "Code")]
    code: Option<String>,
    #[serde(rename = "Message")]
    message: Option<String>,
}
