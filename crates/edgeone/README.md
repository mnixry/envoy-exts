# `edgeone` (Envoy proxy-wasm filter)

Validates whether the downstream connection IP is a **Tencent EdgeOne** IP by calling the Tencent Cloud TEO API action **`DescribeIPRegion`** (TC3-HMAC-SHA256 signing), with an in-memory **LRU + TTL** cache.

## Configuration (plugin configuration JSON)

Durations are **seconds**.

```json
{
  "secret_id": "",
  "secret_key": "",
  "api_endpoint": "teo.tencentcloudapi.com",
  "api_cluster": "teo.tencentcloudapi.com",
  "cache_size": 1000,
  "cache_ttl": 3600,
  "timeout": 5,
  "region": ""
}
```

## Credentials (AK/SK)

The filter prefers reading credentials from env **properties**:

- `TENCENTCLOUD_SECRET_ID`
- `TENCENTCLOUD_SECRET_KEY`

Implementation detail: it tries `get_property(["env", NAME])` and `get_property(["environment", NAME])`.

If your runtime does **not** expose env vars via `get_property`, you can also set:

```json
{ "secret_id": "...", "secret_key": "..." }
```

## Output header

- `x-edgeone-trusted`: set to `yes`/`no` based on whether the downstream IP is an EdgeOne IP.

