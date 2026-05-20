# Vendor Matrix

| Vendor | Auth mechanism | Features supported | Known limitations | Cost model |
|---|---|---|---|---|
| Cloudflare WAF | Sites/workers API token | Request inspect, deny, tarpit mapping | v0.1 expects an API inspection endpoint configured by the pilot | Cloudflare plan dependent |
| AWS WAF | IAM v4 signature | Stubbed | Not implemented in v0.1 | AWS request and rule charges |
| Imperva | Per-resource signature | Stubbed | Not implemented in v0.1 | Imperva plan dependent |
| ModSecurity | Local, no auth; runs as Apache/Nginx module | Stubbed | Not implemented in v0.1 | Self-hosted infrastructure |
