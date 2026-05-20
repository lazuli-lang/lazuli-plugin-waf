# @plugin/waf

## Purpose

`@plugin/waf` is the perimeter WAF filter for Lazuli. It wraps cloud WAF APIs behind `waf.Filter` so generated HTTP servers can reject hostile requests before they enter the runtime.

## Status

| Face | Status |
|---|---|
| Go server | in development |
| TS web | not planned |
| TS mobile | not planned |

## Usage

`Lazurite.toml`:

```toml
[plugins]
waf = "@plugin/waf"
```

`registry.lzi`:

```lzi
registry
  bindings
    waf: WAFFilter
      adapter @plugin/waf
      endpoint env.CLOUDFLARE_WAF_ZONE_ID
      auth keys env.CLOUDFLARE_WAF_API_TOKEN
```

## Environment

| Variable | Required | Default | Vendor | Notes |
|---|---:|---|---|---|
| `CLOUDFLARE_WAF_ZONE_ID` | production | none | Cloudflare WAF | Zone to inspect against. |
| `CLOUDFLARE_WAF_API_TOKEN` | production | none | Cloudflare WAF | Token with WAF read/evaluate scope. |
| `CLOUDFLARE_WAF_API_BASE` | optional | `https://api.cloudflare.com` | Cloudflare WAF | Test override. |
| `AWS_WAF_WEB_ACL_ARN` | future | none | AWS WAF | Stubbed in v0.1. |
| `IMPERVA_SITE_ID` | future | none | Imperva | Stubbed in v0.1. |
| `MODSECURITY_CONFIG_PATH` | future | none | ModSecurity | Stubbed in v0.1. |

## Vendor-Specific Notes

See `VENDORS.md` for the supported vendor matrix. v0.1 ships the Cloudflare WAF flavor; AWS WAF, Imperva, and ModSecurity return `ErrUnimplemented`.

## Local Development

No backing container is required. Tests use `httptest` to mock the Cloudflare API.

## Auditability

This plugin can close perimeter input-filter findings when it is bound in production and audit logs record deny/tarpit decisions. It cannot prove application-layer authorization, data validation, or tenant isolation.
