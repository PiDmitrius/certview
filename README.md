# certview

Web certificate inspection service and TLS certificate-chain probe.

Version source: `VERSION`.

This repository contains:

- `cmd/certview`: web UI/API for parsing, storing, and inspecting certificate chains.
- `cmd/certget`: stateless TLS probe used by certview for site analysis, including GOST-capable OpenSSL probing.
- `web`: embedded single-page UI.
- `Dockerfile.certview`, `Dockerfile.certget`, `docker-compose.yml`: local and production container build/deploy assets.
- `build/Dockerfile.gost-openssl`: source Dockerfile for the OpenSSL/GOST runtime image used by certget.
- `e2e`: browser tests for site-analysis routing and copy/deep-link behavior.

`certview` depends on MiniPKI core for the C ABI library (`minipki.h`, `libminipki.a`). Local Docker builds read that source via the `MINIPKI_CORE_DIR` build context. By default the local script uses a `minipki/` submodule when present, otherwise `/home/claw/work/MiniPKI`.

## Local development

```sh
./scripts/local-certview.sh up
```

Default local URL: `http://127.0.0.1:18080`.

Useful knobs:

- `MINIPKI_CORE_DIR=/path/to/MiniPKI`
- `CERTVIEW_HTTP_PORT=18080`
- `SKIP_BROWSER_E2E=1`

Git workflow follows `/home/claw/memory/git-dev-pr-main.md`: work on `dev`, PR into `main`, user approval, merge commit, then tag/release.
