#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${COMPOSE_PROJECT_NAME:-certview-local}"
MINIPKI_CORE_DIR="${MINIPKI_CORE_DIR:-/home/claw/work/MiniPKI}"
HTTP_PORT="${CERTVIEW_HTTP_PORT:-18080}"
ADMIN_PORT="${CERTVIEW_ADMIN_PORT:-18081}"
HTTP_BIND="${CERTVIEW_HTTP_BIND:-0.0.0.0}"
ADMIN_BIND="${CERTVIEW_ADMIN_BIND:-127.0.0.1}"
E2E_URL="${CERTVIEW_E2E_URL:-https://www.gosuslugi.ru}"
E2E_TIMEOUT="${CERTVIEW_E2E_TIMEOUT:-45}"
RUNTIME_UID="${CERTVIEW_RUNTIME_UID:-65532}"
RUNTIME_GID="${CERTVIEW_RUNTIME_GID:-65532}"

existing_data_volume() {
  local name volume
  for name in certview "${PROJECT}-certview-1"; do
    volume="$(
      docker inspect "$name" \
        --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' \
        2>/dev/null || true
    )"
    if [[ -n "$volume" ]]; then
      printf '%s\n' "$volume"
      return 0
    fi
  done
}

DATA_VOLUME="${CERTVIEW_DATA_VOLUME:-$(existing_data_volume)}"
DATA_VOLUME="${DATA_VOLUME:-certview-data}"

export CERTVIEW_HTTP_PORT="$HTTP_PORT"
export CERTVIEW_ADMIN_PORT="$ADMIN_PORT"
export CERTVIEW_HTTP_BIND="$HTTP_BIND"
export CERTVIEW_ADMIN_BIND="$ADMIN_BIND"
export CERTVIEW_DATA_VOLUME="$DATA_VOLUME"

compose() {
  docker compose \
    -p "$PROJECT" \
    -f "$ROOT/docker-compose.yml" \
    -f "$ROOT/docker-compose.local.yml" \
    "$@"
}

build_certget() {
  docker build \
    -f "$ROOT/Dockerfile.certget" \
    --build-context gost-openssl=docker-image://pidmitrius/gost-openssl:latest \
    -t pidmitrius/certget:latest \
    "$ROOT"
}

build_certview() {
  docker build \
    -f "$ROOT/Dockerfile.certview" \
    --build-context gost-openssl=docker-image://pidmitrius/gost-openssl:latest \
    --build-context minipki-core="$MINIPKI_CORE_DIR" \
    -t pidmitrius/certview:latest \
    "$ROOT"
}

wait_http() {
  local url="http://127.0.0.1:${HTTP_PORT}/api/config"
  for _ in $(seq 1 30); do
    if curl -fsS "$url" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "certview did not become ready at $url" >&2
  return 1
}

e2e_smoke() {
  local api="http://127.0.0.1:${HTTP_PORT}/api/site"
  local body
  body="$(
    curl -fsS \
      -m "$E2E_TIMEOUT" \
      -H 'Content-Type: application/json' \
      -d "{\"url\":\"${E2E_URL}\"}" \
      "$api"
  )"
  if [[ "$body" != *'"ok":true'* ]]; then
    echo "e2e smoke failed for ${E2E_URL}" >&2
    printf '%s\n' "$body" | head -c 2000 >&2
    echo >&2
    return 1
  fi
}

browser_e2e() {
  if [[ "${SKIP_BROWSER_E2E:-0}" == "1" ]]; then
    echo "browser e2e skipped (SKIP_BROWSER_E2E=1)"
    return 0
  fi
  if [[ ! -d "$ROOT/node_modules/@playwright/test" ]]; then
    (cd "$ROOT" && npm install)
  fi
  local install_dirs
  local missing_browser=0
  if ! install_dirs="$((cd "$ROOT" && npx playwright install --dry-run chromium) | awk '/Install location:/ {print $3}')"; then
    missing_browser=1
  elif [[ -z "$install_dirs" ]]; then
    missing_browser=1
  fi
  while IFS= read -r install_dir; do
    [[ -z "$install_dir" ]] && continue
    if [[ ! -d "$install_dir" ]]; then
      missing_browser=1
    fi
  done <<< "$install_dirs"
  if [[ "$missing_browser" == "1" ]]; then
    (cd "$ROOT" && npx playwright install chromium)
  fi
  CERTVIEW_E2E_BASE_URL="http://127.0.0.1:${HTTP_PORT}" \
    CERTVIEW_E2E_HOST="${CERTVIEW_E2E_HOST:-www.gosuslugi.ru}" \
    CERTVIEW_E2E_UNRESOLVED_HOST="${CERTVIEW_E2E_UNRESOLVED_HOST:-не-существует.invalid}" \
    npm --prefix "$ROOT" run e2e
}

ensure_data_volume_owner() {
  docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1 || docker volume create "$DATA_VOLUME" >/dev/null
  docker run --rm \
    -v "${DATA_VOLUME}:/data" \
    debian:bookworm-slim \
    sh -c "chown -R ${RUNTIME_UID}:${RUNTIME_GID} /data"
}

up() {
  build_certget
  build_certview

  # Older local runs used hand-made containers named certview/certget on :18080.
  # Remove them so Compose can own the local development stack.
  docker rm -f certview certget >/dev/null 2>&1 || true
  ensure_data_volume_owner

  compose up -d --force-recreate
  wait_http
  e2e_smoke
  browser_e2e
  echo "certview: http://127.0.0.1:${HTTP_PORT}"
  echo "site example: http://127.0.0.1:${HTTP_PORT}/www.gosuslugi.ru"
}

down() {
  compose down
}

case "${1:-up}" in
  up)
    up
    ;;
  build)
    build_certget
    build_certview
    ;;
  restart)
    ensure_data_volume_owner
    compose up -d --force-recreate
    wait_http
    e2e_smoke
    browser_e2e
    ;;
  test)
    build_certget
    build_certview
    wait_http
    e2e_smoke
    browser_e2e
    ;;
  down)
    down
    ;;
  logs)
    compose logs -f "${@:2}"
    ;;
  status)
    compose ps
    ;;
  *)
    echo "usage: ${0##*/} [up|build|restart|test|down|logs|status]" >&2
    exit 2
    ;;
esac
