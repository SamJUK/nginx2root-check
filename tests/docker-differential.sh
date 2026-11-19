#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_id="${GITHUB_RUN_ID:-local}-$$"
label="io.samdjames.nginx2root-check=${run_id}"
python_image="python@sha256:6ff506466f8b1e981719b468cc0023b8ef000b983cdec0eafe119d01f379e31d"
nginx_1_31_8_image="nginx@sha256:165ddde8751e75a1c907d24ef10d9f6deb08b57e0fe56caf67512486aff76d82"
nginx_1_31_9_image="nginx@sha256:08f354a3b44c422021a5c0f5efb3e27f8f90236b5447d3bac4053f5f50ab6760"

cleanup() {
    docker ps -aq --filter "label=${label}" | xargs -r docker rm -f >/dev/null
}
trap cleanup EXIT

wait_for_listener() {
    local name=$1
    docker run --rm \
        --network "container:${name}" \
        "${python_image}" \
        python -c 'import socket,time; deadline=time.monotonic()+15
while True:
    try:
        socket.create_connection(("127.0.0.1",80),0.2).close(); break
    except OSError:
        if time.monotonic() >= deadline: raise
        time.sleep(0.1)'
}

run_shipped_wrapper() {
    local name=$1
    docker exec -u 0 "${name}" sh -c \
        'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 >/dev/null'

    local output
    local status
    set +e
    output=$(docker exec -u 0 "${name}" \
        python3 /src/nginx2root-check \
        --acknowledge-owned-system I-AM-AUTHORIZED \
        --json)
    status=$?
    set -e

    python3 -c 'import json,sys; result=json.loads(sys.argv[1]); status=int(sys.argv[2]); assert status == 2, (status,result); assert result["outcome"] == "INCONCLUSIVE", result; assert result["probe"]["outcome"] == "NO_OVER_CREDIT_OBSERVED", result; assert result["probe"]["control_bytes"] == 65535, result; assert result["probe"]["production_pids_unchanged"] is True, result' "${output}" "${status}"
}

run_control() {
    local version=$1
    local expected=$2
    local expected_detail=$3
    local image=$4
    local name="nginx2root-check-${version}-${run_id}"

    docker run --rm -d \
        --name "${name}" \
        --label "${label}" \
        --memory 256m \
        --pids-limit 128 \
        --cap-drop ALL \
        --cap-add CHOWN \
        --cap-add DAC_OVERRIDE \
        --cap-add FOWNER \
        --cap-add KILL \
        --cap-add SETGID \
        --cap-add SETUID \
        --cap-add SYS_PTRACE \
        --security-opt no-new-privileges \
        -v "${repo_root}:/src:ro" \
        --entrypoint sh \
        "${image}" \
        -c "dd if=/dev/zero of=/usr/share/nginx/html/big.bin bs=1048576 count=8 status=none; head -c 896 /dev/zero | tr '\\0' A > /usr/share/nginx/html/index.html; printf '%s' 'user nginx; worker_processes 1; events { worker_connections 1024; } http { default_type application/octet-stream; sendfile on; server { listen 80 http2; server_name localhost; root /usr/share/nginx/html; location / { try_files \$uri =404; } } }' > /etc/nginx/nginx.conf; exec nginx -g 'daemon off;'" \
        >/dev/null

    wait_for_listener "${name}"

    local output
    output=$(docker run --rm \
        --network "container:${name}" \
        --memory 128m \
        --pids-limit 64 \
        --security-opt no-new-privileges \
        -v "${repo_root}:/src:ro" \
        "${python_image}" \
        python -I /src/nginx2root_check/probe.py \
        --probe-host 127.0.0.1 \
        --probe-port 80)

    python3 -c 'import json,sys; result=json.loads(sys.argv[1]); expected=sys.argv[2]; detail=sys.argv[3]; assert result["outcome"] == expected, result; assert result["detail"] == detail, result; assert result["control_bytes"] == 65535, result' "${output}" "${expected}" "${expected_detail}"

    if [[ ${version} == 1.31.9 ]]; then
        run_shipped_wrapper "${name}"
    fi
}

run_control 1.31.8 VULNERABLE "over-credit update was accepted and acknowledged on the same connection" "${nginx_1_31_8_image}"
run_control 1.31.9 NO_OVER_CREDIT_OBSERVED "server rejected the four-MiB over-credit precursor" "${nginx_1_31_9_image}"

echo "PASS: vulnerable and patched controls behaved as expected"
