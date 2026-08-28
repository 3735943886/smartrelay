#!/usr/bin/env python3
"""
MTTL-W01 기본(fallback) 응답 규칙 — 여기가 기기별 하드코딩이 전부 모이는 곳이다.
relay.py(엔진)는 이 파일 내용을 몰라도 동작해야 한다.

파일명이 `99-`라 항상 최저 우선순위(fallback) — 특정 기기만 다르게 다루고 싶으면 이 파일보다
앞서 정렬되는 이름(`10-xxx.py` 등)의 파일을 추가해서 override.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import time

from rules_engine import HttpResponse, PublishSpec

# --- 이 기기 실측값 (ANALYSIS.md / captures 기준) ---
VENDOR_CODE = "0000564"
DEVICE_MODEL = "MTTL-W01"
FW_VERSION_DEFAULT = "0.1.60"

_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _b62(data: bytes, length: int) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while len(out) < length:
        n, r = divmod(n, 62)
        out.append(_B62[r])
    return "".join(reversed(out))


def _derive_credentials(device_key: str):
    """기기 고유값(mac/시리얼)마다 안정적으로(재부팅해도 동일) 다른 entityId/enrmtKey/token을
    만든다 — Decloud에선 이 값을 발급하는 게 우리 자신이므로, 형식만 맞으면 되고 원본 식별자를
    그대로 노출할 필요가 없다(해시로 감춤). 여러 대가 동시에 이 서버에 붙어도 서로 다른 MQTT
    client_id/password를 받게 되어 registry/topic 네임스페이스가 겹치지 않는다."""
    seed = device_key.strip().upper().encode()
    h = hashlib.sha256(seed).digest()
    entity_mid = _b62(h[:8], 10)
    enrmt_key = _b62(hashlib.sha256(seed + b"enrmt").digest(), 22)
    token = _b62(hashlib.sha256(seed + b"token1").digest()[:6], 7) + "-" + \
        _b62(hashlib.sha256(seed + b"token2").digest(), 35)
    entity_id = f"ASN_CSE-D-{entity_mid}-MTAP"
    return entity_id, enrmt_key, token


_MAC_RE = re.compile(rb"<mac>([^<]*)</mac>")
_SERIAL_RE = re.compile(rb"<deviceSerialNo>([^<]*)</deviceSerialNo>")


# --------------------------------------------------------------------------
# :443 POST /mef — MEF 인증 성공 응답 (구조는 captures/ 골든 그대로, 자격증명만 기기별로 발급)
# --------------------------------------------------------------------------

def on_http_request(ctx, method, path, headers, body):
    if method != b"POST" or path != b"/mef":
        return None
    m = _MAC_RE.search(body) or _SERIAL_RE.search(body)
    device_key = m.group(1).decode(errors="replace") if m else "unknown-device"
    entity_id, enrmt_key, token = _derive_credentials(device_key)
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        "<authdata>"
        f"<http><enrmtKey>{enrmt_key}</enrmtKey><entityId>{entity_id}</entityId>"
        f"<token>{token}</token></http>"
        f"<coap><enrmtKey>{enrmt_key}</enrmtKey><entityId>{entity_id}</entityId>"
        f"<token>{token}</token><encryptionMethod>TLS_PSK_WITH_AES_128_CCM_8</encryptionMethod></coap>"
        f"<mqtt><enrmtKey>{enrmt_key}</enrmtKey><entityId>{entity_id}</entityId>"
        f"<token>{token}</token></mqtt>"
        "</authdata>"
    ).encode()
    return HttpResponse(
        status_line=b"HTTP/1.1 200 OK",
        headers={"Content-Type": "application/xml;charset=UTF-8", "Connection": "close"},
        body=xml,
    )


# --------------------------------------------------------------------------
# :18831 — oneM2M CSE 부트스트랩 시퀀스 (captures/ 골든 구조 그대로, ri/ct/lt만 그때그때 생성)
# --------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime())


NEVER_EXPIRES = "99991231T000000"


def _new_ri(ty) -> str:
    return f"ri_{ty}_{random.randint(10000, 99999)}"


def _reply_envelope(req: dict, pc: dict) -> dict:
    """요청의 rqi를 그대로 echo, to/fr을 뒤집어서 응답 봉투를 만든다.
    (captures 전수 조사로 확인된 패턴: 응답 fr = 요청 to의 첫 세그먼트, 응답 to = 요청 fr.)"""
    req_to = (req.get("to") or "").strip("/")
    base = "/" + req_to.split("/")[0] if req_to else ""
    return {
        "rsc": 2000 if req.get("rqi") == "cseBaseRetrieve" else 2001,
        "rqi": req.get("rqi"),
        "to": req.get("fr"),
        "fr": base,
        "pc": pc,
    }


def _session_id_for(client_id: bytes) -> str:
    """captures 관찰: SID-<entityId 중간 세그먼트 마지막 7글자>-MTAP 형식."""
    cid = client_id.decode(errors="replace")
    parts = cid.split("-")
    hashpart = parts[2] if len(parts) >= 4 else cid
    suffix = hashpart[-7:] if len(hashpart) >= 7 else hashpart
    return f"SID-{suffix}-MTAP"


def on_message(ctx, msg, topic):
    rqi = msg.get("rqi") or ""
    pc = msg.get("pc") or {}

    if rqi == "cseBaseRetrieve":
        reply_pc = {
            "m2m:cb": {
                "ri": "cb-1", "rn": "cb-1", "ty": 5, "csi": "/IN_CSE-BASE-1", "cst": 1, "pi": "",
                "ct": "20260101T000000", "lt": "20260101T000000",
                "srt": [1, 2, 3, 4, 5, 9, 13, 14, 16, 23], "poa": ["mqtt"],
            }
        }
        return [_envelope_to_pub(ctx, _reply_envelope(msg, reply_pc))]

    if rqi == "remoteCSECreate":
        csr = dict(pc.get("m2m:csr") or {})
        csr.update(ri=_new_ri(16), ct=_now(), lt=_now(), et=NEVER_EXPIRES)
        return [_envelope_to_pub(ctx, _reply_envelope(msg, {"m2m:csr": csr}))]

    if rqi == "accessControlPolicyCreate":
        acp = dict(pc.get("m2m:acp") or {})
        acp.update(ri=_new_ri(1), ct=_now(), lt=_now(), et=NEVER_EXPIRES)
        return [_envelope_to_pub(ctx, _reply_envelope(msg, {"m2m:acp": acp}))]

    if rqi == "nodeCreate":
        nod = dict(pc.get("m2m:nod") or {})
        nod.update(ri=_new_ri(14), ct=_now(), lt=_now(), et=NEVER_EXPIRES)
        return [_envelope_to_pub(ctx, _reply_envelope(msg, {"m2m:nod": nod}))]

    if rqi == "firmwareCreate":
        fwr = dict(pc.get("m2m:fwr") or {})
        fwr.update(ri=_new_ri(13), ct=_now(), lt=_now(), et=NEVER_EXPIRES)
        return [_envelope_to_pub(ctx, _reply_envelope(msg, {"m2m:fwr": fwr}))]

    if rqi == "smartplugbootstrap":
        cin = pc.get("m2m:cin") or {}
        req_con = _b64_json_decode(cin.get("con"))
        content = (req_con or {}).get("content", {}).get("device", {})
        ack = {
            "header": {
                "version": "v2", "vendor_code": VENDOR_CODE, "api_key": "device_bootstrap",
                "device_id": content.get("id", ""), "device_uuid": content.get("id", ""),
                "device_type": content.get("type", "MULTITAP"), "device_model": DEVICE_MODEL,
                "ret_code": "200", "message": "success",
                "session_id": _session_id_for(ctx.client_id or b""),
            }
        }
        reply_pc = {"m2m:cin": {"et": NEVER_EXPIRES, "cnf": cin.get("cnf", "text/plain: 0"),
                                 "con": _b64_json_encode(ack)}}
        return [_envelope_to_pub(ctx, _reply_envelope(msg, reply_pc))]

    if rqi.startswith("plugeventreport") or rqi.startswith("controlreport") or "control-report" in rqi:
        return None  # 상태 리포트/ack — PUBACK만으로 충분(엔진이 이미 보냄), 응답 불필요

    print(f"[rules/99-default] 미인식 rqi={rqi!r} (PUBACK만 보내고 응답 없음)")
    return None


def _envelope_to_pub(ctx, envelope: dict) -> PublishSpec:
    topic = f"/oneM2M/resp/{(ctx.client_id or b'').decode(errors='replace')}/IN_CSE-BASE-1".encode()
    payload = json.dumps(envelope).encode()
    return PublishSpec(topic=topic, payload=payload, qos=1)


def _b64_json_decode(con):
    if not con:
        return None
    try:
        return json.loads(base64.b64decode(con))
    except Exception:
        return None


def _b64_json_encode(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


# --------------------------------------------------------------------------
# observer 로컬 주입 -> 실제 device_control oneM2M PUBLISH로 번역
#
# *** 미실증 ***: §16 펌웨어 디스어셈블로 형태는 확정했지만, 이 방향(서버->기기 명령)의
# 실제 와이어 캡처는 아직 없다. envelope의 to/fr은 req-resp 토픽 대칭성에서 추론한 것(§16.3
# 구독 토픽 `/oneM2M/req/IN_CSE-BASE-1/{client_id}`의 fr=IN_CSE-BASE-1, to={client_id}
# 패턴을 그대로 따름) — 처음 실기기로 시험할 때 반드시 사람이 지켜볼 것.
# --------------------------------------------------------------------------

def on_local_inject(ctx, cmd):
    if not ctx.device_client_id:
        print("[rules/99-default] 주입 대상 기기 세션 없음 — 무시")
        return None

    outlet = int(cmd.get("outlet", 1))
    on = bool(cmd.get("on", False))
    command = f"POWER{outlet}"
    inner = {
        "type": "control",
        "content": {
            "cmd_request": {
                "cmd_id": command,
                "parameters": [{"command": command, f"switchBinary{outlet}": "FF" if on else "00"}],
            }
        },
    }
    client_id = ctx.device_client_id.decode(errors="replace")
    envelope = {
        "op": "1",
        "to": f"/{client_id}",
        "fr": "/IN_CSE-BASE-1",
        "rqi": f"devicecontrol-{random.randint(10000, 99999)}",
        "ty": "4",
        "pc": {"m2m:cin": {"con": _b64_json_encode(inner)}},
    }
    topic = f"/oneM2M/req/IN_CSE-BASE-1/{client_id}".encode()
    return [PublishSpec(topic=topic, payload=json.dumps(envelope).encode(), qos=1)]
