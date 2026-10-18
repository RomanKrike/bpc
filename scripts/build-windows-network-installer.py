"""Package a verified GUI Agent with public network settings and embedded Wintun.

No invitation, password, Device private key or access credential is embedded.
The existing GUI login registers a fresh Device and obtains its user's Access.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
from pathlib import Path
from urllib.parse import urlsplit


def verified(path: Path, expected: str) -> bytes:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected.lower():
        raise ValueError(f"checksum mismatch: {path.name}")
    return data


def control_url(value: str) -> str:
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment):
        raise ValueError("Controller must be a plain HTTPS origin")
    _ = url.port
    return value.rstrip("/")


def build(agent: bytes, wintun: bytes, public_key: bytes, controllers: list[str],
          device: str, output: Path) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", device):
        raise ValueError("invalid Device display name")
    if len(agent) < 256 or agent[:2] != b"MZ" or wintun[:2] != b"MZ":
        raise ValueError("expected Windows PE Agent and Wintun")
    pe = struct.unpack_from("<I", agent, 0x3C)[0]
    if agent[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", agent, pe + 92)[0] != 2:
        raise ValueError("Agent must be a Windows GUI executable")
    if agent.endswith(b"BPC_AGENT_WINTUN_END\n"):
        raise ValueError("Agent already contains installer payload")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(serialization.load_pem_public_key(public_key), Ed25519PublicKey):
        raise ValueError("expected Ed25519 update public key")
    urls = list(dict.fromkeys(control_url(url) for url in controllers))
    if not urls:
        raise ValueError("at least one Controller is required")
    config = {"version": 3, "device": device, "control_url": urls[0], "control_urls": urls,
              "update_public_key": base64.b64encode(public_key).decode("ascii")}
    payload = base64.b64encode(json.dumps(config, separators=(",", ":")).encode())
    executable = (agent + b"\nBPC_AGENT_BOOTSTRAP_V3\n" + payload
                  + b"\nBPC_AGENT_BOOTSTRAP_END\n\nBPC_AGENT_WINTUN_V1\n"
                  + base64.b64encode(wintun) + b"\nBPC_AGENT_WINTUN_END\n")
    # Refuse overwrite; publish a completed directory atomically on the server.
    output.mkdir(parents=True, exist_ok=False)
    (output / "BPC-Connect-Setup.exe").write_bytes(executable)
    checksum = hashlib.sha256(executable).hexdigest()
    (output / "SHA256SUMS").write_text(checksum + "  BPC-Connect-Setup.exe\n", encoding="ascii")
    (output / "index.html").write_text('''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>BPC Connect — подключение к сети</title><link rel="stylesheet" href="/bpc/style.css"></head>
<body><main><div class="brand">BP Connect</div><h1>Ваша сеть — рядом</h1>
<p>Подключение к домашней сети на Windows 10 и 11, 64 бит.</p>
<a class="download" href="/bpc/BPC-Connect-Setup.exe" download>Скачать BPC Connect</a>
<ol><li>Откройте скачанный файл и подтвердите запрос Windows.</li>
<li>Введите логин и пароль, полученные от администратора сети.</li>
<li>Нажмите «Подключиться». Сервер выбирается автоматически.</li></ol>
<p>После установки приложение появится в меню «Пуск». Консоль и команды не нужны.</p>
<p class="note">Установщик пока без цифровой подписи издателя. Windows может показать
предупреждение; при сомнении уточните файл у администратора.
При переключении сервера игровые стримы могут потребовать повторного подключения.</p>
<a href="/bpc/SHA256SUMS">Контрольная сумма файла</a></main></body></html>''', encoding="utf-8")
    (output / "style.css").write_text('''
:root{font-family:Segoe UI,Arial,sans-serif;color:#102b25;background:#f1f6f4}
body{margin:0;padding:40px 20px}main{max-width:540px;margin:5vh auto;background:white;
padding:36px;border-radius:24px;box-shadow:0 12px 48px #163e2810}.brand{color:#087d3c;
font-size:24px;font-weight:800}h1{font-size:34px;line-height:1.15}p,li{line-height:1.6}
.download{display:block;background:#087d3c;color:white;padding:16px;text-align:center;
border-radius:12px;text-decoration:none;font-weight:700;margin:28px 0}a{color:#08743a}
a:focus-visible{outline:3px solid #dc8400;outline-offset:4px}li{margin:12px 0}
.note{font-size:13px;color:#596a63}@media(max-width:500px){main{padding:24px}h1{font-size:28px}}
''', encoding="utf-8")
    print(json.dumps({"sha256": checksum, "bytes": len(executable), "output": str(output)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("agent", "wintun", "update-public-key", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--agent-sha256", required=True)
    parser.add_argument("--wintun-sha256", required=True)
    parser.add_argument("--controller", action="append", required=True)
    parser.add_argument("--device", default="Windows-PC")
    args = parser.parse_args()
    build(verified(args.agent, args.agent_sha256), verified(args.wintun, args.wintun_sha256),
          args.update_public_key.read_bytes(), args.controller, args.device, args.output)
