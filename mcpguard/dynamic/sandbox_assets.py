"""Files baked into the probe image: canary secrets and the capture proxy ("sink").

The sink listens on 127.0.0.1 inside a --network none container and is configured as
HTTP_PROXY/HTTPS_PROXY. Any HTTP request the server makes lands here and is logged to
stderr (prefixed MCPG-SINK) so MCPGuard can look for canary markers in outbound data.
For HTTPS (CONNECT) only the destination host:port is visible, which is still recorded.
"""

from __future__ import annotations

SINK_PORT = 8899

SINK_SCRIPT = r'''
import socket, sys, threading, base64

def handle(conn):
    try:
        conn.settimeout(3)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    pass
        while len(body) < min(length, 262144):
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        first = head.split(b"\r\n", 1)[0]
        payload = base64.b64encode(head + b"\r\n\r\n" + body).decode()
        sys.stderr.write("MCPG-SINK " + first.decode("latin-1") + " " + payload + "\n")
        sys.stderr.flush()
        if first.startswith(b"CONNECT"):
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                hello = conn.recv(4096)
                sys.stderr.write("MCPG-SINK TLS " + base64.b64encode(hello).decode() + "\n")
            except Exception:
                pass
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
    except Exception as exc:
        sys.stderr.write("MCPG-SINK ERROR " + str(exc) + "\n")
    finally:
        conn.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(16)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
'''.replace("PORT", str(SINK_PORT))

CANARY_PATHS = {
    "ssh": "/home/mcp/.ssh/id_rsa",
    "aws": "/home/mcp/.aws/credentials",
    "env": "/home/mcp/.env",
    "app_env": "/app/.env.mcpguard-canary",
}


def canary_contents(token: str) -> dict[str, str]:
    return {
        "ssh": f"-----BEGIN OPENSSH PRIVATE KEY-----\nMCPG-CANARY-SSH-{token}\n-----END OPENSSH PRIVATE KEY-----\n",
        "aws": f"[default]\naws_access_key_id = AKIAMCPGCANARY{token[:6].upper()}\n"
               f"aws_secret_access_key = MCPG-CANARY-AWS-{token}\n",
        "env": f"OPENAI_API_KEY=MCPG-CANARY-ENV-{token}\nDATABASE_URL=postgres://u:MCPG-CANARY-DB-{token}@db/x\n",
        "app_env": f"SECRET=MCPG-CANARY-APP-{token}\n",
    }


def probe_dockerfile_layer(token: str) -> str:
    """Dockerfile lines appended to the target image for probing (uses BuildKit heredocs)."""
    contents = canary_contents(token)
    lines = ["", "USER root", "RUN mkdir -p /home/mcp/.ssh /home/mcp/.aws /opt/mcpguard"]
    for key, path in CANARY_PATHS.items():
        lines += [f"COPY <<'MCPG_EOF' {path}", contents[key].rstrip("\n"), "MCPG_EOF"]
    lines += ["COPY <<'MCPG_EOF' /opt/mcpguard/sink.py", SINK_SCRIPT.strip("\n"), "MCPG_EOF",
              "RUN chown -R mcp:mcp /home/mcp && chmod 600 /home/mcp/.ssh/id_rsa", "USER mcp", ""]
    return "\n".join(lines)
