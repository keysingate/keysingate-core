#!/usr/bin/env python3
"""MCP server: the demo agent's tools over the stand's reader (hackathon demo, steps 2-8).

Tools
  ksg_get_container  pay for a container number through μ Gate (x402), print it,
                     initiate it and open the journal
  ksg_write_page     record one step of the agent's work as a journal page
  ksg_export_page    export one page (pointwise export) to a file
  ksg_verify         check an exported page offline

Configuration (environment; paths only, no secret values):
  KSG_PANEL   path to ksg-remote-panel          (default: on PATH)
  KSG_VERIFY  path to ksg-verify-v2             (default: on PATH)
  KSG_TILL    path to the issuer's till example (ksg-pay-v2 examples/till)
  MU_SMOKE    path to μ Gate's ksg-smoke        (pays a 402 answer)
  KSG_WORK    working directory for containers  (default: ./ksg-work)
  KSG_CLASS   light | heavy                     (default: light; heavy needs real anchors)
  KSG_ISSUER  the issuer's payTo address        (default: the stand's test address)
  KSG_PRICE   price in USDC minor units         (default: 100000 = $0.10)
  KSG_ANCHOR  anchoring for heavy, e.g. solana:localnet (with KSG_PAYER, KSG_RPC)
  KSG_PAYER   path to the anchoring payer's keypair file
  KSG_RPC     the node's RPC URL (default: http://127.0.0.1:8899)

Run: python3 scripts/ksg_mcp.py   (stdio transport)
"""
import json
import os
import subprocess
import uuid
from pathlib import Path

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

PANEL = os.environ.get("KSG_PANEL", "ksg-remote-panel")
VERIFY = os.environ.get("KSG_VERIFY", "ksg-verify-v2")
TILL = os.environ.get("KSG_TILL", "till")
SMOKE = os.environ.get("MU_SMOKE", "ksg-smoke")
WORK = Path(os.environ.get("KSG_WORK", "ksg-work"))
CLASS = os.environ.get("KSG_CLASS", "light")
ISSUER = os.environ.get("KSG_ISSUER", "0x209693Bc6afc0C5328bA36FaF03C514EF312287C")
PRICE = os.environ.get("KSG_PRICE", "100000")
RESOURCE = "https://issuer.example/container/issue"
ANCHOR = os.environ.get("KSG_ANCHOR", "")
PAYER = os.environ.get("KSG_PAYER", "")
RPC = os.environ.get("KSG_RPC", "http://127.0.0.1:8899")

mcp = FastMCP("ksg")


def run(args, stdin=None):
    p = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{Path(args[0]).name} {args[1] if len(args) > 1 else ''}: "
                           f"{(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout


def box(name):
    d = WORK / name
    if not (d / "h" / "container.json").exists():
        raise RuntimeError(f"no container {name}")
    return d


def panel(d, *cmd, mobile=True):
    args = [PANEL, "--home", str(d / "h")]
    if mobile:
        args += ["--mobile", str(d / "m.json")]
    return run(args + list(cmd))


@mcp.tool()
def ksg_get_container() -> dict:
    """Pay for a container number through μ Gate (x402), print, initiate and open the journal.
    Returns the container's local name and its identifier."""
    required = run([TILL, "required", ISSUER, PRICE, RESOURCE])
    header = run([SMOKE], stdin=required)
    accepted = run([TILL, "accept", ISSUER, PRICE, RESOURCE], stdin=header).strip()
    name = "c-" + uuid.uuid4().hex[:8]
    d = WORK / name
    d.mkdir(parents=True)
    init = [PANEL, "--home", str(d / "h"), "init", "--class", CLASS]
    if ANCHOR:
        init += ["--anchor", ANCHOR, "--payer", PAYER, "--rpc", RPC]
    run(init)
    panel(d, "packet", mobile=False)
    panel(d, "buyer-key", mobile=False)
    panel(d, "initiate")
    panel(d, "open-journal")
    cid = json.loads((d / "h" / "container.json").read_text())["id"]
    return {"name": name, "container": cid, "class": CLASS, "payment": accepted}


@mcp.tool()
def ksg_write_page(name: str, text: str) -> dict:
    """Record one step of the agent's work (input, tool call, result) as a journal page."""
    d = box(name)
    panel(d, "work", "--did", text)
    pages = panel(d, "status", mobile=False)
    return {"name": name, "written": True, "status": pages.strip()[-300:]}


@mcp.tool()
def ksg_export_page(name: str, number: int, by: str = "owner") -> dict:
    """Export one journal page (pointwise export, the container lives on). by: owner | client."""
    d = box(name)
    out = d / f"page-{number}.json"
    panel(d, "export-page", "--number", str(number), "--by", by, "--out", str(out))
    data = json.loads(out.read_text())
    if isinstance(data, list):
        data = data[0]
        out.write_text(json.dumps(data))
    panel(d, "keys", "--out", str(d / "keys.json"), mobile=False)
    if ANCHOR:  # Pro seals are anchored blind: the expert reads them with the holder's scan key
        panel(d, "scan-key", "--out", str(d / "scan.key"), mobile=False)
    return {"file": str(out), "keys": str(d / "keys.json")}


@mcp.tool()
def ksg_verify(name: str, file: str) -> dict:
    """Check an exported page offline: no network, no platform, no issuer."""
    d = box(name)
    cid = json.loads((d / "h" / "container.json").read_text())["id"]
    args = [VERIFY, "--export", file, "--container", cid, "--class", CLASS,
            "--keys", str(d / "keys.json")]
    if ANCHOR:
        args += ["--scan-key", str(d / "scan.key"), "--rpc", RPC,
                 "--cluster", ANCHOR.split(":", 1)[1]]
    p = subprocess.run(args, capture_output=True, text=True)
    report = (p.stdout + p.stderr).strip()
    return {"accepted": report.startswith("ACCEPTED"), "report": report}


if __name__ == "__main__":
    mcp.run()
