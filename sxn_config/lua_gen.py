"""Helpers to render and execute Lua scripts for SXN configuration."""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Iterable

ROOT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT_DIR / "logs"
BASE_LUA_DIR = ROOT_DIR / "tio" / "base_SXN"


def _escape_cmd(cmd: str) -> str:
    """Escape quotes/backslashes for Lua string literals."""
    return cmd.replace("\\", "\\\\").replace('"', '\\"')


LUA_COMMON_HEADER = """-- Auto-generated SXN configuration script
local GATE = "{gate}"
local CONFIG_ID = {config_id}
local ADMIN_USER = "{user}"
local ADMIN_PASS = "{password}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local CONFIG_PROMPT = "SecOS-" .. GATE .. " \\(config\\)>"

local function login()
  msleep(500)
  write("\\n")
  local rc = expect("login:", 1000)
  if rc == 1 then
    write(ADMIN_USER .. "\\n")
    expect("Password:", 5000)
    write(ADMIN_PASS .. "\\n")
    expect(SYSTEM_PROMPT, 5000)
  else
    write("\\n")
    expect(SYSTEM_PROMPT, 5000)
  end
end

local function enter_config()
  write("config edit " .. CONFIG_ID .. "\\n")
  expect(CONFIG_PROMPT, 5000)
end

local function run_cmd(cmd)
  write(cmd .. "\\n")
  expect(CONFIG_PROMPT, 5000)
end

local function exit_and_save()
  write("exit\\n")
  expect(SYSTEM_PROMPT, 5000)
  write("config save " .. CONFIG_ID .. "\\n")
  expect(SYSTEM_PROMPT, 5000)
end

login()
enter_config()
"""


def render_block_lua(commands: Iterable[str], *, gate: str, user: str, password: str, config_id: int = 1) -> str:
    """Render a Lua script that logs in and executes commands inside config edit."""
    body = []
    for cmd in commands:
        body.append(f'run_cmd("{_escape_cmd(cmd)}")')
    body_lines = "\n".join(body)
    return "\n".join(
        [
            LUA_COMMON_HEADER.format(gate=gate, user=user, password=password, config_id=config_id),
            body_lines,
            "",
            "exit_and_save()",
            "exit(0)",
        ]
    )


def render_reboot_lua(*, gate: str) -> str:
    """Lua script to reboot the SXN then wait for login prompt."""
    return f"""-- reboot_and_wait_login_{gate}.lua
-- Redemarre le SXN puis attend le prompt "Sec-XN-{gate} login:"

local GATE = "{gate}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local LOGIN_PROMPT  = "Sec-XN-" .. GATE .. " login:"

msleep(500)
write("\\n")

local rc = expect(SYSTEM_PROMPT, 2000)

if rc == 1 then
  write("system reboot\\n")
  msleep(2000)
end

local rc2 = expect(LOGIN_PROMPT, 600000)

if rc2 ~= 1 then
  print("ERROR: login prompt 'Sec-XN-" .. GATE .. " login:' non vu apres reboot.")
  exit(1)
end

exit(0)
"""


def render_syslog_basic_lua(
    *,
    gate: str,
    user: str,
    password: str,
    config_id: int,
    iface: str,
    server: str,
    port: str,
    protocol: str = "tcp",
    extra_commands: list[str] | None = None,
) -> str:
    """Syslog basique (tcp/udp, sans TLS)."""
    protocol = protocol.lower()
    cmds = [
        f"syslog bind on iface {iface}",
        f"syslog set remote protocol {protocol}",
        f"syslog set remote addr {server} port {port}",
        "syslog enable remote",
    ]
    if extra_commands:
        cmds.extend(extra_commands)
    return render_block_lua(cmds, gate=gate, user=user, password=password, config_id=config_id)


def render_syslog_tls_lua(
    *,
    gate: str,
    user: str,
    password: str,
    config_id: int,
    iface: str,
    server: str,
    port: str,
    remote_cert: Path,
    remote_ca: Path,
    client_cert: Path,
    client_key: Path,
    client_ca: Path,
) -> str:
    """Syslog TLS avec import des certificats/cles (similaire au shell)."""
    return f"""-- syslog_tls_{gate}.lua
-- Configurer syslog TLS distant dans la config {config_id} pour la gate {gate}

local GATE = "{gate}"
local CONFIG_ID = {config_id}

local ADMIN_USER = "{user}"
local ADMIN_PASS = "{password}"

local SYSLOG_IFACE  = "{iface}"
local SYSLOG_SERVER = "{server}"
local SYSLOG_PORT   = {port}

local REMOTE_CERT_PATH  = "{remote_cert}"
local REMOTE_CA_PATH    = "{remote_ca}"

local CLIENT_CERT_PATH  = "{client_cert}"
local CLIENT_CA_PATH    = "{client_ca}"
local CLIENT_KEY_PATH   = "{client_key}"

local SYSTEM_PROMPT = "SecOS-" .. GATE .. ">"
local CONFIG_PROMPT = "SecOS-" .. GATE .. " \\(config\\)>"

local IMPORT_REMOTE_BLOCK1 = "Paste certificate here then type Ctrl"
local IMPORT_REMOTE_BLOCK2 = "Paste certificate chain here then type Ctrl"
local IMPORT_REMOTE_BLOCK3 = "Paste key here then type Ctrl"

local function send_pem_file(path)
  local f, err = io.open(path, "r")
  if not f then
    print("ERROR: cannot open " .. path .. ": " .. tostring(err))
    exit(1)
  end

  local data = f:read("*a")
  f:close()

  if not data or data == "" then
    print("ERROR: empty PEM file: " .. path)
    exit(1)
  end

  local ends_with_nl = (data:match("\\n$") ~= nil)

  for line in data:gmatch("([^\\r\\n]*)\\r?\\n") do
    write(line .. "\\n")
    msleep(30)
  end

  if not ends_with_nl then
    write("\\n")
    msleep(30)
  end
end

msleep(500)
write("\\n")
local rc = expect("login:", 1000)

if rc == 1 then
  write(ADMIN_USER .. "\\n")
  expect("Password:", 5000)
  write(ADMIN_PASS .. "\\n")
  expect(SYSTEM_PROMPT)
else
  write("\\n")
  expect(SYSTEM_PROMPT)
end

write("config edit " .. CONFIG_ID .. "\\n")
expect(CONFIG_PROMPT)

write("syslog bind on iface " .. SYSLOG_IFACE .. "\\n")
expect(CONFIG_PROMPT)

write("syslog set remote protocol tcp\\n")
expect(CONFIG_PROMPT)

write("syslog set remote addr " .. SYSLOG_SERVER .. " port " .. SYSLOG_PORT .. "\\n")
expect(CONFIG_PROMPT)

write("syslog enable remote\\n")
expect(CONFIG_PROMPT)

write("syslog set remote tls mode on\\n")
expect(CONFIG_PROMPT)

write("syslog import remote cert pem\\n")
expect(IMPORT_REMOTE_BLOCK1)
msleep(100)
send_pem_file(REMOTE_CERT_PATH)
write("\\4")
msleep(500)

expect(IMPORT_REMOTE_BLOCK2)
msleep(100)
send_pem_file(REMOTE_CA_PATH)
write("\\4")
msleep(500)

expect(CONFIG_PROMPT)

write("syslog set client tls auth cert\\n")
expect(CONFIG_PROMPT)

write("syslog import client cert pem\\n")
expect(IMPORT_REMOTE_BLOCK1)
msleep(100)
send_pem_file(CLIENT_CERT_PATH)
write("\\4")
msleep(500)

expect(IMPORT_REMOTE_BLOCK3)
msleep(100)
send_pem_file(CLIENT_KEY_PATH)
write("\\4")
msleep(500)

expect(IMPORT_REMOTE_BLOCK2)
msleep(100)
send_pem_file(CLIENT_CA_PATH)
write("\\4")
msleep(500)

expect(CONFIG_PROMPT)

write("exit\\n")
expect(SYSTEM_PROMPT)

write("config save " .. CONFIG_ID .. "\\n")
expect(SYSTEM_PROMPT)

exit(0)
"""


def run_tio_with_lua(lua_content: str, device: str, block_name: str, *, gate: str, log_dir: Path = LOG_DIR) -> None:
    """Write Lua content to disk, run tio, and append output to log."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    lua_path = BASE_LUA_DIR / f"sxn_{gate}_{block_name}_{timestamp}.lua"
    log_path = log_dir / f"sxn_{gate}_{block_name}_{timestamp}.log"

    lua_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lua_path.write_text(lua_content)

    cmd = ["tio", "--script-file", str(lua_path), device]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    output = (proc.stdout or "") + (proc.stderr or "")

    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(f"==== tio {block_name} on {device} ====\n")
        fh.write(output)
        fh.write("\n====================================\n")

    if proc.returncode != 0:
        raise RuntimeError(f"tio failed for block {block_name}: see {log_path}")
