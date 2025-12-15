"""SXN configuration helpers: parse .cmd and push blocks via tio/Lua."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import List, Optional, Tuple

from . import lua_gen


@dataclasses.dataclass
class SxnCommandPlan:
    net: list[str]
    clock: list[str]
    syslog: list[str]
    snmp: list[str]
    remaining: list[str]

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "net": self.net,
            "clock": self.clock,
            "syslog": self.syslog,
            "snmp": self.snmp,
            "remaining": self.remaining,
        }


def normalize_line(line: str) -> str:
    return " ".join(line.strip().split())


def parse_command_file(cmd_path: Path) -> SxnCommandPlan:
    """Parse a .cmd file into logical blocks (net, clock/ntp, syslog, snmp)."""
    if not cmd_path.exists():
        raise FileNotFoundError(f"Fichier .cmd introuvable: {cmd_path}")

    net: List[str] = []
    clock: List[str] = []
    syslog_cmds: List[str] = []
    snmp: List[str] = []
    remaining: List[str] = []

    with cmd_path.open() as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                continue

            line = normalize_line(stripped)

            if line.startswith("config edit") or line.startswith("config save"):
                continue

            if line.startswith("net "):
                net.append(line)
            elif line.startswith("clock ") or line.startswith("ntp "):
                clock.append(line)
            elif line.startswith("syslog "):
                syslog_cmds.append(line)
            elif line.startswith("snmpd ") or line.startswith("snmp "):
                snmp.append(line)
            else:
                remaining.append(line)

    return SxnCommandPlan(net=net, clock=clock, syslog=syslog_cmds, snmp=snmp, remaining=remaining)


def run_block(block_name: str, commands: list[str], *, gate: str, user: str, password: str, device: str, config_id: int = 1) -> None:
    """Render and execute a Lua block if commands exist."""
    if not commands:
        print(f"[INFO] Bloc {block_name} : rien à exécuter.")
        return
    lua = lua_gen.render_block_lua(commands, gate=gate, user=user, password=password, config_id=config_id)
    lua_gen.run_tio_with_lua(lua, device, block_name, gate=gate)
    print(f"[OK] Bloc {block_name} exécuté ({len(commands)} commandes).")


def run_reboot(*, gate: str, device: str) -> None:
    """Execute reboot-and-wait block."""
    lua = lua_gen.render_reboot_lua(gate=gate)
    lua_gen.run_tio_with_lua(lua, device, "reboot", gate=gate)
    print(f"[OK] Reboot SXN gate {gate} termine (login vu).")


def parse_syslog_settings(commands: list[str]) -> dict[str, Optional[str]]:
    """Extract iface/server/port/protocol from syslog commands."""
    settings: dict[str, Optional[str]] = {"iface": None, "server": None, "port": None, "protocol": None}
    for cmd in commands:
        if cmd.startswith("syslog bind on iface"):
            parts = cmd.split()
            if len(parts) >= 5:
                settings["iface"] = parts[-1]
        elif cmd.startswith("syslog set remote protocol"):
            parts = cmd.split()
            if len(parts) >= 5:
                settings["protocol"] = parts[-1]
        elif cmd.startswith("syslog set remote addr"):
            parts = cmd.split()
            # expected: syslog set remote addr <server> port <port>
            if len(parts) >= 7:
                settings["server"] = parts[4]
                settings["port"] = parts[6]
    return settings


def override_syslog_protocol(commands: list[str], protocol: str) -> list[str]:
    """Override or inject syslog protocol command."""
    protocol = protocol.lower()
    updated: list[str] = []
    has_protocol = False
    for cmd in commands:
        if cmd.startswith("syslog set remote protocol"):
            updated.append(f"syslog set remote protocol {protocol}")
            has_protocol = True
        else:
            updated.append(cmd)
    if not has_protocol:
        updated.insert(0, f"syslog set remote protocol {protocol}")
    return updated


def split_syslog_commands(commands: list[str]) -> Tuple[list[str], list[str]]:
    """Split syslog commands into base (bind/remote) and extras."""
    base_prefixes = (
        "syslog bind on iface",
        "syslog set remote protocol",
        "syslog set remote addr",
        "syslog enable remote",
    )
    base = []
    extras = []
    for cmd in commands:
        if any(cmd.startswith(prefix) for prefix in base_prefixes):
            base.append(cmd)
        else:
            extras.append(cmd)
    return base, extras


def run_syslog(
    commands: list[str],
    *,
    gate: str,
    user: str,
    password: str,
    device: str,
    config_id: int,
    mode: str,
    protocol: str,
    tls_paths: Optional["SyslogTlsPaths"],
) -> bool:
    """Execute syslog block (basic or TLS). Returns True if something ran."""
    mode = mode.lower()
    protocol = protocol.lower()
    base_cmds, extras = split_syslog_commands(commands)

    if mode == "basic":
        ran = False
        if base_cmds:
            cmds = override_syslog_protocol(base_cmds, protocol)
            run_block("syslog", cmds, gate=gate, user=user, password=password, device=device, config_id=config_id)
            ran = True
        if extras:
            run_block("syslog_extra", extras, gate=gate, user=user, password=password, device=device, config_id=config_id)
            ran = True
        if not ran:
            print("[INFO] Bloc syslog (basic) : aucune commande à exécuter.")
        return ran

    if mode == "tls":
        if not tls_paths:
            raise ValueError("tls_paths requis pour mode syslog TLS")
        settings = parse_syslog_settings(base_cmds)
        iface = settings.get("iface") or ""
        server = settings.get("server") or ""
        port = settings.get("port") or "6514"
        if not iface or not server:
            raise ValueError("Impossible de determiner iface/serveur pour syslog TLS (commande syslog bind/set remote manquante).")
        for path in dataclasses.asdict(tls_paths).values():
            if not path.exists():
                raise FileNotFoundError(f"Fichier TLS manquant pour syslog: {path}")
        lua = lua_gen.render_syslog_tls_lua(
            gate=gate,
            user=user,
            password=password,
            config_id=config_id,
            iface=iface,
            server=server,
            port=port,
            remote_cert=tls_paths.remote_cert,
            remote_ca=tls_paths.remote_ca,
            client_cert=tls_paths.client_cert,
            client_key=tls_paths.client_key,
            client_ca=tls_paths.client_ca,
        )
        lua_gen.run_tio_with_lua(lua, device, "syslog_tls", gate=gate)
        print(f"[OK] Bloc syslog TLS exécuté pour gate {gate}.")
        if extras:
            run_block("syslog_extra", extras, gate=gate, user=user, password=password, device=device, config_id=config_id)
        return True

    raise ValueError(f"Mode syslog inconnu: {mode}")


@dataclasses.dataclass
class SyslogTlsPaths:
    remote_cert: Path
    remote_ca: Path
    client_cert: Path
    client_key: Path
    client_ca: Path


def run_plan(
    plan: SxnCommandPlan,
    *,
    gate: str,
    user: str,
    password: str,
    device: str,
    config_id: int = 1,
    reboot_after: tuple[str, ...] = ("net", "clock", "syslog", "snmp"),
    syslog_mode: str = "basic",
    syslog_protocol: str = "tcp",
    syslog_tls_paths: Optional[SyslogTlsPaths] = None,
) -> None:
    """Execute known blocks sequentially, with optional reboot after certain blocks."""
    for block_name, commands in (
        ("net", plan.net),
        ("clock", plan.clock),
    ):
        run_block(block_name, commands, gate=gate, user=user, password=password, device=device, config_id=config_id)
        if commands and block_name in reboot_after:
            run_reboot(gate=gate, device=device)

    syslog_ran = run_syslog(
        plan.syslog,
        gate=gate,
        user=user,
        password=password,
        device=device,
        config_id=config_id,
        mode=syslog_mode,
        protocol=syslog_protocol,
        tls_paths=syslog_tls_paths,
    )
    if syslog_ran and "syslog" in reboot_after:
        run_reboot(gate=gate, device=device)

    run_block("snmp", plan.snmp, gate=gate, user=user, password=password, device=device, config_id=config_id)
    if plan.snmp and "snmp" in reboot_after:
        run_reboot(gate=gate, device=device)

    if plan.remaining:
        print("[WARN] Commandes non traitées (à implémenter) :")
        for cmd in plan.remaining:
            print(f"  - {cmd}")
        print("Aucune action exécutée pour ces lignes.")
