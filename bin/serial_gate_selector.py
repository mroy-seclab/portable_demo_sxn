#!/usr/bin/env python3
"""Interactive helper to map SXN gates (A/B) to serial devices."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT_DIR / "logs"
CONFIG_DIR = ROOT_DIR / "config"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "gate_serial_mapping.json"
DETECT_LUA_SOURCE = ROOT_DIR / "tio" / "lua_scripts" / "detect_gate.lua"
DETECT_LUA_TARGET = ROOT_DIR / "tio" / "base_SXN" / "detect_gate.lua"


def run_command(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Wrapper around subprocess.run with text mode."""
    return subprocess.run(
        cmd,
        check=False,
        text=True,
        capture_output=True,
    )


def list_serial_ports() -> list[str]:
    """Return the list of serial ports reported by `tio -l`."""
    proc = run_command(["tio", "-l"])
    if proc.returncode != 0:
        raise RuntimeError(f"`tio -l` failed: {proc.stderr or proc.stdout}")

    ports: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("/dev/"):
            ports.append(line.split()[0])
    return ports


def choose_port(ports: list[str], prompt: str) -> str:
    """Ask the user to pick a port by number."""
    while True:
        choice = input(prompt).strip()
        if not choice.isdigit():
            print("Merci d'entrer un numero valide.")
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(ports):
            return ports[idx]
        print("Numero en dehors de la liste.")


def ensure_detect_script(source: Path, target: Path) -> Path:
    """Ensure detect_gate.lua exists at target, copying from source if needed."""
    if not source.exists():
        raise FileNotFoundError(f"Script Lua introuvable: {source}")

    target.parent.mkdir(parents=True, exist_ok=True)
    src_content = source.read_text()
    dst_content = target.read_text() if target.exists() else ""
    if src_content != dst_content:
        target.write_text(src_content)
    return target


def detect_gate_for_device(dev: str, detect_script: Path, log_file: Path) -> str | None:
    """Run tio with the detect script and return the gate letter if found."""
    cmd = ["tio", "--script-file", str(detect_script), dev]
    proc = run_command(cmd)
    output = (proc.stdout or "") + (proc.stderr or "")

    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(f"==== detect_gate_for_device({dev}) ====\n")
        fh.write(output)
        fh.write("\n========================================\n\n")

    for line in output.splitlines():
        if "GATE=" in line:
            value = line.split("GATE=", 1)[1].strip()
            if value and value != "?":
                return value[0]
    return None


def save_mapping(config_path: Path, mapping: dict[str, str]) -> None:
    """Persist the tty to gate mapping as JSON."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "updated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "mapping": mapping,
    }
    config_path.write_text(json.dumps(data, indent=2))


def load_mapping(config_path: Path) -> dict[str, str]:
    """Load an existing mapping file if present; returns {} otherwise."""
    if not config_path.exists():
        return {}
    try:
        payload = json.loads(config_path.read_text())
    except json.JSONDecodeError:
        return {}
    mapping = payload.get("mapping")
    return mapping if isinstance(mapping, dict) else {}


def detect_mapping_interactive(
    config_path: Path = DEFAULT_CONFIG_PATH,
    *,
    log_dir: Path = LOG_DIR,
) -> dict[str, str]:
    """Interactive mapping between gates and serial devices (persists to config)."""
    try:
        ports = list_serial_ports()
    except RuntimeError as exc:
        print(f"[ERREUR] Impossible de lister les ports serie: {exc}", file=sys.stderr)
        return {}

    if not ports:
        print("[ERREUR] Aucun port serie detecte via `tio -l`.", file=sys.stderr)
        return {}

    print("Ports serie disponibles :")
    for i, port in enumerate(ports, start=1):
        print(f"  {i}) {port}")
    print()

    print("Selectionne les ports correspondant aux SXN A et B.")
    dev1 = choose_port(ports, "Port pour le premier SXN (numero) : ")
    dev2 = choose_port(ports, "Port pour le second SXN (numero) : ")

    detect_script = ensure_detect_script(DETECT_LUA_SOURCE, DETECT_LUA_TARGET)
    log_file = log_dir / f"gate_detection_{datetime.now():%Y%m%d_%H%M%S}.log"

    mapping: dict[str, str] = {}
    for dev in (dev1, dev2):
        print(f"[INFO] Detection de la gate sur {dev} ...")
        gate = detect_gate_for_device(dev, detect_script, log_file)
        if not gate:
            print(f"[WARN] Impossible de determiner la gate sur {dev}.")
            continue
        if gate in mapping:
            print(f"[WARN] Gate {gate} deja associee a {mapping[gate]}, on ignore {dev}.")
            continue
        mapping[gate] = dev
        print(f"  -> {dev} <-> gate {gate}")

    if not mapping:
        print("[ERREUR] Aucun mapping gate detecte, abandon.", file=sys.stderr)
        return {}

    save_mapping(config_path, mapping)
    print()
    print(f"Mapping enregistre dans {config_path}:")
    for gate, dev in mapping.items():
        print(f"  gate {gate} : {dev}")
    print(f"Journal detaille: {log_file}")
    return mapping


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Detect serial ports, map gates A/B, and persist the result."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Fichier de sortie pour le mapping (defaut: {DEFAULT_CONFIG_PATH})",
    )
    args = parser.parse_args(argv)

    mapping = detect_mapping_interactive(args.config)
    if not mapping:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
