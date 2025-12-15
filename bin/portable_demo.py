#!/usr/bin/env python3
"""Orchestrateur Python pour le portable demo SXN (CLI, prêt pour GUI)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from serial_gate_selector import (  # type: ignore
    DEFAULT_CONFIG_PATH,
    detect_mapping_interactive,
    load_mapping,
)
from sxn_config import sxn

MODES = ("all", "sxn", "dockers")
DEFAULT_SXN_USER = "admin"
DEFAULT_SXN_PASSWORD = "SeclabFR2011!"
CERT_BASE_DIR = ROOT_DIR / "dockers" / "base_SXN" / "syslog-ng" / "cert"


def configure_sxn(
    mapping: dict[str, str],
    cmd_file: Path,
    user: str,
    password: str,
    config_id: int,
    syslog_mode: str,
    syslog_protocol: str,
    syslog_tls_paths: sxn.SyslogTlsPaths | None,
) -> None:
    """Configure SXN gates en séquences (net/clock/snmp) depuis un .cmd."""
    plan = sxn.parse_command_file(cmd_file)

    for gate, device in mapping.items():
        print(f"[SXN] Gate {gate} sur {device} avec {cmd_file}")
        try:
            sxn.run_plan(
                plan,
                gate=gate,
                user=user,
                password=password,
                device=device,
                config_id=config_id,
                syslog_mode=syslog_mode,
                syslog_protocol=syslog_protocol,
                syslog_tls_paths=syslog_tls_paths,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[ERREUR] Echec sur gate {gate}: {exc}")
            return


def configure_dockers(env_path: Path | None) -> None:
    """Placeholder pour la stack Docker."""
    print("[TODO] Stack Docker a implementer.")
    if env_path:
        print(f"  config env    : {env_path}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Setup portable demo SXN (Python).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--config-env",
        type=Path,
        help="Fichier de configuration .env (ex: config/sxn_lab.env)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=MODES,
        default="all",
        help="all = SXN + Dockers, sxn = seulement SXN, dockers = seulement Dockers",
    )
    parser.add_argument(
        "--gate-mapping",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Fichier JSON de mapping gate->tty",
    )
    parser.add_argument(
        "--skip-gate-detect",
        action="store_true",
        help="Ne pas lancer la detection, utiliser le mapping existant si present.",
    )
    parser.add_argument(
        "--sxn-cmd-file",
        type=Path,
        default=ROOT_DIR / "config" / "SECLAB-PRD-A-v1.cmd",
        help="Fichier .cmd a appliquer aux SXN.",
    )
    parser.add_argument(
        "--sxn-user",
        default=DEFAULT_SXN_USER,
        help="Login admin SXN.",
    )
    parser.add_argument(
        "--sxn-password",
        default=DEFAULT_SXN_PASSWORD,
        help="Mot de passe admin SXN.",
    )
    parser.add_argument(
        "--config-id",
        type=int,
        default=1,
        help="ID de configuration SXN a editer (config edit <id>).",
    )
    parser.add_argument(
        "--syslog-mode",
        choices=["basic", "tls"],
        default="basic",
        help="Mode syslog: basic (tcp/udp) ou tls (import certs).",
    )
    parser.add_argument(
        "--syslog-protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help="Protocol syslog distant (basic uniquement).",
    )
    parser.add_argument(
        "--syslog-remote-cert",
        type=Path,
        default=CERT_BASE_DIR / "server.crt",
        help="Certificat serveur distant (TLS).",
    )
    parser.add_argument(
        "--syslog-remote-ca",
        type=Path,
        default=CERT_BASE_DIR / "ca.crt",
        help="CA serveur distant (TLS).",
    )
    parser.add_argument(
        "--syslog-client-cert",
        type=Path,
        default=CERT_BASE_DIR / "client.crt",
        help="Certificat client (TLS).",
    )
    parser.add_argument(
        "--syslog-client-key",
        type=Path,
        default=CERT_BASE_DIR / "client.key",
        help="Clé privée client (TLS).",
    )
    parser.add_argument(
        "--syslog-client-ca",
        type=Path,
        default=CERT_BASE_DIR / "ca.crt",
        help="CA client (TLS).",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    mapping: dict[str, str] = {}
    if args.skip_gate_detect:
        mapping = load_mapping(args.gate_mapping)
        if not mapping:
            print("[ERREUR] Aucun mapping charge; relance sans --skip-gate-detect.")
            return 1
        print(f"[INFO] Mapping charge depuis {args.gate_mapping}: {mapping}")
    else:
        mapping = detect_mapping_interactive(args.gate_mapping)
        if not mapping:
            return 1

    syslog_tls_paths = None
    syslog_protocol = args.syslog_protocol
    if args.syslog_mode == "tls":
        syslog_protocol = "tcp"
        syslog_tls_paths = sxn.SyslogTlsPaths(
            remote_cert=args.syslog_remote_cert,
            remote_ca=args.syslog_remote_ca,
            client_cert=args.syslog_client_cert,
            client_key=args.syslog_client_key,
            client_ca=args.syslog_client_ca,
        )

    if args.mode in ("all", "sxn"):
        configure_sxn(
            mapping,
            args.sxn_cmd_file,
            args.sxn_user,
            args.sxn_password,
            args.config_id,
            args.syslog_mode,
            syslog_protocol,
            syslog_tls_paths,
        )

    if args.mode in ("all", "dockers"):
        configure_dockers(args.config_env)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
