from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OperationCard:
    key: str
    title: str
    summary: str
    risk: str
    prerequisites: str
    danger: bool = False


@dataclass(frozen=True)
class FieldDef:
    name: str
    label: str
    ftype: str
    options: tuple[str, ...] = ()
    help_text: str = ""
    display_options: tuple[tuple[str, str], ...] = ()
    empty_text: str = "Not set"


@dataclass(frozen=True)
class WizardStep:
    key: str
    title: str
    fields: tuple[str, ...]


INSTALL_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("base_domain", "Website address", "text", help_text="The address people will use to open Despatch."),
    FieldDef("listen_addr", "Internal port", "text", help_text="Where Despatch listens on this server, for example :8080."),
    FieldDef("install_service", "Start Despatch automatically with this server", "bool", help_text="Keeps Despatch running after a restart."),
    FieldDef("proxy_setup", "Connect Despatch to your web server", "bool", help_text="Recommended when you already use Nginx or Apache on this machine."),
    FieldDef("proxy_server", "Web server", "choice", ("nginx", "apache2"), display_options=(("nginx", "Nginx"), ("apache2", "Apache"))),
    FieldDef("proxy_server_name", "Public address", "text", help_text="The public address your web server should answer for."),
    FieldDef("proxy_tls", "Use HTTPS", "bool", help_text="Turn this on to serve Despatch over a secure connection."),
    FieldDef("proxy_cert", "HTTPS certificate file", "text", help_text="Path to the certificate file used for HTTPS."),
    FieldDef("proxy_key", "HTTPS private key file", "text", help_text="Path to the private key that matches the certificate."),
    FieldDef(
        "dovecot_auth_mode",
        "Sign-in source",
        "choice",
        ("pam", "sql"),
        help_text="Choose whether people sign in with system users on this server or a mailbox database.",
        display_options=(("pam", "System users on this server"), ("sql", "Database-backed mailbox logins")),
    ),
    FieldDef(
        "dovecot_auth_db_driver",
        "Database type",
        "choice",
        ("", "mysql", "pgx"),
        help_text="Only needed when sign-ins come from a database.",
        display_options=(("mysql", "MySQL / MariaDB"), ("pgx", "PostgreSQL")),
    ),
    FieldDef(
        "dovecot_auth_db_dsn",
        "Database connection string",
        "text",
        help_text="Only needed when sign-ins come from a database.",
    ),
    FieldDef("ufw_enable", "Adjust firewall rules", "bool", help_text="Lets the installer open the network access Despatch needs."),
    FieldDef("ufw_open_proxy_ports", "Open standard web ports", "bool", help_text="Open ports 80 and 443 for web traffic."),
    FieldDef("ufw_open_direct_port", "Open the app port directly", "bool", help_text="Open the internal Despatch port for direct access."),
    FieldDef("run_diagnose", "Check everything after install", "bool", help_text="Runs a final health check when setup is done."),
    FieldDef("auto_install_deps", "Install required packages automatically", "bool", help_text="Lets the installer add missing packages for you."),
)

UNINSTALL_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("backup_env", "Backup /opt/despatch/.env", "bool"),
    FieldDef("backup_data", "Backup /var/lib/despatch", "bool"),
    FieldDef("remove_app_files", "Remove /opt/despatch", "bool"),
    FieldDef("remove_app_data", "Remove /var/lib/despatch", "bool"),
    FieldDef("remove_system_user", "Remove System User", "bool"),
    FieldDef("remove_nginx_site", "Remove Nginx Site", "bool"),
    FieldDef("remove_apache_site", "Remove Apache2 Site", "bool"),
    FieldDef("remove_checkout", "Remove /opt/despatch-installer", "bool"),
)

INSTALL_STEPS: tuple[WizardStep, ...] = (
    WizardStep("general", "General", ("base_domain", "listen_addr", "install_service")),
    WizardStep("network", "Network", ("proxy_setup", "proxy_server", "proxy_server_name", "proxy_tls", "proxy_cert", "proxy_key")),
    WizardStep("mail_auth", "Mail Auth", ("dovecot_auth_mode", "dovecot_auth_db_driver", "dovecot_auth_db_dsn")),
    WizardStep("safety", "Safety", ("ufw_enable", "ufw_open_proxy_ports", "ufw_open_direct_port", "auto_install_deps", "run_diagnose")),
    WizardStep("review", "Review", ()),
)

UNINSTALL_STEPS: tuple[WizardStep, ...] = (
    WizardStep("general", "General", ("backup_env", "backup_data")),
    WizardStep("cleanup", "Cleanup", ("remove_app_files", "remove_app_data", "remove_system_user")),
    WizardStep("proxy", "Proxy", ("remove_nginx_site", "remove_apache_site", "remove_checkout")),
    WizardStep("review", "Review", ()),
)

FIELD_INDEX_INSTALL: dict[str, FieldDef] = {f.name: f for f in INSTALL_FIELDS}
FIELD_INDEX_UNINSTALL: dict[str, FieldDef] = {f.name: f for f in UNINSTALL_FIELDS}


def field_display_value(field: FieldDef, value: Any) -> str:
    if field.ftype == "bool":
        return "On" if bool(value) else "Off"
    shown = str(value or "")
    if field.display_options:
        return dict(field.display_options).get(shown, shown or field.empty_text)
    return shown or field.empty_text


def build_review_rows(obj: Any, fields: tuple[FieldDef, ...]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for field in fields:
        rows.append((field.label, field_display_value(field, getattr(obj, field.name, ""))))
    return rows


def build_review_lines(obj: Any, fields: tuple[FieldDef, ...]) -> list[str]:
    return [f"{label:<34} {value}" for label, value in build_review_rows(obj, fields)]
