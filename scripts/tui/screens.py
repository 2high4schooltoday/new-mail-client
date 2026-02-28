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


@dataclass(frozen=True)
class WizardStep:
    key: str
    title: str
    fields: tuple[str, ...]


INSTALL_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("base_domain", "Base Domain", "text", help_text="Primary mail domain used by setup."),
    FieldDef("listen_addr", "Listen Address", "text", help_text="Bind address for web service, e.g. :8080."),
    FieldDef("install_service", "Install Systemd Service", "bool"),
    FieldDef("proxy_setup", "Configure Reverse Proxy", "bool"),
    FieldDef("proxy_server", "Proxy Server", "choice", ("nginx", "apache2")),
    FieldDef("proxy_server_name", "Proxy Server Name", "text"),
    FieldDef("proxy_tls", "Enable Proxy TLS", "bool"),
    FieldDef("proxy_cert", "TLS Cert Path", "text"),
    FieldDef("proxy_key", "TLS Key Path", "text"),
    FieldDef("dovecot_auth_mode", "Dovecot Auth Mode", "choice", ("pam", "sql")),
    FieldDef("dovecot_auth_db_driver", "SQL Driver", "choice", ("", "mysql", "pgx")),
    FieldDef("dovecot_auth_db_dsn", "SQL DSN", "text"),
    FieldDef("ufw_enable", "Enable UFW", "bool"),
    FieldDef("ufw_open_proxy_ports", "Open 80/443 in UFW", "bool"),
    FieldDef("ufw_open_direct_port", "Open 8080 in UFW", "bool"),
    FieldDef("run_diagnose", "Run Diagnose After Install", "bool"),
    FieldDef("auto_install_deps", "Auto-install Missing Dependencies", "bool"),
)

UNINSTALL_FIELDS: tuple[FieldDef, ...] = (
    FieldDef("backup_env", "Backup /opt/mailclient/.env", "bool"),
    FieldDef("backup_data", "Backup /var/lib/mailclient", "bool"),
    FieldDef("remove_app_files", "Remove /opt/mailclient", "bool"),
    FieldDef("remove_app_data", "Remove /var/lib/mailclient", "bool"),
    FieldDef("remove_system_user", "Remove System User", "bool"),
    FieldDef("remove_nginx_site", "Remove Nginx Site", "bool"),
    FieldDef("remove_apache_site", "Remove Apache2 Site", "bool"),
    FieldDef("remove_checkout", "Remove /opt/mailclient-installer", "bool"),
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


def build_review_lines(obj: Any, fields: tuple[FieldDef, ...]) -> list[str]:
    lines: list[str] = []
    for field in fields:
        value = getattr(obj, field.name, "")
        if isinstance(value, bool):
            shown = "Enabled" if value else "Disabled"
        else:
            shown = str(value) or "(empty)"
        lines.append(f"{field.label:<34} {shown}")
    return lines
