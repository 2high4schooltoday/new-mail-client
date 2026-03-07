from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .screens import FIELD_INDEX_INSTALL, FIELD_INDEX_UNINSTALL, FieldDef


Operation = Literal["install", "uninstall", "diagnose", "status"]
StepKind = Literal["welcome", "form", "review", "status", "progress", "completion", "intro"]


@dataclass(frozen=True)
class AssistantStep:
    key: str
    title: str
    summary: str
    kind: StepKind
    fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class OperationMeta:
    key: Operation
    title: str
    short_title: str
    summary: str
    accent: str
    risk: str


OPERATIONS: tuple[OperationMeta, ...] = (
    OperationMeta(
        key="install",
        title="Install Or Upgrade Despatch",
        short_title="Install",
        summary="Prepare the host, configure network exposure, review the install contract, and run staged checks.",
        accent="Install / Upgrade",
        risk="LOW",
    ),
    OperationMeta(
        key="uninstall",
        title="Uninstall Despatch",
        short_title="Uninstall",
        summary="Back up selected data, review removal scope, and run a controlled teardown.",
        accent="Uninstall",
        risk="HIGH",
    ),
    OperationMeta(
        key="diagnose",
        title="Run Deployment Diagnostics",
        short_title="Diagnose",
        summary="Check service reachability, proxy wiring, and deployment health without destructive changes.",
        accent="Diagnose",
        risk="LOW",
    ),
    OperationMeta(
        key="status",
        title="Inspect Host Status",
        short_title="Status",
        summary="Read current service and environment status without changing the system.",
        accent="Status",
        risk="LOW",
    ),
)


INSTALL_FLOW: tuple[AssistantStep, ...] = (
    AssistantStep(
        key="scope",
        title="Install Scope And Host Summary",
        summary="Confirm the host target, fixed application paths, and whether Despatch should manage its systemd service.",
        kind="form",
        fields=("install_service",),
    ),
    AssistantStep(
        key="network",
        title="Network And Exposure",
        summary="Define the primary domain, listen address, and whether external traffic is routed through a reverse proxy.",
        kind="form",
        fields=("base_domain", "listen_addr", "proxy_setup", "proxy_server", "proxy_server_name"),
    ),
    AssistantStep(
        key="security",
        title="Security And Mail Auth",
        summary="Choose the mail authentication mode, optional SQL settings, TLS, firewall behavior, and dependency automation.",
        kind="form",
        fields=(
            "dovecot_auth_mode",
            "dovecot_auth_db_driver",
            "dovecot_auth_db_dsn",
            "proxy_tls",
            "proxy_cert",
            "proxy_key",
            "ufw_enable",
            "ufw_open_proxy_ports",
            "ufw_open_direct_port",
            "auto_install_deps",
            "run_diagnose",
        ),
    ),
    AssistantStep(
        key="review",
        title="Review",
        summary="Validate the install contract, inspect detected values, and start the installer when ready.",
        kind="review",
    ),
    AssistantStep(
        key="progress",
        title="Installing",
        summary="Despatch is executing the staged install flow and validating runtime invariants.",
        kind="progress",
    ),
    AssistantStep(
        key="completion",
        title="Completion",
        summary="The install flow has finished. Review result details and next actions.",
        kind="completion",
    ),
)

UNINSTALL_FLOW: tuple[AssistantStep, ...] = (
    AssistantStep(
        key="backup",
        title="Backup Policy",
        summary="Choose whether to preserve environment and data artifacts before removal.",
        kind="form",
        fields=("backup_env", "backup_data"),
    ),
    AssistantStep(
        key="removal",
        title="Removal Scope",
        summary="Select which files, users, proxy assets, and installer checkout paths should be removed.",
        kind="form",
        fields=(
            "remove_app_files",
            "remove_app_data",
            "remove_system_user",
            "remove_nginx_site",
            "remove_apache_site",
            "remove_checkout",
        ),
    ),
    AssistantStep(
        key="review",
        title="Review",
        summary="Confirm the removal contract and start the uninstall run when ready.",
        kind="review",
    ),
    AssistantStep(
        key="progress",
        title="Removing",
        summary="Despatch is tearing down selected components and exporting a final summary.",
        kind="progress",
    ),
    AssistantStep(
        key="completion",
        title="Completion",
        summary="The uninstall flow has finished. Review result details and next actions.",
        kind="completion",
    ),
)

DIAGNOSE_FLOW: tuple[AssistantStep, ...] = (
    AssistantStep(
        key="intro",
        title="Deployment Diagnostics",
        summary="Run non-destructive diagnostics against the current host and collect a summary artifact.",
        kind="intro",
    ),
    AssistantStep(
        key="progress",
        title="Running Diagnostics",
        summary="Despatch is verifying service, proxy, and network invariants.",
        kind="progress",
    ),
    AssistantStep(
        key="completion",
        title="Findings",
        summary="Diagnostics are complete. Review findings and next actions.",
        kind="completion",
    ),
)

STATUS_FLOW: tuple[AssistantStep, ...] = (
    AssistantStep(
        key="status",
        title="Host Status",
        summary="Inspect current host signals and jump into diagnostics if deeper checks are needed.",
        kind="status",
    ),
)


def operation_meta(key: Operation) -> OperationMeta:
    for item in OPERATIONS:
        if item.key == key:
            return item
    return OPERATIONS[0]


def operation_flow(key: Operation) -> tuple[AssistantStep, ...]:
    if key == "install":
        return INSTALL_FLOW
    if key == "uninstall":
        return UNINSTALL_FLOW
    if key == "diagnose":
        return DIAGNOSE_FLOW
    return STATUS_FLOW


def field_def(operation: Operation, name: str) -> FieldDef | None:
    if operation == "install":
        return FIELD_INDEX_INSTALL.get(name)
    if operation == "uninstall":
        return FIELD_INDEX_UNINSTALL.get(name)
    return None


def visible_fields(operation: Operation, step: AssistantStep, values: object) -> list[str]:
    names = list(step.fields)
    if operation == "install":
        auth_mode = str(getattr(values, "dovecot_auth_mode", "pam"))
        if auth_mode != "sql":
            names = [name for name in names if name not in {"dovecot_auth_db_driver", "dovecot_auth_db_dsn"}]
        if not bool(getattr(values, "proxy_setup", False)):
            names = [name for name in names if name not in {"proxy_server", "proxy_server_name", "proxy_tls", "proxy_cert", "proxy_key"}]
        elif not bool(getattr(values, "proxy_tls", False)):
            names = [name for name in names if name not in {"proxy_cert", "proxy_key"}]
        if not bool(getattr(values, "ufw_enable", False)):
            names = [name for name in names if name not in {"ufw_open_proxy_ports", "ufw_open_direct_port"}]
    return names
