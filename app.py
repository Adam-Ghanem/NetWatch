from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from advisory_engine import advice_to_markdown, build_advice
from config import APP_NAME, APP_VERSION
from export_utils import safe_csv_bytes
from history_store import add_history, load_history
from host_profiler import profile_host
from inventory_store import (
    add_scan_run,
    asset_inventory,
    asset_port_findings,
    init_db,
    recent_asset_events,
    recent_audit_log,
    recent_scan_runs,
    record_audit_event,
    record_network_scan,
    update_asset_context,
    update_asset_ports,
    upsert_hosts,
)
from logger import log_event
from network_scanner import scan_network
from network_tools import guess_gateway, network_profile
from port_scanner import scan_ports
from report_builder import build_html_report, build_markdown_report
from risk_engine import RiskSummary, summarize_exposure, top_recommendations
from safe_text import clean_text
from security import validate_cidr, validate_target_ip
from ui_components import premium_css, premium_hero, premium_sidebar

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.markdown(
    r"""
<style>
:root{--paper:#f7f4ee;--ink:#111;--muted:#756f66;--card:#fffdf8}
.stApp{background:linear-gradient(90deg,rgba(17,17,17,.045) 1px,transparent 1px),linear-gradient(180deg,rgba(17,17,17,.045) 1px,transparent 1px),var(--paper);background-size:44px 44px;color:var(--ink)}
.block-container{max-width:1340px;padding-top:2rem}.main .block-container{padding-left:3rem;padding-right:3rem}
div[data-testid="stSidebarContent"]{background:#fff;border-right:2px solid var(--ink);padding-top:1.2rem}div[data-testid="stSidebarContent"] img{display:none}div[data-testid="stSidebarContent"] *{color:var(--ink)!important}
.brand-card{border:2px solid var(--ink);border-radius:18px;background:var(--paper);padding:1.2rem 1.25rem;margin:.5rem 0 1.4rem}.brand-title{font-size:1.55rem;font-weight:950;letter-spacing:-.05em}.brand-sub{color:var(--muted)!important;font-size:.92rem;margin-top:.2rem}
.metric-card{border:2px solid var(--ink);border-radius:20px;background:#fff;padding:1.2rem 1.35rem;min-height:135px;box-shadow:9px 9px 0 var(--ink)}.metric-label{color:var(--muted);font-size:.84rem;text-transform:uppercase;letter-spacing:.11em;font-weight:950}.metric-value{font-size:2.7rem;line-height:1;font-weight:950;letter-spacing:-.04em;margin-top:.5rem}.metric-note{color:var(--muted);font-size:1rem;margin-top:.45rem}.panel{border:2px solid var(--ink);border-radius:20px;background:var(--card);padding:1.2rem 1.35rem;margin-bottom:1rem}.section-title{font-size:1.05rem;letter-spacing:.13em;text-transform:uppercase;font-weight:950;margin:1.35rem 0 .8rem}.muted{color:var(--muted);line-height:1.5;font-size:1rem}.stButton>button,.stDownloadButton>button{border:2px solid var(--ink)!important;border-radius:999px!important;background:var(--ink)!important;color:var(--paper)!important;font-weight:900!important;text-transform:uppercase;letter-spacing:.04em}.stTextInput input{border:2px solid var(--ink)!important;border-radius:14px!important;background:#fff!important;color:var(--ink)!important}div[data-testid="stDataFrame"]{border:2px solid var(--ink);border-radius:18px;overflow:hidden;background:#fff}
</style>
""",
    unsafe_allow_html=True,
)
st.markdown(premium_css(), unsafe_allow_html=True)


def add_event(event: str) -> None:
    stamped = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {event}"
    st.session_state.events.insert(0, stamped)
    st.session_state.events = st.session_state.events[:20]
    log_event(event)


def init_state() -> None:
    init_db()
    st.session_state.setdefault(
        "network_results", pd.DataFrame(columns=["IP Address", "Status", "Details"])
    )
    st.session_state.setdefault(
        "port_results",
        pd.DataFrame(columns=["Port", "Protocol", "Service", "Status", "Risk", "Recommendation"]),
    )
    st.session_state.setdefault("events", [])


def metric_card(label: str, value: str | int | float, note: str = "") -> None:
    st.markdown(
        "<div class='metric-card'>"
        f"<div class='metric-label'>{clean_text(label, 80)}</div>"
        f"<div class='metric-value'>{clean_text(value, 120)}</div>"
        f"<div class='metric-note'>{clean_text(note, 220)}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def hero() -> None:
    st.markdown(premium_hero(APP_VERSION), unsafe_allow_html=True)


def empty_panel(title: str, message: str) -> None:
    st.markdown(
        "<div class='panel'>"
        f"<div class='section-title'>{clean_text(title, 120)}</div>"
        f"<div class='muted'>{clean_text(message, 500)}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def section_title(title: str) -> None:
    st.markdown(
        f'<div class="section-title">{clean_text(title, 100)}</div>', unsafe_allow_html=True
    )


def require_authorization(label: str) -> bool:
    return st.checkbox(
        label,
        value=False,
        help="Confirm you are testing only systems you own or are allowed to check.",
    )


def current_exposure() -> RiskSummary:
    ports_df = active_ports()
    return summarize_exposure(ports_df.to_dict("records"))


def active_ports() -> pd.DataFrame:
    ports_df = st.session_state.port_results
    return ports_df if not ports_df.empty else pd.DataFrame(asset_port_findings())


def active_hosts() -> pd.DataFrame:
    hosts_df = st.session_state.network_results
    return hosts_df if not hosts_df.empty else pd.DataFrame(asset_inventory())


def show_overview() -> None:
    hero()
    hosts_df = st.session_state.network_results
    exposure = current_exposure()
    inventory = asset_inventory()
    runs = recent_scan_runs(limit=8)
    changes = recent_asset_events(limit=8)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Online hosts", len(hosts_df), "Latest scan")
    with c2:
        metric_card("Inventory", len(inventory), "Saved assets")
    with c3:
        metric_card("Open ports", exposure.open_ports, "Review needed")
    with c4:
        metric_card("Exposure", exposure.level, f"Score: {exposure.score}")

    left, right = st.columns([1.05, 0.95])
    with left:
        section_title("Risk overview")
        ports_df = active_ports()
        if ports_df.empty:
            empty_panel(
                "No port audit yet", "Run a Port Audit to build risk charts and recommendations."
            )
        else:
            chart_df = ports_df.groupby(["Status", "Risk"]).size().reset_index(name="Count")
            fig = px.bar(
                chart_df,
                x="Status",
                y="Count",
                color="Risk",
                barmode="group",
                title="Port status by risk",
            )
            fig.update_layout(
                height=330,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#111111",
            )
            st.plotly_chart(fig, use_container_width=True)
    with right:
        section_title("Recent saved runs")
        if runs:
            st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
        else:
            empty_panel("Quiet for now", "Checks will appear here after you run them.")

    section_title("Recent asset changes")
    if changes:
        st.dataframe(pd.DataFrame(changes), use_container_width=True, hide_index=True)
    else:
        empty_panel("No changes recorded", "Run a network scan to establish a baseline.")


def show_network_scan() -> None:
    hero()
    section_title("Network Scan")
    col_form, col_help = st.columns([1.1, 0.9])
    with col_form:
        cidr = st.text_input("Local CIDR range", "192.168.1.0/24")
        validation = validate_cidr(cidr)
        if validation.ok:
            st.success(f"Valid local range: {validation.value}")
        else:
            st.warning(validation.error)
        authorized = require_authorization("I have permission to check this local network.")
        start = st.button(
            "Start scan", type="primary", disabled=(not authorized or not validation.ok)
        )
    with col_help:
        profile = network_profile(cidr)
        empty_panel(
            "Scan rules",
            f"Network: {profile.cidr} | Usable: {profile.usable_hosts} | Gateway guess: {guess_gateway(cidr)}",
        )
    if start:
        with st.spinner("Checking local hosts..."):
            try:
                target = validation.value or cidr
                results = scan_network(target)
                hosts_df = pd.DataFrame(results)
                st.session_state.network_results = hosts_df
                changes = record_network_scan(target, results)
                record_audit_event("legacy", "network_scan", target, "completed", changes.summary)
                add_event(f"Network scan completed for {target}: {changes.summary}")
                add_history("network", target, changes.summary)
                st.success(changes.summary)
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    metric_card("Observed", len(changes.observed_assets), "Latest snapshot")
                with c2:
                    metric_card("New", len(changes.new_assets), "First observed")
                with c3:
                    metric_card("Returned", len(changes.returned_assets), "Observed again")
                with c4:
                    metric_card(
                        "Not observed",
                        len(changes.not_observed_assets),
                        "No reply; verify manually",
                    )
            except ValueError as exc:
                st.error(str(exc))
                add_scan_run("network", cidr, str(exc), status="blocked")
    hosts_df = st.session_state.network_results
    if hosts_df.empty:
        empty_panel("No hosts displayed", "Run a scan to populate the table.")
    else:
        st.dataframe(hosts_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download hosts CSV", safe_csv_bytes(hosts_df), "netwatch_hosts.csv", "text/csv"
        )


def show_host_check() -> None:
    hero()
    section_title("Host Check + Profile")
    ip = st.text_input("Private/local IP address", "192.168.1.1")
    validation = validate_target_ip(ip)
    if validation.ok:
        st.info(f"Target accepted: {validation.value}")
    else:
        st.warning(validation.error)
    authorized = require_authorization("I have permission to check this host precisely.")
    if st.button(
        "Check host precisely",
        type="primary",
        disabled=(not authorized or not validation.ok),
    ):
        target = validation.value or ip
        profile = profile_host(target)
        status = "online" if profile.online else "offline/blocked"
        msg = f"{profile.notes}; latency={profile.latency_ms}; ttl={profile.ttl}; hostname={profile.hostname}"
        add_event(f"Host profile for {target}: {msg}")
        add_history("host_profile", target, msg, status=status)
        scan_run_id = add_scan_run("host_profile", target, msg, status=status)
        if profile.online:
            upsert_hosts(
                [
                    {
                        "IP Address": profile.ip_address,
                        "Status": "Online",
                        "Details": profile.notes,
                        "Hostname": profile.hostname,
                        "MAC Address": profile.mac_address,
                        "Manufacturer": profile.manufacturer,
                        "Device Name": profile.device_name,
                        "Device Type": profile.device_type,
                        "Device Family": profile.device_family,
                        "Identity Confidence": profile.identity_confidence,
                        "Identity Source": profile.identity_source,
                        "Randomized MAC": profile.randomized_mac,
                    }
                ],
                source="host check",
                scan_run_id=scan_run_id,
            )
            st.success("Host replied to ICMP ping")
        else:
            st.error(profile.notes)
        record_audit_event("legacy", "host_check", target, "completed", f"Status: {status}.")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("Status", status, profile.notes)
        with c2:
            metric_card(
                "Latency",
                profile.latency_ms if profile.latency_ms is not None else "-",
                "milliseconds",
            )
        with c3:
            metric_card("TTL", profile.ttl if profile.ttl is not None else "-", profile.os_hint)
        with c4:
            metric_card("Hostname", profile.hostname, "reverse DNS")
        st.dataframe(pd.DataFrame([profile.__dict__]), use_container_width=True, hide_index=True)


def show_port_audit() -> None:
    hero()
    section_title("Port Audit + Service Details")
    col1, col2 = st.columns([1, 1])
    with col1:
        ip = st.text_input("Target private/local IP", "192.168.1.1")
        validation = validate_target_ip(ip)
        if validation.ok:
            st.success(f"Target accepted: {validation.value}")
        else:
            st.warning(validation.error)
        authorized = require_authorization("I have permission to check this host.")
        scan = st.button(
            "Audit common ports", type="primary", disabled=(not authorized or not validation.ok)
        )
    with col2:
        empty_panel(
            "More detailed output",
            "Each port includes protocol, response time, service description and recommendation.",
        )
    if scan:
        with st.spinner("Auditing common ports..."):
            target = validation.value or ip
            results = scan_ports(target)
            ports_df = pd.DataFrame(results)
            st.session_state.port_results = ports_df
            exposure = summarize_exposure(results)
            msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}"
            add_event(f"Port audit completed for {target}: {msg}")
            add_history("ports", target, msg)
            scan_run_id = add_scan_run("ports", target, msg)
            update_asset_ports(
                target,
                results,
                exposure.score,
                exposure.level,
                scan_run_id=scan_run_id,
            )
            record_audit_event("legacy", "port_audit", target, "completed", msg)
            st.success(msg)
    ports_df = st.session_state.port_results
    if ports_df.empty:
        empty_panel("No port results yet", "Run a port audit to see service metadata.")
        return
    exposure = current_exposure()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Checked", exposure.checked, "Ports in list")
    with c2:
        metric_card("Open", exposure.open_ports, "Detected open")
    with c3:
        metric_card("High", exposure.high, "Needs review")
    with c4:
        metric_card("Exposure", exposure.level, f"Score: {exposure.score}")
    top_items = top_recommendations(ports_df.to_dict("records"))
    if top_items:
        section_title("Top recommendations")
        st.dataframe(pd.DataFrame(top_items), use_container_width=True, hide_index=True)
    st.dataframe(ports_df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download detailed port CSV",
        safe_csv_bytes(ports_df),
        "netwatch_detailed_ports.csv",
        "text/csv",
    )


def show_risk_advisor() -> None:
    hero()
    section_title("Risk Advisor")
    hosts_df = active_hosts()
    ports_df = active_ports()
    inventory = asset_inventory()
    changes = recent_asset_events(limit=25)
    advice = build_advice(
        hosts_df.to_dict("records"),
        ports_df.to_dict("records"),
        inventory,
        changes,
    )
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("Risk level", advice.risk_level, "Advisor output")
    with c2:
        metric_card("Confidence", advice.confidence, "Based on data")
    with c3:
        metric_card("Inventory", len(inventory), "Saved assets")
    empty_panel("Advisor summary", advice.summary)
    section_title("Priority findings")
    st.dataframe(
        pd.DataFrame({"Priority": advice.priorities}), use_container_width=True, hide_index=True
    )
    section_title("Suggested next steps")
    st.dataframe(
        pd.DataFrame({"Next step": advice.next_steps}), use_container_width=True, hide_index=True
    )
    markdown = advice_to_markdown(advice)
    st.download_button(
        "Download advisor notes",
        markdown.encode("utf-8"),
        "netwatch_advisor_notes.md",
        "text/markdown",
    )


def show_inventory() -> None:
    hero()
    section_title("Asset Inventory")
    inventory = asset_inventory()
    if not inventory:
        empty_panel("Inventory is empty", "Run checks to save local assets here.")
        return
    inventory_df = pd.DataFrame(inventory)
    st.dataframe(inventory_df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download inventory CSV", safe_csv_bytes(inventory_df), "netwatch_inventory.csv", "text/csv"
    )
    section_title("Company asset context")
    st.caption(
        "Legacy local interface. Use the FastAPI dashboard when role-based access is required."
    )
    selected_ip = st.selectbox(
        "Saved asset",
        options=[row["ip_address"] for row in inventory],
        key="legacy_context_asset",
    )
    selected = next(row for row in inventory if row["ip_address"] == selected_ip)
    with st.form("legacy_asset_context"):
        owner = st.text_input("Owner", value=selected.get("owner", ""), max_chars=120)
        department = st.text_input(
            "Department", value=selected.get("department", ""), max_chars=120
        )
        location = st.text_input("Location", value=selected.get("location", ""), max_chars=120)
        criticalities = ["Low", "Medium", "High", "Critical"]
        current_criticality = selected.get("criticality", "Medium")
        criticality = st.selectbox(
            "Criticality",
            options=criticalities,
            index=(
                criticalities.index(current_criticality)
                if current_criticality in criticalities
                else 1
            ),
        )
        notes = st.text_area(
            "Operational notes (do not store secrets)",
            value=selected.get("notes", ""),
            max_chars=1_000,
        )
        save_context = st.form_submit_button("Save asset context")
    if save_context:
        update_asset_context(
            selected_ip,
            owner=owner,
            department=department,
            location=location,
            criticality=criticality,
            notes=notes,
            actor_role="legacy",
        )
        st.success("Asset context saved and added to the operations audit log.")
    changes = recent_asset_events(limit=50)
    section_title("Recent asset changes")
    if changes:
        st.dataframe(pd.DataFrame(changes), use_container_width=True, hide_index=True)
    else:
        empty_panel("No changes recorded", "Run a network scan to establish a baseline.")


def show_network_tools() -> None:
    hero()
    section_title("Network Tools")
    cidr = st.text_input("CIDR to analyze", "192.168.1.0/24")
    profile = network_profile(cidr, sample_size=12)
    if profile.scan_allowed:
        st.success(profile.message)
    else:
        st.warning(profile.message)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Network", profile.network_address, f"/{profile.prefix_length}")
    with c2:
        metric_card("Netmask", profile.netmask, "IPv4 mask")
    with c3:
        metric_card("Broadcast", profile.broadcast_address, "Last address")
    with c4:
        metric_card("Usable", profile.usable_hosts, "Host addresses")
    if profile.first_hosts:
        st.code("\n".join(profile.first_hosts), language="text")


def show_reports() -> None:
    hero()
    section_title("Reports & History")
    hosts_df = active_hosts()
    ports_df = active_ports()
    changes_df = pd.DataFrame(recent_asset_events(limit=50))
    audit_df = pd.DataFrame(recent_audit_log(limit=100))
    markdown_report = build_markdown_report(hosts_df, ports_df, changes_df, audit_df)
    html_report = build_html_report(hosts_df, ports_df, changes_df, audit_df)
    c1, c2 = st.columns(2)
    with c1:
        st.download_button(
            "Download Markdown report",
            markdown_report.encode("utf-8"),
            "netwatch_report.md",
            "text/markdown",
        )
    with c2:
        st.download_button(
            "Download HTML report", html_report.encode("utf-8"), "netwatch_report.html", "text/html"
        )
    with st.expander("Preview Markdown report", expanded=True):
        st.markdown(markdown_report)
    runs = recent_scan_runs(limit=50)
    if runs:
        st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
    history = load_history(limit=25)
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)


def show_audit_log() -> None:
    hero()
    section_title("Operations Audit Log")
    st.caption("Records operational role, action, target, outcome, and time. Keys are not stored.")
    audit = recent_audit_log(limit=200)
    if audit:
        st.dataframe(pd.DataFrame(audit), use_container_width=True, hide_index=True)
    else:
        empty_panel("No operational events", "Run an authorized check to create an audit entry.")


def show_safety() -> None:
    hero()
    st.markdown("""
    ### Built-in limits
    - Private/local IP validation
    - Maximum CIDR size
    - Short common-port list
    - Authorization checkbox before network checks
    - Local Risk Advisor with local project data
    """)


init_state()
with st.sidebar:
    st.markdown(premium_sidebar(), unsafe_allow_html=True)
    st.caption(f"v{APP_VERSION}")
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Network Scan",
            "Host Check",
            "Port Audit",
            "Risk Advisor",
            "Inventory",
            "Audit Log",
            "Network Tools",
            "Reports",
            "Safety",
        ],
    )
    st.divider()
    st.caption("Private networks only. Keep it local and authorized.")

if page == "Overview":
    show_overview()
elif page == "Network Scan":
    show_network_scan()
elif page == "Host Check":
    show_host_check()
elif page == "Port Audit":
    show_port_audit()
elif page == "Risk Advisor":
    show_risk_advisor()
elif page == "Inventory":
    show_inventory()
elif page == "Audit Log":
    show_audit_log()
elif page == "Network Tools":
    show_network_tools()
elif page == "Reports":
    show_reports()
elif page == "Safety":
    show_safety()
