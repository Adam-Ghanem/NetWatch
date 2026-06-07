from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from config import APP_NAME, APP_VERSION
from history_store import add_history, load_history
from host_profiler import profile_host
from inventory_store import add_scan_run, asset_inventory, init_db, recent_scan_runs, update_asset_ports, upsert_hosts
from logger import log_event
from network_scanner import scan_network
from network_tools import guess_gateway, network_profile
from port_scanner import scan_ports
from report_builder import build_html_report, build_markdown_report, summarize_ports
from risk_engine import risk_badge, summarize_exposure, top_recommendations
from security import validate_cidr, validate_target_ip

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root {--card-bg:rgba(15,23,42,.78);--card-border:rgba(148,163,184,.18);--soft:#94a3b8;}
    .stApp {background: radial-gradient(circle at top left, rgba(45,212,191,.14), transparent 34%), radial-gradient(circle at 80% 10%, rgba(56,189,248,.12), transparent 28%), linear-gradient(135deg,#020617 0%,#0f172a 52%,#111827 100%);}
    .hero {padding:1.65rem 1.85rem;border:1px solid var(--card-border);border-radius:24px;background:linear-gradient(135deg,rgba(15,23,42,.94),rgba(30,41,59,.72));box-shadow:0 22px 70px rgba(0,0,0,.32);margin-bottom:1.1rem;}
    .hero-title {font-size:2.55rem;font-weight:850;letter-spacing:-.05em;margin:0;}
    .hero-subtitle {color:#cbd5e1;font-size:1.03rem;margin-top:.35rem;max-width:950px;}
    .pill {display:inline-block;border:1px solid rgba(56,189,248,.28);background:rgba(14,165,233,.09);color:#bae6fd;padding:.33rem .65rem;border-radius:999px;margin-right:.42rem;margin-top:.75rem;font-size:.84rem;}
    .metric-card {border:1px solid var(--card-border);border-radius:20px;background:var(--card-bg);padding:1rem 1.1rem;min-height:118px;}
    .metric-label {color:var(--soft);font-size:.82rem;text-transform:uppercase;letter-spacing:.08em;}
    .metric-value {font-size:1.85rem;line-height:1.1;font-weight:800;margin-top:.25rem;word-break:break-word;}
    .metric-note {color:#cbd5e1;font-size:.86rem;margin-top:.35rem;}
    .panel {border:1px solid var(--card-border);border-radius:20px;background:rgba(15,23,42,.70);padding:1.1rem;margin-bottom:1rem;}
    .section-title {font-size:1.35rem;font-weight:750;margin-bottom:.25rem;}
    .muted {color:var(--soft);}.small-code{color:#93c5fd;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86rem;}
    div[data-testid="stSidebarContent"] {background:rgba(2,6,23,.38);}
    </style>
    """,
    unsafe_allow_html=True,
)


def add_event(event: str) -> None:
    stamped = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {event}"
    st.session_state.events.insert(0, stamped)
    st.session_state.events = st.session_state.events[:20]
    log_event(event)


def init_state() -> None:
    init_db()
    st.session_state.setdefault("network_results", pd.DataFrame(columns=["IP Address", "Status", "Details"]))
    st.session_state.setdefault("port_results", pd.DataFrame(columns=["Port", "Protocol", "Service", "Status", "Risk", "Recommendation"]))
    st.session_state.setdefault("events", [])
    st.session_state.setdefault("last_target", "-")


def metric_card(label: str, value: str | int | float, note: str = "") -> None:
    st.markdown(
        f"<div class='metric-card'><div class='metric-label'>{label}</div><div class='metric-value'>{value}</div><div class='metric-note'>{note}</div></div>",
        unsafe_allow_html=True,
    )


def hero() -> None:
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-title">🛡️ {APP_NAME}</div>
            <div class="hero-subtitle">
                Local network visibility dashboard with host profiling, latency details, service metadata, inventory storage, risk scoring, and reports.
            </div>
            <span class="pill">v{APP_VERSION}</span><span class="pill">Private IP only</span><span class="pill">Latency + TTL</span><span class="pill">Service catalog</span><span class="pill">SQLite inventory</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def empty_panel(title: str, message: str) -> None:
    st.markdown(f"<div class='panel'><div class='section-title'>{title}</div><div class='muted'>{message}</div></div>", unsafe_allow_html=True)


def require_authorization(label: str) -> bool:
    return st.checkbox(label, value=False, help="Confirm you are testing only systems you own or are allowed to check.")


def show_overview() -> None:
    hero()
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results
    exposure = summarize_exposure(ports_df.to_dict("records")) if not ports_df.empty else summarize_exposure([])
    inventory = asset_inventory()
    runs = recent_scan_runs(limit=8)

    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card("Online hosts", len(hosts_df), "Latest scan")
    with c2: metric_card("Inventory", len(inventory), "Saved assets")
    with c3: metric_card("Open ports", exposure.open_ports, risk_badge(exposure.level))
    with c4: metric_card("Exposure", exposure.level, f"Score: {exposure.score}")

    left, right = st.columns([1.2, .85])
    with left:
        st.markdown('<div class="section-title">Risk overview</div>', unsafe_allow_html=True)
        if ports_df.empty:
            empty_panel("No port audit yet", "Run a Port Audit to build precise risk charts and recommendations.")
        else:
            chart_df = ports_df.groupby(["Status", "Risk"]).size().reset_index(name="Count")
            fig = px.bar(chart_df, x="Status", y="Count", color="Risk", barmode="group", title="Port status by risk")
            fig.update_layout(height=380, margin=dict(l=10, r=10, t=45, b=10))
            st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown('<div class="section-title">Recent saved runs</div>', unsafe_allow_html=True)
        if runs:
            st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
        elif st.session_state.events:
            st.code("\n".join(st.session_state.events), language="text")
        else:
            empty_panel("Quiet for now", "Checks will appear here after you run them.")

    if inventory:
        st.markdown('<div class="section-title">Inventory snapshot</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(inventory).head(10), use_container_width=True, hide_index=True)


def show_network_scan() -> None:
    hero()
    st.markdown('<div class="section-title">Network Scan</div>', unsafe_allow_html=True)
    col_form, col_help = st.columns([1.1, .9])
    with col_form:
        cidr = st.text_input("Local CIDR range", "192.168.1.0/24")
        validation = validate_cidr(cidr)
        st.success(f"Valid local range: {validation.value}") if validation.ok else st.warning(validation.error)
        start = st.button("Start scan", type="primary", disabled=(not require_authorization("I have permission to check this local network.") or not validation.ok))
    with col_help:
        profile = network_profile(cidr)
        empty_panel("CIDR quick profile", f"Network: {profile.cidr} | Usable: {profile.usable_hosts} | Gateway guess: {guess_gateway(cidr)} | {profile.message}")
    if start:
        with st.spinner("Checking local hosts..."):
            try:
                results = scan_network(cidr)
                df = pd.DataFrame(results)
                st.session_state.network_results = df
                summary = f"{len(results)} online host(s) found"
                add_event(f"Network scan completed for {cidr}: {summary}")
                add_history("network", cidr, summary)
                add_scan_run("network", cidr, summary)
                upsert_hosts(results)
                st.success(summary)
            except ValueError as exc:
                st.error(str(exc))
                add_scan_run("network", cidr, str(exc), status="blocked")
    hosts_df = st.session_state.network_results
    if hosts_df.empty:
        empty_panel("No hosts displayed", "Run a scan to populate the table.")
    else:
        st.dataframe(hosts_df, use_container_width=True, hide_index=True)
        st.download_button("Download hosts CSV", hosts_df.to_csv(index=False).encode("utf-8"), "netwatch_hosts.csv", "text/csv")


def show_host_check() -> None:
    hero()
    st.markdown('<div class="section-title">Host Check + Profile</div>', unsafe_allow_html=True)
    ip = st.text_input("Private/local IP address", "192.168.1.1")
    validation = validate_target_ip(ip)
    st.info(f"Target accepted: {validation.value}") if validation.ok else st.warning(validation.error)

    if st.button("Check host precisely", type="primary", disabled=not validation.ok):
        profile = profile_host(ip)
        status = "online" if profile.online else "offline/blocked"
        msg = f"{profile.notes}; latency={profile.latency_ms}; ttl={profile.ttl}; hostname={profile.hostname}"
        add_event(f"Host profile for {ip}: {msg}")
        add_history("host_profile", ip, msg, status=status)
        add_scan_run("host_profile", ip, msg, status=status)
        if profile.online:
            upsert_hosts([{"IP Address": profile.ip_address, "Status": "Online", "Details": profile.notes}])
            st.success("Host replied to ICMP ping")
        else:
            st.error(profile.notes)

        c1, c2, c3, c4 = st.columns(4)
        with c1: metric_card("Status", status, profile.notes)
        with c2: metric_card("Latency", profile.latency_ms if profile.latency_ms is not None else "-", "milliseconds")
        with c3: metric_card("TTL", profile.ttl if profile.ttl is not None else "-", profile.os_hint)
        with c4: metric_card("Hostname", profile.hostname, "reverse DNS")

        st.dataframe(pd.DataFrame([profile.__dict__]), use_container_width=True, hide_index=True)

    empty_panel("Precision note", "Latency, TTL, and hostname depend on the target and local network. Some devices block ping or reverse DNS.")


def show_port_audit() -> None:
    hero()
    st.markdown('<div class="section-title">Port Audit + Service Details</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([1, 1])
    with col1:
        ip = st.text_input("Target private/local IP", "192.168.1.1")
        validation = validate_target_ip(ip)
        st.success(f"Target accepted: {validation.value}") if validation.ok else st.warning(validation.error)
        scan = st.button("Audit common ports", type="primary", disabled=(not require_authorization("I have permission to check this host.") or not validation.ok))
    with col2:
        empty_panel("More detailed output", "Each port now includes protocol, response time, service description, common role, recommendation, and device role hint.")

    if scan:
        with st.spinner("Auditing common ports..."):
            results = scan_ports(ip)
            df = pd.DataFrame(results)
            st.session_state.port_results = df
            exposure = summarize_exposure(results)
            role = df["Device Role Hint"].iloc[0] if "Device Role Hint" in df.columns and not df.empty else "Unknown"
            msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}, role hint: {role}"
            add_event(f"Port audit completed for {ip}: {msg}")
            add_history("ports", ip, msg)
            add_scan_run("ports", ip, msg)
            update_asset_ports(ip, results, exposure.score, exposure.level)
            st.success(msg)

    ports_df = st.session_state.port_results
    if ports_df.empty:
        empty_panel("No port results yet", "Run a port audit to see detailed service metadata.")
        return

    exposure = summarize_exposure(ports_df.to_dict("records"))
    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card("Checked", exposure.checked, "Ports in list")
    with c2: metric_card("Open", exposure.open_ports, "Detected open")
    with c3: metric_card("High", exposure.high, "Needs review")
    with c4: metric_card("Exposure", exposure.level, f"Score: {exposure.score}")

    chart_left, chart_right = st.columns(2)
    with chart_left:
        status_df = ports_df.groupby("Status").size().reset_index(name="Count")
        st.plotly_chart(px.pie(status_df, names="Status", values="Count", title="Port status split", hole=.45), use_container_width=True)
    with chart_right:
        risk_df = ports_df.groupby("Risk").size().reset_index(name="Count")
        st.plotly_chart(px.bar(risk_df, x="Risk", y="Count", title="Risk levels"), use_container_width=True)

    top_items = top_recommendations(ports_df.to_dict("records"))
    if top_items:
        st.markdown('<div class="section-title">Top recommendations</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(top_items), use_container_width=True, hide_index=True)

    risk_filter = st.multiselect("Filter by risk", sorted(ports_df["Risk"].unique()), default=list(sorted(ports_df["Risk"].unique())))
    filtered = ports_df[ports_df["Risk"].isin(risk_filter)] if risk_filter else ports_df
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button("Download detailed port CSV", ports_df.to_csv(index=False).encode("utf-8"), "netwatch_detailed_ports.csv", "text/csv")


def show_inventory() -> None:
    hero()
    st.markdown('<div class="section-title">Asset Inventory</div>', unsafe_allow_html=True)
    inventory = asset_inventory()
    if not inventory:
        empty_panel("Inventory is empty", "Run Host Check, Network Scan, or Port Audit to save local assets here.")
        return
    df = pd.DataFrame(inventory)
    c1, c2, c3 = st.columns(3)
    with c1: metric_card("Assets", len(df), "Saved in SQLite")
    with c2: metric_card("With open ports", int((df["open_port_count"] > 0).sum()), "From port audits")
    with c3: metric_card("Highest score", int(df["exposure_score"].max()), "Local exposure")
    st.plotly_chart(px.bar(df.groupby("exposure_level").size().reset_index(name="Count"), x="exposure_level", y="Count", title="Inventory by exposure level"), use_container_width=True)
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button("Download inventory CSV", df.to_csv(index=False).encode("utf-8"), "netwatch_inventory.csv", "text/csv")


def show_network_tools() -> None:
    hero()
    st.markdown('<div class="section-title">Network Tools</div>', unsafe_allow_html=True)
    cidr = st.text_input("CIDR to analyze", "192.168.1.0/24")
    profile = network_profile(cidr, sample_size=12)
    st.success(profile.message) if profile.scan_allowed else st.warning(profile.message)
    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card("Network", profile.network_address, f"/{profile.prefix_length}")
    with c2: metric_card("Netmask", profile.netmask, "IPv4 mask")
    with c3: metric_card("Broadcast", profile.broadcast_address, "Last address")
    with c4: metric_card("Usable", profile.usable_hosts, "Host addresses")
    st.markdown('<div class="section-title">First host addresses</div>', unsafe_allow_html=True)
    st.code("\n".join(profile.first_hosts) if profile.first_hosts else "No sample", language="text")


def show_reports() -> None:
    hero()
    st.markdown('<div class="section-title">Reports & History</div>', unsafe_allow_html=True)
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results
    md = build_markdown_report(hosts_df, ports_df)
    html = build_html_report(hosts_df, ports_df)
    c1, c2 = st.columns(2)
    with c1: st.download_button("Download Markdown report", md.encode("utf-8"), "netwatch_report.md", "text/markdown")
    with c2: st.download_button("Download HTML report", html.encode("utf-8"), "netwatch_report.html", "text/html")
    with st.expander("Preview Markdown report", expanded=True): st.markdown(md)
    runs = recent_scan_runs(limit=50)
    if runs:
        st.markdown('<div class="section-title">SQLite scan runs</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
    history = load_history(limit=25)
    if history:
        st.markdown('<div class="section-title">Legacy CSV history</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)


def show_safety() -> None:
    hero()
    st.markdown("""
    ### Built-in limits
    - Private/local IP validation
    - Maximum CIDR size
    - Short common-port list
    - Authorization checkbox before scan actions
    - No exploitation, brute force, password attacks, stealth, or evasion
    - Defensive recommendations only

    ### Accuracy notes
    - Latency and TTL come from the local ping response.
    - Hostname depends on reverse DNS availability.
    - Device role is a hint based on observed open ports, not a guaranteed identification.
    - A closed or filtered port does not always mean the service does not exist; firewalls can hide it.
    """)


init_state()
with st.sidebar:
    st.image("assets/netwatch-banner-v2.svg", use_container_width=True)
    st.markdown(f"**{APP_NAME}**")
    st.caption(f"Local defensive dashboard · v{APP_VERSION}")
    page = st.radio("Navigation", ["Overview", "Network Scan", "Host Check", "Port Audit", "Inventory", "Network Tools", "Reports", "Safety"])
    st.divider()
    st.caption("Private networks only. Keep it local and authorized.")

if page == "Overview": show_overview()
elif page == "Network Scan": show_network_scan()
elif page == "Host Check": show_host_check()
elif page == "Port Audit": show_port_audit()
elif page == "Inventory": show_inventory()
elif page == "Network Tools": show_network_tools()
elif page == "Reports": show_reports()
elif page == "Safety": show_safety()
