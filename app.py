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
    init_db,
    recent_scan_runs,
    update_asset_ports,
    upsert_hosts,
)
from logger import log_event
from network_scanner import scan_network
from network_tools import guess_gateway, network_profile
from port_scanner import scan_ports
from report_builder import build_html_report, build_markdown_report
from risk_engine import summarize_exposure, top_recommendations
from safe_text import clean_text
from security import validate_cidr, validate_target_ip

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root{
        --paper:#F7F4EE;
        --ink:#111111;
        --muted:#706A61;
        --line:#111111;
        --soft:#E6E0D6;
        --card:#FFFDF8;
        --accent:#111111;
    }
    .stApp{
        background:
            linear-gradient(90deg,rgba(17,17,17,.045) 1px,transparent 1px),
            linear-gradient(180deg,rgba(17,17,17,.045) 1px,transparent 1px),
            var(--paper);
        background-size:44px 44px;
        color:var(--ink);
    }
    .block-container{max-width:1320px;padding-top:1.8rem;position:relative;z-index:2}
    div[data-testid="stSidebarContent"]{
        background:#FFFFFF;
        border-right:2px solid var(--line);
        padding-top:1.2rem;
    }
    div[data-testid="stSidebarContent"] img{display:none}
    div[data-testid="stSidebarContent"] h1,
    div[data-testid="stSidebarContent"] h2,
    div[data-testid="stSidebarContent"] h3,
    div[data-testid="stSidebarContent"] p,
    div[data-testid="stSidebarContent"] span,
    div[data-testid="stSidebarContent"] label{color:var(--ink)!important}
    div[role="radiogroup"] label{
        border-radius:999px;
        padding:.38rem .55rem;
        margin:.2rem 0;
    }
    .brand-card{
        border:2px solid var(--ink);
        border-radius:18px;
        background:var(--paper);
        padding:1.2rem 1.25rem;
        margin:.5rem 0 1.5rem 0;
    }
    .brand-title{font-size:1.5rem;font-weight:950;letter-spacing:-.04em;color:var(--ink)}
    .brand-sub{color:var(--muted);font-size:.92rem;margin-top:.2rem}
    .hero{
        padding:1.9rem 0 1.35rem 0;
        border-top:3px solid var(--ink);
        border-bottom:3px solid var(--ink);
        margin-bottom:1.35rem;
    }
    .hero-kicker{
        font-size:.86rem;
        letter-spacing:.16em;
        text-transform:uppercase;
        font-weight:950;
        color:var(--ink);
        margin-bottom:1.05rem;
    }
    .hero-title{
        color:var(--ink);
        font-size:clamp(4rem,8.6vw,7.4rem);
        line-height:.9;
        letter-spacing:-.075em;
        font-weight:950;
        max-width:900px;
    }
    .hero-subtitle{
        color:var(--muted);
        font-size:clamp(1.25rem,2.2vw,1.75rem);
        line-height:1.28;
        max-width:980px;
        margin-top:1rem;
    }
    .pill{
        display:inline-block;
        border:2px solid var(--ink);
        background:#FFFFFF;
        color:var(--ink);
        padding:.5rem .8rem;
        border-radius:999px;
        margin-right:.55rem;
        margin-top:1.25rem;
        font-size:.85rem;
        font-weight:950;
        text-transform:uppercase;
        letter-spacing:.04em;
    }
    .pill.dark{background:var(--ink);color:var(--paper)}
    .metric-card{
        border:2px solid var(--ink);
        border-radius:20px;
        background:#FFFFFF;
        padding:1.2rem 1.35rem;
        min-height:135px;
        box-shadow:9px 9px 0 var(--ink);
    }
    .metric-label{
        color:var(--muted);
        font-size:.86rem;
        text-transform:uppercase;
        letter-spacing:.11em;
        font-weight:950;
    }
    .metric-value{
        color:var(--ink);
        font-size:2.75rem;
        line-height:1;
        font-weight:950;
        margin-top:.5rem;
        letter-spacing:-.04em;
        word-break:break-word;
    }
    .metric-note{color:var(--muted);font-size:1rem;margin-top:.45rem}
    .panel{
        border:2px solid var(--ink);
        border-radius:20px;
        background:#FFFDF8;
        padding:1.2rem 1.35rem;
        margin-bottom:1rem;
    }
    .section-title{
        color:var(--ink);
        font-size:1.05rem;
        letter-spacing:.13em;
        text-transform:uppercase;
        font-weight:950;
        margin:1.3rem 0 .8rem 0;
    }
    .muted{color:var(--muted);line-height:1.5;font-size:1rem}
    .stButton>button,.stDownloadButton>button{
        border:2px solid var(--ink)!important;
        border-radius:999px!important;
        background:var(--ink)!important;
        color:var(--paper)!important;
        font-weight:900!important;
        text-transform:uppercase;
        letter-spacing:.04em;
    }
    .stTextInput input{
        border:2px solid var(--ink)!important;
        border-radius:14px!important;
        background:#FFFFFF!important;
        color:var(--ink)!important;
    }
    div[data-testid="stDataFrame"]{
        border:2px solid var(--ink);
        border-radius:18px;
        overflow:hidden;
        background:#FFFFFF;
    }
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
    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">NetWatch / Defensive Network Visibility</div>
            <div class="hero-title">Local network,<br>clear signals.</div>
            <div class="hero-subtitle">Host profiling, service checks, inventory, risk scoring, and clean reports for authorized local networks.</div>
            <span class="pill dark">v0.6.2</span>
            <span class="pill">Private IP Only</span>
            <span class="pill">Risk Advisor</span>
            <span class="pill">Safe Exports</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def empty_panel(title: str, message: str) -> None:
    st.markdown(
        "<div class='panel'>"
        f"<div class='section-title'>{clean_text(title, 120)}</div>"
        f"<div class='muted'>{clean_text(message, 500)}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def require_authorization(label: str) -> bool:
    return st.checkbox(label, value=False, help="Confirm you are testing only systems you own or are allowed to check.")


def show_overview() -> None:
    hero()
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results
    if ports_df.empty:
        exposure = summarize_exposure([])
    else:
        exposure = summarize_exposure(ports_df.to_dict("records"))
    inventory = asset_inventory()
    runs = recent_scan_runs(limit=8)

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
        st.markdown('<div class="section-title">Risk overview</div>', unsafe_allow_html=True)
        if ports_df.empty:
            empty_panel("No port audit yet", "Run a Port Audit to build risk charts and recommendations.")
        else:
            chart_df = ports_df.groupby(["Status", "Risk"]).size().reset_index(name="Count")
            fig = px.bar(chart_df, x="Status", y="Count", color="Risk", barmode="group", title="Port status by risk")
            fig.update_layout(
                height=330,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#111111",
            )
            st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown('<div class="section-title">Recent saved runs</div>', unsafe_allow_html=True)
        if runs:
            st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
        else:
            empty_panel("Quiet for now", "Checks will appear here after you run them.")


def show_network_scan() -> None:
    hero()
    st.markdown('<div class="section-title">Network Scan</div>', unsafe_allow_html=True)
    col_form, col_help = st.columns([1.1, 0.9])

    with col_form:
        cidr = st.text_input("Local CIDR range", "192.168.1.0/24")
        validation = validate_cidr(cidr)
        if validation.ok:
            st.success(f"Valid local range: {validation.value}")
        else:
            st.warning(validation.error)
        authorized = require_authorization("I have permission to check this local network.")
        start = st.button("Start scan", type="primary", disabled=(not authorized or not validation.ok))

    with col_help:
        profile = network_profile(cidr)
        empty_panel("Scan rules", f"Network: {profile.cidr} | Usable: {profile.usable_hosts} | Gateway guess: {guess_gateway(cidr)}")

    if start:
        with st.spinner("Checking local hosts..."):
            try:
                results = scan_network(cidr)
                hosts_df = pd.DataFrame(results)
                st.session_state.network_results = hosts_df
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
        st.download_button("Download hosts CSV", safe_csv_bytes(hosts_df), "netwatch_hosts.csv", "text/csv")


def show_host_check() -> None:
    hero()
    st.markdown('<div class="section-title">Host Check + Profile</div>', unsafe_allow_html=True)
    ip = st.text_input("Private/local IP address", "192.168.1.1")
    validation = validate_target_ip(ip)
    if validation.ok:
        st.info(f"Target accepted: {validation.value}")
    else:
        st.warning(validation.error)

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
        with c1:
            metric_card("Status", status, profile.notes)
        with c2:
            metric_card("Latency", profile.latency_ms if profile.latency_ms is not None else "-", "milliseconds")
        with c3:
            metric_card("TTL", profile.ttl if profile.ttl is not None else "-", profile.os_hint)
        with c4:
            metric_card("Hostname", profile.hostname, "reverse DNS")
        st.dataframe(pd.DataFrame([profile.__dict__]), use_container_width=True, hide_index=True)


def show_port_audit() -> None:
    hero()
    st.markdown('<div class="section-title">Port Audit + Service Details</div>', unsafe_allow_html=True)
    col1, col2 = st.columns([1, 1])

    with col1:
        ip = st.text_input("Target private/local IP", "192.168.1.1")
        validation = validate_target_ip(ip)
        if validation.ok:
            st.success(f"Target accepted: {validation.value}")
        else:
            st.warning(validation.error)
        authorized = require_authorization("I have permission to check this host.")
        scan = st.button("Audit common ports", type="primary", disabled=(not authorized or not validation.ok))

    with col2:
        empty_panel("More detailed output", "Each port includes protocol, response time, service description and recommendation.")

    if scan:
        with st.spinner("Auditing common ports..."):
            results = scan_ports(ip)
            ports_df = pd.DataFrame(results)
            st.session_state.port_results = ports_df
            exposure = summarize_exposure(results)
            msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}"
            add_event(f"Port audit completed for {ip}: {msg}")
            add_history("ports", ip, msg)
            add_scan_run("ports", ip, msg)
            update_asset_ports(ip, results, exposure.score, exposure.level)
            st.success(msg)

    ports_df = st.session_state.port_results
    if ports_df.empty:
        empty_panel("No port results yet", "Run a port audit to see service metadata.")
        return

    exposure = summarize_exposure(ports_df.to_dict("records"))
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
        st.markdown('<div class="section-title">Top recommendations</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(top_items), use_container_width=True, hide_index=True)

    st.dataframe(ports_df, use_container_width=True, hide_index=True)
    st.download_button("Download detailed port CSV", safe_csv_bytes(ports_df), "netwatch_detailed_ports.csv", "text/csv")


def show_risk_advisor() -> None:
    hero()
    st.markdown('<div class="section-title">Risk Advisor</div>', unsafe_allow_html=True)
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results
    inventory = asset_inventory()
    advice = build_advice(hosts_df.to_dict("records"), ports_df.to_dict("records"), inventory)

    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("Risk level", advice.risk_level, "Advisor output")
    with c2:
        metric_card("Confidence", advice.confidence, "Based on data")
    with c3:
        metric_card("Inventory", len(inventory), "Saved assets")

    empty_panel("Advisor summary", advice.summary)
    st.markdown('<div class="section-title">Priority findings</div>', unsafe_allow_html=True)
    st.dataframe(pd.DataFrame({"Priority": advice.priorities}), use_container_width=True, hide_index=True)
    st.markdown('<div class="section-title">Suggested next steps</div>', unsafe_allow_html=True)
    st.dataframe(pd.DataFrame({"Next step": advice.next_steps}), use_container_width=True, hide_index=True)

    markdown = advice_to_markdown(advice)
    st.download_button("Download advisor notes", markdown.encode("utf-8"), "netwatch_advisor_notes.md", "text/markdown")


def show_inventory() -> None:
    hero()
    st.markdown('<div class="section-title">Asset Inventory</div>', unsafe_allow_html=True)
    inventory = asset_inventory()
    if not inventory:
        empty_panel("Inventory is empty", "Run checks to save local assets here.")
        return
    inventory_df = pd.DataFrame(inventory)
    st.dataframe(inventory_df, use_container_width=True, hide_index=True)
    st.download_button("Download inventory CSV", safe_csv_bytes(inventory_df), "netwatch_inventory.csv", "text/csv")


def show_network_tools() -> None:
    hero()
    st.markdown('<div class="section-title">Network Tools</div>', unsafe_allow_html=True)
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
    st.markdown('<div class="section-title">Reports & History</div>', unsafe_allow_html=True)
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results
    markdown_report = build_markdown_report(hosts_df, ports_df)
    html_report = build_html_report(hosts_df, ports_df)

    c1, c2 = st.columns(2)
    with c1:
        st.download_button("Download Markdown report", markdown_report.encode("utf-8"), "netwatch_report.md", "text/markdown")
    with c2:
        st.download_button("Download HTML report", html_report.encode("utf-8"), "netwatch_report.html", "text/html")

    with st.expander("Preview Markdown report", expanded=True):
        st.markdown(markdown_report)

    runs = recent_scan_runs(limit=50)
    if runs:
        st.dataframe(pd.DataFrame(runs), use_container_width=True, hide_index=True)
    history = load_history(limit=25)
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)


def show_safety() -> None:
    hero()
    st.markdown(
        """
        ### Built-in limits
        - Private/local IP validation
        - Maximum CIDR size
        - Short common-port list
        - Authorization checkbox before network checks
        - Local Risk Advisor with local project data
        """
    )


init_state()

with st.sidebar:
    st.markdown(
        """
        <div class="brand-card">
            <div class="brand-title">NetWatch</div>
            <div class="brand-sub">Local defensive dashboard</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption(f"v{APP_VERSION}")
    page = st.radio(
        "Navigation",
        ["Overview", "Network Scan", "Host Check", "Port Audit", "Risk Advisor", "Inventory", "Network Tools", "Reports", "Safety"],
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
elif page == "Network Tools":
    show_network_tools()
elif page == "Reports":
    show_reports()
elif page == "Safety":
    show_safety()
