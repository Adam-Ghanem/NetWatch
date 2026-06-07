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
from risk_engine import risk_badge, summarize_exposure, top_recommendations
from safe_text import clean_text
from security import validate_cidr, validate_target_ip

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root{
        --bg:#02040A;--card:rgba(7,16,31,.82);--line:rgba(148,163,184,.18);
        --blue:#22D3EE;--purple:#A855F7;--orange:#FB923C;--green:#22F5A8;
        --text:#F8FAFC;--muted:#94A3B8
    }
    .stApp{
        background:radial-gradient(circle at 62% 16%,rgba(34,211,238,.16),transparent 23%),
        radial-gradient(circle at 80% 42%,rgba(168,85,247,.15),transparent 20%),
        radial-gradient(circle at 13% 84%,rgba(251,146,60,.10),transparent 19%),
        linear-gradient(180deg,#030712,#02040A 55%,#010207);
        color:var(--text)
    }
    .stApp:before{
        content:"";position:fixed;inset:0;pointer-events:none;
        background:linear-gradient(90deg,rgba(56,189,248,.05) 1px,transparent 1px),
        linear-gradient(180deg,rgba(56,189,248,.035) 1px,transparent 1px),
        repeating-linear-gradient(0deg,transparent 0 54px,rgba(59,130,246,.13) 55px,transparent 57px);
        background-size:44px 44px,44px 44px,100% 57px;opacity:.52;z-index:0
    }
    .block-container{position:relative;z-index:2;max-width:1440px;padding-top:1.2rem}
    div[data-testid="stSidebarContent"]{background:rgba(3,7,18,.96);border-right:1px solid rgba(148,163,184,.16)}
    div[data-testid="stSidebarContent"] img{border-radius:18px;border:1px solid rgba(34,211,238,.26);box-shadow:0 0 32px rgba(34,211,238,.14)}
    .hero{position:relative;min-height:300px;overflow:hidden;border:1px solid rgba(34,211,238,.28);border-radius:26px;background:linear-gradient(135deg,rgba(7,16,31,.96),rgba(3,8,18,.70));box-shadow:0 22px 80px rgba(0,0,0,.42),inset 0 0 80px rgba(34,211,238,.06);padding:2rem 2.2rem;margin-bottom:1.1rem}
    .hero:before{content:"";position:absolute;right:110px;top:38px;width:290px;height:205px;border-radius:43% 57% 61% 39%/48% 40% 60% 52%;background:radial-gradient(circle at 30% 20%,rgba(255,255,255,.30),transparent 18%),linear-gradient(135deg,rgba(251,146,60,.65),rgba(168,85,247,.48),rgba(34,211,238,.56));filter:drop-shadow(0 0 38px rgba(34,211,238,.36));opacity:.80;border:1px solid rgba(34,211,238,.38)}
    .hero:after{content:"";position:absolute;right:55px;top:185px;width:110px;height:84px;border-radius:48% 52% 41% 59%;background:linear-gradient(135deg,rgba(168,85,247,.62),rgba(34,211,238,.50));filter:drop-shadow(0 0 24px rgba(168,85,247,.36));border:1px solid rgba(168,85,247,.40)}
    .hero-kicker{color:var(--muted);font-size:.78rem;letter-spacing:.18em;text-transform:uppercase;font-weight:800;margin-bottom:.75rem}
    .hero-title{position:relative;z-index:3;color:#fff;font-size:clamp(3.1rem,6.4vw,6.2rem);font-weight:950;line-height:.9;letter-spacing:-.065em;max-width:780px;text-shadow:2px 0 rgba(34,211,238,.55),-2px 0 rgba(249,115,22,.42),0 0 30px rgba(255,255,255,.12)}
    .hero-subtitle{position:relative;z-index:3;color:#B8C4D8;font-size:1.15rem;line-height:1.55;max-width:680px;margin-top:1.1rem}
    .pill{display:inline-block;position:relative;z-index:3;border:1px solid rgba(148,163,184,.22);background:rgba(7,17,34,.74);color:#DDEBFF;padding:.5rem .78rem;border-radius:13px;margin-right:.55rem;margin-top:1.2rem;font-size:.84rem}.pill b{color:var(--green)}
    .metric-card,.panel{border:1px solid var(--line);background:linear-gradient(180deg,rgba(7,16,31,.86),rgba(3,8,18,.72));border-radius:20px;box-shadow:inset 0 0 36px rgba(34,211,238,.035),0 16px 48px rgba(0,0,0,.22)}
    .metric-card{min-height:132px;padding:1.15rem 1.25rem;position:relative;overflow:hidden}
    .metric-card:after{content:"";position:absolute;left:14px;right:14px;bottom:14px;height:42px;background:linear-gradient(90deg,rgba(34,211,238,.12),rgba(168,85,247,.11),rgba(251,146,60,.12));clip-path:polygon(0 75%,10% 55%,20% 70%,32% 38%,45% 64%,58% 50%,70% 76%,84% 34%,100% 58%,100% 100%,0 100%);opacity:.72}
    .metric-label{color:#B6C4D9;font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;font-weight:800}.metric-value{color:#fff;font-size:2.35rem;line-height:1;font-weight:900;margin-top:.55rem}.metric-note{color:var(--muted);font-size:.88rem;margin-top:.45rem}
    .panel{padding:1.15rem 1.25rem;margin-bottom:1rem}.section-title{font-size:.86rem;letter-spacing:.16em;text-transform:uppercase;font-weight:900;color:#BFD2EA;margin:1rem 0 .65rem}.muted{color:var(--muted);line-height:1.55}
    .stButton>button,.stDownloadButton>button{border-radius:13px!important;border:1px solid rgba(34,211,238,.28)!important;background:rgba(8,21,42,.92)!important;color:#EAF6FF!important;box-shadow:0 0 20px rgba(34,211,238,.10)}
    div[data-testid="stDataFrame"]{border:1px solid rgba(148,163,184,.16);border-radius:18px;overflow:hidden;background:rgba(3,8,18,.78)}
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
            <div class="hero-kicker">Defensive Network Visibility</div>
            <div class="hero-title">local network,<br>clear signals.</div>
            <div class="hero-subtitle">Scan. Inspect. Understand. Everything you need to keep your local network visible and under control.</div>
            <span class="pill"><b>●</b> Private IP Only</span>
            <span class="pill">Local Processing</span>
            <span class="pill">No Data Sharing</span>
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
        metric_card("Online hosts", len(hosts_df), "Latest check")
    with c2:
        metric_card("Open ports", exposure.open_ports, "From audit")
    with c3:
        metric_card("Inventory", len(inventory), "Saved assets")
    with c4:
        metric_card("Risk score", exposure.score, f"Level: {exposure.level}")

    left, right = st.columns([1.35, 0.9])
    with left:
        st.markdown('<div class="section-title">Risk overview</div>', unsafe_allow_html=True)
        if ports_df.empty:
            empty_panel("No port audit yet", "Run a Port Audit to build risk charts and recommendations.")
        else:
            chart_df = ports_df.groupby(["Status", "Risk"]).size().reset_index(name="Count")
            fig = px.bar(chart_df, x="Status", y="Count", color="Risk", barmode="group", title="Port status by risk")
            fig.update_layout(
                height=360,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#DDEBFF",
            )
            st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown('<div class="section-title">Recent activity</div>', unsafe_allow_html=True)
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
    st.image("assets/netwatch-banner-v2.svg", use_container_width=True)
    st.markdown(f"**{APP_NAME}**")
    st.caption(f"Defensive visibility · v{APP_VERSION}")
    page = st.radio(
        "Navigation",
        ["Overview", "Network Scan", "Host Check", "Port Audit", "Risk Advisor", "Inventory", "Network Tools", "Reports", "Safety"],
    )
    st.divider()
    st.caption("Private · Local · Safe")

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
