from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from config import APP_NAME, APP_VERSION
from history_store import add_history, load_history
from logger import log_event
from network_scanner import scan_network
from ping_checker import ping_host
from port_scanner import scan_ports
from report_builder import build_markdown_report, summarize_ports
from security import validate_cidr, validate_target_ip

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --card-bg: rgba(15, 23, 42, 0.78);
        --card-border: rgba(148, 163, 184, 0.18);
        --soft-text: #94a3b8;
        --blue: #38bdf8;
        --green: #22c55e;
        --orange: #f59e0b;
        --red: #ef4444;
    }
    .stApp {
        background:
            radial-gradient(circle at top left, rgba(56, 189, 248, 0.18), transparent 32%),
            radial-gradient(circle at 80% 10%, rgba(34, 197, 94, 0.12), transparent 25%),
            linear-gradient(135deg, #020617 0%, #0f172a 52%, #111827 100%);
    }
    .hero {
        padding: 1.6rem 1.8rem;
        border: 1px solid var(--card-border);
        border-radius: 24px;
        background: linear-gradient(135deg, rgba(15,23,42,0.94), rgba(30,41,59,0.74));
        box-shadow: 0 22px 70px rgba(0, 0, 0, 0.32);
        margin-bottom: 1.1rem;
    }
    .hero-title {
        font-size: 2.45rem;
        font-weight: 850;
        letter-spacing: -0.05em;
        margin: 0;
    }
    .hero-subtitle {
        color: #cbd5e1;
        font-size: 1.02rem;
        margin-top: 0.35rem;
        max-width: 860px;
    }
    .pill-row {margin-top: 1rem;}
    .pill {
        display: inline-block;
        border: 1px solid rgba(56,189,248,0.28);
        background: rgba(14,165,233,0.09);
        color: #bae6fd;
        padding: 0.33rem 0.65rem;
        border-radius: 999px;
        margin-right: 0.42rem;
        margin-bottom: 0.35rem;
        font-size: 0.84rem;
    }
    .metric-card {
        border: 1px solid var(--card-border);
        border-radius: 20px;
        background: var(--card-bg);
        padding: 1rem 1.1rem;
        min-height: 118px;
    }
    .metric-label {
        color: var(--soft-text);
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }
    .metric-value {
        font-size: 2rem;
        line-height: 1.1;
        font-weight: 800;
        margin-top: 0.25rem;
    }
    .metric-note {color: #cbd5e1; font-size: 0.86rem; margin-top: 0.35rem;}
    .panel {
        border: 1px solid var(--card-border);
        border-radius: 20px;
        background: rgba(15,23,42,0.70);
        padding: 1.1rem;
        margin-bottom: 1rem;
    }
    .section-title {
        font-size: 1.35rem;
        font-weight: 750;
        margin-bottom: 0.25rem;
    }
    .muted {color: var(--soft-text);}
    .good {color: var(--green); font-weight: 700;}
    .warn {color: var(--orange); font-weight: 700;}
    .bad {color: var(--red); font-weight: 700;}
    div[data-testid="stSidebarContent"] {
        background: rgba(2, 6, 23, 0.38);
    }
    .small-code {
        color: #93c5fd;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 0.86rem;
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
    if "network_results" not in st.session_state:
        st.session_state.network_results = pd.DataFrame(columns=["IP Address", "Status", "Details"])
    if "port_results" not in st.session_state:
        st.session_state.port_results = pd.DataFrame(columns=["Port", "Service", "Status", "Risk", "Recommendation"])
    if "events" not in st.session_state:
        st.session_state.events = []
    if "last_target" not in st.session_state:
        st.session_state.last_target = "-"


def metric_card(label: str, value: str | int, note: str = "") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def hero() -> None:
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-title">🛡️ {APP_NAME}</div>
            <div class="hero-subtitle">
                Local network visibility tool for lab work, home routers, and basic defensive checks.
                Built with Python and Streamlit, limited to private networks on purpose.
            </div>
            <div class="pill-row">
                <span class="pill">v{APP_VERSION}</span>
                <span class="pill">Private IP only</span>
                <span class="pill">Ping sweep</span>
                <span class="pill">Port audit</span>
                <span class="pill">CSV + Markdown report</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def require_authorization(label: str) -> bool:
    return st.checkbox(
        label,
        value=False,
        help="This confirms you are scanning only systems you own or are allowed to test.",
    )


def empty_panel(title: str, message: str) -> None:
    st.markdown(
        f"""
        <div class="panel">
            <div class="section-title">{title}</div>
            <div class="muted">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def port_summary_from_state() -> dict[str, int]:
    ports_df = st.session_state.port_results
    if ports_df.empty:
        return {"checked": 0, "open": 0, "high": 0, "medium": 0, "score": 0}
    return summarize_ports(ports_df.to_dict("records"))


def show_overview() -> None:
    hero()
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results
    port_summary = port_summary_from_state()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Online hosts", len(hosts_df), "Latest network sweep")
    with col2:
        metric_card("Ports checked", port_summary["checked"], "Common services only")
    with col3:
        metric_card("Open ports", port_summary["open"], "Review exposed services")
    with col4:
        metric_card("Exposure score", port_summary["score"], "Simple local risk score")

    left, right = st.columns([1.25, 0.85])

    with left:
        st.markdown('<div class="section-title">Latest port picture</div>', unsafe_allow_html=True)
        if ports_df.empty:
            empty_panel("No port audit yet", "Run a Port Audit to see charts and recommendations here.")
        else:
            chart_df = ports_df.groupby(["Status", "Risk"]).size().reset_index(name="Count")
            fig = px.bar(chart_df, x="Status", y="Count", color="Risk", barmode="group", title="Port status by risk")
            fig.update_layout(height=380, margin=dict(l=10, r=10, t=45, b=10))
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown('<div class="section-title">Recent activity</div>', unsafe_allow_html=True)
        history = load_history(limit=6)
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
        elif st.session_state.events:
            st.code("\n".join(st.session_state.events), language="text")
        else:
            empty_panel("Quiet for now", "Scans you run will appear here and in the local history CSV.")

    if not hosts_df.empty:
        st.markdown('<div class="section-title">Discovered hosts</div>', unsafe_allow_html=True)
        st.dataframe(hosts_df, use_container_width=True, hide_index=True)


def show_network_scan() -> None:
    hero()
    st.markdown('<div class="section-title">Network Scan</div>', unsafe_allow_html=True)
    st.caption("For your router, home lab, school lab, or authorized local network.")

    col_form, col_help = st.columns([1.1, 0.9])
    with col_form:
        cidr = st.text_input("Local CIDR range", "192.168.1.0/24")
        validation = validate_cidr(cidr)
        if validation.ok:
            st.success(f"Valid local range: {validation.value}")
        else:
            st.warning(validation.error)

        authorized = require_authorization("I have permission to scan this local network.")
        start = st.button("Start scan", type="primary", disabled=(not authorized or not validation.ok))

    with col_help:
        st.markdown(
            """
            <div class="panel">
                <div class="section-title">Scan rules</div>
                <div class="muted">
                    NetWatch blocks public IP ranges and caps scan size. This keeps the project focused on admin practice, not Internet scanning.
                </div>
                <br>
                <div class="small-code">Examples: 192.168.1.0/24 · 10.0.0.0/28 · 172.16.0.0/24</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if start:
        with st.spinner("Checking local hosts..."):
            try:
                results = scan_network(cidr)
                df = pd.DataFrame(results)
                st.session_state.network_results = df
                st.session_state.last_target = cidr
                summary = f"{len(results)} online host(s) found"
                add_event(f"Network scan completed for {cidr}: {summary}")
                add_history("network", cidr, summary)
                st.success(summary)
            except ValueError as exc:
                st.error(str(exc))
                add_history("network", cidr, str(exc), status="blocked")

    hosts_df = st.session_state.network_results
    if hosts_df.empty:
        empty_panel("No hosts displayed", "Run a scan to populate the table.")
    else:
        st.dataframe(hosts_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download hosts CSV",
            hosts_df.to_csv(index=False).encode("utf-8"),
            "netwatch_hosts.csv",
            "text/csv",
        )


def show_ping_checker() -> None:
    hero()
    st.markdown('<div class="section-title">Host Check</div>', unsafe_allow_html=True)
    ip = st.text_input("Private/local IP address", "192.168.1.1")
    validation = validate_target_ip(ip)
    if validation.ok:
        st.info(f"Target accepted: {validation.value}")
    else:
        st.warning(validation.error)

    if st.button("Check host", type="primary", disabled=not validation.ok):
        online, message = ping_host(ip)
        status = "online" if online else "offline/blocked"
        add_event(f"Ping check for {ip}: {message}")
        add_history("ping", ip, message, status=status)
        if online:
            st.success(f"{ip} is online — {message}")
        else:
            st.error(f"{ip} is offline or blocking ICMP — {message}")

    st.markdown(
        """
        <div class="panel">
            <div class="section-title">Tip</div>
            <div class="muted">Some devices block ICMP ping. If a host looks offline here, it can still have services running.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_port_audit() -> None:
    hero()
    st.markdown('<div class="section-title">Port Audit</div>', unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])
    with col1:
        ip = st.text_input("Target private/local IP", "192.168.1.1")
        validation = validate_target_ip(ip)
        if validation.ok:
            st.success(f"Target accepted: {validation.value}")
        else:
            st.warning(validation.error)
        authorized = require_authorization("I have permission to scan this host.")
        scan = st.button("Audit common ports", type="primary", disabled=(not authorized or not validation.ok))

    with col2:
        st.markdown(
            """
            <div class="panel">
                <div class="section-title">What gets checked?</div>
                <div class="muted">
                    The app checks a short list of common services: SSH, HTTP, HTTPS, SMB, MySQL, RDP, PostgreSQL and a few mail/FTP ports.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if scan:
        with st.spinner("Auditing common ports..."):
            results = scan_ports(ip)
            df = pd.DataFrame(results)
            st.session_state.port_results = df
            st.session_state.last_target = ip
            summary = port_summary_from_state()
            msg = f"{summary['open']} open port(s), {summary['high']} high risk"
            add_event(f"Port audit completed for {ip}: {msg}")
            add_history("ports", ip, msg)
            st.success(msg)

    ports_df = st.session_state.port_results
    if ports_df.empty:
        empty_panel("No port results yet", "Run a port audit to see the table, charts, and recommendations.")
        return

    summary = port_summary_from_state()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Checked", summary["checked"], "Ports in list")
    with c2:
        metric_card("Open", summary["open"], "Detected open")
    with c3:
        metric_card("High", summary["high"], "Needs review")
    with c4:
        metric_card("Score", summary["score"], "Local exposure")

    chart_left, chart_right = st.columns(2)
    with chart_left:
        status_df = ports_df.groupby("Status").size().reset_index(name="Count")
        fig = px.pie(status_df, names="Status", values="Count", title="Port status split", hole=0.45)
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=45, b=10))
        st.plotly_chart(fig, use_container_width=True)
    with chart_right:
        risk_df = ports_df.groupby("Risk").size().reset_index(name="Count")
        fig = px.bar(risk_df, x="Risk", y="Count", title="Risk levels")
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=45, b=10))
        st.plotly_chart(fig, use_container_width=True)

    risk_filter = st.multiselect("Filter by risk", sorted(ports_df["Risk"].unique()), default=list(sorted(ports_df["Risk"].unique())))
    filtered = ports_df[ports_df["Risk"].isin(risk_filter)] if risk_filter else ports_df
    st.dataframe(filtered, use_container_width=True, hide_index=True)

    open_df = ports_df[ports_df["Status"] == "Open"]
    if not open_df.empty:
        st.markdown('<div class="section-title">Recommended checks</div>', unsafe_allow_html=True)
        st.dataframe(open_df[["Port", "Service", "Risk", "Recommendation"]], use_container_width=True, hide_index=True)

    st.download_button(
        "Download port report CSV",
        ports_df.to_csv(index=False).encode("utf-8"),
        "netwatch_port_report.csv",
        "text/csv",
    )


def show_reports() -> None:
    hero()
    st.markdown('<div class="section-title">Reports & History</div>', unsafe_allow_html=True)
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results

    report = build_markdown_report(hosts_df, ports_df)
    st.download_button(
        "Download Markdown report",
        report.encode("utf-8"),
        "netwatch_report.md",
        "text/markdown",
    )

    with st.expander("Preview report", expanded=True):
        st.markdown(report)

    st.markdown('<div class="section-title">Saved local history</div>', unsafe_allow_html=True)
    history = load_history(limit=50)
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
    else:
        empty_panel("No saved history", "Run a scan or port audit first.")


def show_safety() -> None:
    hero()
    st.markdown(
        """
        <div class="panel">
            <div class="section-title">Safety Policy</div>
            <div class="muted">
                NetWatch is made for learning, home labs, school labs, and authorized local administration.
                It is not made for scanning public targets or third-party systems.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        ### Built-in limits

        - Private/local IP validation
        - Maximum CIDR size
        - Short common-port list
        - Authorization checkbox before scan actions
        - No exploitation, brute force, password attacks, stealth, or evasion
        - Defensive recommendations only

        ### Good use cases

        - Check your router LAN
        - Practice in a VM/lab network
        - Document a small internship/networking project
        - Learn how ports and services appear from a basic admin tool
        """
    )


init_state()

with st.sidebar:
    st.image("assets/banner.svg", use_container_width=True)
    st.markdown(f"**{APP_NAME}**  ")
    st.caption(f"Local defensive dashboard · v{APP_VERSION}")
    page = st.radio(
        "Navigation",
        ["Overview", "Network Scan", "Host Check", "Port Audit", "Reports", "Safety"],
    )
    st.divider()
    st.caption("Private networks only. No public target scanning.")

if page == "Overview":
    show_overview()
elif page == "Network Scan":
    show_network_scan()
elif page == "Host Check":
    show_ping_checker()
elif page == "Port Audit":
    show_port_audit()
elif page == "Reports":
    show_reports()
elif page == "Safety":
    show_safety()
