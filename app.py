from __future__ import annotations

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from config import APP_NAME, APP_VERSION
from logger import log_event
from network_scanner import scan_network
from ping_checker import ping_host
from port_scanner import scan_ports
from security import validate_cidr, validate_target_ip

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .main-title {font-size: 2.4rem; font-weight: 800; margin-bottom: 0;}
    .subtitle {color: #64748b; font-size: 1.05rem; margin-top: 0.2rem;}
    .policy-box {border: 1px solid #e2e8f0; border-radius: 12px; padding: 1rem; background: #f8fafc;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(f"<p class='main-title'>🛡️ {APP_NAME}</p>", unsafe_allow_html=True)
st.markdown(
    f"<p class='subtitle'>Secure network monitoring dashboard • v{APP_VERSION} • built for authorized local labs</p>",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.image("assets/banner.svg", use_container_width=True)
    page = st.radio(
        "Navigation",
        ["Dashboard", "Network Scan", "Ping Checker", "Port Scanner", "Security Policy"],
    )
    st.divider()
    st.caption("Safety defaults: private/local IPs only, conservative port list, scan-size limit.")

if "network_results" not in st.session_state:
    st.session_state.network_results = pd.DataFrame(columns=["IP Address", "Status", "Details"])
if "port_results" not in st.session_state:
    st.session_state.port_results = pd.DataFrame(columns=["Port", "Service", "Status", "Risk", "Recommendation"])
if "events" not in st.session_state:
    st.session_state.events = []


def add_event(event: str) -> None:
    stamped = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {event}"
    st.session_state.events.insert(0, stamped)
    st.session_state.events = st.session_state.events[:20]
    log_event(event)


def require_authorization(label: str) -> bool:
    return st.checkbox(
        label,
        value=False,
        help="This confirms you are scanning only systems you own or are allowed to test.",
    )


if page == "Dashboard":
    hosts_df = st.session_state.network_results
    ports_df = st.session_state.port_results

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Online Hosts", len(hosts_df))
    col2.metric("Ports Checked", len(ports_df))
    open_count = int((ports_df["Status"] == "Open").sum()) if not ports_df.empty else 0
    high_count = int((ports_df["Risk"] == "High").sum()) if not ports_df.empty else 0
    col3.metric("Open Ports", open_count)
    col4.metric("High Risk Findings", high_count)

    st.subheader("Latest Network Discovery")
    if hosts_df.empty:
        st.info("Run a Network Scan to populate this table.")
    else:
        st.dataframe(hosts_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download hosts CSV",
            hosts_df.to_csv(index=False).encode("utf-8"),
            "netwatch_hosts.csv",
            "text/csv",
        )

    st.subheader("Latest Port Assessment")
    if ports_df.empty:
        st.info("Run a Port Scanner assessment to populate this table.")
    else:
        status_df = ports_df.groupby("Status").size().reset_index(name="Count")
        fig = px.bar(status_df, x="Status", y="Count", title="Port Status Summary")
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(ports_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download port report CSV",
            ports_df.to_csv(index=False).encode("utf-8"),
            "netwatch_port_report.csv",
            "text/csv",
        )

    st.subheader("Activity Log")
    if st.session_state.events:
        st.code("\n".join(st.session_state.events), language="text")
    else:
        st.caption("No activity yet.")

elif page == "Network Scan":
    st.header("Network Scan")
    st.markdown(
        "<div class='policy-box'>NetWatch only accepts private/local CIDR ranges and caps scan size to keep usage safe.</div>",
        unsafe_allow_html=True,
    )
    cidr = st.text_input("Network CIDR", "192.168.1.0/24")
    validation = validate_cidr(cidr)
    if not validation.ok:
        st.warning(validation.error)

    authorized = require_authorization("I confirm I own or have permission to scan this local network.")
    if st.button("Start Network Scan", disabled=not authorized):
        with st.spinner("Scanning authorized local network..."):
            try:
                results = scan_network(cidr)
                st.session_state.network_results = pd.DataFrame(results)
                add_event(f"Network scan completed for {cidr}; online hosts: {len(results)}")
                if results:
                    st.success(f"Found {len(results)} online host(s).")
                    st.dataframe(st.session_state.network_results, use_container_width=True, hide_index=True)
                else:
                    st.warning("No online hosts found. Some devices may block ICMP ping.")
            except ValueError as exc:
                st.error(str(exc))

elif page == "Ping Checker":
    st.header("Ping Checker")
    ip = st.text_input("Private/local IP address", "192.168.1.1")
    validation = validate_target_ip(ip)
    if not validation.ok:
        st.warning(validation.error)

    if st.button("Check Host"):
        online, message = ping_host(ip)
        add_event(f"Ping check for {ip}: {message}")
        if online:
            st.success(f"{ip} is Online — {message}")
        else:
            st.error(f"{ip} is Offline/Blocked — {message}")

elif page == "Port Scanner":
    st.header("Port Scanner")
    st.markdown(
        "<div class='policy-box'>The scanner checks a conservative list of common TCP ports and adds risk-based recommendations.</div>",
        unsafe_allow_html=True,
    )
    ip = st.text_input("Target private/local IP address", "192.168.1.1")
    validation = validate_target_ip(ip)
    if not validation.ok:
        st.warning(validation.error)

    authorized = require_authorization("I confirm I own or have permission to scan this host.")
    if st.button("Scan Common Ports", disabled=not authorized):
        with st.spinner("Checking common ports..."):
            results = scan_ports(ip)
            df = pd.DataFrame(results)
            st.session_state.port_results = df
            add_event(f"Port scan completed for {ip}; open ports: {int((df['Status'] == 'Open').sum())}")
            st.dataframe(df, use_container_width=True, hide_index=True)

            open_df = df[df["Status"] == "Open"]
            if open_df.empty:
                st.success("No open ports detected in the default common-port list.")
            else:
                st.warning("Open services detected. Review recommendations below.")
                st.dataframe(open_df[["Port", "Service", "Risk", "Recommendation"]], use_container_width=True, hide_index=True)

elif page == "Security Policy":
    st.header("Security Policy")
    st.markdown(
        """
        NetWatch is built for ethical learning and authorized local administration only.

        **Built-in safeguards:**
        - Accepts private/local IP ranges only.
        - Blocks broad public Internet scanning from the UI.
        - Uses a conservative common-port list.
        - Requires explicit authorization confirmation before scans.
        - Adds security recommendations instead of exploitation steps.
        - Keeps a local activity log for accountability.

        **Allowed usage:** home lab, school lab, company network with permission, your own router/devices.

        **Not allowed:** scanning public targets, third-party networks, or systems where you do not have permission.
        """
    )
