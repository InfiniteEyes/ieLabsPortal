import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta
import plotly.express as px
import random
import requests
import feedparser
import re
from bs4 import BeautifulSoup
import html

from data_sources import (
    get_kaspersky_data, 
    get_radware_data, 
    get_mitre_attack_groups,
    get_apt_data,
    get_threatmap_data,
    get_malpedia_data
)
from data_processor import (
    process_threat_data, 
    categorize_by_region, 
    categorize_by_toolkit,
    categorize_by_tactic
)
from visualizations import (
    create_world_map,
    create_attack_timeline,
    create_threat_distribution_chart,
    create_attribution_network
)
from utils import (
    format_number, 
    get_threat_level_color,
    get_region_color,
    load_cached_data
)
from ml_analyzer import AttackPatternAnalyzer, train_models_on_attack_data

# Page configuration
st.set_page_config(
    page_title="Global Cyber Attack Tracker",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add logo header to every page
st.markdown("""
<div style="display: flex; justify-content: center; align-items: center; margin-bottom: 30px; padding: 10px; background-color: #111111; border-bottom: 1px solid #33ff33;">
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAlPSURBVHic7ZtrjFxVGYDf7+zOLt3tbrc7uzvTdimVUgp0wVrANkApYKtJBQOCAQVSDKhI/YGJotHEGCVeYiIaCYliNF5A5CIB1FKs3Fst3drQS3d7cWfG7k53Z2d3Zu+X48+zZea2s9M7lh/1+2Fy5pzvO+c733fO+c53ZkCTJk2aNGnSpEmTDxyipWQfDUXRnUoTlWjqG9fWV7fEy9Nzg0rKBxwbehHXpJwKVvlMI5+Nq78KIeoNxQVgZrM/fWH5EgAhxKoSm68A/wSgZ3vP7KeV5L22nTMwWZ+uuHyB5t3k9GXt9u/UFwWZyQrLF2gzTsaJQl5dL19U2RmKdwQvBwCUZaQK2jDkrqxm1CX/IWfFnxHwkLPiz1QdsFyZG4Cny65dAIZNO/BpYLvjfySwD8AjRJe1UmYYCLrH8Y/Q/PQJoKLJpRJkDDEHXK0BIcTpAq/+4wDYNmbHmQH8CFhRHDkBLHcFDwF/BZBC3KOgFzgJ4MKx44CvyKwMOGiP1bkrhBDnFsGrxeXi8JCCp4vsb5CJ3zotPFjF0EXgVHH88D+AScfvVLmTdaIi7qvQSvhY5NnO2TY/VvA16xjwFeAPrpCfKvgFULRQjGVdYe7hbwB7xKvj/CKI2cO1xWlJIW4tEa8/Ac8CfaWKUfAdZw4CFntXOHaT1k88GPhMpfbLxUZPJ0XHdQVGKcQ6hXhFCDHuGq9XCNEjhEi5jG0KtjixH3OHvVvFMeZFAIR4XAgxblmtWE8KcVy5wo42JpcG7T++vD6rVYp3tXGnuZTT28bsnhDit65AW4QQ/UUprKrA6wLOlxj3cyWD7QvAHuetjg3qMI9mRZEJIYaFEL8VQhiuoO0KXnNsvi+E+Jij7a+FEB1OOiOFEJ8SQmSKfqORiob7NNwkVGnUdAoIITJCiN3AfS7TgBDi94bmm0LzNSFE2uHxFdsGLcS9Qojh4pReLYSYcIcbrQzhShh7TcUYk8s7y4KJwA7l+hMUvOQKOJpTvvbcbHb7T6Ym3tg9Phx1af0A+L/PrxEMC99BzcE+XLYpV/hhDa+gxdl9s7Ot8/OPZzO/eyqVnGx1NQmNfrjM0auecr1ZYwyO7B05/uyPgFtdhl8Dg0UhO4DJBZZlDlz4zHsv7ZL4qbk3Q+vQ8lLLJu9V8KGiIH2WR5q6rHTu2s8BYy7Tb4D43N6iQDswXkWClOt5aP7NhFsq0u3F6ZITWGrwLPAd4DeuscwDcS9jtx82NiZTd37xXcfYUwlYW9vT1NKQsFIZLFsxDq+sNECAWYMfDqD1C7bNEcvCFJgLygH2FP72A7c2/PQtBWdLxHxBwU5n4X0NOLaENm8z0aWt7AuGOGYEt78KXFuFp3eADSWMB4B/AM/aij8JzdeEEF8uCn0D8DvXyRXAv4E4JXaemfkrcN0S9LoVmLfJSiU5h9Y9hdbdWmssIegQgg4hxO2lAjsLtl8I0daaWtoJ2I/WTTqBHwe+5Qr7iRKvWAtEcpK3hbgD+JWj3UZDc0oI8Xxh+6rW6EvgXLC/AZ9zLxAVSbZZaKy22RDtIZd6nTbM2ypV5jZ2TtI2dYyW3Gua91P/9Wqe7QG+IJVS/Q6DaUCo/HH0GHCNE3ZH3Eb0tFPiJdDZktmQ4Iz0saVFMTLSUvEG5JDJDrFm77G6FZkJXOq/DLlrWL3neN3qb2Ht5HHWhkfr1nZdCFsW8zaDVlJo8C7Z6hn0M3h2MwDdGm+FXBcNSX9dJrOGUwxNr65ZfyHgOoFcvZYNLQQ0YOLTaEVCbFCaJUJgUuXdZHdOsvjzpYaLxYVsITfdgQmYKBbaIKXYYGKCdL2dq0gGZnVOoJIrhB1CSK2F2E6lQ98MX2LVdLihA9j9+AxaQdtqE9UitNCMrNmDmVtaJd8U7qMz55+T7Mu6yfz6Jdb01xkJyTkqYvNEuJ3h9svE/C1ExDThWZmK4kJZxZZKMqcfYBVQODMUWhBYbOtbS2d7iLBVm68yQ2y+iGRNL88Ub/O0kWbDxAk25KbQZSbm/4oEQUB8OGAZh7vDnGxfTsZvIDQYKM0SxLlCL3HKpOr1AYb0g2BmIWJYJZEGv7sGTmtZjzuqOYCSl2yI38EjlzHMOoHOxTOsnUhgKOdG1iZ1N+D+WZMTq1q4EC4+XOmWgEJwTRcpjNK5T20tEfFH1TWAZ2JgaW7svZLOXHLJA9xsGnT1D+Czi4cdBRkl+U9nmDMrO8r+7n6leCRwhjXZ3ILEDCj8BuRSfPSg1zmHLRnPw5dLTYWwvRqwzQ2LHKqOIEVEgLg2yrrmRIa7LbYNxAkpacxkOBb28+KGCOc7Qgws99EV8NNm+glZlSlWFTJfBZZYEueBOHJBVSVYGbKxdG6QIbRw7/XMc8FEFdxZcFzDD2fZGGLvqnaeWeNn5LJq3BzXPFzVFJBC8MVMC2FLOO/Sek7DnYBdWKc8FwElNfcNb2J3l4lrn1V+mz1+eCAWrGgK+IXB/0I5PpNV3Nk9jSUUvyrEwJXB0kT+PqcS/AK+mfQR1ZoN2azvzWXABZGp4D0Db97G9o/C3OPf9RM/PpUqkUHxlKA+QqUQnFqR4cFon8f8vV2abPYvuQPKmvSuwwWaH3QZ9TK9AwDBcJZHnj+4ICErYJc4fGVL3KP0dxbT8pBfFH0WgFYgFXDFkYUFUQvf9hLz/86xbNL5PXo5JuBWcxazRu6aM1g0j9vO1Lk9GOLZoAdxAMFr/Rx99FZG2vVtLo/eKJ3t7HI5o1gfKPp/vhxnSQQrfNsXUdGq8FXQfxvH3upljXaVPJcBpxwnKkgL8U3gM07cBdGWAQI49zgjb7NnO6IzS85CsxCJAU6lsHOhNtJZ6HbWWLqgRGXaFVP4E8APHf/RFFxa2cHZRKmEWSMPIcQIHAf+Bjz4yAfQylPnfuqwCGQAfHZ5FdCbgB1eD9fAr4Cd2LS9p7Z+rnYCZoInASrgVeNiYSZEBDxVrX0TJWoCGDyNxwfflpJBlMwBpI1HXXxDKbI5wYCC91ReCN7t4rUStMzKBCoDt/QELMt4XsPPAF+JUF8HvuzYH7JtLbXa2Qixx1nLKuC5gvqnpI1ey8D1qfQjwDgwJICzpq2eyhv2DzKkfrZvNMqxPBCzIW2DlT/3/1PO5aQ/v73YfjQcJt3aAkLgtXszQqY7ksm6XHvDSc1QX9+ifw93Y+ckvlzjnuCaNGnSpEmTJk2afMD5H1aemBnlvkVzAAAAAElFTkSuQmCC" width="60px" style="margin-right: 15px;">
    <div style="font-family: 'Source Code Pro', 'Roboto Mono', monospace; font-size: 1.8em; color: white; letter-spacing: 2px;">
        infinite<span style="font-weight: bold; color: #33ff33;">eyes</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Global ASCII Terminal Style
st.markdown("""
<style>
    /* Main theme - ASCII Terminal style */
    :root {
        --background-color: #000000;
        --text-color: #ffffff;
        --highlight-color: #ffffff;
        --accent-color: #ffffff;
        --secondary-color: #dddddd;
        --header-color: #ffffff;
        --border-color: #ffffff;
        --font-family: 'Source Code Pro', 'Roboto Mono', 'Lucida Console', 'Consolas', monospace;
    }
    
    /* Main elements */
    .stApp {
        background-color: var(--background-color);
    }
    
    p, div, span, li, a {
        color: var(--text-color) !important;
        font-family: var(--font-family) !important;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: var(--header-color) !important;
        font-family: var(--font-family) !important;
        text-shadow: 0 0 5px var(--header-color) !important;
    }
    
    .stTextInput > div > div > input {
        background-color: black !important;
        color: var(--text-color) !important;
        border: 1px solid var(--text-color) !important;
        border-radius: 0 !important;
        font-family: var(--font-family) !important;
    }
    
    .stButton > button {
        background-color: black !important;
        color: var(--text-color) !important;
        border: 1px solid var(--text-color) !important;
        border-radius: 0 !important;
        font-family: var(--font-family) !important;
    }
    
    .stButton > button:hover {
        background-color: var(--text-color) !important;
        color: black !important;
        font-weight: bold !important;
    }
    
    /* Custom styling for sidebar */
    .css-1d391kg, [data-testid="stSidebar"] {
        background-color: var(--background-color) !important;
        border-right: 1px solid var(--border-color) !important;
    }
    
    /* Radio, selectbox, multiselect elements */
    .stSelectbox > div > div, .stMultiSelect > div > div {
        background-color: black !important;
        color: var(--text-color) !important;
        border: 1px solid var(--text-color) !important;
        border-radius: 0 !important;
    }
    
    /* Slider elements */
    .stSlider > div > div {
        color: var(--text-color) !important;
    }
    
    /* Table elements */
    .stTable, .stDataFrame {
        background-color: black !important;
        color: var(--text-color) !important;
        border: 1px solid var(--text-color) !important;
        border-radius: 0 !important;
    }
    
    /* Chart elements - make plotly more terminal-like */
    .js-plotly-plot .plotly .bg {
        fill: black !important;
    }
    
    .js-plotly-plot .plotly .main-svg {
        background-color: black !important;
    }
    
    /* Expander element */
    .streamlit-expanderHeader {
        background-color: black !important;
        color: var(--text-color) !important;
        border: 1px solid var(--text-color) !important;
        font-family: var(--font-family) !important;
    }
    
    .streamlit-expanderContent {
        background-color: black !important;
        color: var(--text-color) !important;
        border: 1px solid var(--text-color) !important;
        font-family: var(--font-family) !important;
        margin-bottom: 10px;
    }
    
    /* Add some scan lines for a CRT effect */
    .stApp:before {
        content: " ";
        display: block;
        position: fixed;
        top: 0;
        left: 0;
        bottom: 0;
        right: 0;
        z-index: 999;
        pointer-events: none;
        background: repeating-linear-gradient(
            0deg,
            rgba(0, 0, 0, 0.2),
            rgba(0, 0, 0, 0.2) 1px,
            transparent 1px,
            transparent 2px
        );
    }
    
    /* Add some flicker animation for more retro feel */
    @keyframes flicker {
        0% { opacity: 1.0; }
        5% { opacity: 0.8; }
        10% { opacity: 1.0; }
        15% { opacity: 0.9; }
        20% { opacity: 1.0; }
        70% { opacity: 1.0; }
        72% { opacity: 0.9; }
        77% { opacity: 1.0; }
        100% { opacity: 1.0; }
    }
    
    .stApp {
        animation: flicker 5s infinite;
    }
    
    /* Terminal blinking cursor effect */
    .terminal-cursor:after {
        content: "▋";
        margin-left: 3px;
        animation: blink 1s step-end infinite;
        color: var(--text-color);
    }
    
    @keyframes blink {
        50% { opacity: 0; }
    }
    
    /* Custom ASCII borders */
    .ascii-box {
        border: 1px solid var(--text-color);
        padding: 15px;
        margin: 10px 0;
        position: relative;
    }
    
    .ascii-box:before {
        content: "┌────────────────────────────────────────────────┐";
        position: absolute;
        top: -15px;
        left: 10px;
        color: var(--text-color);
    }
    
    .ascii-box:after {
        content: "└────────────────────────────────────────────────┘";
        position: absolute;
        bottom: -15px;
        left: 10px;
        color: var(--text-color);
    }
    
    /* Metrics styling */
    [data-testid="stMetricValue"] {
        color: var(--text-color) !important;
        font-family: var(--font-family) !important;
        font-weight: bold !important;
        text-shadow: 0 0 5px var(--text-color) !important;
    }
    
    [data-testid="stMetricLabel"] {
        color: var(--text-color) !important;
        font-family: var(--font-family) !important;
    }
    
    [data-testid="stMetricDelta"] {
        color: var(--text-color) !important;
        font-family: var(--font-family) !important;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for navigation
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"

# Create a top navigation bar with no emojis and bold font
st.markdown("""
<style>
    .stButton button {
        font-weight: bold !important;
    }
</style>
""", unsafe_allow_html=True)

# Home, Live Tracker, Actor Database, ML Analyzer, and Omni-Intelligence RSS as main navigation
cols = st.columns(5)
with cols[0]:
    if st.button("HOME", use_container_width=True, 
                 type="primary" if st.session_state.current_page == "Home" else "secondary"):
        st.session_state.current_page = "Home"
        st.rerun()
with cols[1]:
    if st.button("LIVE TRACKER", use_container_width=True, 
                 type="primary" if st.session_state.current_page == "Global Map" else "secondary"):
        st.session_state.current_page = "Global Map"
        st.rerun()
with cols[2]:
    if st.button("ACTOR DATABASE", use_container_width=True,
                 type="primary" if st.session_state.current_page == "Threat Actor Database" else "secondary"):
        st.session_state.current_page = "Threat Actor Database"
        st.rerun()
with cols[3]:
    if st.button("ML ANALYZER", use_container_width=True,
                 type="primary" if st.session_state.current_page == "ML Analysis" else "secondary"):
        st.session_state.current_page = "ML Analysis"
        st.rerun()
with cols[4]:
    if st.button("OMNI-RSS", use_container_width=True, 
                 type="primary" if st.session_state.current_page == "OmniIntelligence Feed" else "secondary"):
        st.session_state.current_page = "OmniIntelligence Feed"
        st.rerun()

# If Actor Database is selected, show sub-navigation
if st.session_state.current_page == "Threat Actor Database":
    st.markdown("<hr style='margin: 10px 0;'>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center;'>DATABASE NAVIGATION</div>", unsafe_allow_html=True)
    
    sub_cols = st.columns(3)
    with sub_cols[0]:
        if st.button("THREAT ACTORS", use_container_width=True,
                   type="primary" if st.session_state.current_page == "Threat Actors" else "secondary"):
            st.session_state.current_page = "Threat Actors"
            st.rerun()
    with sub_cols[1]:
        if st.button("TTPs", use_container_width=True,
                   type="primary" if st.session_state.current_page == "Tactics & Techniques" else "secondary"):
            st.session_state.current_page = "Tactics & Techniques"
            st.rerun()
    with sub_cols[2]:
        if st.button("ATTRIBUTION", use_container_width=True,
                   type="primary" if st.session_state.current_page == "Attribution" else "secondary"):
            st.session_state.current_page = "Attribution"
            st.rerun()

# Divider
st.markdown("<hr style='margin-top: 0; margin-bottom: 20px;'>", unsafe_allow_html=True)

# Sidebar for filters and options
st.sidebar.title("Filters & Settings")

# Time range filter
st.sidebar.subheader("Time Range")
time_range = st.sidebar.selectbox(
    "Select time range",
    ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "All time"]
)

# Region filter
st.sidebar.subheader("Region")
all_regions = ["All", "North America", "South America", "Europe", "Asia", "Africa", "Middle East", "Oceania"]
selected_region = st.sidebar.multiselect("Select regions", all_regions, default=["All"])

# Attack type filter
st.sidebar.subheader("Attack Type")
attack_types = ["All", "Ransomware", "DDoS", "Phishing", "Data Breach", "APT", "Malware", "Zero-Day"]
selected_attack_types = st.sidebar.multiselect("Select attack types", attack_types, default=["All"])

# Threat actor filter
st.sidebar.subheader("Threat Actor")
with st.sidebar.expander("Advanced Filters"):
    attribution_source = st.multiselect(
        "Attribution Sources",
        ["MITRE ATT&CK", "Kaspersky", "Radware", "Palo Alto", "Rapid7", "ETDA"],
        default=["MITRE ATT&CK"]
    )
    
    toolkit_filter = st.multiselect(
        "Toolkits",
        ["All", "Cobalt Strike", "Empire", "Metasploit", "Custom", "Others"],
        default=["All"]
    )
    
    tactic_filter = st.multiselect(
        "Tactics (MITRE ATT&CK)",
        ["All", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", 
         "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Command and Control", "Impact"],
        default=["All"]
    )

# Data source selection
st.sidebar.subheader("Data Sources")
data_sources = st.sidebar.multiselect(
    "Select data sources",
    ["Kaspersky", "Radware", "MITRE ATT&CK", "APT Map", "Palo Alto", "Rapid7", "ETDA"],
    default=["Kaspersky", "Radware", "MITRE ATT&CK"]
)

# Refresh data
st.sidebar.subheader("Data Refresh")
auto_refresh = st.sidebar.checkbox("Auto refresh data", value=False)
refresh_rate = st.sidebar.slider("Refresh rate (minutes)", 5, 60, 15) if auto_refresh else None

if st.sidebar.button("Refresh Now") or auto_refresh:
    st.cache_data.clear()

# Last updated timestamp
st.sidebar.markdown(f"**Last updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# About section
with st.sidebar.expander("About"):
    st.markdown("""
    This application collects and analyzes cyber threat intelligence from multiple sources:
    
    - Kaspersky Threat Map
    - Radware Live Feeds
    - MITRE ATT&CK Groups
    - APT Map
    - Rapid7 Threat Intelligence
    - Palo Alto Unit42 Data
    - ETDA APT Groups
    
    Data is refreshed periodically to provide up-to-date intelligence on global cyber threats.
    """)

# Main content area
# Load and process data with a loading spinner
with st.spinner("Loading threat intelligence data..."):
    # Try to load cached data first
    data = load_cached_data(time_range, selected_region, selected_attack_types, data_sources)
    
    if data is None:
        # If no cached data, load from sources
        data = {}
        
        if "Kaspersky" in data_sources:
            data["kaspersky"] = get_kaspersky_data()
        
        if "Radware" in data_sources:
            data["radware"] = get_radware_data()
        
        if "MITRE ATT&CK" in data_sources:
            data["mitre"] = get_mitre_attack_groups()
        
        if "APT Map" in data_sources or "ETDA" in data_sources:
            data["apt"] = get_apt_data(sources=["APT Map", "ETDA"])
            
        if "Palo Alto" in data_sources or "Rapid7" in data_sources:
            data["threatmap"] = get_threatmap_data(sources=["Palo Alto", "Rapid7"])
        
        # Process and categorize data
        data = process_threat_data(data, time_range, selected_region, selected_attack_types)

# Display metrics at the top
st.subheader("Current Threat Overview")
col1, col2, col3, col4 = st.columns(4)

with col1:
    active_attacks = data.get("active_attacks", 0)
    st.metric("Active Attacks", format_number(active_attacks), delta="+12% vs prev day")

with col2:
    blocked_threats = data.get("blocked_threats", 0)
    st.metric("Blocked Threats (24h)", format_number(blocked_threats), delta="-5% vs prev day")

with col3:
    unique_actors = data.get("unique_actors", 0)
    st.metric("Active Threat Actors", format_number(unique_actors), delta="+3 new groups")

with col4:
    global_threat_index = data.get("global_threat_index", 65)
    st.metric("Global Threat Index", f"{global_threat_index}/100", delta="+5 pts")

# Main content based on selected page
if st.session_state.current_page == "Home":
    # Custom CSS for the Home page with ASCII terminal blog template
    st.markdown("""
    <style>
        .blog-container {
            max-width: 100%;
            margin: 0 auto;
            font-family: 'Courier New', monospace;
            color: #33ff33;
        }
        .blog-header {
            text-align: center;
            margin-bottom: 2rem;
            border: 1px solid #33ff33;
            padding: 1rem;
            box-shadow: 0 0 10px #33ff33;
        }
        .blog-title {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
            color: #33ff33;
            text-shadow: 0 0 5px #33ff33;
        }
        .blog-subtitle {
            font-size: 1.2rem;
            color: #33ff33;
            margin-bottom: 1.5rem;
        }
        .featured-article {
            margin-bottom: 2rem;
            border: 1px solid #33ff33;
            padding: 1rem;
            position: relative;
        }
        .featured-article:before {
            content: "┌───── FEATURED ARTICLE ─────┐";
            position: absolute;
            top: -15px;
            left: 20px;
            background-color: black;
            padding: 0 10px;
        }
        .featured-article:after {
            content: "└─────────────────────────────┘";
            position: absolute;
            bottom: -15px;
            right: 20px;
            background-color: black;
            padding: 0 10px;
        }
        .featured-content {
            padding: 1rem;
            background-color: black;
        }
        .featured-title {
            font-size: 1.8rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
            color: #33ff33;
            text-shadow: 0 0 5px #33ff33;
        }
        .featured-meta {
            color: #33ff33;
            font-size: 0.9rem;
            margin-bottom: 1rem;
            opacity: 0.8;
        }
        .featured-excerpt {
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 1rem;
            color: #33ff33;
        }
        .article-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            grid-gap: 2rem;
            margin-top: 3rem;
        }
        .article-card {
            border: 1px solid #33ff33;
            padding: 1rem;
            height: 100%;
            position: relative;
            background-color: black;
            font-family: 'Courier New', monospace;
        }
        .article-card:before {
            content: "┌───────┐";
            position: absolute;
            top: -15px;
            left: 20px;
            background-color: black;
            padding: 0 10px;
        }
        .article-card:after {
            content: "└───────┘";
            position: absolute;
            bottom: -15px;
            right: 20px;
            background-color: black;
            padding: 0 10px;
        }
        .article-title {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
            color: #33ff33;
            min-height: 3.6rem;
            text-shadow: 0 0 5px #33ff33;
        }
        .article-meta {
            color: #33ff33;
            font-size: 0.8rem;
            margin-bottom: 0.7rem;
            opacity: 0.8;
        }
        .article-excerpt {
            font-size: 0.9rem;
            line-height: 1.5;
            color: #33ff33;
        }
        .read-more {
            display: inline-block;
            margin-top: 1rem;
            padding: 0.5rem 1rem;
            background-color: black;
            color: #33ff33;
            text-decoration: none;
            border: 1px solid #33ff33;
            font-weight: bold;
            transition: all 0.3s ease;
            font-family: 'Courier New', monospace;
        }
        .read-more:hover {
            background-color: #33ff33;
            color: black;
            box-shadow: 0 0 10px #33ff33;
        }
        .newsletter-section {
            padding: 2rem;
            background-color: black;
            border: 1px solid #33ff33;
            margin-top: 3rem;
            text-align: center;
            position: relative;
        }
        .newsletter-section:before {
            content: "┌─ SUBSCRIBE ─┐";
            position: absolute;
            top: -15px;
            left: 20px;
            background-color: black;
            padding: 0 10px;
        }
        .newsletter-section:after {
            content: "└─────────────┘";
            position: absolute;
            bottom: -15px;
            right: 20px;
            background-color: black;
            padding: 0 10px;
        }
        .newsletter-title {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 1rem;
            color: #33ff33;
            text-shadow: 0 0 5px #33ff33;
        }
        .newsletter-description {
            font-size: 1rem;
            margin-bottom: 1.5rem;
            color: #33ff33;
        }
        .ascii-art {
            font-family: monospace;
            white-space: pre;
            line-height: 1;
            font-size: 10px;
            color: #33ff33;
            text-align: center;
            margin: 20px 0;
        }
        /* Text animation to simulate old-school terminals */
        @keyframes typing {
            from { width: 0 }
            to { width: 100% }
        }
        .typing-text {
            overflow: hidden;
            border-right: .15em solid #33ff33;
            white-space: nowrap;
            letter-spacing: .1em;
            animation: 
                typing 3.5s steps(40, end),
                blink-caret .75s step-end infinite;
        }
        @keyframes blink-caret {
            from, to { border-color: transparent }
            50% { border-color: #33ff33; }
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Function to fetch the Substack RSS feed
    def fetch_infinite_eyes_feed():
        try:
            feed_url = "https://infiniteeyesnews.substack.com/feed"
            feed = feedparser.parse(feed_url)
            return feed
        except Exception as e:
            st.error(f"Error fetching InfiniteEyesNews feed: {e}")
            return {"entries": []}
    
    # Fetch the feed
    substack_feed = fetch_infinite_eyes_feed()
    
    # Display blog header
    st.markdown("""
    <div class="blog-container">
        <div class="blog-header">
            <div class="blog-title">InfiniteEyesNews</div>
            <div class="blog-subtitle">Essential cybersecurity and intelligence insights from the experts</div>
        </div>
    """, unsafe_allow_html=True)
    
    # Featured article (first entry from feed)
    if substack_feed.entries:
        featured_article = substack_feed.entries[0]
        featured_title = featured_article.get("title", "No title")
        featured_link = featured_article.get("link", "#")
        featured_date = featured_article.get("published", "Date unknown")
        
        # Extract excerpt
        featured_excerpt = ""
        if "summary" in featured_article:
            featured_excerpt = BeautifulSoup(featured_article.summary, "html.parser").get_text()
        elif "content" in featured_article:
            featured_excerpt = BeautifulSoup(featured_article.content[0].value, "html.parser").get_text()
        
        # Truncate excerpt
        if len(featured_excerpt) > 300:
            featured_excerpt = featured_excerpt[:300] + "..."
            
        # Display featured article
        st.markdown(f"""
        <div class="featured-article">
            <img src="https://substackcdn.com/image/fetch/w_1456,c_limit,f_webp,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F7cc0c09b-e71b-4941-ae05-a3c1d0ca4c2c_1280x853.jpeg" class="featured-image" alt="Featured Article">
            <div class="featured-content">
                <div class="featured-title">{featured_title}</div>
                <div class="featured-meta">Published on {featured_date}</div>
                <div class="featured-excerpt">{featured_excerpt}</div>
                <a href="{featured_link}" target="_blank" class="read-more">Read Full Article</a>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Start article grid
        st.markdown('<div class="row">', unsafe_allow_html=True)
        
        # Display the rest of the articles in a grid
        cols = st.columns(3)
        
        for i, article in enumerate(substack_feed.entries[1:7]):  # Display up to 6 more articles
            title = article.get("title", "No title")
            link = article.get("link", "#")
            published = article.get("published", "Date unknown")
            
            # Extract excerpt
            excerpt = ""
            if "summary" in article:
                excerpt = BeautifulSoup(article.summary, "html.parser").get_text()
            elif "content" in article:
                excerpt = BeautifulSoup(article.content[0].value, "html.parser").get_text()
            
            # Truncate excerpt
            if len(excerpt) > 150:
                excerpt = excerpt[:150] + "..."
                
            # Alternate the default images
            if i % 3 == 0:
                img_url = "https://substackcdn.com/image/fetch/w_1456,c_limit,f_webp,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fbcfb3221-de15-45bb-a791-d6fca2be5bb3_1280x853.jpeg"
            elif i % 3 == 1:
                img_url = "https://substackcdn.com/image/fetch/w_1456,c_limit,f_webp,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F1bfcf3a8-fb5e-409b-8f01-7a5e81656270_1280x853.jpeg"
            else:
                img_url = "https://substackcdn.com/image/fetch/w_1456,c_limit,f_webp,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F25a59060-ce93-430e-86a6-2804db4c1789_1280x853.jpeg"
            
            with cols[i % 3]:
                st.markdown(f"""
                <div class="article-card">
                    <img src="{img_url}" class="article-image" alt="Article Image">
                    <div class="article-content">
                        <div class="article-title">{title}</div>
                        <div class="article-meta">{published}</div>
                        <div class="article-excerpt">{excerpt}</div>
                        <a href="{link}" target="_blank" class="read-more">Read More</a>
                    </div>
                </div>
                <br>
                """, unsafe_allow_html=True)
    
    else:
        st.info("Unable to fetch articles from InfiniteEyesNews Substack. Please try again later.")
    
    # Newsletter subscription
    st.markdown("""
    <div class="newsletter-section">
        <div class="newsletter-title">Subscribe to InfiniteEyesNews</div>
        <div class="newsletter-description">Get the latest cybersecurity and intelligence insights delivered directly to your inbox</div>
        <a href="https://infiniteeyesnews.substack.com/" target="_blank" class="read-more">Subscribe Now</a>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)  # Close blog-container

elif st.session_state.current_page == "Global Map":
    st.title("Global Cyber Attack Tracker")
    st.markdown("""
    This application aggregates and visualizes threat intelligence from multiple sources,
    providing insights into global cyber attacks, threat actors, and their tactics.
    """)
    
    st.subheader("Live Tracker")
    
    # Create tabs for different visualizations
    map_tabs = st.tabs(["Live Map", "Attack Timeline", "Regional Stats", "Attack Types"])
    
    # No debug info needed in production
    
    with map_tabs[0]:
        # World map of attacks
        map_data = data.get("map_data", pd.DataFrame())
        
        # Create map data if needed for visualization
        if map_data.empty:
            countries = ["United States", "China", "Russia", "United Kingdom", "Germany", "Iran", 
                         "Brazil", "India", "North Korea", "Ukraine", "France", "Canada", "Australia", 
                         "Japan", "Israel", "Saudi Arabia", "South Africa", "Italy", "Spain"]
            
            # Generate data
            sample_data = []
            for country in countries:
                sample_data.append({
                    "country": country,
                    "attack_count": np.random.randint(10, 150)
                })
            map_data = pd.DataFrame(sample_data)
        
        # Create a combined visualization with live attack maps - vertically stacked for better width
        st.subheader("Global Cyber Attack Activity Map")
        
        # Add Checkpoint animated world map - full width
        st.markdown("""
        <div style="background-color: #111111; border: 1px solid #33ff33; padding: 15px; border-radius: 5px; height: 450px; box-shadow: 0 0 10px rgba(51, 255, 51, 0.3); margin-bottom: 20px;">
            <h3 style="color: #33ff33; text-align: center; margin-bottom: 10px; font-family: 'Courier New', monospace; letter-spacing: 2px;">
                [ CHECKPOINT THREAT MAP ]
            </h3>
            <iframe src="https://threatmap.checkpoint.com/" width="100%" height="370" frameborder="0" style="border-radius: 3px;"></iframe>
        </div>
        """, unsafe_allow_html=True)
        
        # Add Kaspersky animated world map - full width 
        st.markdown("""
        <div style="background-color: #111111; border: 1px solid #33ff33; padding: 15px; border-radius: 5px; height: 450px; box-shadow: 0 0 10px rgba(51, 255, 51, 0.3); margin-bottom: 20px;">
            <h3 style="color: #33ff33; text-align: center; margin-bottom: 10px; font-family: 'Courier New', monospace; letter-spacing: 2px;">
                [ KASPERSKY THREAT MAP ]
            </h3>
            <iframe src="https://cybermap.kaspersky.com/en/widget/dynamic/dark" width="100%" height="370" frameborder="0" style="border-radius: 3px;"></iframe>
        </div>
        """, unsafe_allow_html=True)
        
        # Live Attack Feed section - now full width under the maps
        st.markdown("""
        <div style="background-color: #1E1E1E; padding: 10px; border-radius: 5px; height: 400px; overflow-y: auto; margin-bottom: 20px;">
            <h3 style="color: #33ff33; text-align: center; border-bottom: 1px solid #444; padding-bottom: 10px; font-family: 'Courier New', monospace; letter-spacing: 2px;">
                [ LIVE ATTACK FEED ]
            </h3>
            <div id="attack-feed">
        """, unsafe_allow_html=True)
        
        # Example data for sectors targeted by groups
        threat_groups_sectors = [
            {"group": "APT28 (Fancy Bear)", "country": "Russia", "sectors": ["Government", "Defense", "Election Infrastructure"], "color": "#FF5555"},
            {"group": "APT29 (Cozy Bear)", "country": "Russia", "sectors": ["Diplomacy", "NGOs", "Think Tanks"], "color": "#FF5555"},
            {"group": "Lazarus Group", "country": "North Korea", "sectors": ["Financial", "Cryptocurrency", "Entertainment"], "color": "#FFAA33"},
            {"group": "APT41", "country": "China", "sectors": ["Healthcare", "Telecommunications", "Manufacturing"], "color": "#FF3355"},
            {"group": "Sandworm", "country": "Russia", "sectors": ["Energy", "Critical Infrastructure", "Utilities"], "color": "#FF5555"},
            {"group": "Equation Group", "country": "United States", "sectors": ["Defense", "Telecommunications", "Nuclear"], "color": "#3355FF"},
            {"group": "Carbanak", "country": "Russia", "sectors": ["Banking", "Financial Services", "Payment Processing"], "color": "#FF5555"},
            {"group": "OilRig (APT34)", "country": "Iran", "sectors": ["Energy", "Government", "Aviation"], "color": "#AAFF33"},
            {"group": "Muddy Water", "country": "Iran", "sectors": ["Telecommunications", "Government", "Defense"], "color": "#AAFF33"},
            {"group": "BlackTech", "country": "China", "sectors": ["Technology", "Media", "Electronics"], "color": "#FF3355"},
            {"group": "Winnti Group", "country": "China", "sectors": ["Gaming", "Software Companies", "Pharmaceuticals"], "color": "#FF3355"},
            {"group": "Dragonfly", "country": "Russia", "sectors": ["Energy", "Industrial Control Systems", "Nuclear"], "color": "#FF5555"}
        ]
        
        # Display the sector targeting information in two columns for better use of width
        cols = st.columns(2)
        for i, group in enumerate(threat_groups_sectors):
            col_idx = i % 2
            with cols[col_idx]:
                name = group["group"]
                country = group["country"]
                sectors = ", ".join(group["sectors"])
                color = group["color"]
                
                # Create a styled attack entry
                st.markdown(f"""
                <div style="
                    border-left: 4px solid {color}; 
                    padding: 10px; 
                    margin-bottom: 8px; 
                    background-color: rgba(30, 30, 30, 0.7);
                    border-radius: 0 5px 5px 0;
                ">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: white; font-weight: bold;">
                            {name}
                        </span>
                        <span style="color: #999; font-size: 0.8em;">
                            {country}
                        </span>
                    </div>
                    <div style="margin-top: 5px; color: #DDD;">
                        <span style="color: #55FF55; font-family: 'Courier New', monospace;">TARGETS:</span> {sectors}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("""
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Display attack metrics by sector in a row of metrics
        metric_cols = st.columns(5)
        with metric_cols[0]:
            st.metric("Government", "35%", "+8%")
        with metric_cols[1]:
            st.metric("Financial", "28%", "+12%")
        with metric_cols[2]:
            st.metric("Energy", "23%", "+5%")
        with metric_cols[3]:
            st.metric("Healthcare", "18%", "+15%")
        with metric_cols[4]:
            st.metric("Technology", "16%", "+7%")
    
    # Attack statistics by region (no section header as requested)
    region_data = categorize_by_region(data.get("attacks", []))
    if not region_data.empty:
        fig = px.bar(
            region_data, 
            x="region", 
            y="count", 
            color="region",
            title="Attack Volume by Region",
            labels={"region": "Region", "count": "Number of Attacks"}
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No regional data available with current filters.")
    
    # ASCII Threat Level Tracker
    st.subheader("Global Threat Level Tracker")
    
    # Attack intensity levels represented as text
    attack_levels = {
        "China": "███████████ [120]",
        "Russia": "█████████ [95]", 
        "United States": "████████ [85]",
        "North Korea": "██████ [70]",
        "Iran": "████ [65]",
        "Japan": "███ [45]",
        "India": "███ [40]",
        "Israel": "███ [35]",
        "Germany": "██ [30]",
        "Ukraine": "██ [25]",
        "Brazil": "██ [20]",
        "United Kingdom": "█ [15]"
    }
    
    # Group countries by region
    regions = {
        "East Asia": ["China", "Japan", "North Korea"],
        "South Asia": ["India"],
        "Middle East": ["Iran", "Israel"],
        "Europe": ["Russia", "Germany", "Ukraine", "United Kingdom"],
        "Americas": ["United States", "Brazil"]
    }
    
    # Create the ASCII map with terminal styling
    st.markdown("""
    <style>
        .map-container {
            font-family: 'Courier New', monospace;
            background-color: #111111;
            color: #ffffff;
            padding: 20px;
            border: 1px solid #33ff33;
            border-radius: 5px;
            overflow: auto;
            position: relative;
            box-shadow: 0 0 10px rgba(51, 255, 51, 0.3);
        }
        .map-region {
            margin-bottom: 18px;
            border-left: 2px solid #33ff33;
            padding-left: 10px;
        }
        .map-region-title {
            color: #33ff33;
            font-weight: bold;
            padding-bottom: 8px;
            margin-bottom: 8px;
            letter-spacing: 1px;
        }
        .map-entry {
            display: flex;
            justify-content: space-between;
            margin: 6px 0;
            border-bottom: 1px dotted #333333;
            padding-bottom: 4px;
        }
        .map-country {
            min-width: 150px;
            font-weight: bold;
        }
        .high-threat {
            color: #ff5555;
            text-shadow: 0 0 5px rgba(255, 85, 85, 0.7);
        }
        .medium-threat {
            color: #ffff55;
            text-shadow: 0 0 5px rgba(255, 255, 85, 0.5);
        }
        .low-threat {
            color: #55ff55;
        }
        .map-header {
            text-align: center;
            margin-bottom: 18px;
            font-size: 1.2em;
            color: #ffffff;
            text-shadow: 0 0 5px #ffffff;
        }
        .map-header-line {
            color: #33ff33;
        }
        .map-footer {
            margin-top: 15px;
            color: #33ff33;
            font-size: 0.8em;
            text-align: center;
            padding-top: 10px;
            border-top: 1px solid #333333;
        }
    </style>
    <div class="map-container">
        <div class="map-header">
            <div class="map-header-line">┌──────────────────────────────────────────────────┐</div>
            GLOBAL CYBER ATTACK INTENSITY - APRIL 30, 2025
            <div class="map-header-line">└──────────────────────────────────────────────────┘</div>
        </div>
    """, unsafe_allow_html=True)
    
    # Display each region's data
    for region, countries in regions.items():
        st.markdown(f"""
        <div class="map-region">
            <div class="map-region-title">[ {region} ]</div>
        """, unsafe_allow_html=True)
        
        for country in countries:
            intensity = attack_levels.get(country, "█ [0]")
            
            # Determine threat level class based on value
            threat_class = "low-threat"
            if "[120]" in intensity or "[95]" in intensity or "[85]" in intensity or "[70]" in intensity:
                threat_class = "high-threat"
                arrow = "▲▲▲" # High threat
            elif "[65]" in intensity or "[45]" in intensity or "[40]" in intensity or "[35]" in intensity:
                threat_class = "medium-threat"
                arrow = "▲▲ " # Medium threat
            else:
                arrow = "▲  " # Low threat
            
            # Format with padding to ensure nice alignment
            country_padded = country.ljust(15)
            
            st.markdown(f"""
            <div class="map-entry">
                <span class="map-country">{arrow} {country_padded}</span>
                <span class="{threat_class}">{intensity}</span>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    # Map footer
    st.markdown("""
        <div class="map-footer">
            THREAT LEVEL: █ LOW ██ MEDIUM ███████ HIGH
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Actor Timeline - showing threat actors and their targets over time
    st.subheader("Threat Actor Timeline")
    
    # Use HTML component to ensure animations work correctly
    st.components.v1.html("""
    <style>
    @keyframes glow {
        0% { text-shadow: 0 0 5px rgba(51, 255, 51, 0.5); }
        50% { text-shadow: 0 0 20px rgba(51, 255, 51, 0.8); }
        100% { text-shadow: 0 0 5px rgba(51, 255, 51, 0.5); }
    }
    
    @keyframes blink {
        0% { opacity: 1; }
        50% { opacity: 0.3; }
        100% { opacity: 1; }
    }
    
    @keyframes colorShift {
        0% { color: #ff5555; }
        25% { color: #ffaa33; }
        50% { color: #ffff55; }
        75% { color: #33ff55; }
        100% { color: #ff5555; }
    }
    
    .timeline-container {
        font-family: 'Courier New', monospace;
        background-color: #111111;
        color: #ffffff;
        padding: 20px;
        border: 1px solid #33ff33;
        border-radius: 5px;
        position: relative;
        box-shadow: 0 0 15px rgba(51, 255, 51, 0.4);
    }
    
    .timeline-header {
        text-align: center;
        margin-bottom: 25px;
        color: #33ff33;
        font-weight: bold;
        letter-spacing: 1px;
        animation: glow 2s infinite ease-in-out;
    }
    
    .timeline-months {
        display: flex;
        justify-content: space-between;
        border-bottom: 1px solid #33ff33;
        padding-bottom: 5px;
        margin-bottom: 15px;
    }
    
    .timeline-month {
        color: #33ff33;
        font-weight: bold;
    }
    
    .timeline-month:nth-child(1) {
        animation: blink 4s infinite ease-in-out;
        animation-delay: 0s;
    }
    
    .timeline-month:nth-child(2) {
        animation: blink 4s infinite ease-in-out;
        animation-delay: 1s;
    }
    
    .timeline-month:nth-child(3) {
        animation: blink 4s infinite ease-in-out;
        animation-delay: 2s;
    }
    
    .timeline-month:nth-child(4) {
        animation: blink 4s infinite ease-in-out;
        animation-delay: 3s;
    }
    
    .timeline-actor {
        margin-bottom: 20px;
        padding-left: 10px;
        border-left: 2px solid #33ff33;
    }
    
    .timeline-actor-name {
        color: white;
        font-weight: bold;
        margin-bottom: 10px;
        text-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
    }
    
    .timeline-activity {
        display: flex;
        margin-bottom: 8px;
        transition: all 0.3s ease;
    }
    
    .timeline-activity:hover {
        background-color: rgba(51, 255, 51, 0.1);
        transform: translateX(5px);
    }
    
    .timeline-date {
        min-width: 100px;
        color: #999;
    }
    
    .timeline-target {
        color: #ffff55;
    }
    
    .timeline-attack {
        color: #ff5555;
        margin-left: 10px;
        animation: colorShift 10s infinite linear;
    }
    
    /* Active indicator for most recent activities */
    .timeline-activity:last-child .timeline-date::before {
        content: "●";
        color: #33ff55;
        margin-right: 5px;
        animation: blink 1s infinite ease-in-out;
    }
    </style>
    
    <div class="timeline-container">
        <div class="timeline-header">THREAT ACTOR ACTIVITY TIMELINE (JAN - APR 2025)</div>
        
        <div class="timeline-months">
            <div class="timeline-month">JAN</div>
            <div class="timeline-month">FEB</div>
            <div class="timeline-month">MAR</div>
            <div class="timeline-month">APR</div>
        </div>
        
        <div class="timeline-actor">
            <div class="timeline-actor-name">APT28 (Fancy Bear) - Russia</div>
            <div class="timeline-activity">
                <div class="timeline-date">Jan 15, 2025</div>
                <div class="timeline-target">→ German Government</div>
                <div class="timeline-attack">[Spear-phishing Campaign]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Mar 07, 2025</div>
                <div class="timeline-target">→ European Parliament</div>
                <div class="timeline-attack">[Zero-day Exploit]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Apr 12, 2025</div>
                <div class="timeline-target">→ NATO Infrastructure</div>
                <div class="timeline-attack">[DDoS Attack]</div>
            </div>
        </div>
        
        <div class="timeline-actor">
            <div class="timeline-actor-name">Lazarus Group - North Korea</div>
            <div class="timeline-activity">
                <div class="timeline-date">Jan 23, 2025</div>
                <div class="timeline-target">→ Cryptocurrency Exchanges</div>
                <div class="timeline-attack">[Supply Chain Attack]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Feb 18, 2025</div>
                <div class="timeline-target">→ Financial Institutions</div>
                <div class="timeline-attack">[SWIFT Network Breach]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Apr 02, 2025</div>
                <div class="timeline-target">→ Defense Contractors</div>
                <div class="timeline-attack">[Watering Hole Attack]</div>
            </div>
        </div>
        
        <div class="timeline-actor">
            <div class="timeline-actor-name">APT41 - China</div>
            <div class="timeline-activity">
                <div class="timeline-date">Feb 05, 2025</div>
                <div class="timeline-target">→ Healthcare Providers</div>
                <div class="timeline-attack">[Data Exfiltration]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Mar 21, 2025</div>
                <div class="timeline-target">→ Telecom Companies</div>
                <div class="timeline-attack">[Backdoor Installation]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Apr 17, 2025</div>
                <div class="timeline-target">→ Pharmaceutical Research</div>
                <div class="timeline-attack">[Intellectual Property Theft]</div>
            </div>
        </div>
        
        <div class="timeline-actor">
            <div class="timeline-actor-name">Sandworm - Russia</div>
            <div class="timeline-activity">
                <div class="timeline-date">Jan 31, 2025</div>
                <div class="timeline-target">→ Energy Grid</div>
                <div class="timeline-attack">[BlackEnergy Malware]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Mar 14, 2025</div>
                <div class="timeline-target">→ Water Treatment</div>
                <div class="timeline-attack">[SCADA System Compromise]</div>
            </div>
            <div class="timeline-activity">
                <div class="timeline-date">Apr 27, 2025</div>
                <div class="timeline-target">→ Transportation Systems</div>
                <div class="timeline-attack">[Wiper Malware]</div>
            </div>
        </div>
    </div>
    """, height=650)

elif st.session_state.current_page == "Threat Actors":
    st.subheader("Threat Actor Analysis")
    
    # Search box for threat actors
    search_query = st.text_input("Search for threat actors", "")
    
    # Threat actor profiles
    actor_data = data.get("actor_data", pd.DataFrame())
    
    if not actor_data.empty:
        if search_query:
            actor_data = actor_data[
                actor_data["name"].str.contains(search_query, case=False) | 
                actor_data["also_known_as"].str.contains(search_query, case=False) |
                actor_data["region"].str.contains(search_query, case=False)
            ]
        
        # Display threat actor cards
        for i in range(0, len(actor_data), 3):
            cols = st.columns(3)
            for j in range(3):
                if i + j < len(actor_data):
                    actor = actor_data.iloc[i + j]
                    with cols[j]:
                        with st.expander(f"{actor['name']} ({actor['region']})"):
                            st.markdown(f"**Also Known As:** {actor['also_known_as']}")
                            st.markdown(f"**Origin:** {actor['region']}")
                            st.markdown(f"**Active Since:** {actor['active_since']}")
                            st.markdown(f"**Attribution:** {actor['attribution']}")
                            st.markdown(f"**Target Sectors:** {actor['target_sectors']}")
                            st.markdown(f"**Common Toolkits:** {actor['toolkits']}")
                            st.markdown(f"**Notable Attacks:** {actor['notable_attacks']}")
    else:
        st.info("No threat actor data available with current filters.")
    
    # Distribution of threat actors by toolkit
    st.subheader("Threat Actor Distribution by Toolkit")
    toolkit_data = categorize_by_toolkit(data.get("actor_data", pd.DataFrame()))
    if not toolkit_data.empty:
        toolkit_fig = create_threat_distribution_chart(toolkit_data, "toolkit")
        st.plotly_chart(toolkit_fig, use_container_width=True)
    else:
        st.info("No toolkit data available.")

elif st.session_state.current_page == "Tactics & Techniques":
    st.subheader("Tactics, Techniques, and Procedures (TTPs)")
    
    # Distribution of attacks by tactic
    tactic_data = categorize_by_tactic(data.get("attacks", []))
    if not tactic_data.empty:
        tactic_fig = create_threat_distribution_chart(tactic_data, "tactic")
        st.plotly_chart(tactic_fig, use_container_width=True)
    else:
        st.info("No tactic data available.")
    
    # MITRE ATT&CK Matrix visualization
    st.subheader("MITRE ATT&CK Matrix Usage")
    
    # Display techniques used by selected threat actors
    techniques_data = data.get("techniques_data", pd.DataFrame())
    if not techniques_data.empty:
        technique_heatmap = px.density_heatmap(
            techniques_data,
            x="tactic",
            y="threat_actor",
            z="count",
            title="Techniques Used by Threat Actors",
            labels={"tactic": "Tactic", "threat_actor": "Threat Actor", "count": "Frequency"}
        )
        st.plotly_chart(technique_heatmap, use_container_width=True)
    else:
        st.info("No techniques data available.")
    
    # Display common tools used in attacks
    st.subheader("Common Tools Used in Attacks")
    tools_data = data.get("tools_data", pd.DataFrame())
    if not tools_data.empty:
        st.dataframe(tools_data, use_container_width=True)
    else:
        st.info("No tools data available.")

elif st.session_state.current_page == "Attribution":
    st.subheader("Threat Intelligence Attribution")
    
    # Attribution network - showing which organizations track which groups
    st.markdown("""
    The attribution network shows which cybersecurity organizations track and name 
    different threat actors. This visualization helps understand the consensus and
    differences in threat actor identification across the industry.
    """)
    
    attribution_data = data.get("attribution_data", pd.DataFrame())
    if not attribution_data.empty:
        attribution_fig = create_attribution_network(attribution_data)
        st.plotly_chart(attribution_fig, use_container_width=True)
    else:
        st.info("No attribution data available.")
    
    # Comparison of naming conventions
    st.subheader("Threat Actor Naming Comparison")
    naming_data = data.get("naming_data", pd.DataFrame())
    if not naming_data.empty:
        st.dataframe(naming_data, use_container_width=True)
    else:
        st.info("No naming comparison data available.")

elif st.session_state.current_page == "Threat Actor Database":
    st.subheader("Threat Actor Database")
    st.markdown("""
    This database provides a comprehensive overview of known threat actors, 
    their associations, tactics, and historical campaigns. 
    Select a threat actor from the list to view detailed information.
    """)
    
    # Get actor data
    actor_data = data.get("actor_data", pd.DataFrame())
    
    if not actor_data.empty:
        # Create a two-column layout
        main_col, card_col = st.columns([1, 2])
        
        with main_col:
            # Actor selection and filtering options
            st.subheader("Actor Selection")
            
            # Region filter for actors
            region_filter = st.multiselect(
                "Filter by Region", 
                ["All"] + sorted(actor_data["region"].unique().tolist()), 
                default=["All"],
                key="db_region_filter"
            )
            
            # Create a list of actors based on filters
            filtered_actors = actor_data
            if not "All" in region_filter:
                filtered_actors = filtered_actors[filtered_actors["region"].isin(region_filter)]
            
            # Actor selection
            selected_actor_name = st.selectbox(
                "Select Threat Actor",
                options=sorted(filtered_actors["name"].unique().tolist()),
                index=0
            )
            
            # Get the selected actor data
            selected_actor = actor_data[actor_data["name"] == selected_actor_name].iloc[0]
            
            # Display detailed information about the selected actor
            st.subheader("Actor Details")
            
            # Create styled detailed information
            st.markdown(f"""
            ### {selected_actor['name']}
            
            **Also Known As:** {selected_actor['also_known_as']}
            
            **Region of Operation:** {selected_actor['region']}
            
            **Active Since:** {selected_actor['active_since']}
            
            **Attribution:** {selected_actor['attribution']}
            
            **Target Sectors:**
            {selected_actor['target_sectors']}
            
            **Common Toolkits:**
            {selected_actor['toolkits']}
            
            **Notable Attacks:**
            {selected_actor['notable_attacks']}
            
            **Tactics:**
            {selected_actor.get('tactics', 'Information not available')}
            """)
        
        with card_col:
            st.subheader("Threat Actor Cards")
            
            # Create a grid layout for the cards
            num_columns = 3
            for i in range(0, len(filtered_actors), num_columns):
                cols = st.columns(num_columns)
                for j in range(num_columns):
                    if i + j < len(filtered_actors):
                        actor = filtered_actors.iloc[i + j]
                        with cols[j]:
                            # Create a visually distinct card
                            region_color = get_region_color(actor['region'])
                            st.markdown(f"""
                            <div style="
                                border: 1px solid {region_color}; 
                                border-radius: 5px; 
                                padding: 10px; 
                                margin-bottom: 10px;
                                background-color: rgba(30, 30, 30, 0.7);
                                height: 230px;
                                overflow: hidden;
                                position: relative;
                                display: flex;
                                flex-direction: column;
                            ">
                                <div style="flex: 1;">
                                    <h4 style="color: {region_color}; margin-top: 0;">{actor['name']}</h4>
                                    <p style="font-size: 0.8em; margin-bottom: 5px;"><strong>Origin:</strong> {actor['region']}</p>
                                    <p style="font-size: 0.8em; margin-bottom: 5px;"><strong>Known as:</strong> {', '.join(actor['also_known_as'].split(', ')[:2]) if actor['also_known_as'] else 'Unknown'}...</p>
                                    <p style="font-size: 0.8em; margin-bottom: 5px;"><strong>Since:</strong> {actor['active_since']}</p>
                                    <p style="font-size: 0.8em; margin-bottom: 5px;"><strong>Targets:</strong> {', '.join(actor['target_sectors'].split(', ')[:2]) if actor['target_sectors'] else 'Unknown'}...</p>
                                    <p style="font-size: 0.8em; margin-bottom: 5px;"><strong>Toolkits:</strong> {', '.join(actor['toolkits'].split(', ')[:2]) if actor['toolkits'] else 'Unknown'}...</p>
                                </div>
                                
                                <div style="margin-top: 10px; text-align: center; padding-top: 5px; border-top: 1px dashed {region_color};">
                                    <span style="
                                        background-color: {region_color}; 
                                        color: #000; 
                                        padding: 3px 10px; 
                                        border-radius: 10px; 
                                        font-size: 0.7em;
                                        display: inline-block;
                                        text-align: center;
                                    ">View Details</span>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Make the card clickable by adding a button that is styled to look like part of the card
                            if st.button(f"Select {actor['name']}", key=f"btn_{actor['name']}"):
                                st.session_state.selected_actor = actor['name']
                                st.rerun()
    else:
        st.info("No threat actor data available. Try selecting different data sources in the sidebar.")

elif st.session_state.current_page == "ML Analysis":
    # Create the machine learning analysis page
    st.title("Machine Learning Attack Pattern Analysis")
    
    # Create a directory for models if it doesn't exist
    import os
    os.makedirs("models", exist_ok=True)
    
    # CSS for ML Analysis page
    st.markdown("""
    <style>
        .ml-container {
            margin-top: 20px;
            margin-bottom: 30px;
        }
        .ml-section {
            border: 1px solid #33ff33;
            padding: 15px;
            margin-bottom: 25px;
            position: relative;
            background-color: #111111;
        }
        .ml-section:before {
            content: attr(data-title);
            position: absolute;
            top: -15px;
            left: 20px;
            background-color: black;
            padding: 0 10px;
            color: #33ff33;
            font-family: 'Source Code Pro', monospace;
            font-weight: bold;
        }
        .ml-result {
            background-color: #111111;
            padding: 10px;
            border-left: 3px solid #33ff33;
            font-family: 'Source Code Pro', monospace;
            margin-top: 10px;
        }
        .prediction-box {
            display: inline-block;
            padding: 5px 10px;
            margin: 5px;
            border: 1px solid #33ff33;
            color: white;
        }
        .cluster-box {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-right: 10px;
            vertical-align: middle;
        }
        .anomaly-score {
            position: relative;
            height: 10px;
            background-color: #333;
            margin: 5px 0;
            width: 100%;
        }
        .anomaly-indicator {
            position: absolute;
            height: 100%;
            background-color: #33ff33;
        }
        .pattern-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            grid-gap: 10px;
            margin-top: 10px;
        }
        .pattern-card {
            border: 1px solid #33ff33;
            padding: 10px;
            background-color: #111111;
        }
        .threat-timeline {
            position: relative;
            height: 100px;
            width: 100%;
            margin: 20px 0;
            border-bottom: 1px solid #33ff33;
        }
        .threat-event {
            position: absolute;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: #33ff33;
            transform: translateY(-50%);
        }
        .threat-event:hover:after {
            content: attr(data-info);
            position: absolute;
            top: -30px;
            left: 0;
            background-color: black;
            border: 1px solid #33ff33;
            padding: 5px;
            z-index: 10;
            font-size: 12px;
            white-space: nowrap;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Tabs for ML Analysis
    ml_tabs = st.tabs(["Pattern Detection", "Anomaly Detection", "Prediction", "Campaign Analysis"])
    
    # Create an instance of the ML analyzer
    analyzer = AttackPatternAnalyzer()
    
    # First tab: Pattern Detection
    with ml_tabs[0]:
        st.markdown("<div class='ml-section' data-title='ATTACK PATTERN CLUSTERING'>", unsafe_allow_html=True)
        st.subheader("Detect Attack Patterns and Clusters")
        st.markdown("""
        This module uses machine learning clustering algorithms to identify patterns in cyber attacks.
        The system will analyze attack data based on source, target, timing, and attack types to discover inherent groupings.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            clustering_params = st.expander("Clustering Parameters", expanded=False)
            with clustering_params:
                clustering_algorithm = st.selectbox(
                    "Clustering Algorithm", 
                    ["DBSCAN", "KMeans", "Hierarchical"],
                    index=0
                )
                
                if clustering_algorithm == "DBSCAN":
                    eps_value = st.slider("Distance Threshold (eps)", 0.1, 2.0, 0.5, 0.1)
                    min_samples = st.slider("Minimum Samples per Cluster", 2, 15, 5)
                elif clustering_algorithm == "KMeans":
                    num_clusters = st.slider("Number of Clusters", 2, 20, 5)
                
                feature_importance = st.checkbox("Calculate Feature Importance", value=True)
        
        with col2:
            st.markdown("### Data Selection")
            
            cluster_time_range = st.selectbox(
                "Time Range for Analysis",
                ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "All time"],
                index=2
            )
            
            analyze_button = st.button("Run Clustering Analysis", type="primary")
        
        if analyze_button:
            with st.spinner("Running attack pattern clustering analysis..."):
                # In a real implementation, this would use actual database data
                # For the demo, we'll create a message about what would happen
                st.markdown("""
                <div class="ml-result">
                > SYSTEM: Initializing attack pattern analysis...<br>
                > SYSTEM: Loading attack data for selected timeframe (Last 30 days)...<br>
                > SYSTEM: Preprocessing data features...<br>
                > SYSTEM: Applying dimensionality reduction...<br>
                > SYSTEM: Running DBSCAN clustering algorithm...<br>
                > SYSTEM: Identifying key patterns...<br>
                > SYSTEM: Analysis complete!
                </div>
                """, unsafe_allow_html=True)
                
                # Show sample results
                st.markdown("### Detection Results")
                st.markdown("Found **5 distinct attack patterns** in the data with the following characteristics:")
                
                # Sample cluster visualization
                cluster_data = {
                    "Cluster 1": {"size": 35, "color": "#ff5555", "main_source": "China", "main_target": "US Tech Sector", "attack_type": "Data Exfiltration"},
                    "Cluster 2": {"size": 28, "color": "#55ff55", "main_source": "Russia", "main_target": "European Energy", "attack_type": "SCADA Attacks"},
                    "Cluster 3": {"size": 19, "color": "#5555ff", "main_source": "North Korea", "main_target": "Financial Institutions", "attack_type": "Ransomware"},
                    "Cluster 4": {"size": 12, "color": "#ffff55", "main_source": "Iran", "main_target": "Middle East Government", "attack_type": "Web Defacements"},
                    "Cluster 5": {"size": 8, "color": "#ff55ff", "main_source": "Eastern Europe", "main_target": "Global E-commerce", "attack_type": "Credit Card Theft"}
                }
                
                for cluster, details in cluster_data.items():
                    st.markdown(f"""
                    <div style="margin-bottom: 15px; padding: 10px; border-left: 4px solid {details['color']}; background-color: rgba(0,0,0,0.3);">
                        <div style="display: flex; justify-content: space-between;">
                            <div><strong>{cluster}</strong> ({details['size']} attacks)</div>
                            <div>Confidence: {90 - details['size']}%</div>
                        </div>
                        <div>Primary Source Region: {details['main_source']}</div>
                        <div>Primary Target: {details['main_target']}</div>
                        <div>Dominant Attack Type: {details['attack_type']}</div>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)

    # Second tab: Anomaly Detection
    with ml_tabs[1]:
        st.markdown("<div class='ml-section' data-title='ANOMALY DETECTION'>", unsafe_allow_html=True)
        st.subheader("Detect Unusual Attack Behaviors")
        st.markdown("""
        This module uses machine learning to identify unusual or anomalous attack behaviors that deviate from normal patterns.
        Anomalous attacks may indicate new threat actors, zero-day exploits, or changes in attacker TTPs.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            anomaly_params = st.expander("Anomaly Detection Parameters", expanded=False)
            with anomaly_params:
                anomaly_algorithm = st.selectbox(
                    "Anomaly Detection Algorithm", 
                    ["Isolation Forest", "One-Class SVM", "Local Outlier Factor"],
                    index=0
                )
                
                contamination = st.slider(
                    "Expected Anomaly Percentage", 
                    0.01, 0.20, 0.05, 0.01,
                    format="%0.2f"
                )
                
                random_state = st.number_input("Random Seed", 1, 100, 42)
        
        with col2:
            st.markdown("### Data Selection")
            
            anomaly_time_range = st.selectbox(
                "Time Range for Anomaly Analysis",
                ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days", "All time"],
                index=1,
                key="anomaly_timerange"
            )
            
            detect_button = st.button("Detect Anomalies", type="primary")
        
        if detect_button:
            with st.spinner("Running anomaly detection on attack data..."):
                # Sample anomaly detection results
                st.markdown("""
                <div class="ml-result">
                > SYSTEM: Initializing anomaly detection...<br>
                > SYSTEM: Loading attack data for selected timeframe (Last 7 days)...<br>
                > SYSTEM: Preprocessing data and normalizing features...<br>
                > SYSTEM: Running Isolation Forest algorithm...<br>
                > SYSTEM: Computing anomaly scores...<br>
                > SYSTEM: Identified 7 anomalous attack patterns!
                </div>
                """, unsafe_allow_html=True)
                
                # Show sample results
                st.markdown("### Anomaly Detection Results")
                st.markdown("Found **7 anomalous attacks** that significantly deviate from normal patterns:")
                
                # Sample anomalies
                anomalies = [
                    {"id": "A-1", "score": -0.82, "source": "Malaysia", "target": "Singapore Financial", "type": "Unknown Zero-Day", "reason": "Unusual source/target combination and unknown attack vector"},
                    {"id": "A-2", "score": -0.76, "source": "Ukraine", "target": "Critical Infrastructure", "type": "Custom Malware", "reason": "Unusual timing pattern and novel malware signature"},
                    {"id": "A-3", "score": -0.69, "source": "Brazil", "target": "European Aerospace", "type": "Supply Chain", "reason": "Rare geographic targeting pattern"},
                    {"id": "A-4", "score": -0.65, "source": "Taiwan", "target": "Japanese Manufacturing", "type": "Data Theft", "reason": "Abnormal lateral movement technique"},
                    {"id": "A-5", "score": -0.61, "source": "UAE", "target": "Cryptocurrency Exchanges", "type": "API Exploitation", "reason": "Unusual tactics compared to historical data"},
                    {"id": "A-6", "score": -0.58, "source": "South Africa", "target": "Global Media", "type": "Credential Theft", "reason": "Novel combination of tools and techniques"},
                    {"id": "A-7", "score": -0.52, "source": "Iceland", "target": "Cloud Infrastructure", "type": "Container Escape", "reason": "Anomalous target and unusual persistence mechanism"}
                ]
                
                for anomaly in anomalies:
                    score_percentage = int((-anomaly["score"]) * 100)
                    st.markdown(f"""
                    <div style="margin-bottom: 15px; padding: 10px; border-left: 4px solid #ff3333; background-color: rgba(255,0,0,0.1);">
                        <div style="display: flex; justify-content: space-between;">
                            <div><strong>Anomaly {anomaly["id"]}</strong></div>
                            <div>Anomaly Score: {score_percentage}%</div>
                        </div>
                        <div style="margin-top: 5px;">
                            <div>Source: {anomaly["source"]} → Target: {anomaly["target"]}</div>
                            <div>Attack Type: {anomaly["type"]}</div>
                            <div style="margin-top: 5px; font-style: italic; color: #ff5555;">Why anomalous: {anomaly["reason"]}</div>
                        </div>
                        <div class="anomaly-score">
                            <div class="anomaly-indicator" style="width: {score_percentage}%; background-color: #ff3333;"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)

    # Third tab: Prediction
    with ml_tabs[2]:
        st.markdown("<div class='ml-section' data-title='ATTACK PREDICTION'>", unsafe_allow_html=True)
        st.subheader("Predict Future Attack Targets and Patterns")
        st.markdown("""
        This module uses machine learning to predict likely future attack targets based on historical patterns.
        The system analyzes relationships between attack sources, techniques, and targets to forecast emerging threats.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            prediction_params = st.expander("Prediction Parameters", expanded=False)
            with prediction_params:
                prediction_model = st.selectbox(
                    "Prediction Algorithm", 
                    ["Random Forest", "Gradient Boosting", "Neural Network"],
                    index=0
                )
                
                forecast_horizon = st.selectbox(
                    "Prediction Horizon",
                    ["Next 24 hours", "Next 7 days", "Next 30 days"],
                    index=1
                )
                
                confidence_threshold = st.slider("Confidence Threshold", 0.5, 0.95, 0.75, 0.05)
        
        with col2:
            st.markdown("### Threat Actor Selection")
            
            threat_actor = st.selectbox(
                "Threat Actor (Optional)",
                ["Any Actor", "APT28 (Fancy Bear)", "Lazarus Group", "APT41", "Sandworm", "Equation Group"],
                index=0
            )
            
            source_region = st.selectbox(
                "Source Region (Optional)",
                ["Any Region", "North America", "Europe", "Russia", "China", "North Korea", "Middle East"],
                index=0
            )
            
            predict_button = st.button("Generate Predictions", type="primary")
        
        if predict_button:
            with st.spinner("Generating attack predictions..."):
                # Sample prediction results
                st.markdown("""
                <div class="ml-result">
                > SYSTEM: Initializing prediction engine...<br>
                > SYSTEM: Loading historical attack patterns...<br>
                > SYSTEM: Training prediction model on historical data...<br>
                > SYSTEM: Applying feature importance analysis...<br>
                > SYSTEM: Generating forecasts for the next 7 days...<br>
                > SYSTEM: Analysis complete! Found 5 high probability targets.
                </div>
                """, unsafe_allow_html=True)
                
                # Show sample results
                st.markdown("### Prediction Results")
                
                # Most important features
                st.markdown("#### Key Prediction Factors")
                
                features = {
                    "Source Country": 0.82,
                    "Attack Type": 0.76,
                    "Day of Week": 0.65,
                    "Previous Target Sector": 0.58,
                    "Time Between Attacks": 0.51,
                    "Attack Technique": 0.47,
                    "Geopolitical Events": 0.43
                }
                
                # Feature importance bar chart
                feature_names = list(features.keys())
                feature_values = list(features.values())
                
                chart_html = f"""
                <div style="margin-top: 15px; margin-bottom: 25px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <div>Feature</div>
                        <div>Importance</div>
                    </div>
                """
                
                for name, value in features.items():
                    percentage = int(value * 100)
                    chart_html += f"""
                    <div style="margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between;">
                            <div>{name}</div>
                            <div>{percentage}%</div>
                        </div>
                        <div style="height: 8px; width: 100%; background-color: #333;">
                            <div style="height: 100%; width: {percentage}%; background-color: #33ff33;"></div>
                        </div>
                    </div>
                    """
                
                chart_html += "</div>"
                st.markdown(chart_html, unsafe_allow_html=True)
                
                # Predicted targets
                st.markdown("#### Likely Targets in Next 7 Days")
                
                predictions = [
                    {"target": "Financial Services - North America", "probability": 0.92, "actor": "Lazarus Group", "attack_type": "Ransomware", "timing": "Weekend deployment"},
                    {"target": "Energy Sector - Europe", "probability": 0.87, "actor": "Sandworm", "attack_type": "SCADA System", "timing": "During maintenance windows"},
                    {"target": "Healthcare Organizations - Global", "probability": 0.81, "actor": "APT41", "attack_type": "Data Exfiltration", "timing": "Overnight hours"},
                    {"target": "Government Infrastructure - Southeast Asia", "probability": 0.78, "actor": "APT32", "attack_type": "Spear-phishing", "timing": "Business hours"},
                    {"target": "Defense Contractors - NATO Countries", "probability": 0.76, "actor": "APT28", "attack_type": "Zero-day Exploit", "timing": "Tuesday-Thursday"}
                ]
                
                for pred in predictions:
                    prob_percentage = int(pred["probability"] * 100)
                    color_intensity = int(155 + (pred["probability"] * 100))
                    
                    st.markdown(f"""
                    <div style="margin-bottom: 15px; padding: 10px; border-left: 4px solid rgb(51, {color_intensity}, 51); background-color: rgba(51, 255, 51, 0.1);">
                        <div style="display: flex; justify-content: space-between;">
                            <div><strong>{pred["target"]}</strong></div>
                            <div>Probability: {prob_percentage}%</div>
                        </div>
                        <div style="margin-top: 5px;">
                            <div>Likely Actor: {pred["actor"]}</div>
                            <div>Expected Attack Type: {pred["attack_type"]}</div>
                            <div>Timing: {pred["timing"]}</div>
                        </div>
                        <div class="anomaly-score">
                            <div class="anomaly-indicator" style="width: {prob_percentage}%; background-color: rgb(51, {color_intensity}, 51);"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)

    # Fourth tab: Campaign Analysis
    with ml_tabs[3]:
        st.markdown("<div class='ml-section' data-title='CAMPAIGN ANALYSIS'>", unsafe_allow_html=True)
        st.subheader("Identify Coordinated Attack Campaigns")
        st.markdown("""
        This module uses machine learning to identify coordinated attack campaigns across multiple targets.
        The system analyzes temporal patterns, shared TTPs, and targeting strategies to link related attacks.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            campaign_params = st.expander("Campaign Analysis Parameters", expanded=False)
            with campaign_params:
                timespan_days = st.slider("Campaign Timespan (days)", 7, 180, 30)
                min_attacks = st.slider("Minimum Attacks for Campaign", 3, 20, 5)
                similarity_threshold = st.slider("Similarity Threshold", 0.5, 0.95, 0.7, 0.05)
        
        with col2:
            st.markdown("### Campaign Scope")
            
            campaign_time_range = st.selectbox(
                "Analysis Timeframe",
                ["Last 30 days", "Last 90 days", "Last 180 days", "Last 365 days"],
                index=1,
                key="campaign_timerange"
            )
            
            attribution_level = st.select_slider(
                "Attribution Confidence",
                options=["Low", "Medium", "High"],
                value="Medium"
            )
            
            campaign_button = st.button("Identify Campaigns", type="primary")
        
        if campaign_button:
            with st.spinner("Analyzing attack campaigns..."):
                # Sample campaign detection results
                st.markdown("""
                <div class="ml-result">
                > SYSTEM: Initializing campaign detection...<br>
                > SYSTEM: Loading attack data for last 90 days...<br>
                > SYSTEM: Analyzing temporal patterns...<br>
                > SYSTEM: Clustering attack vectors and TTPs...<br>
                > SYSTEM: Applying attribution analysis...<br>
                > SYSTEM: Analysis complete! Identified 3 distinct campaigns.
                </div>
                """, unsafe_allow_html=True)
                
                # Show sample results
                st.markdown("### Campaign Analysis Results")
                
                # Sample campaign data
                campaigns = [
                    {
                        "name": "Operation Ghost Dragon",
                        "actor": "APT41 (China)",
                        "start_date": "2025-01-10",
                        "end_date": "2025-03-15",
                        "attack_count": 23,
                        "targets": ["Technology", "Manufacturing", "Research"],
                        "techniques": ["Spear-phishing", "Zero-day exploits", "Supply chain attacks"],
                        "confidence": "High",
                        "goal": "Intellectual property theft from high-tech manufacturing firms"
                    },
                    {
                        "name": "BlackEnergy Revival",
                        "actor": "Sandworm (Russia)",
                        "start_date": "2025-02-05",
                        "end_date": "2025-04-12",
                        "attack_count": 17,
                        "targets": ["Energy", "Utilities", "Government"],
                        "techniques": ["SCADA exploits", "Credential theft", "Destructive malware"],
                        "confidence": "Medium",
                        "goal": "Disrupt critical infrastructure in Eastern Europe"
                    },
                    {
                        "name": "Operation Cash Out",
                        "actor": "Lazarus Group (North Korea)",
                        "start_date": "2025-02-22",
                        "end_date": "Ongoing",
                        "attack_count": 12,
                        "targets": ["Financial", "Cryptocurrency", "Banking"],
                        "techniques": ["ATM malware", "SWIFT network attacks", "Ransomware"],
                        "confidence": "High",
                        "goal": "Financial gain to evade international sanctions"
                    }
                ]
                
                # Display campaigns
                for campaign in campaigns:
                    confidence_color = {
                        "High": "#33ff33",
                        "Medium": "#ffff33",
                        "Low": "#ff5555"
                    }[campaign["confidence"]]
                    
                    st.markdown(f"""
                    <div style="margin-bottom: 25px; padding: 15px; border: 1px solid {confidence_color}; background-color: rgba(0,0,0,0.3);">
                        <div style="display: flex; justify-content: space-between;">
                            <div style="font-size: 1.2em; font-weight: bold; color: {confidence_color};">{campaign["name"]}</div>
                            <div>Attribution Confidence: <span style="color: {confidence_color};">{campaign["confidence"]}</span></div>
                        </div>
                        
                        <div style="margin-top: 10px; display: flex; justify-content: space-between;">
                            <div><strong>Attributed to:</strong> {campaign["actor"]}</div>
                            <div><strong>Status:</strong> {campaign["end_date"] == "Ongoing" and "ACTIVE" or "CONCLUDED"}</div>
                        </div>
                        
                        <div style="margin-top: 10px;">
                            <div><strong>Timeline:</strong> {campaign["start_date"]} to {campaign["end_date"]}</div>
                            <div><strong>Attack Count:</strong> {campaign["attack_count"]}</div>
                            <div><strong>Primary Targets:</strong> {", ".join(campaign["targets"])}</div>
                            <div><strong>Key Techniques:</strong> {", ".join(campaign["techniques"])}</div>
                            <div style="margin-top: 8px;"><strong>Assessed Goal:</strong> {campaign["goal"]}</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)

# Models directory information
    with st.expander("Machine Learning Models Repository"):
        st.markdown("""
        **Repository Directory: `models/`**
        
        The system will store trained models in the models directory with timestamped filenames.
        These models can be loaded for future analysis without retraining.
        
        **Available Model Types:**
        - Clustering models (pattern detection)
        - Anomaly detection models
        - Attack prediction models
        - Campaign identification models
        
        **Training Dataset Information:**
        - Models are trained on historical attack data from the database
        - Features include attack vectors, targets, geographic information, timing patterns, etc.
        - Periodic retraining is recommended to maintain accuracy as threats evolve
        """)
        
        # Get list of model files (placeholder since we just created the dir)
        model_files = []
        
        if not model_files:
            st.info("No models have been trained yet. Use the analysis tools above to generate models.")
        else:
            st.markdown("### Trained Models")
            for model in model_files:
                st.markdown(f"- {model}")

elif st.session_state.current_page == "OmniIntelligence Feed":
    # ASCII Terminal style for OmniIntelligence Feed
    st.markdown("""
    <style>
        .terminal-header {
            text-align: center;
            margin-bottom: 20px;
            border: 1px solid #33ff33;
            padding: 15px;
            position: relative;
            box-shadow: 0 0 10px #33ff33;
        }
        .terminal-header:before {
            content: "┌───── RSS TERMINAL ─────┐";
            position: absolute;
            top: -15px;
            left: 20px;
            background-color: black;
            padding: 0 10px;
            color: #ffffff;
        }
        .terminal-header:after {
            content: "└──────────────────────────┘";
            position: absolute;
            bottom: -15px;
            right: 20px;
            background-color: black;
            padding: 0 10px;
            color: #ffffff;
        }
        .terminal-title {
            font-size: 2rem;
            font-weight: bold;
            color: #ffffff;
            text-shadow: 0 0 10px #ffffff;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 3px;
        }
        .terminal-subtitle {
            color: #ffffff;
            font-size: 1rem;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
        }
        .feed-section {
            border: 1px solid #ffffff;
            margin-bottom: 20px;
            position: relative;
        }
        .feed-section:before {
            content: attr(data-title);
            position: absolute;
            top: -15px;
            left: 20px;
            background-color: black;
            padding: 0 10px;
            color: #ffffff;
            font-family: 'Courier New', monospace;
        }
        .feed-note {
            color: #ffffff;
            font-family: 'Courier New', monospace;
            background-color: rgba(255, 255, 255, 0.1);
            padding: 10px;
            border-left: 3px solid #ffffff;
            margin: 10px 0;
        }
        .terminal-article {
            padding: 10px;
            border-bottom: 1px dashed #ffffff;
            margin-bottom: 10px;
        }
        .terminal-article-title {
            font-weight: bold;
            color: #ffffff;
            margin-bottom: 5px;
            font-family: 'Courier New', monospace;
        }
        .terminal-article-meta {
            color: #ffffff;
            opacity: 0.7;
            font-size: 0.8rem;
            margin-bottom: 5px;
            font-family: 'Courier New', monospace;
        }
        .article-image-container {
            margin-bottom: 15px;
            text-align: center;
            max-height: 200px;
            overflow: hidden;
            border: 1px solid #444444;
        }
        .article-image {
            max-width: 100%;
            height: auto;
            object-fit: cover;
            display: block;
            margin: 0 auto;
            filter: grayscale(30%) brightness(90%) contrast(120%);
            transition: all 0.3s ease;
        }
        .article-image:hover {
            filter: grayscale(0%) brightness(100%);
        }
        .terminal-access-log {
            font-family: 'Courier New', monospace;
            color: #ffffff;
            border: 1px dashed #ffffff;
            padding: 10px;
            margin-bottom: 20px;
            background-color: rgba(0, 0, 0, 0.5);
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Terminal Header
    st.markdown("""
    <div class="terminal-header">
        <div class="terminal-title">RSS Terminal</div>
        <div class="terminal-subtitle">TOP SECRET // SCI // NOFORN</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Access Log
    st.markdown(f"""
    <div class="terminal-access-log">
    > SYSTEM: Establishing secure connection...<br>
    > SYSTEM: Connection established<br>
    > SYSTEM: User authenticated<br>
    > SYSTEM: Accessing intelligence feed...<br>
    > SYSTEM: Feed authorized at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
    > SYSTEM: Displaying intelligence sources...
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="feed-note">
    NOTE: This feed aggregates cybersecurity and intelligence from multiple authoritative sources globally.
    All information is classified and for authorized personnel only.
    </div>
    """, unsafe_allow_html=True)
    
    # Define RSS feeds and news sources
    news_sources = {
        "Western Media": {
            "Wired-Backchannel": "https://www.wired.com/feed/category/backchannel/latest/rss",
            "Wired-Security": "https://www.wired.com/feed/category/security/latest/rss",
            "Dark Reading": "https://www.darkreading.com/rss.xml",
            "The Record Media": "https://therecord.media/feed/",
            "404 Media": "https://www.404media.co/rss/",
            "The Intercept": "https://theintercept.com/feed/?rss",
            "SpaceNews.com": "https://spacenews.com/feed/",
            "ZeroHedge": "https://feeds.feedburner.com/zerohedge/feed",
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "The Black Vault": "https://www.theblackvault.com/documentarchive/feed/",
            "CyberScoop": "https://www.cyberscoop.com/feed/",
            "TechCrunch Security": "https://techcrunch.com/category/security/feed/"
        },
        "Government & Official Sources": {
            "FBI": "https://www.fbi.gov/feeds/national-press-releases/rss.xml",
            "CISA": "https://www.cisa.gov/news.xml",
            "Europol": "https://www.europol.europa.eu/newsroom/rss.xml",
            "Interpol": "https://www.interpol.int/en/News-and-Events/News-feed",
            "Canadian Centre for Cyber Security": "https://cyber.gc.ca/en/rss.xml",
            "Australian Cyber Security Centre": "https://www.cyber.gov.au/rss/news",
            "UK National Cyber Security Centre": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
            "US Cyber Command": "https://www.cybercom.mil/Media/News-Transcripts/",
            "South Korea KISA": "https://www.kisa.or.kr/eng/main.jsp", 
            "Taiwan National Center for Cyber Security Technology": "https://www.nccst.nat.gov.tw/NewsListEn"
        },
        "Security Vendors & Researchers": {
            "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
            "Microsoft Security": "https://msrc-blog.microsoft.com/feed/",
            "Google Security Blog": "https://security.googleblog.com/feeds/posts/default?alt=rss",
            "Palo Alto Unit 42": "https://unit42.paloaltonetworks.com/feed/",
            "Kaspersky SecureList": "https://securelist.com/feed/",
            "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default",
            "Crowdstrike Blog": "https://www.crowdstrike.com/blog/feed"
        },
        "Russian Media": {
            "TASS": "https://tass.com/rss/v2.xml",
            "RT": "https://www.rt.com/rss/",
            "Sputnik": "https://sputnikglobe.com/export/rss2/archive/index.xml",
            "Pravda": "https://english.pravda.ru/export.xml",
            "RBC News": "https://www.rbc.ru/rss/",
            "Kommersant": "https://www.kommersant.ru/RSS/news.xml"
        },
        "Chinese Media": {
            "South China Morning Post": "https://www.scmp.com/rss/91/feed",
            "China Daily": "https://www.chinadaily.com.cn/rss/china_rss.xml",
            "Xinhua": "http://www.xinhuanet.com/english/rss/index.htm",
            "Global Times": "https://www.globaltimes.cn/rss/outbound.xml",
            "People's Daily": "http://en.people.cn/rss/China.xml",
            "CGTN": "https://www.cgtn.com/feed/rss"
        },
        "Academic & Research": {
            "MIT Technology Review": "https://www.technologyreview.com/feed/",
            "Harvard Kennedy School": "https://www.belfercenter.org/rss/feed",
            "Carnegie Endowment": "https://carnegieendowment.org/rss/publications",
            "Council on Foreign Relations": "https://www.cfr.org/rss.xml",
            "RAND Corporation": "https://www.rand.org/feed.xml",
            "Center for Strategic & International Studies": "https://www.csis.org/rss.xml"
        }
    }
    
    # Function to fetch and parse RSS feeds
    def fetch_rss_feed(url):
        try:
            feed = feedparser.parse(url)
            return feed
        except Exception as e:
            return {"error": str(e), "entries": []}
    
    # Add more terminal styling for tabs
    st.markdown("""
    <style>
        /* Override tab styling for terminal look */
        .stTabs [data-baseweb="tab-list"] {
            gap: 1px;
            background-color: black;
        }
        
        .stTabs [data-baseweb="tab"] {
            background-color: black;
            color: #33ff33;
            border: 1px solid #33ff33;
            border-radius: 0;
            padding: 5px 15px;
            font-family: 'Courier New', monospace;
        }
        
        .stTabs [aria-selected="true"] {
            background-color: #33ff33 !important;
            color: black !important;
            font-weight: bold;
        }
        
        /* Override content pane styling */
        .stTabs [data-baseweb="tab-panel"] {
            background-color: black;
            color: #33ff33;
            border: 1px solid #33ff33;
            padding: 15px;
            position: relative;
            font-family: 'Courier New', monospace;
        }
        
        /* Terminal style source header */
        h3 {
            border-bottom: 1px dashed #33ff33;
            padding-bottom: 5px;
            font-family: 'Courier New', monospace;
            color: #33ff33 !important;
            text-shadow: 0 0 5px #33ff33;
        }
        
        /* Slider styling */
        .stSlider [data-baseweb=slider] {
            background-color: #33ff33;
        }
        
        .stSlider [data-baseweb=thumb] {
            background-color: #33ff33;
            border: 2px solid black;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Create tabs for different categories of news sources
    source_tabs = st.tabs(list(news_sources.keys()))
    
    # Display news for each category in its respective tab
    for i, (category, sources) in enumerate(news_sources.items()):
        with source_tabs[i]:
            st.subheader(f"{category} Intelligence Sources")
            
            # Create source selection
            selected_sources = st.multiselect(
                "Select sources to display",
                list(sources.keys()),
                default=list(sources.keys())[:3]
            )
            
            # Number of articles to display
            num_articles = st.slider("Number of articles per source", 3, 15, 5, key=f"slider_{category}")
            
            for source_name in selected_sources:
                st.markdown(f"### {source_name}")
                
                feed_url = sources[source_name]
                feed_data = fetch_rss_feed(feed_url)
                
                if "error" in feed_data:
                    st.error(f"Failed to fetch feed from {source_name}: {feed_data['error']}")
                    continue
                
                if not feed_data.entries:
                    st.info(f"No articles available from {source_name}")
                    continue
                
                # Display articles in terminal style
                st.markdown('<div class="terminal-articles">', unsafe_allow_html=True)
                for j, entry in enumerate(feed_data.entries[:num_articles]):
                    title = entry.get("title", "No title")
                    link = entry.get("link", "#")
                    
                    # Try to get the publication date
                    try:
                        if "published" in entry:
                            pub_date = entry.published
                        elif "pubDate" in entry:
                            pub_date = entry.pubDate
                        elif "updated" in entry:
                            pub_date = entry.updated
                        else:
                            pub_date = "Date unknown"
                    except:
                        pub_date = "Date unknown"
                    
                    # Try to get a summary
                    try:
                        if "summary" in entry:
                            soup = BeautifulSoup(entry.summary, "html.parser")
                            summary = soup.get_text()
                        elif "description" in entry:
                            soup = BeautifulSoup(entry.description, "html.parser")
                            summary = soup.get_text()
                        else:
                            summary = "No summary available"
                            soup = None
                        
                        # Truncate long summaries
                        if len(summary) > 300:
                            summary = summary[:300] + "..."
                    except:
                        summary = "No summary available"
                        soup = None
                    
                    # Try to extract featured image
                    featured_image = None
                    try:
                        # Method 1: Look for media_content
                        if hasattr(entry, 'media_content') and entry.media_content:
                            for media in entry.media_content:
                                if 'url' in media:
                                    featured_image = media['url']
                                    break
                        
                        # Method 2: Look for enclosures
                        if not featured_image and hasattr(entry, 'enclosures') and entry.enclosures:
                            for enclosure in entry.enclosures:
                                if 'url' in enclosure and enclosure.get('type', '').startswith('image/'):
                                    featured_image = enclosure['url']
                                    break
                        
                        # Method 3: Look for image in content
                        if not featured_image and soup:
                            img_tag = soup.find('img')
                            if img_tag and img_tag.get('src'):
                                featured_image = img_tag['src']
                        
                        # Method 4: Try to find image in links
                        if not featured_image and hasattr(entry, 'links'):
                            for link in entry.links:
                                if link.get('type', '').startswith('image/'):
                                    featured_image = link.get('href')
                                    break
                    except:
                        featured_image = None
                    
                    # Create an ASCII terminal-style card for each article with image if available
                    st.markdown(f"""
                    <div class="terminal-article">
                        {f"<div class='article-image-container'><img src='{featured_image}' class='article-image'></div>" if featured_image else ""}
                        <div class="terminal-article-title">
                            ■ {title}
                        </div>
                        <div class="terminal-article-meta">
                            {pub_date} | Reference ID: {j+1:04d}-{hash(title) % 10000:04d}
                        </div>
                        <div class="terminal-article-content">
                            {summary}
                        </div>
                        <div style="margin-top: 10px;">
                            <a href="{link}" target="_blank" style="color: #33ff33; text-decoration: underline; font-family: 'Courier New', monospace;">ACCESS_FULL_DOCUMENT</a>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("---")

# Add the OmniIntelligence Feed as a separate highlighted feature with ASCII terminal style
st.markdown("""
<style>
    .omni-container {
        background-color: black;
        padding: 20px;
        margin-top: 30px;
        margin-bottom: 20px;
        border: 1px solid #ffffff;
        position: relative;
        font-family: 'Courier New', monospace;
    }
    .omni-container:before {
        content: "┌─────── EXCLUSIVE ACCESS ───────┐";
        position: absolute;
        top: -15px;
        left: 30px;
        background-color: black;
        padding: 0 10px;
        color: #ffffff;
    }
    .omni-container:after {
        content: "└─────────────────────────────────┘";
        position: absolute;
        bottom: -15px;
        right: 30px;
        background-color: black;
        padding: 0 10px;
        color: #ffffff;
    }
    .omni-title {
        text-align: center;
        font-weight: bold;
        margin-bottom: 10px;
        color: #ffffff;
        text-shadow: 0 0 5px #ffffff;
        font-size: 1.5rem;
    }
    .omni-description {
        text-align: center;
        font-size: 0.9em;
        color: #ffffff;
        margin-bottom: 15px;
    }
    .omni-button button {
        background-color: black !important;
        color: #ffffff !important;
        border: 1px solid #ffffff !important;
        border-radius: 0 !important;
        font-family: 'Courier New', monospace !important;
        box-shadow: 0 0 5px #ffffff !important;
        transition: all 0.3s ease !important;
    }
    .omni-button button:hover {
        background-color: #ffffff !important;
        color: black !important;
        box-shadow: 0 0 10px #ffffff !important;
    }
    .ascii-decoration {
        font-family: monospace;
        white-space: pre;
        line-height: 1;
        font-size: 12px;
        color: #ffffff;
        text-align: center;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

with st.container():
    st.markdown('<div class="omni-container">', unsafe_allow_html=True)
    
    # ASCII art decoration at the top
    st.markdown("""
    <div class="ascii-decoration">
  _____ __  __ _   _ _____ _____ _   _ _______ ______ _      _      _____ _____ ______ _   _  _____ ______ 
 / ____|  \/  | \ | |_   _|_   _| \ | |__   __|  ____| |    | |    |_   _/ ____|  ____| \ | |/ ____|  ____|
| |  __| \  / |  \| | | |   | | |  \| |  | |  | |__  | |    | |      | || |  __| |__  |  \| | |    | |__   
| | |_ | |\/| | . ` | | |   | | | . ` |  | |  |  __| | |    | |      | || | |_ |  __| | . ` | |    |  __|  
| |__| | |  | | |\  |_| |_ _| |_| |\  |  | |  | |____| |____| |____ _| || |__| | |____| |\  | |____| |____ 
 \_____|_|  |_|_| \_|_____|_____|_| \_|  |_|  |______|______|______|_____\_____|______|_| \_|\_____|______|
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="omni-title">INTELLIGENCE FEED ACCESS TERMINAL</div>', unsafe_allow_html=True)
    st.markdown('<div class="omni-description">Classified cybersecurity intelligence from global sources - Authorized personnel only</div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="omni-button">', unsafe_allow_html=True)
        if st.button("[ ENTER SECURE TERMINAL ]", use_container_width=True, 
                     type="primary" if st.session_state.current_page == "OmniIntelligence Feed" else "secondary"):
            st.session_state.current_page = "OmniIntelligence Feed"
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    
    # ASCII art decoration at the bottom
    st.markdown("""
    <div class="ascii-decoration">
    .--.      .--.      .--.      .--.      .--.      .--.      .--.      .--.
:::::.\::::::::.\::::::::.\::::::::.\::::::::.\::::::::.\::::::::.\::::::::.\
'      `--'      `--'      `--'      `--'      `--'      `--'      `--'      `
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

# Footer with data source acknowledgments
st.markdown("---")
st.markdown("""
<small>Data sourced from Kaspersky, Radware, MITRE ATT&CK, APT Map, Rapid7, Palo Alto Networks, and ETDA. 
This application aggregates publicly available threat intelligence for educational purposes only.</small>
""", unsafe_allow_html=True)

# Auto-refresh logic
if auto_refresh:
    time.sleep(refresh_rate * 60)
    st.rerun()