import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def format_number(num):
    """Format a number with K, M, B suffixes as appropriate"""
    if num >= 1_000_000_000:
        return f"{num / 1_000_000_000:.1f}B"
    elif num >= 1_000_000:
        return f"{num / 1_000_000:.1f}M"
    elif num >= 1_000:
        return f"{num / 1_000:.1f}K"
    else:
        return str(num)


def get_threat_level_color(level):
    """Return color code for a threat level"""
    if level == "Critical":
        return "#FF0000"  # Red
    elif level == "High":
        return "#FF7700"  # Orange
    elif level == "Medium":
        return "#FFFF00"  # Yellow
    elif level == "Low":
        return "#00CC00"  # Green
    else:
        return "#CCCCCC"  # Gray


def get_region_color(region):
    """Return color code for a region"""
    region_colors = {
        "North America": "#3366CC",  # Blue
        "South America": "#33CC33",  # Green
        "Europe": "#FF9900",        # Orange
        "Asia": "#FF3333",          # Red
        "Middle East": "#9933CC",   # Purple
        "Africa": "#FFCC00",        # Yellow
        "Oceania": "#00CCCC",       # Teal
        "Unknown": "#999999"        # Gray
    }
    
    return region_colors.get(region, "#999999")


def get_attack_type_icon(attack_type):
    """Return an emoji icon for an attack type"""
    attack_icons = {
        "Malware": "🦠",
        "Phishing": "🎣",
        "DDoS": "🌊",
        "Web Attack": "🕸️",
        "Ransomware": "🔒",
        "Data Breach": "📊",
        "APT": "🎯",
        "Zero-Day": "0️⃣",
        "Botnet": "🤖",
        "SQL Injection": "💉"
    }
    
    return attack_icons.get(attack_type, "⚠️")


def get_attack_type_color(attack_type):
    """Return color code for an attack type"""
    attack_colors = {
        "Malware": "#FF3333",      # Red
        "Phishing": "#33CC33",     # Green
        "DDoS": "#3366CC",         # Blue
        "Web Attack": "#FF9900",   # Orange
        "Ransomware": "#9933CC",   # Purple
        "Data Breach": "#FF6600",  # Dark Orange
        "APT": "#CC0000",          # Dark Red
        "Zero-Day": "#000000",     # Black
        "Botnet": "#666699",       # Slate Blue
        "SQL Injection": "#996633" # Brown
    }
    
    return attack_colors.get(attack_type, "#999999")


def format_time_ago(timestamp):
    """Format a timestamp as time ago (e.g., '2 minutes ago')"""
    now = datetime.now()
    delta = now - timestamp
    
    if delta.days > 0:
        return f"{delta.days} days ago"
    elif delta.seconds >= 3600:
        hours = delta.seconds // 3600
        return f"{hours} hours ago"
    elif delta.seconds >= 60:
        minutes = delta.seconds // 60
        return f"{minutes} minutes ago"
    else:
        return f"{delta.seconds} seconds ago"


@st.cache_data(ttl=3600)
def load_cached_data(time_range, selected_region, selected_attack_types, data_sources):
    """
    Attempt to load cached data for the current selection
    Returns None if no cached data is available
    """
    # In a real implementation, this would check for cached data
    # For this demo, we always return None to simulate always fetching fresh data
    return None
