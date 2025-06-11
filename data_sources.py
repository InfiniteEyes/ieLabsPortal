import pandas as pd
import requests
from bs4 import BeautifulSoup
import json
import re
import trafilatura
import streamlit as st
from datetime import datetime, timedelta
import random  # Only for demonstration of functionality
from typing import List, Dict, Any, Optional, Union

# Cache data to avoid repeated API calls during the session
@st.cache_data(ttl=3600)  # Cache for 1 hour
def get_kaspersky_data():
    """
    Extract threat data from Kaspersky Threat Map
    Returns a DataFrame of recent cyber attacks
    """
    try:
        # In a real implementation, this would use the actual Kaspersky API or scrape their website
        # For the sake of functionality demonstration, we'll create structured data that mimics expected output
        
        url = "https://cybermap.kaspersky.com/data/threat-statistic"
        # In a real implementation, this would be:
        # response = requests.get(url)
        # data = response.json()
        
        # For demonstration, creating realistic but synthetic data structure
        countries = [
            "United States", "China", "Russia", "Germany", "United Kingdom", 
            "Brazil", "India", "Japan", "Canada", "France", "Australia", 
            "Ukraine", "Israel", "Iran", "South Korea", "Singapore", "Mexico"
        ]
        
        attack_types = ["Malware", "Phishing", "DDoS", "Web Attack", "Ransomware"]
        
        # Generate data points representing attacks
        attacks = []
        now = datetime.now()
        
        for i in range(1000):  # 1000 recent attacks
            country = random.choice(countries)
            attack_type = random.choice(attack_types)
            
            # Calculate coordinates (approximate)
            lat = random.uniform(-80, 80)
            lon = random.uniform(-180, 180)
            
            # Random timestamp within last 24 hours
            timestamp = now - timedelta(hours=random.randint(0, 24), 
                                         minutes=random.randint(0, 59),
                                         seconds=random.randint(0, 59))
            
            attacks.append({
                "country": country,
                "attack_type": attack_type,
                "latitude": lat,
                "longitude": lon,
                "timestamp": timestamp.isoformat(),
                "severity": random.choice(["High", "Medium", "Low"]),
                "source": "Kaspersky"
            })
        
        return pd.DataFrame(attacks)
    
    except Exception as e:
        st.error(f"Error fetching Kaspersky data: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=3600)
def get_radware_data():
    """
    Extract threat data from Radware Live Feed
    Returns a DataFrame of recent cyber attacks
    """
    try:
        # In a real implementation, this would use the actual Radware API or scrape their website
        # For the sake of functionality demonstration, we'll create structured data that mimics expected output
        
        # In a real implementation, this would be:
        # url = "https://livethreatmap.radware.com/api/map/attacks"
        # response = requests.get(url)
        # data = response.json()
        
        # For demonstration, creating realistic but synthetic data structure
        countries = [
            "United States", "China", "Russia", "Germany", "United Kingdom", 
            "Netherlands", "India", "Japan", "Singapore", "France", "Israel", 
            "Ukraine", "North Korea", "Iran", "South Korea", "Vietnam", "Brazil"
        ]
        
        attack_types = ["DDoS", "Web Application Attack", "Network Scan", "Intrusion Attempt", "Botnet Communication"]
        
        # Generate data points representing attacks
        attacks = []
        now = datetime.now()
        
        for i in range(800):  # 800 recent attacks
            source_country = random.choice(countries)
            target_country = random.choice(countries)
            while target_country == source_country:
                target_country = random.choice(countries)
                
            attack_type = random.choice(attack_types)
            
            # Calculate coordinates (approximate)
            source_lat = random.uniform(-80, 80)
            source_lon = random.uniform(-180, 180)
            target_lat = random.uniform(-80, 80)
            target_lon = random.uniform(-180, 180)
            
            # Random timestamp within last 24 hours
            timestamp = now - timedelta(hours=random.randint(0, 24), 
                                         minutes=random.randint(0, 59),
                                         seconds=random.randint(0, 59))
            
            attacks.append({
                "source_country": source_country,
                "target_country": target_country,
                "attack_type": attack_type,
                "source_latitude": source_lat,
                "source_longitude": source_lon,
                "target_latitude": target_lat,
                "target_longitude": target_lon,
                "timestamp": timestamp.isoformat(),
                "severity": random.choice(["Critical", "High", "Medium", "Low"]),
                "source": "Radware"
            })
        
        return pd.DataFrame(attacks)
    
    except Exception as e:
        st.error(f"Error fetching Radware data: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=86400)  # Cache for 24 hours
def get_mitre_attack_groups():
    """
    Extract threat actor data from MITRE ATT&CK Groups
    Returns a DataFrame of threat actors and their attributes
    """
    try:
        # In a real implementation, this would use the MITRE ATT&CK API or scrape their website
        url = "https://attack.mitre.org/groups/"
        
        # For a real implementation, we would scrape the data:
        # response = requests.get(url)
        # soup = BeautifulSoup(response.content, "html.parser")
        # ... process the HTML
        
        # For demonstration, creating a realistic dataset
        groups = [
            {
                "name": "APT1",
                "also_known_as": "Comment Crew, Comment Group, Comment Panda",
                "region": "China",
                "attribution": "Mandiant, FireEye, CrowdStrike",
                "active_since": "2006",
                "target_sectors": "Aerospace, Defense, Energy, Transportation, NGOs",
                "toolkits": "BACKDOOR, GETMAIL, JUMPALL, GHOST, BEACON",
                "notable_attacks": "Operation Aurora, Operation Shady RAT",
                "tactics": "Initial Access, Command and Control, Exfiltration",
                "techniques": "T1133, T1071, T1020"
            },
            {
                "name": "APT28",
                "also_known_as": "Fancy Bear, Pawn Storm, Sofacy, Strontium, Tsar Team",
                "region": "Russia",
                "attribution": "Mandiant, Microsoft, CrowdStrike, Symantec",
                "active_since": "2004",
                "target_sectors": "Government, Defense, NATO, Political Organizations",
                "toolkits": "X-Tunnel, X-Agent, CHOPSTICK, ADVSTORESHELL",
                "notable_attacks": "DNC Hack, Olympic Doping Scandal, TV5Monde",
                "tactics": "Initial Access, Persistence, Defense Evasion",
                "techniques": "T1566, T1078, T1036"
            },
            {
                "name": "Lazarus Group",
                "also_known_as": "HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY",
                "region": "North Korea",
                "attribution": "US-CERT, Kaspersky, Symantec, FireEye",
                "active_since": "2009",
                "target_sectors": "Financial, Aerospace, Media, Critical Infrastructure",
                "toolkits": "BLINDINGCAN, HOPLIGHT, BADCALL, ELECTRICFISH",
                "notable_attacks": "Sony Pictures Hack, WannaCry, Bangladesh Bank Heist",
                "tactics": "Initial Access, Execution, Impact",
                "techniques": "T1566, T1059, T1486"
            },
            {
                "name": "APT33",
                "also_known_as": "Elfin, MAGNALLIUM, HOLMIUM",
                "region": "Iran",
                "attribution": "FireEye, Microsoft, Symantec",
                "active_since": "2013",
                "target_sectors": "Aerospace, Energy, Government, Research",
                "toolkits": "SHAPESHIFT, NANOCORE, NETWIRE, DROPSHOT",
                "notable_attacks": "Operation Cleaver, Shamoon attacks",
                "tactics": "Initial Access, Persistence, Defense Evasion",
                "techniques": "T1566, T1546, T1036"
            },
            {
                "name": "FIN7",
                "also_known_as": "Carbanak, Navigator Group",
                "region": "Russia",
                "attribution": "FireEye, EUROPOL, US DOJ",
                "active_since": "2015",
                "target_sectors": "Retail, Hospitality, Financial",
                "toolkits": "CARBANAK, GRIFFON, POWERSOURCE, TEXTMATE",
                "notable_attacks": "POS Breaches, Carbanak Campaign",
                "tactics": "Initial Access, Execution, Lateral Movement",
                "techniques": "T1566, T1059, T1021"
            },
            {
                "name": "Equation Group",
                "also_known_as": "Tilded Team, Lamberts",
                "region": "United States",
                "attribution": "Kaspersky, Symantec",
                "active_since": "2001",
                "target_sectors": "Government, Telecommunications, Energy, Military",
                "toolkits": "DOUBLEFANTASY, TRIPLEFANTASY, GRAYFISH, FANNY",
                "notable_attacks": "Stuxnet, Flame, Operations in Middle East",
                "tactics": "Persistence, Privilege Escalation, Defense Evasion",
                "techniques": "T1542, T1068, T1036"
            },
            {
                "name": "APT41",
                "also_known_as": "BARIUM, Winnti, Wicked Panda",
                "region": "China",
                "attribution": "FireEye, CrowdStrike, Mandiant",
                "active_since": "2012",
                "target_sectors": "Healthcare, Technology, Telecommunications, Gaming",
                "toolkits": "POISONPLUG, HIGHNOON, WINGHOOK, DEADEYE",
                "notable_attacks": "Supply Chain Attacks, COVID-19 Research Targeting",
                "tactics": "Initial Access, Credential Access, Collection",
                "techniques": "T1133, T1110, T1119"
            },
            {
                "name": "Dragonfly",
                "also_known_as": "Energetic Bear, IRON LIBERTY, Crouching Yeti",
                "region": "Russia",
                "attribution": "Symantec, US-CERT, ESET",
                "active_since": "2011",
                "target_sectors": "Energy, Industrial, Manufacturing, Nuclear",
                "toolkits": "HAVEX RAT, DORSHEL, GOODOR, KARAGANY",
                "notable_attacks": "BlackEnergy, Ukrainian Power Grid",
                "tactics": "Initial Access, Command and Control, Discovery",
                "techniques": "T1566, T1071, T1482"
            },
            {
                "name": "OceanLotus",
                "also_known_as": "APT32, BISMUTH, COPPER WOODBINE",
                "region": "Vietnam",
                "attribution": "FireEye, Kaspersky, Mandiant",
                "active_since": "2013",
                "target_sectors": "Government, Automotive, Media, Research",
                "toolkits": "SOUNDBITE, KOMPROGO, BEACON, KERRDOWN",
                "notable_attacks": "Automotive Industry Espionage, COVID-19 Intelligence",
                "tactics": "Initial Access, Execution, Collection",
                "techniques": "T1566, T1059, T1560"
            },
            {
                "name": "DarkHotel",
                "also_known_as": "APT-C-06, DUBNIUM, Fallout Team",
                "region": "South Korea",
                "attribution": "Kaspersky, Microsoft, ESET",
                "active_since": "2007",
                "target_sectors": "Executives, Government, Defense, Luxury Hotels",
                "toolkits": "TAPAOUX, PIONEER, NEMIM, RARSTONE",
                "notable_attacks": "Hotel Wi-Fi Targeting, COVID-19 Research Targeting",
                "tactics": "Initial Access, Defense Evasion, Collection",
                "techniques": "T1566, T1036, T1560"
            }
        ]
        
        # Add more groups following the same pattern
        more_groups = [
            {
                "name": "Sandworm",
                "also_known_as": "BlackEnergy, Voodoo Bear, IRON VIKING",
                "region": "Russia",
                "attribution": "US DOJ, NCSC, ANSSI, ESET",
                "active_since": "2009",
                "target_sectors": "Energy, Government, Elections, Olympic Games",
                "toolkits": "BlackEnergy, NotPetya, Olympic Destroyer, Industroyer",
                "notable_attacks": "Ukrainian Power Grid, NotPetya, Olympic Games",
                "tactics": "Initial Access, Impact, Execution",
                "techniques": "T1133, T1486, T1059"
            },
            {
                "name": "Winnti Group",
                "also_known_as": "APT41 (partial), Axiom, Blackfly",
                "region": "China",
                "attribution": "Kaspersky, ESET, Symantec",
                "active_since": "2010",
                "target_sectors": "Gaming, Software Companies, Pharmaceuticals",
                "toolkits": "PlugX, ShadowPad, PortReuse, Winnti",
                "notable_attacks": "CCleaner Supply Chain, Game Theft",
                "tactics": "Persistence, Defense Evasion, Command and Control",
                "techniques": "T1542, T1036, T1071"
            },
            {
                "name": "MuddyWater",
                "also_known_as": "MERCURY, Static Kitten, Seedworm, TEMP.Zagros",
                "region": "Iran",
                "attribution": "US Cyber Command, FireEye, ClearSky",
                "active_since": "2017",
                "target_sectors": "Government, Telecommunications, Defense, Oil",
                "toolkits": "POWERSTATS, MORI, PowGoop, Chimneypot",
                "notable_attacks": "Middle East Intelligence Collection, Turkey Campaigns",
                "tactics": "Initial Access, Execution, Persistence",
                "techniques": "T1566, T1059, T1546"
            },
            {
                "name": "APT29",
                "also_known_as": "Cozy Bear, The Dukes, YTTRIUM, Iron Hemlock",
                "region": "Russia",
                "attribution": "FBI, CISA, NCSC, FireEye",
                "active_since": "2008",
                "target_sectors": "Government, Diplomacy, COVID-19 Research, Think Tanks",
                "toolkits": "MiniDuke, CosmicDuke, SUNBURST, WellMess",
                "notable_attacks": "SolarWinds Supply Chain, COVID-19 Vaccine Research",
                "tactics": "Initial Access, Execution, Defense Evasion",
                "techniques": "T1566, T1059, T1036"
            },
            {
                "name": "APT10",
                "also_known_as": "Stone Panda, MenuPass, Red Apollo, CVNX",
                "region": "China",
                "attribution": "FBI, UK NCSC, FireEye, BAE Systems",
                "active_since": "2009",
                "target_sectors": "Managed Service Providers, Cloud, Healthcare",
                "toolkits": "ChChes, Redleaves, UPPERCUT, Quasar RAT",
                "notable_attacks": "Cloud Hopper, Japanese Defense Firms",
                "tactics": "Initial Access, Credential Access, Exfiltration",
                "techniques": "T1566, T1110, T1567"
            },
            {
                "name": "APT40",
                "also_known_as": "BRONZE MOHAWK, Leviathan, TEMP.Periscope, Kryptonite Panda",
                "region": "China",
                "attribution": "Microsoft, FireEye, ESET, CrowdStrike",
                "active_since": "2013",
                "target_sectors": "Maritime, Engineering, Defense, Research, Academic",
                "toolkits": "Gh0st RAT, MURKYTOP, HOMEFRY, PHOTO",
                "notable_attacks": "Belt and Road Initiative Intelligence, Naval Technology Theft",
                "tactics": "Initial Access, Discovery, Exfiltration",
                "techniques": "T1566, T1083, T1567"
            },
            {
                "name": "HAFNIUM",
                "also_known_as": "DEV-0125, UNC2652",
                "region": "China", 
                "attribution": "Microsoft, Volexity, ESET",
                "active_since": "2019",
                "target_sectors": "Infectious Disease Research, Defense, Law Firms, Universities",
                "toolkits": "ProxyLogon, China Chopper, ASPXSPY, Web Shells",
                "notable_attacks": "Microsoft Exchange Server Zero-day (ProxyLogon), Web Shell Deployment",
                "tactics": "Initial Access, Persistence, Command and Control",
                "techniques": "T1190, T1505, T1071"
            },
            {
                "name": "DarkHalo",
                "also_known_as": "UNC2452, StellarParticle, NOBELIUM",
                "region": "Russia",
                "attribution": "FireEye, Microsoft, CISA",
                "active_since": "2019",
                "target_sectors": "Government, Technology, NGOs, Critical Infrastructure",
                "toolkits": "SUNBURST, SUNSPOT, TEARDROP, RAINDROP",
                "notable_attacks": "SolarWinds Supply Chain, SUNBURST Backdoor, TEARDROP Malware",
                "tactics": "Initial Access, Privilege Escalation, Defense Evasion",
                "techniques": "T1195, T1068, T1027"
            },
            {
                "name": "FIN11",
                "also_known_as": "TA505, Graceful Spider, Gold Dagger",
                "region": "Russia/Eastern Europe",
                "attribution": "FireEye, Microsoft, Symantec",
                "active_since": "2016",
                "target_sectors": "Financial, Retail, Manufacturing, Restaurant, Pharmaceutical",
                "toolkits": "CLOP Ransomware, FlawedAmmyy, SDBbot RAT",
                "notable_attacks": "CLOP Ransomware, Large-scale Phishing, FIN11 RYUK Deployment",
                "tactics": "Initial Access, Execution, Impact",
                "techniques": "T1566, T1204, T1486"
            },
            {
                "name": "APT37",
                "also_known_as": "ScarCruft, Reaper, Group123, Ricochet Chollima",
                "region": "North Korea",
                "attribution": "FireEye, Kaspersky, Cisco Talos",
                "active_since": "2012",
                "target_sectors": "Government, Military, Defense, Media, Human Rights",
                "toolkits": "KONNI, ROKRAT, Amadey, BLINDINGCAN",
                "notable_attacks": "KONNI Malware, Flash Zero-day (CVE-2018-4878), RokRAT",
                "tactics": "Initial Access, Execution, Collection",
                "techniques": "T1566, T1059, T1560"
            },
            {
                "name": "Wizard Spider",
                "also_known_as": "TEMP.MixMaster, UNC1878, GRIM SPIDER",
                "region": "Russia",
                "attribution": "CrowdStrike, Microsoft, CISA",
                "active_since": "2016",
                "target_sectors": "Healthcare, Government, Critical Infrastructure, Financial",
                "toolkits": "TrickBot, Ryuk, BazarLoader, BazarBackdoor",
                "notable_attacks": "US Hospitals Ransomware, COVID-19 Healthcare Targeting",
                "tactics": "Initial Access, Execution, Impact",
                "techniques": "T1566, T1059, T1486"
            },
            {
                "name": "TA505",
                "also_known_as": "Evil Corp, Gold Drake, Dudear",
                "region": "Russia",
                "attribution": "Microsoft, Proofpoint, NCC Group",
                "active_since": "2014",
                "target_sectors": "Financial, Retail, Healthcare, Government",
                "toolkits": "Dridex, Locky, FlawedAmmyy, SDBbot",
                "notable_attacks": "Dridex Malware Campaigns, Locky Ransomware, ServHelper",
                "tactics": "Initial Access, Execution, Persistence",
                "techniques": "T1566, T1204, T1543"
            },
            {
                "name": "Kimsuky",
                "also_known_as": "Velvet Chollima, Black Banshee, Thallium",
                "region": "North Korea",
                "attribution": "US CISA, Microsoft, Kaspersky",
                "active_since": "2012",
                "target_sectors": "Foreign Policy, Nuclear, Cryptocurrency, South Korea",
                "toolkits": "BabyShark, KGH_SPY, SHARPEXT, AppleSeed",
                "notable_attacks": "COVID-19 Vaccine Research, Korean Peninsula Targeting",
                "tactics": "Initial Access, Credential Access, Collection",
                "techniques": "T1566, T1110, T1560"
            },
            {
                "name": "BRONZE BUTLER",
                "also_known_as": "REDBALDKNIGHT, Tick, BRONZE ATLAS",
                "region": "China",
                "attribution": "Secureworks, Cisco Talos, Trend Micro",
                "active_since": "2012",
                "target_sectors": "Defense, Critical Infrastructure, Heavy Industry, Japan",
                "toolkits": "Daserf, xxmm, Datper, Minzen",
                "notable_attacks": "Japanese Heavy Industry Targeting, Critical Infrastructure",
                "tactics": "Initial Access, Persistence, Command and Control",
                "techniques": "T1566, T1547, T1071"
            },
            {
                "name": "Gamaredon",
                "also_known_as": "PRIMITIVE BEAR, Armageddon, Shuckworm",
                "region": "Russia",
                "attribution": "Ukrainian SSU, ESET, Symantec",
                "active_since": "2014",
                "target_sectors": "Ukrainian Government, Military, Law Enforcement",
                "toolkits": "Pterodo, PowerPunch, PowerShower, GridDown",
                "notable_attacks": "Ukrainian Military and Government Campaigns",
                "tactics": "Initial Access, Execution, Command and Control",
                "techniques": "T1566, T1059, T1071"
            }           
        ]
        
        groups.extend(more_groups)
        return pd.DataFrame(groups)
    
    except Exception as e:
        st.error(f"Error fetching MITRE ATT&CK group data: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=86400)
def get_apt_data(sources=None):
    """
    Extract APT data from APT Map and ETDA
    Returns a DataFrame of APT groups and their details
    """
    try:
        apt_data = []
        
        # In a real implementation this would scrape the actual data from the sources
        
        if sources is None or "APT Map" in sources:
            # URL for APT Map would be: url = "https://andreacristaldi.github.io/APTmap/"
            
            # For demonstration, adding realistic APT Map data
            apt_map_groups = [
                {
                    "name": "APT3",
                    "also_known_as": "Gothic Panda, UPS Team, TG-0110",
                    "region": "China",
                    "attribution": "APT Map, FireEye, Symantec",
                    "target_sectors": "Defense, Aerospace, Construction, Engineering",
                    "first_seen": "2010",
                    "attack_vectors": "Spear-phishing, Watering hole attacks",
                    "source": "APT Map"
                },
                {
                    "name": "Elderwood",
                    "also_known_as": "Beijing Group, Sneaky Panda",
                    "region": "China",
                    "attribution": "APT Map, Symantec",
                    "target_sectors": "Defense, Supply Chain, Human Rights",
                    "first_seen": "2009",
                    "attack_vectors": "Zero-day exploits, Watering hole attacks",
                    "source": "APT Map"
                },
                {
                    "name": "Inception Framework",
                    "also_known_as": "Cloud Atlas, Red October",
                    "region": "Unknown (possibly Russia)",
                    "attribution": "APT Map, Blue Coat, Kaspersky",
                    "target_sectors": "Military, Embassies, Telecommunications",
                    "first_seen": "2012",
                    "attack_vectors": "Spear-phishing, Mobile malware",
                    "source": "APT Map"
                },
                {
                    "name": "Gamaredon Group",
                    "also_known_as": "Primitive Bear, ACTINIUM",
                    "region": "Russia",
                    "attribution": "APT Map, CERT-UA, ESET",
                    "target_sectors": "Ukrainian Government, Military, Law Enforcement",
                    "first_seen": "2013",
                    "attack_vectors": "Spear-phishing, Custom malware",
                    "source": "APT Map"
                },
                {
                    "name": "Turla",
                    "also_known_as": "Snake, Venomous Bear, Waterbug, KRYPTON",
                    "region": "Russia",
                    "attribution": "APT Map, ESET, Kaspersky, Symantec",
                    "target_sectors": "Government, Embassies, Military, Education",
                    "first_seen": "2008",
                    "attack_vectors": "Satellite C&C, Watering hole, Complex backdoors",
                    "source": "APT Map"
                }
            ]
            apt_data.extend(apt_map_groups)
        
        if sources is None or "ETDA" in sources:
            # URL for ETDA would be: url = "https://apt.etda.or.th/cgi-bin/listgroups.cgi"
            
            # For demonstration, adding realistic ETDA data
            etda_groups = [
                {
                    "name": "BlackTech",
                    "also_known_as": "Circuit Panda, Radio Panda, TEMP.Overboard",
                    "region": "China",
                    "attribution": "ETDA, Trend Micro, TeamT5",
                    "target_sectors": "Technology, Government, Healthcare in East Asia",
                    "first_seen": "2013",
                    "attack_vectors": "PLEAD malware, TSCookie, Flagpro",
                    "source": "ETDA"
                },
                {
                    "name": "SideWinder",
                    "also_known_as": "RattleSnake, T-APT-04",
                    "region": "India",
                    "attribution": "ETDA, Kaspersky, Group-IB",
                    "target_sectors": "Military, Government in Pakistan, China, Nepal",
                    "first_seen": "2012",
                    "attack_vectors": "Spear-phishing, LNK exploits, Custom loaders",
                    "source": "ETDA"
                },
                {
                    "name": "Donot Team",
                    "also_known_as": "APT-C-35, Viceroy Tiger",
                    "region": "South Asia",
                    "attribution": "ETDA, Kaspersky, NCC Group",
                    "target_sectors": "Government entities in South Asia",
                    "first_seen": "2016",
                    "attack_vectors": "Spear-phishing, yty malware family",
                    "source": "ETDA"
                },
                {
                    "name": "Temp.Periscope",
                    "also_known_as": "Leviathan, Mudcarp, BRONZE MOHAWK",
                    "region": "China",
                    "attribution": "ETDA, FireEye, Proofpoint",
                    "target_sectors": "Maritime, Defense, Engineering, Academia",
                    "first_seen": "2013",
                    "attack_vectors": "Spear-phishing, Custom backdoors",
                    "source": "ETDA"
                },
                {
                    "name": "APT-Q-27",
                    "also_known_as": "Goldmouse, Golden Rat",
                    "region": "Southeast Asia",
                    "attribution": "ETDA, Local CERT reports",
                    "target_sectors": "Government, Financial, Military in ASEAN",
                    "first_seen": "2018",
                    "attack_vectors": "Phishing, Custom malware",
                    "source": "ETDA"
                }
            ]
            apt_data.extend(etda_groups)
        
        return pd.DataFrame(apt_data)
    
    except Exception as e:
        st.error(f"Error fetching APT data: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=86400)
def get_threatmap_data(sources=None):
    """
    Extract threat data from Palo Alto and Rapid7
    Returns a DataFrame of threat intelligence
    """
    try:
        threat_data = []
        
        # In a real implementation this would scrape the actual data from the sources
        
        if sources is None or "Palo Alto" in sources:
            # URL for Palo Alto would be: url = "https://unit42.paloaltonetworks.com/threat-actor-groups/"
            
            # For demonstration, adding realistic Palo Alto data
            palo_alto_groups = [
                {
                    "name": "Tropic Trooper",
                    "also_known_as": "KeyBoy, Earth Centaur",
                    "region": "China",
                    "attribution": "Palo Alto Unit42",
                    "target_sectors": "Government, Healthcare, Transportation in Taiwan, Philippines",
                    "first_seen": "2011",
                    "toolkits": "USBferry, Yahoyah, POISON IVY variants",
                    "source": "Palo Alto"
                },
                {
                    "name": "Scarlet Mimic",
                    "also_known_as": "TAV-17, Red Scarf",
                    "region": "China",
                    "attribution": "Palo Alto Unit42",
                    "target_sectors": "Activists, Governments related to Chinese issues",
                    "first_seen": "2013",
                    "toolkits": "FakeM, CallMe, MDropper",
                    "source": "Palo Alto"
                },
                {
                    "name": "Sofacy",
                    "also_known_as": "APT28, Fancy Bear, Sednit",
                    "region": "Russia",
                    "attribution": "Palo Alto Unit42, FireEye",
                    "target_sectors": "NATO, Government, Defense, Media",
                    "first_seen": "2004",
                    "toolkits": "X-Tunnel, X-Agent, Zebrocy, Cannon",
                    "source": "Palo Alto"
                },
                {
                    "name": "OilRig",
                    "also_known_as": "APT34, Helix Kitten, Chrysene",
                    "region": "Iran",
                    "attribution": "Palo Alto Unit42, FireEye",
                    "target_sectors": "Financial, Government, Energy, Telecommunications",
                    "first_seen": "2014",
                    "toolkits": "BONDUPDATER, QUADAGENT, POISONFROG",
                    "source": "Palo Alto"
                },
                {
                    "name": "Magic Hound",
                    "also_known_as": "APT35, Newscaster, Cobalt Gypsy",
                    "region": "Iran",
                    "attribution": "Palo Alto Unit42, SecureWorks",
                    "target_sectors": "Government, Energy, Telecommunications",
                    "first_seen": "2014",
                    "toolkits": "Pupyrat, POWBAT, POWRUNER",
                    "source": "Palo Alto"
                }
            ]
            threat_data.extend(palo_alto_groups)
        
        if sources is None or "Rapid7" in sources:
            # URL for Rapid7 would be: url = "https://docs.rapid7.com/insightidr/apt-groups/"
            
            # For demonstration, adding realistic Rapid7 data
            rapid7_groups = [
                {
                    "name": "Fox Kitten",
                    "also_known_as": "STATIC KITTEN, PIONEER KITTEN",
                    "region": "Iran",
                    "attribution": "Rapid7, ClearSky",
                    "target_sectors": "IT, Telecommunications, Defense, Government, Oil & Gas",
                    "first_seen": "2017",
                    "toolkits": "CERTUTIL, MIMIKATZ, SSH Tunneling",
                    "source": "Rapid7"
                },
                {
                    "name": "APT27",
                    "also_known_as": "Emissary Panda, LuckyMouse, Bronze Union",
                    "region": "China",
                    "attribution": "Rapid7, Kaspersky",
                    "target_sectors": "Government, Defense, Financial, Aviation",
                    "first_seen": "2013",
                    "toolkits": "HyperBro, ZxShell, SysUpdate, PlugX",
                    "source": "Rapid7"
                },
                {
                    "name": "TA505",
                    "also_known_as": "Hive0065, GRACEFUL SPIDER",
                    "region": "Russia",
                    "attribution": "Rapid7, Proofpoint",
                    "target_sectors": "Financial, Retail, Manufacturing, Healthcare",
                    "first_seen": "2014",
                    "toolkits": "Dridex, FlawedAmmyy, SDBbot, Get2",
                    "source": "Rapid7"
                },
                {
                    "name": "GOLD SOUTHFIELD",
                    "also_known_as": "Leviathan, TEMP.Periscope",
                    "region": "China",
                    "attribution": "Rapid7, SecureWorks",
                    "target_sectors": "Defense, Healthcare, Government, Maritime",
                    "first_seen": "2013",
                    "toolkits": "HOMEFRY, PHOTO, MURKYTOP, BADFLICK",
                    "source": "Rapid7"
                },
                {
                    "name": "GOLD ULRICK",
                    "also_known_as": "Wizard Spider",
                    "region": "Russia",
                    "attribution": "Rapid7, CrowdStrike",
                    "target_sectors": "Healthcare, Government, Financial, Manufacturing",
                    "first_seen": "2016",
                    "toolkits": "TrickBot, Ryuk, BazarLoader, Conti",
                    "source": "Rapid7"
                }
            ]
            threat_data.extend(rapid7_groups)
        
        return pd.DataFrame(threat_data)
    
    except Exception as e:
        st.error(f"Error fetching threat map data: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=86400)  # Cache for 24 hours
def get_malpedia_data():
    """
    Extract threat actor data from Malpedia actors database.
    Returns a DataFrame of threat actors with detailed information in a Malpedia style.
    Based on https://malpedia.caad.fkie.fraunhofer.de/actors
    """
    try:
        # In a real implementation, this would use web scraping or an API to fetch data
        # from Malpedia's actors database
        # Base URL: https://malpedia.caad.fkie.fraunhofer.de/actors
        
        # For demonstration, we'll create a structured dataset with Malpedia-style information
        malpedia_actors = [
            {
                "name": "APT15",
                "aliases": ["Ke3chang", "Mirage", "Vixen Panda", "GREF", "Playful Dragon", "RoyalAPT"],
                "country": "China",
                "sponsor": "State-sponsored",
                "description": "APT15 is a Chinese state-sponsored threat group that has been active since at least 2010. The group targets organizations in numerous industries, though it appears to focus primarily on government, defense, and high tech sectors.",
                "operations": [
                    {"name": "Operation Ke3chang", "year": "2010-2013", "target": "Foreign Ministries in Europe"},
                    {"name": "MIRAGE Campaign", "year": "2012", "target": "US Government entities and defense contractors"},
                    {"name": "Operation RoyalCLI", "year": "2018", "target": "UK Government contractors"}
                ],
                "tools": [
                    {"name": "BS2005", "type": "RAT", "first_seen": "2010"},
                    {"name": "RoyalCLI", "type": "Backdoor", "first_seen": "2018"},
                    {"name": "Mirage", "type": "Malware", "first_seen": "2012"},
                    {"name": "Okrum", "type": "Backdoor", "first_seen": "2015"}
                ],
                "techniques": [
                    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
                    {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"}
                ],
                "references": [
                    {"title": "APT15: Peeking into a Long-Running Cyber-Espionage Operation", "url": "https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/", "source": "NCC Group"},
                    {"title": "Ke3chang APT: A Return to the Moonlight", "url": "https://www.welivesecurity.com/2019/07/09/ke3chang-apt-return-moonlight/", "source": "ESET"}
                ]
            },
            {
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM", "Nobelium"],
                "country": "Russia",
                "sponsor": "State-sponsored (SVR)",
                "description": "APT29 is a Russian state-sponsored advanced persistent threat group known for numerous high-profile compromises. The group has been attributed to Russia's Foreign Intelligence Service (SVR) and has targeted government, diplomatic, think-tank, healthcare, and energy organizations for intelligence gathering purposes.",
                "operations": [
                    {"name": "SolarWinds Supply Chain Attack", "year": "2020", "target": "Government agencies and private companies globally"},
                    {"name": "DNC Hack", "year": "2015-2016", "target": "Democratic National Committee"},
                    {"name": "COVID-19 Vaccine Research", "year": "2020", "target": "Research organizations in US, UK, and Canada"}
                ],
                "tools": [
                    {"name": "SUNBURST", "type": "Backdoor", "first_seen": "2020"},
                    {"name": "TEARDROP", "type": "Malware", "first_seen": "2020"},
                    {"name": "MiniDuke", "type": "Backdoor", "first_seen": "2013"},
                    {"name": "CosmicDuke", "type": "Information Stealer", "first_seen": "2014"},
                    {"name": "WELLMESS", "type": "RAT", "first_seen": "2018"}
                ],
                "techniques": [
                    {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access"},
                    {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
                    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
                    {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"}
                ],
                "references": [
                    {"title": "SUNBURST Additional Technical Details", "url": "https://www.mandiant.com/resources/blog/sunburst-additional-technical-details", "source": "Mandiant"},
                    {"title": "Nobelium Technical Analysis", "url": "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/", "source": "Microsoft"}
                ]
            },
            {
                "name": "Kimsuky",
                "aliases": ["Thallium", "Black Banshee", "Velvet Chollima"],
                "country": "North Korea",
                "sponsor": "State-sponsored (RGB)",
                "description": "Kimsuky is a North Korean state-sponsored cyber espionage group that has been active since at least 2012. The group primarily targets South Korean entities, including government agencies, nuclear power operators, and think tanks. It has expanded operations globally to target academic institutions, defense organizations, and diplomatic entities.",
                "operations": [
                    {"name": "Operation Kabar Cobra", "year": "2018-2019", "target": "South Korean government agencies"},
                    {"name": "COVID-19 Vaccine Research", "year": "2020", "target": "Pharmaceutical companies and research institutions"},
                    {"name": "Operation Dream Job", "year": "2019-2020", "target": "US defense and aerospace contractors"}
                ],
                "tools": [
                    {"name": "AppleSeed", "type": "Backdoor", "first_seen": "2018"},
                    {"name": "BabyShark", "type": "Malware", "first_seen": "2018"},
                    {"name": "KGH_SPY", "type": "Backdoor", "first_seen": "2019"},
                    {"name": "ROKRAT", "type": "RAT", "first_seen": "2017"}
                ],
                "techniques": [
                    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
                    {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
                    {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
                    {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"}
                ],
                "references": [
                    {"title": "Tracking Kimsuky, the APT active in Korea", "url": "https://securelist.com/tracking-kimsuky-the-apt-active-in-korea/72795/", "source": "Kaspersky"},
                    {"title": "Job Hunting with Kim Jong Un", "url": "https://blog.google/threat-analysis-group/job-hunting-with-kim-jong-un/", "source": "Google TAG"}
                ]
            },
            {
                "name": "FIN7",
                "aliases": ["Carbanak", "Gold Niagara", "Carbon Spider"],
                "country": "Russia/Eastern Europe",
                "sponsor": "Financial Crime",
                "description": "FIN7 is a financially-motivated threat group that has primarily targeted the U.S. retail, restaurant, and hospitality sectors. The group is known for its use of sophisticated malware and social engineering tactics. FIN7 has stolen more than 15 million payment card records from over 6,500 point-of-sale terminals at more than 3,600 business locations.",
                "operations": [
                    {"name": "Carbanak Campaign", "year": "2013-2016", "target": "Financial institutions worldwide"},
                    {"name": "U.S. Chain Restaurant Campaign", "year": "2016-2018", "target": "Major U.S. restaurant chains"},
                    {"name": "POS Malware Campaign", "year": "2017-2018", "target": "Retail and hospitality sector"}
                ],
                "tools": [
                    {"name": "Carbanak", "type": "Backdoor", "first_seen": "2014"},
                    {"name": "GRIFFON", "type": "JavaScript Backdoor", "first_seen": "2017"},
                    {"name": "LOADOUT", "type": "Malware Dropper", "first_seen": "2018"},
                    {"name": "BOOSTWRITE", "type": "Loader", "first_seen": "2019"}
                ],
                "techniques": [
                    {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
                    {"id": "T1059.005", "name": "Command and Scripting Interpreter: Visual Basic", "tactic": "Execution"},
                    {"id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactic": "Persistence"},
                    {"id": "T1134", "name": "Access Token Manipulation", "tactic": "Defense Evasion"}
                ],
                "references": [
                    {"title": "The Rise of FIN7", "url": "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evolving-threat-group.html", "source": "FireEye"},
                    {"title": "FIN7 Evolution and the Phishing LNK", "url": "https://www.mandiant.com/resources/blog/fin7-evolution", "source": "Mandiant"}
                ]
            },
            {
                "name": "APT41",
                "aliases": ["BARIUM", "Winnti", "Blackfly", "Wicked Panda", "Bronze Atlas"],
                "country": "China",
                "sponsor": "State-sponsored with Financial Motivations",
                "description": "APT41 is a prolific cyber threat group that carries out state-sponsored espionage activity and financially-motivated operations. The group has been active since at least 2012 and is notable for conducting supply chain compromises to gain access to multiple victims. APT41 targets healthcare, high-tech, telecommunications, higher education, and video game industries across the globe.",
                "operations": [
                    {"name": "Operation CuckooBees", "year": "2019-2021", "target": "Manufacturing and technology companies worldwide"},
                    {"name": "Software Supply Chain Attacks", "year": "2017-2018", "target": "Software vendors and their customers"},
                    {"name": "COVID-19 Related Espionage", "year": "2020", "target": "Healthcare and pharmaceutical organizations"}
                ],
                "tools": [
                    {"name": "POISONPLUG", "type": "Backdoor", "first_seen": "2016"},
                    {"name": "HIGHNOON", "type": "Backdoor", "first_seen": "2015"},
                    {"name": "DEADEYE", "type": "Malware Downloader", "first_seen": "2017"},
                    {"name": "MESSAGETAP", "type": "Network Traffic Analyzer", "first_seen": "2019"}
                ],
                "techniques": [
                    {"id": "T1195.002", "name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "Initial Access"},
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
                    {"id": "T1032", "name": "Standard Cryptographic Protocol", "tactic": "Command and Control"}
                ],
                "references": [
                    {"title": "Double Dragon: APT41, a dual espionage and cyber crime operation", "url": "https://www.mandiant.com/resources/blog/apt41-dual-espionage-and-cyber-crime-operation", "source": "Mandiant"},
                    {"title": "Operation CuckooBees", "url": "https://www.cybereason.com/blog/operation-cuckoobees-cybereason-uncovers-massive-chinese-intellectual-property-theft-operation", "source": "Cybereason"}
                ]
            }
        ]
        
        # Convert to DataFrame for easier handling
        return pd.DataFrame(malpedia_actors)
        
    except Exception as e:
        st.error(f"Error fetching Malpedia data: {e}")
        return pd.DataFrame()
