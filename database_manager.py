import pandas as pd
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta

from database_models import (
    Session, 
    ThreatActor, 
    AttributionSource, 
    Technique, 
    Tool, 
    Attack,
    init_db
)

class DatabaseManager:
    """Class to manage database operations for the cyber attack tracker"""
    
    def __init__(self):
        # Initialize database if not already created
        init_db()
        self.session = Session()
    
    def close(self):
        """Close the database session"""
        self.session.close()
    
    # Threat Actor methods
    def add_threat_actor(self, name, also_known_as=None, region=None, active_since=None, 
                        target_sectors=None, notable_attacks=None):
        """Add a new threat actor to the database"""
        threat_actor = ThreatActor(
            name=name,
            also_known_as=also_known_as,
            region=region,
            active_since=active_since,
            target_sectors=target_sectors,
            notable_attacks=notable_attacks
        )
        self.session.add(threat_actor)
        self.session.commit()
        return threat_actor
    
    def get_threat_actors(self, region=None, search_query=None):
        """Get all threat actors, optionally filtered by region or search term"""
        query = self.session.query(ThreatActor)
        
        if region and region != "All":
            query = query.filter(ThreatActor.region == region)
        
        if search_query:
            search_filter = or_(
                ThreatActor.name.ilike(f"%{search_query}%"),
                ThreatActor.also_known_as.ilike(f"%{search_query}%"),
                ThreatActor.region.ilike(f"%{search_query}%")
            )
            query = query.filter(search_filter)
        
        return query.all()
    
    def get_threat_actor_by_id(self, actor_id):
        """Get a threat actor by ID"""
        return self.session.query(ThreatActor).filter(ThreatActor.id == actor_id).first()
    
    def get_threat_actor_by_name(self, name):
        """Get a threat actor by name"""
        return self.session.query(ThreatActor).filter(ThreatActor.name == name).first()
    
    # Attribution Source methods
    def add_attribution_source(self, name, url=None):
        """Add a new attribution source to the database"""
        source = AttributionSource(name=name, url=url)
        self.session.add(source)
        self.session.commit()
        return source
    
    def get_attribution_sources(self):
        """Get all attribution sources"""
        return self.session.query(AttributionSource).all()
    
    def add_attribution(self, threat_actor_id, attribution_source_id):
        """Connect a threat actor to an attribution source"""
        threat_actor = self.get_threat_actor_by_id(threat_actor_id)
        attribution_source = self.session.query(AttributionSource).filter(
            AttributionSource.id == attribution_source_id
        ).first()
        
        if threat_actor and attribution_source:
            threat_actor.attributions.append(attribution_source)
            self.session.commit()
            return True
        return False
    
    # Technique methods
    def add_technique(self, technique_id, name, tactic=None, description=None):
        """Add a new technique to the database"""
        technique = Technique(
            technique_id=technique_id,
            name=name,
            tactic=tactic,
            description=description
        )
        self.session.add(technique)
        self.session.commit()
        return technique
    
    def get_techniques(self, tactic=None):
        """Get all techniques, optionally filtered by tactic"""
        query = self.session.query(Technique)
        
        if tactic and tactic != "All":
            query = query.filter(Technique.tactic == tactic)
        
        return query.all()
    
    def associate_technique_with_actor(self, threat_actor_id, technique_id):
        """Connect a technique to a threat actor"""
        threat_actor = self.get_threat_actor_by_id(threat_actor_id)
        technique = self.session.query(Technique).filter(Technique.id == technique_id).first()
        
        if threat_actor and technique:
            threat_actor.techniques.append(technique)
            self.session.commit()
            return True
        return False
    
    # Tool methods
    def add_tool(self, name, tool_type=None, description=None, first_observed=None):
        """Add a new tool to the database"""
        tool = Tool(
            name=name,
            type=tool_type,
            description=description,
            first_observed=first_observed
        )
        self.session.add(tool)
        self.session.commit()
        return tool
    
    def get_tools(self, tool_type=None):
        """Get all tools, optionally filtered by type"""
        query = self.session.query(Tool)
        
        if tool_type and tool_type != "All":
            query = query.filter(Tool.type == tool_type)
        
        return query.all()
    
    def associate_tool_with_actor(self, threat_actor_id, tool_id):
        """Connect a tool to a threat actor"""
        threat_actor = self.get_threat_actor_by_id(threat_actor_id)
        tool = self.session.query(Tool).filter(Tool.id == tool_id).first()
        
        if threat_actor and tool:
            threat_actor.tools.append(tool)
            self.session.commit()
            return True
        return False
    
    # Attack methods
    def add_attack(self, attack_type, timestamp, source_country=None, target_country=None, 
                source_lat=None, source_lon=None, target_lat=None, target_lon=None, 
                severity=None, data_source=None):
        """Add a new attack to the database"""
        attack = Attack(
            attack_type=attack_type,
            source_country=source_country,
            target_country=target_country,
            source_latitude=source_lat,
            source_longitude=source_lon,
            target_latitude=target_lat,
            target_longitude=target_lon,
            timestamp=timestamp,
            severity=severity,
            data_source=data_source
        )
        self.session.add(attack)
        self.session.commit()
        return attack
    
    def get_attacks(self, time_range=None, region=None, attack_type=None):
        """Get attacks, optionally filtered by time range, region, and attack type"""
        query = self.session.query(Attack)
        
        # Filter by time range
        if time_range:
            now = datetime.now()
            if time_range == "Last 24 hours":
                start_time = now - timedelta(days=1)
            elif time_range == "Last 7 days":
                start_time = now - timedelta(days=7)
            elif time_range == "Last 30 days":
                start_time = now - timedelta(days=30)
            elif time_range == "Last 90 days":
                start_time = now - timedelta(days=90)
            else:  # All time
                start_time = None
                
            if start_time:
                query = query.filter(Attack.timestamp >= start_time)
        
        # Filter by attack type
        if attack_type and attack_type != "All":
            query = query.filter(Attack.attack_type == attack_type)
        
        # Get results
        attacks = query.all()
        
        # Filter by region manually since it involves complex logic
        if region and region != "All":
            filtered_attacks = []
            for attack in attacks:
                source_region = self._get_region_for_country(attack.source_country)
                target_region = self._get_region_for_country(attack.target_country)
                if region in [source_region, target_region]:
                    filtered_attacks.append(attack)
            return filtered_attacks
        
        return attacks
    
    def _get_region_for_country(self, country):
        """Map a country to its region - simplified version for filtering"""
        if not country:
            return "Unknown"
            
        region_map = {
            "United States": "North America",
            "Canada": "North America",
            "Mexico": "North America",
            
            "Brazil": "South America",
            "Argentina": "South America",
            "Colombia": "South America",
            "Chile": "South America",
            "Peru": "South America",
            
            "United Kingdom": "Europe",
            "Germany": "Europe",
            "France": "Europe",
            "Italy": "Europe",
            "Spain": "Europe",
            "Russia": "Europe",
            "Ukraine": "Europe",
            
            "China": "Asia",
            "Japan": "Asia",
            "South Korea": "Asia",
            "North Korea": "Asia",
            "India": "Asia",
            "Vietnam": "Asia",
            "Singapore": "Asia",
            
            "Israel": "Middle East",
            "Iran": "Middle East",
            "Saudi Arabia": "Middle East",
            "Turkey": "Middle East",
            "Iraq": "Middle East",
            "Egypt": "Middle East",
            
            "South Africa": "Africa",
            "Nigeria": "Africa",
            "Kenya": "Africa",
            "Morocco": "Africa",
            
            "Australia": "Oceania",
            "New Zealand": "Oceania"
        }
        
        return region_map.get(country, "Unknown")
    
    # Analytics methods
    def get_attack_stats_by_region(self):
        """Get attack statistics grouped by region"""
        attacks = self.get_attacks()
        
        # Create a DataFrame for easier manipulation
        attack_data = []
        for attack in attacks:
            # Add source country data
            if attack.source_country:
                region = self._get_region_for_country(attack.source_country)
                attack_data.append({"country": attack.source_country, "region": region, "role": "Source"})
            
            # Add target country data
            if attack.target_country:
                region = self._get_region_for_country(attack.target_country)
                attack_data.append({"country": attack.target_country, "region": region, "role": "Target"})
        
        if not attack_data:
            return pd.DataFrame(columns=["region", "count"])
        
        # Convert to DataFrame and group by region
        df = pd.DataFrame(attack_data)
        region_counts = df["region"].value_counts().reset_index()
        region_counts.columns = ["region", "count"]
        
        return region_counts
    
    # Data conversion helpers
    def attacks_to_dataframe(self, attacks):
        """Convert attack objects to a pandas DataFrame"""
        attack_data = []
        
        for attack in attacks:
            attack_dict = {
                "attack_type": attack.attack_type,
                "source_country": attack.source_country,
                "target_country": attack.target_country,
                "source_latitude": attack.source_latitude,
                "source_longitude": attack.source_longitude,
                "target_latitude": attack.target_latitude,
                "target_longitude": attack.target_longitude,
                "timestamp": attack.timestamp,
                "severity": attack.severity,
                "source": attack.data_source
            }
            attack_data.append(attack_dict)
        
        return pd.DataFrame(attack_data)
    
    def threat_actors_to_dataframe(self, actors):
        """Convert threat actor objects to a pandas DataFrame"""
        actor_data = []
        
        for actor in actors:
            # Get attribution sources as a comma-separated list
            attribution_sources = [source.name for source in actor.attributions]
            attribution_str = ", ".join(attribution_sources) if attribution_sources else ""
            
            # Get tools as a comma-separated list
            tools = [tool.name for tool in actor.tools]
            tools_str = ", ".join(tools) if tools else ""
            
            # Get techniques grouped by tactic
            tactics_dict = {}
            for technique in actor.techniques:
                tactic = technique.tactic or "Unknown"
                if tactic not in tactics_dict:
                    tactics_dict[tactic] = []
                tactics_dict[tactic].append(technique.name)
            
            # Convert tactics dict to string
            tactics_list = []
            for tactic, techniques in tactics_dict.items():
                tactics_list.append(f"{tactic}: {', '.join(techniques)}")
            tactics_str = "; ".join(tactics_list) if tactics_list else ""
            
            actor_dict = {
                "name": actor.name,
                "also_known_as": actor.also_known_as or "",
                "region": actor.region or "Unknown",
                "active_since": actor.active_since or "Unknown",
                "attribution": attribution_str,
                "target_sectors": actor.target_sectors or "",
                "toolkits": tools_str,
                "tactics": tactics_str,
                "notable_attacks": actor.notable_attacks or ""
            }
            actor_data.append(actor_dict)
        
        return pd.DataFrame(actor_data)

# Create a singleton instance
db_manager = DatabaseManager()