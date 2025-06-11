import pandas as pd
from datetime import datetime
import random

from database_manager import db_manager
from data_sources import (
    get_kaspersky_data, 
    get_radware_data, 
    get_mitre_attack_groups,
    get_apt_data,
    get_threatmap_data
)

def import_kaspersky_data():
    """Import Kaspersky threat data into the database"""
    print("Importing Kaspersky data...")
    kaspersky_data = get_kaspersky_data()
    
    for _, row in kaspersky_data.iterrows():
        timestamp = pd.to_datetime(row['timestamp']) if isinstance(row['timestamp'], str) else row['timestamp']
        
        db_manager.add_attack(
            attack_type=row['attack_type'],
            timestamp=timestamp,
            source_country=None,  # Kaspersky data doesn't have source country
            target_country=row['country'],
            source_lat=None,
            source_lon=None,
            target_lat=row['latitude'],
            target_lon=row['longitude'],
            severity=row['severity'],
            data_source="Kaspersky"
        )
    
    print(f"Imported {len(kaspersky_data)} Kaspersky attacks")

def import_radware_data():
    """Import Radware threat data into the database"""
    print("Importing Radware data...")
    radware_data = get_radware_data()
    
    for _, row in radware_data.iterrows():
        timestamp = pd.to_datetime(row['timestamp']) if isinstance(row['timestamp'], str) else row['timestamp']
        
        db_manager.add_attack(
            attack_type=row['attack_type'],
            timestamp=timestamp,
            source_country=row['source_country'],
            target_country=row['target_country'],
            source_lat=row['source_latitude'],
            source_lon=row['source_longitude'],
            target_lat=row['target_latitude'],
            target_lon=row['target_longitude'],
            severity=row['severity'],
            data_source="Radware"
        )
    
    print(f"Imported {len(radware_data)} Radware attacks")

def import_mitre_groups():
    """Import MITRE ATT&CK Groups into the database"""
    print("Importing MITRE ATT&CK groups...")
    mitre_data = get_mitre_attack_groups()
    
    # Add MITRE as an attribution source
    mitre_source = db_manager.add_attribution_source(
        name="MITRE ATT&CK",
        url="https://attack.mitre.org/groups/"
    )
    
    for _, row in mitre_data.iterrows():
        # Add the threat actor
        actor = db_manager.add_threat_actor(
            name=row['name'],
            also_known_as=row['also_known_as'],
            region=row['region'],
            active_since=row['active_since'],
            target_sectors=row['target_sectors'],
            notable_attacks=row['notable_attacks']
        )
        
        # Associate with MITRE as attribution source
        db_manager.add_attribution(
            threat_actor_id=actor.id,
            attribution_source_id=mitre_source.id
        )
        
        # Add techniques if available
        if 'techniques' in row and pd.notna(row['techniques']):
            techniques = row['techniques'].split(', ')
            tactics = row['tactics'].split(', ') if 'tactics' in row and pd.notna(row['tactics']) else []
            
            for i, technique_id in enumerate(techniques):
                # Get corresponding tactic if available
                tactic = tactics[i] if i < len(tactics) else None
                
                # Add the technique
                technique = db_manager.add_technique(
                    technique_id=technique_id,
                    name=f"Technique {technique_id}",  # In a real app, we'd look up the actual name
                    tactic=tactic
                )
                
                # Associate technique with actor
                db_manager.associate_technique_with_actor(
                    threat_actor_id=actor.id,
                    technique_id=technique.id
                )
        
        # Add tools if available
        if 'toolkits' in row and pd.notna(row['toolkits']):
            tools = row['toolkits'].split(', ')
            
            for tool_name in tools:
                # Add the tool
                tool = db_manager.add_tool(
                    name=tool_name,
                    tool_type="Malware"  # Default type
                )
                
                # Associate tool with actor
                db_manager.associate_tool_with_actor(
                    threat_actor_id=actor.id,
                    tool_id=tool.id
                )
    
    print(f"Imported {len(mitre_data)} MITRE ATT&CK groups")

def import_apt_data():
    """Import APT data into the database"""
    print("Importing APT data...")
    apt_data = get_apt_data(sources=["APT Map", "ETDA"])
    
    # Add APT Map and ETDA as attribution sources
    apt_map_source = db_manager.add_attribution_source(
        name="APT Map",
        url="https://andreacristaldi.github.io/APTmap/"
    )
    
    etda_source = db_manager.add_attribution_source(
        name="ETDA",
        url="https://apt.etda.or.th/cgi-bin/listgroups.cgi"
    )
    
    for _, row in apt_data.iterrows():
        # Check if the actor already exists
        existing_actor = db_manager.get_threat_actor_by_name(row['name'])
        
        if existing_actor:
            actor = existing_actor
        else:
            # Add the threat actor
            actor = db_manager.add_threat_actor(
                name=row['name'],
                also_known_as=row.get('also_known_as', ""),
                region=row.get('region', "Unknown"),
                active_since=row.get('active_since', "Unknown"),
                target_sectors=row.get('target_sectors', ""),
                notable_attacks=row.get('notable_attacks', "")
            )
        
        # Associate with attribution sources
        source_id = apt_map_source.id if row.get('source') == "APT Map" else etda_source.id
        db_manager.add_attribution(
            threat_actor_id=actor.id,
            attribution_source_id=source_id
        )
    
    print(f"Imported {len(apt_data)} APT groups")

def import_threatmap_data():
    """Import threat map data from Palo Alto and Rapid7"""
    print("Importing threat map data...")
    threatmap_data = get_threatmap_data(sources=["Palo Alto", "Rapid7"])
    
    # Add Palo Alto and Rapid7 as attribution sources
    palo_alto_source = db_manager.add_attribution_source(
        name="Palo Alto Unit42",
        url="https://unit42.paloaltonetworks.com/threat-actor-groups-tracked-by-palo-alto-networks-unit-42/"
    )
    
    rapid7_source = db_manager.add_attribution_source(
        name="Rapid7",
        url="https://docs.rapid7.com/insightidr/apt-groups/"
    )
    
    for _, row in threatmap_data.iterrows():
        # Check if the actor already exists
        existing_actor = db_manager.get_threat_actor_by_name(row['name'])
        
        if existing_actor:
            actor = existing_actor
        else:
            # Add the threat actor
            actor = db_manager.add_threat_actor(
                name=row['name'],
                also_known_as=row.get('also_known_as', ""),
                region=row.get('region', "Unknown"),
                active_since=row.get('active_since', "Unknown"),
                target_sectors=row.get('target_sectors', ""),
                notable_attacks=row.get('notable_attacks', "")
            )
        
        # Associate with attribution source
        source_id = palo_alto_source.id if row.get('source') == "Palo Alto" else rapid7_source.id
        db_manager.add_attribution(
            threat_actor_id=actor.id,
            attribution_source_id=source_id
        )
    
    print(f"Imported {len(threatmap_data)} threat map entries")

def import_all_data():
    """Import all data from sources into the database"""
    try:
        import_kaspersky_data()
        import_radware_data()
        import_mitre_groups()
        import_apt_data()
        import_threatmap_data()
        
        print("All data successfully imported!")
        return True
    except Exception as e:
        print(f"Error importing data: {str(e)}")
        return False

if __name__ == "__main__":
    # Run the import when script is executed directly
    import_all_data()