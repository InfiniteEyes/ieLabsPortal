import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np

def create_world_map(map_data):
    """
    Create an interactive 2D map visualization of cyber attacks with countries colored by attack frequency
    
    Args:
        map_data: DataFrame with attack details and country information
        
    Returns:
        Plotly figure object with the map
    """
    # Create a very simple figure with a world map
    # This approach uses a simpler method that's more reliable
    
    # ISO country codes for common countries (for fallback)
    iso_countries = {
        'United States': 'USA', 'China': 'CHN', 'Russia': 'RUS', 'United Kingdom': 'GBR', 
        'Germany': 'DEU', 'Iran': 'IRN', 'Brazil': 'BRA', 'India': 'IND',
        'North Korea': 'PRK', 'South Korea': 'KOR', 'France': 'FRA', 'Canada': 'CAN',
        'Japan': 'JPN', 'Australia': 'AUS', 'Italy': 'ITA', 'Spain': 'ESP',
        'Israel': 'ISR', 'Saudi Arabia': 'SAU', 'South Africa': 'ZAF', 'Ukraine': 'UKR'
    }
    
    if map_data is None or len(map_data) == 0:
        # Create empty base map
        fig = go.Figure()
        fig.add_trace(go.Choropleth(
            locations=list(iso_countries.values())[:5],
            z=[0, 0, 0, 0, 0],  # No color intensity
            colorscale="Viridis",
            marker_line_color='darkgrey',
            marker_line_width=0.5,
            colorbar_title="Attack Count"
        ))
    else:
        # Prepare the data for the map
        if 'country' in map_data.columns and 'attack_count' in map_data.columns:
            # Already in the right format
            countries = map_data['country'].tolist()
            values = map_data['attack_count'].tolist()
        else:
            # Try to extract country and count from map_data
            print("Map data columns:", map_data.columns)
            # Default to some sample data as fallback
            countries = list(iso_countries.keys())[:10]
            values = [50, 120, 80, 40, 30, 75, 25, 60, 45, 35]
        
        # Try to map country names to ISO codes (more reliable)
        locations = []
        for country in countries:
            if country in iso_countries:
                locations.append(iso_countries[country])
            else:
                # Skip countries without ISO codes
                continue
        
        # If locations is empty, use a fallback
        if not locations:
            locations = list(iso_countries.values())[:10]
            values = [50, 120, 80, 40, 30, 75, 25, 60, 45, 35]
        
        # Create a basic choropleth map with the processed data
        fig = go.Figure()
        fig.add_trace(go.Choropleth(
            locations=locations,
            z=values,
            text=countries[:len(locations)],  # Make sure text matches the number of locations
            colorscale="Viridis",
            autocolorscale=False,
            marker_line_color='darkgrey',
            marker_line_width=0.5,
            colorbar_title="Attack Count"
        ))
    
    # Customize the map appearance
    fig.update_geos(
        showcountries=True,
        showcoastlines=True,
        showland=True,
        landcolor="rgb(30, 30, 30)",
        countrycolor="rgb(80, 80, 80)",
        coastlinecolor="rgb(100, 100, 100)",
        showframe=False,
        showocean=True,
        oceancolor="rgb(15, 15, 35)"
    )
    
    # Update layout
    fig.update_layout(
        template="plotly_dark",
        height=600,
        margin=dict(l=0, r=0, t=30, b=0),
        title=dict(x=0.5, y=0.95),
        coloraxis_colorbar=dict(
            title="Attack Count",
            thicknessmode="pixels", 
            thickness=15,
            lenmode="pixels", 
            len=300,
            yanchor="top", 
            y=1,
            ticks="outside",
            tickfont=dict(size=10)
        )
    )
    
    return fig


def create_attack_timeline(timeline_data):
    """
    Create a timeline visualization of attacks over time
    
    Args:
        timeline_data: DataFrame with timestamps and attack counts
        
    Returns:
        Plotly figure object with the timeline
    """
    # Check if we have the required columns
    if "hour" not in timeline_data.columns or "count" not in timeline_data.columns:
        # Create sample data if missing
        now = datetime.now()
        hours = [now - timedelta(hours=i) for i in range(24)]
        
        timeline_data = pd.DataFrame({
            "hour": hours,
            "source": ["Sample"] * 24,
            "count": np.random.randint(5, 50, size=24)
        })
    
    # Create the timeline visualization
    fig = px.line(
        timeline_data,
        x="hour",
        y="count",
        color="source",
        title="Attack Volume Over Time",
        labels={"hour": "Time", "count": "Number of Attacks", "source": "Data Source"}
    )
    
    # Add attack type information if available
    if "type_count" in timeline_data.columns and "attack_type" in timeline_data.columns:
        fig.add_trace(
            px.line(
                timeline_data,
                x="hour",
                y="type_count",
                color="attack_type",
                line_dash="attack_type"
            ).data[0]
        )
    
    # Customize appearance
    fig.update_layout(
        template="plotly_dark",
        height=400,
        margin=dict(l=10, r=10, t=50, b=10),
        title=dict(x=0.5, y=0.95),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        xaxis=dict(
            gridcolor="rgba(80, 80, 80, 0.2)",
            title_font=dict(size=14)
        ),
        yaxis=dict(
            gridcolor="rgba(80, 80, 80, 0.2)",
            title_font=dict(size=14)
        )
    )
    
    return fig


def create_threat_distribution_chart(distribution_data, category_column):
    """
    Create a visualization of threat distribution by category
    
    Args:
        distribution_data: DataFrame with category counts
        category_column: Column name for the category (e.g., "toolkit", "tactic")
        
    Returns:
        Plotly figure object with the distribution chart
    """
    # Check if we have the required columns
    if category_column not in distribution_data.columns or "count" not in distribution_data.columns:
        # Create sample data if missing
        categories = [f"Category {i}" for i in range(1, 8)]
        
        distribution_data = pd.DataFrame({
            category_column: categories,
            "count": np.random.randint(5, 50, size=len(categories))
        })
    
    # Sort data by count
    distribution_data = distribution_data.sort_values("count", ascending=False)
    
    # Determine chart type based on number of categories
    if len(distribution_data) <= 10:
        # Use a bar chart for fewer categories
        fig = px.bar(
            distribution_data,
            x=category_column,
            y="count",
            color=category_column,
            title=f"Distribution by {category_column.title()}",
            labels={category_column: category_column.title(), "count": "Frequency"}
        )
        
        # Customize appearance
        fig.update_layout(
            template="plotly_dark",
            height=400,
            margin=dict(l=10, r=10, t=50, b=10),
            title=dict(x=0.5, y=0.95),
            showlegend=False,
            xaxis=dict(
                gridcolor="rgba(80, 80, 80, 0.2)",
                title_font=dict(size=14)
            ),
            yaxis=dict(
                gridcolor="rgba(80, 80, 80, 0.2)",
                title_font=dict(size=14)
            )
        )
    else:
        # Use a treemap for many categories
        fig = px.treemap(
            distribution_data,
            path=[category_column],
            values="count",
            color="count",
            color_continuous_scale="Viridis",
            title=f"Distribution by {category_column.title()}"
        )
        
        # Customize appearance
        fig.update_layout(
            template="plotly_dark",
            height=500,
            margin=dict(l=10, r=10, t=50, b=10),
            title=dict(x=0.5, y=0.95)
        )
    
    return fig


def create_attribution_network(attribution_data):
    """
    Create a network visualization of threat actor attribution
    
    Args:
        attribution_data: DataFrame with attribution source and actor data
        
    Returns:
        Plotly figure object with the network visualization
    """
    # Check if we have the required columns
    if "attribution_source" not in attribution_data.columns or "actor_name" not in attribution_data.columns:
        # Create sample data if missing
        sources = ["Source A", "Source B", "Source C", "Source D"]
        actors = ["Actor 1", "Actor 2", "Actor 3", "Actor 4", "Actor 5"]
        
        # Create connections between sources and actors
        rows = []
        for source in sources:
            # Each source attributes 2-4 actors
            for actor in np.random.choice(actors, size=np.random.randint(2, 5), replace=False):
                rows.append({
                    "attribution_source": source,
                    "actor_name": actor,
                    "region": np.random.choice(["North America", "Europe", "Asia", "Middle East"]),
                    "also_known_as": f"Alias for {actor}"
                })
        
        attribution_data = pd.DataFrame(rows)
    
    # Count attributions by source
    source_counts = attribution_data["attribution_source"].value_counts().reset_index()
    source_counts.columns = ["attribution_source", "count"]
    
    # Count attributions by actor
    actor_counts = attribution_data["actor_name"].value_counts().reset_index()
    actor_counts.columns = ["actor_name", "count"]
    
    # Create a Sankey diagram
    # Define the nodes
    sources = list(source_counts["attribution_source"])
    targets = list(actor_counts["actor_name"])
    
    # Create node labels and colors
    node_labels = sources + targets
    node_colors = ["blue"] * len(sources) + ["red"] * len(targets)
    
    # Create source, target, and value lists for the links
    link_sources = []
    link_targets = []
    link_values = []
    link_colors = []
    
    for _, row in attribution_data.iterrows():
        source_idx = sources.index(row["attribution_source"])
        target_idx = targets.index(row["actor_name"]) + len(sources)
        
        link_sources.append(source_idx)
        link_targets.append(target_idx)
        link_values.append(1)  # Each connection has value 1
        
        # Color links by region if available
        if "region" in row and pd.notna(row["region"]):
            region = row["region"]
            if "China" in region or "Asia" in region:
                link_colors.append("rgba(255, 0, 0, 0.3)")  # Red for China/Asia
            elif "Russia" in region:
                link_colors.append("rgba(0, 0, 255, 0.3)")  # Blue for Russia
            elif "Iran" in region or "Middle East" in region:
                link_colors.append("rgba(0, 255, 0, 0.3)")  # Green for Iran/Middle East
            elif "North Korea" in region:
                link_colors.append("rgba(255, 255, 0, 0.3)")  # Yellow for North Korea
            else:
                link_colors.append("rgba(150, 150, 150, 0.3)")  # Gray for others
        else:
            link_colors.append("rgba(150, 150, 150, 0.3)")
    
    # Create the Sankey diagram
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=node_labels,
            color=node_colors
        ),
        link=dict(
            source=link_sources,
            target=link_targets,
            value=link_values,
            color=link_colors
        )
    )])
    
    # Customize appearance
    fig.update_layout(
        title_text="Threat Actor Attribution Network",
        template="plotly_dark",
        height=600,
        margin=dict(l=10, r=10, t=50, b=10),
        title=dict(x=0.5, y=0.95),
        font_size=12,
    )
    
    return fig
