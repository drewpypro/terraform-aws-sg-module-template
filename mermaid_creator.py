import pandas as pd
import os
from collections import defaultdict

def read_firewall_rules(csv_file):
    """Read and parse the firewall rules CSV file."""
    return pd.read_csv(csv_file)

def get_subnet_mapping():
    """Define which components belong to which subnet."""
    return {
        'general_subnet': ['rds', 'msk', 'opensearch', 'elasti_cache', 'efs_mount_endpoint', 'dms'],
        'paas_subnet': ['istio_nodes', 'internet_istio_nodes', 'worker_nodes', 'cluster_endpoint'],
        'lambda_subnet': ['app1_lambda', 'app2_lambda'],
        'nlb_subnet': ['nlb'],
        'internet_nlb_subnet': ['internet_nlb']
    }

def generate_mermaid_diagram(df):
    """Generate Mermaid diagram based on firewall rules."""
    # Initialize diagram parts
    subnet_mapping = get_subnet_mapping()
    
    # Start building the diagram
    diagram = [
        "```mermaid",
        "flowchart LR",
        "    %% Styles",
        "    classDef default fill:#1a2433,stroke:#fff,stroke-width:2px,color:#fff",
        "    classDef lb fill:#d86613,stroke:#fff,stroke-width:2px,color:#fff",
        "    classDef nodes fill:#007acc,stroke:#fff,stroke-width:2px,color:#fff",
        "    classDef data fill:#3b48cc,stroke:#fff,stroke-width:2px,color:#fff",
        "    classDef infra fill:#c94f17,stroke:#fff,stroke-width:2px,color:#fff\n"
    ]

    # Generate subnet subgraphs
    for subnet_name, components in subnet_mapping.items():
        diagram.append(f"    %% {subnet_name.replace('_', ' ').title()}")
        diagram.append(f"    subgraph {subnet_name} [{subnet_name.replace('_', ' ').title()}]")
        for component in components:
            # Get ports for this component
            ports = get_component_ports(df, component)
            port_str = f"\\n{ports}" if ports else ""
            diagram.append(f"        {component}[{component.replace('_', ' ').title()}{port_str}]")
        diagram.append("    end\n")

    # Generate connections
    diagram.append("    %% Connections")
    connections = generate_connections(df)
    diagram.extend(connections)

    # Add style classes
    diagram.append("\n    %% Apply styles")
    diagram.append("    class internet_nlb,nlb lb")
    diagram.append("    class internet_istio_nodes,istio_nodes,worker_nodes,app1_lambda,app2_lambda nodes")
    diagram.append("    class rds,msk,opensearch,elasti_cache data")
    diagram.append("    class cluster_endpoint,efs_mount_endpoint,dms infra")
    diagram.append("```")

    return "\n".join(diagram)

def get_component_ports(df, component):
    """Get unique ports for a component."""
    ports = set()
    component_rules = df[
        (df['security_group_id'] == component) | 
        (df['referenced_security_group_id'] == component)
    ]
    
    for _, rule in component_rules.iterrows():
        if rule['from_port'] == rule['to_port']:
            ports.add(str(rule['from_port']))
        else:
            ports.add(f"{rule['from_port']}-{rule['to_port']}")
    
    return ",".join(sorted(ports)) if ports else ""

def generate_connections(df):
    """Generate connection strings for the diagram."""
    connections = []
    seen_connections = set()

    for _, rule in df.iterrows():
        source = rule['security_group_id']
        target = rule['referenced_security_group_id']
        port = f"{rule['from_port']}" if rule['from_port'] == rule['to_port'] else f"{rule['from_port']}-{rule['to_port']}"
        
        connection_key = f"{source}-{target}-{port}"
        if connection_key not in seen_connections:
            connections.append(f"    {source} --> |{port}| {target}")
            seen_connections.add(connection_key)

    return connections

def update_readme(mermaid_diagram):
    """Update README.md with the new Mermaid diagram."""
    readme_path = "README.md"
    marker_start = "<!-- SECURITY_GROUP_DIAGRAM_START -->"
    marker_end = "<!-- SECURITY_GROUP_DIAGRAM_END -->"
    
    if os.path.exists(readme_path):
        with open(readme_path, 'r') as f:
            content = f.read()
        
        # If markers don't exist, add them
        if marker_start not in content:
            content += f"\n\n{marker_start}\n{marker_end}"
        
        # Replace content between markers
        start_idx = content.find(marker_start) + len(marker_start)
        end_idx = content.find(marker_end)
        new_content = (
            content[:start_idx] + 
            "\n" + mermaid_diagram + "\n" + 
            content[end_idx:]
        )
        
        with open(readme_path, 'w') as f:
            f.write(new_content)
    else:
        # Create new README if it doesn't exist
        with open(readme_path, 'w') as f:
            f.write(f"{marker_start}\n{mermaid_diagram}\n{marker_end}")

def main():
    """Main function to process firewall rules and update README."""
    try:
        # Read firewall rules
        df = read_firewall_rules('firewall_rules.csv')
        
        # Generate Mermaid diagram
        mermaid_diagram = generate_mermaid_diagram(df)
        
        # Update README.md
        update_readme(mermaid_diagram)
        print("Successfully updated README.md with new security group diagram!")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()