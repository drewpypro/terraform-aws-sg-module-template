import csv
import os
import json
import pandas as pd

# Define paths for the output directories
output_base_dir = "./sg_rules"
ingress_dir = os.path.join(output_base_dir, "ingress")
egress_dir = os.path.join(output_base_dir, "egress")

# Create the directories if they don't exist
os.makedirs(ingress_dir, exist_ok=True)
os.makedirs(egress_dir, exist_ok=True)

# Input CSV file
input_csv = "firewall_rules.csv"

# Data structure to hold rules categorized by direction and security group
rules = {"ingress": {}, "egress": {}}

# Helper function to read existing JSON state
def read_existing_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as jsonfile:
            try:
                return json.load(jsonfile)
            except json.JSONDecodeError:
                print(f"Warning: {file_path} is not a valid JSON. It will be overwritten.")
    return []

# Helper function to compare and determine if updates are needed
def rules_changed(existing_rules, new_rules):
    return existing_rules != new_rules

# Read the CSV file and organize data
with open(input_csv, "r") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        direction = row["direction"]
        sg_name = row["security_group_id"]

        # Initialize the security group if not already present
        if sg_name not in rules[direction]:
            rules[direction][sg_name] = []

        # Append the rule
        rules[direction][sg_name].append({
            "name": row["name"],
            "security_group_id": row["security_group_id"],
            "direction": row["direction"],
            "from_port": row["from_port"],
            "to_port": row["to_port"],
            "ip_protocol": row["ip_protocol"],
            "referenced_security_group_id": row["referenced_security_group_id"]
        })

# Write JSON files for each security group and direction
changes_detected = False
for direction, groups in rules.items():
    for sg_name, sg_rules in groups.items():
        output_dir = ingress_dir if direction == "ingress" else egress_dir
        output_file = os.path.join(output_dir, f"{sg_name}_{direction}.json")

        # Read existing JSON rules for comparison
        existing_rules = read_existing_json(output_file)

        # Overwrite only if rules have changed
        if rules_changed(existing_rules, sg_rules):
            with open(output_file, "w") as jsonfile:
                json.dump(sg_rules, jsonfile, indent=4)
            print(f"Updated: {output_file}")
            changes_detected = True
        else:
            print(f"No changes: {output_file}")

print(f"JSON files have been synchronized in {output_base_dir}")

# If changes were detected, update the Mermaid diagram in README.md
if changes_detected:
    def read_firewall_rules(csv_file):
        """Read and parse the firewall rules CSV file."""
        return pd.read_csv(csv_file)

    def get_subnet_mapping():
        """Define which components belong to which subnet."""
        return {
            'general_subnet': ['rds', 'msk', 'opensearch', 'elasti_cache', 'efs_mount_endpoint', 'dms',],
            'paas_subnet': ['istio_nodes', 'internet_istio_nodes', 'worker_nodes', 'cluster_endpoint'],
            'lambda_subnet': ['app1_lambda', 'app2_lambda'],
            'nlb_subnet': ['nlb'],
            'internet_nlb_subnet': ['internet_nlb']
        }

    def generate_mermaid_diagram(df):
        """Generate Mermaid diagram based on firewall rules."""
        subnet_mapping = get_subnet_mapping()
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

        for subnet_name, components in subnet_mapping.items():
            diagram.append(f"    %% {subnet_name.replace('_', ' ').title()}")
            diagram.append(f"    subgraph {subnet_name} [{subnet_name.replace('_', ' ').title()}]")
            for component in components:
                ports = get_component_ports(df, component)
                port_str = f"<br>{ports}" if ports else ""
                diagram.append(f"        {component}[{component.replace('_', ' ').title()}{port_str}]")
            diagram.append("    end\n")

        diagram.append("    %% Connections")
        connections = generate_connections(df)
        diagram.extend(connections)

        diagram.append("\n    %% Apply styles")
        diagram.append("    class internet_nlb,nlb lb")
        diagram.append("    class internet_istio_nodes,istio_nodes,worker_nodes,app1_lambda,app2_lambda nodes")
        diagram.append("    class rds,msk,opensearch,elasti_cache data")
        diagram.append("    class cluster_endpoint,efs_mount_endpoint,dms infra")
        diagram.append("```")

        return "\n".join(diagram)

    def get_component_ports(df, component):
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

            if marker_start not in content:
                content += f"\n\n{marker_start}\n{marker_end}"

            start_idx = content.find(marker_start) + len(marker_start)
            end_idx = content.find(marker_end)
            new_content = content[:start_idx] + "\n" + mermaid_diagram + "\n" + content[end_idx:]

            with open(readme_path, 'w') as f:
                f.write(new_content)
        else:
            with open(readme_path, 'w') as f:
                f.write(f"{marker_start}\n{mermaid_diagram}\n{marker_end}")

    # Generate Mermaid diagram and update README
    df = read_firewall_rules(input_csv)
    mermaid_diagram = generate_mermaid_diagram(df)
    update_readme(mermaid_diagram)
    print("Successfully updated README.md with new security group diagram!")
else:
    print("No changes detected, README.md was not updated.")
