import csv
import os
import json
import pandas as pd
import logging
from typing import Dict, List, Any

# Configuration constants
CONFIG = {
    "OUTPUT_DIR": "./sg_rules",
    "INPUT_CSV": "firewall_rules.csv",
    "README_PATH": "README.md",
    "DIAGRAM_START_MARKER": "<!-- SECURITY_GROUP_DIAGRAM_START -->",
    "DIAGRAM_END_MARKER": "<!-- SECURITY_GROUP_DIAGRAM_END -->"
}

os.makedirs(CONFIG["OUTPUT_DIR"], exist_ok=True)

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

# Helper function to detect duplicates in CSV
def detect_duplicates(file_path):
    seen = set()
    duplicates = []
    with open(file_path, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rule_tuple = (
                row["name"],
                row["security_group_id"],
                row["direction"],
                row["from_port"],
                row["to_port"],
                row["ip_protocol"],
                row["referenced_security_group_id"],
                row["cidr_ipv4"],
                row["cidr_ipv6"],
            )
            if rule_tuple in seen:
                duplicates.append(row)
            else:
                seen.add(rule_tuple)
    return duplicates

def validate_port_range(row: Dict[str, str]) -> bool:
    try:
        if row["from_port"] and row["to_port"]:
            return int(row["from_port"]) <= int(row["to_port"])
    except ValueError:
        return False
    return True

def validate_rules(file_path: str) -> Dict[str, List[Dict[str, Any]]]:
    issues = {
        "duplicates": [],
        "invalid_rules": [],
        "port_range": [],
        "protocol": []
    }
    
    # Check for duplicates
    issues["duplicates"] = detect_duplicates(file_path)
    
    # Validate all other rules
    with open(file_path, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            conditions_set = sum([
                bool(row["referenced_security_group_id"] and row["referenced_security_group_id"].lower() != "null"),
                bool(row["cidr_ipv4"] and row["cidr_ipv4"].lower() != "null"),
                bool(row["cidr_ipv6"] and row["cidr_ipv6"].lower() != "null")
            ])

            if conditions_set > 1:  # More than one field is set
                issues["invalid_rules"].append(row)
            
            # Validate port ranges
            if not validate_port_range(row):
                issues["port_range"].append(row)
            
            # Validate protocol (could add more specific protocol validation)
            if row["ip_protocol"] and row["ip_protocol"].lower() not in ["tcp", "udp", "icmp", "-1", "all"]:
                issues["protocol"].append(row)
    
    return {k: v for k, v in issues.items() if v}
# Validate all rules at once
issues = validate_rules(CONFIG["INPUT_CSV"])
if issues:
    print("The following issues were found:")
    for issue_type, rows in issues.items():
        print(f"\n{issue_type.replace('_', ' ').title()}:")
        for row in rows:
            print(row)
    exit(1)


# Read the CSV file and organize data
with open(CONFIG["INPUT_CSV"], "r") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        direction = row["direction"]
        sg_name = row["security_group_id"]

        if sg_name not in rules[direction]:
            rules[direction][sg_name] = []

        # Append the rule
        rules[direction][sg_name].append({
            "RequestID": row["RequestID"],
            "name": row["name"],
            "security_group_id": row["security_group_id"],
            "direction": row["direction"],
            "from_port": row["from_port"],
            "to_port": row["to_port"],
            "ip_protocol": row["ip_protocol"],
            "referenced_security_group_id": row["referenced_security_group_id"] or None,
            "cidr_ipv4": row["cidr_ipv4"] or None,
            "cidr_ipv6": row["cidr_ipv6"] or None,
            "business_justification": row.get("business_justification", ""),
        })
# Write JSON files for each security group
changes_detected = False
all_security_groups = set(rules["ingress"].keys()).union(rules["egress"].keys())

for sg_name in all_security_groups:
    # Combine ingress and egress rules for the security group
    combined_rules = rules["ingress"].get(sg_name, []) + rules["egress"].get(sg_name, [])
    output_file = os.path.join(CONFIG["OUTPUT_DIR"], f"{sg_name}.json")
    
    # Read existing JSON rules for comparison
    existing_rules = read_existing_json(output_file)
    
    # Sort combined rules for consistency
    combined_rules_sorted = sorted(combined_rules, key=lambda x: (
        x["direction"], x["from_port"], x["to_port"], x["ip_protocol"],
        x.get("referenced_security_group_id", ""),
        x.get("cidr_ipv4", ""), x.get("cidr_ipv6", "")
    ))
    
    # Overwrite only if rules have changed
    if rules_changed(existing_rules, combined_rules_sorted):
        with open(output_file, "w") as jsonfile:
            json.dump(combined_rules_sorted, jsonfile, indent=4)
        print(f"Updated: {output_file}")
        changes_detected = True
    else:
        print(f"No changes: {output_file}")

print(f"JSON files have been synchronized in {CONFIG['OUTPUT_DIR']}")

# If changes were detected, update the Mermaid diagram in README.md
if changes_detected:
    def read_firewall_rules(csv_file):
        """Read and parse the firewall rules CSV file."""
        return pd.read_csv(csv_file)

    def get_subnet_mapping():
        """Define which components belong to which subnet."""
        return {
            'general_subnet': ['rds', 'msk', 'opensearch', 'elasti_cache', 'efs_mount_endpoint', 'dms' ],
            'paas_subnet': ['istio_nodes', 'internet_istio_nodes', 'worker_nodes', 'cluster_endpoint'],
            'lambda_subnet': ['app1_lambda', 'app2_lambda'],
            'nlb_subnet': ['nlb'],
            'internet_nlb_subnet': ['internet_nlb'],
            'vpce_subnet': [
                'vpce_autoscaling', 'vpce_dms', 'vpce_ec2', 'vpce_ec2messages', 'vpce_efs', 'vpce_eks',
                'vpce_elasticache', 'vpce_elasticloadbalancing', 'vpce_kms', 'vpce_lambda', 'vpce_logs',
                'vpce_monitoring', 'vpce_rds', 'vpce_s3', 'vpce_sns', 'vpce_sqs', 'vpce_sts', 'vpce_ssm',
                'vpce_ssmmessages', 'vpce_sts'
            ],
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
            diagram.append(f"    %% {subnet_name.replace('_', ' ').title()} Subnet")
            diagram.append(f"    subgraph {subnet_name} [{subnet_name.replace('_', ' ').title()}]")
            for component in components:
                diagram.append(f"        {component}[{component.replace('_', ' ').title()}]")
            diagram.append("    end\n")

        diagram.append("    %% Connections")
        connections = generate_connections(df)
        diagram.extend(connections)

        diagram.append("\n    %% Apply styles")
        diagram.append("    class internet_nlb,nlb lb")
        diagram.append("    class internet_istio_nodes,istio_nodes,worker_nodes,app1_lambda,app2_lambda nodes")
        diagram.append("    class rds,msk,opensearch,elasti_cache, data")
        diagram.append("    class cluster_endpoint,efs_mount_endpoint,dms infra")
        diagram.append("    class vpce_autoscaling,vpce_dms,vpce_ec2,vpce_ec2messages,vpce_efs,vpce_eks,vpce_elasticache,vpce_elasticloadbalancing,vpce_kms,vpce_lambda,vpce_logs,vpce_monitoring,vpce_rds,vpce_s3,vpce_sns,vpce_sqs,vpce_sts,vpce_ssm,vpce_ssmmessages,vpce_sts infra")
        diagram.append("```")

        return "\n".join(diagram)

    def generate_connections(df):
        connections = []
        seen_connections = set()

        for _, rule in df.iterrows():
            source = rule['security_group_id']
            if rule['referenced_security_group_id']:
                target = rule['referenced_security_group_id']
                port = f"{rule['from_port']}" if rule['from_port'] == rule['to_port'] else f"{rule['from_port']}-{rule['to_port']}"
                connection_key = f"{source}-{target}-{port}"
                if connection_key not in seen_connections:
                    connections.append(f"    {source} --> |{port}| {target}")
                    seen_connections.add(connection_key)
            elif rule['cidr_ipv4'] or rule['cidr_ipv6']:
                # Add CIDR connections to diagram
                cidr = rule['cidr_ipv4'] or rule['cidr_ipv6']
                port = f"{rule['from_port']}" if rule['from_port'] == rule['to_port'] else f"{rule['from_port']}-{rule['to_port']}"
                connection_key = f"{source}-{cidr}-{port}"
                if connection_key not in seen_connections:
                    connections.append(f"    {source} --> |{port}| {cidr}")
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
    df = read_firewall_rules(CONFIG["INPUT_CSV"])
    mermaid_diagram = generate_mermaid_diagram(df)
    update_readme(mermaid_diagram)
    print("Successfully updated README.md with new security group diagram!")
else:
    print("No changes detected, README.md was not updated.")
