import csv
import os
import json

# Define the paths for the output directories
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
for direction, groups in rules.items():
    for sg_name, sg_rules in groups.items():
        output_dir = ingress_dir if direction == "ingress" else egress_dir
        output_file = os.path.join(output_dir, f"{sg_name}_{direction}.json")

        # Write the rules to the file
        with open(output_file, "w") as jsonfile:
            json.dump(sg_rules, jsonfile, indent=4)

print(f"JSON files have been generated in {output_base_dir}")
