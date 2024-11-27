import csv
import json
import os

# Input CSV file
csv_file = "firewall_rules.csv"

# Output directory for JSON files
output_dir = "./security_groups/"
os.makedirs(output_dir, exist_ok=True)

# Dictionary to hold security group data
security_groups = {}

# Process the CSV
with open(csv_file, "r") as file:
    reader = csv.DictReader(file)
    
    for row in reader:
        sg_name = row["name"]  # Security group name
        sg_id = row["security_group_id"]  # Security group ID

        # Initialize security group entry if not already present
        if sg_name not in security_groups:
            security_groups[sg_name] = {
                "aws_security_group": sg_name,
                "security_group_id": sg_id,
                "rules": []
            }

        # Prepare the rule
        rule = {
            "self_rule": None if row["self_rule"] == "null" else row["self_rule"],
            "direction": row["direction"],
            "from_port": None if row["from_port"] == "null" else int(row["from_port"]),
            "to_port": None if row["to_port"] == "null" else int(row["to_port"]),
            "ip_protocol": None if row["ip_protocol"] == "null" else row["ip_protocol"],
            "referenced_security_group_id": None if row["referenced_security_group_id"] == "null" else row["referenced_security_group_id"],
            "cidr_ipv4": None if row["cidr_ipv4"] == "null" else row["cidr_ipv4"],
            "cidr_ipv6": None if row["cidr_ipv6"] == "null" else row["cidr_ipv6"]
        }

        # Add rule to the security group
        security_groups[sg_name]["rules"].append(rule)

# Write JSON files
for sg_name, sg_data in security_groups.items():
    json_file = os.path.join(output_dir, f"{sg_name}.json")
    with open(json_file, "w") as outfile:
        json.dump(sg_data, outfile, indent=4)

print(f"JSON files have been generated in: {output_dir}")
