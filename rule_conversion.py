import csv
import json
import os

def csv_to_json(csv_file, output_folder):
    # Create output folder if it does not exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    security_groups = {}

    # Read CSV and process the data
    with open(csv_file, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            name = row['name']
            if name not in security_groups:
                security_groups[name] = []
            
            # Convert 'null' values to None or handle variable references
            for key, value in row.items():
                if value.lower() == 'null':
                    row[key] = None
                elif value.startswith("var."):
                    row[key] = f"${{{value}}}"

            # Handle ip_protocol = -1 (all traffic)
            from_port = None
            to_port = None
            if row["ip_protocol"] != "-1":
                from_port = int(row["from_port"]) if row["from_port"] else None
                to_port = int(row["to_port"]) if row["to_port"] else None

            security_groups[name].append({
                "security_group_id": row["security_group_id"],
                "self_rule": row["self_rule"].lower() == 'yes' if row["self_rule"] else False,
                "direction": row["direction"],
                "from_port": from_port,
                "to_port": to_port,
                "ip_protocol": row["ip_protocol"],
                "referenced_security_group_id": row["referenced_security_group_id"],
                "cidr_ipv4": row["cidr_ipv4"],
                "cidr_ipv6": row["cidr_ipv6"]
            })

    # Write JSON files per security group
    for name, rules in security_groups.items():
        json_file_path = os.path.join(output_folder, f"{name}.json")
        with open(json_file_path, mode='w') as json_file:
            json.dump(rules, json_file, indent=4)

if __name__ == "__main__":
    csv_file = "firewall_rules.csv"
    output_folder = "security-groups"
    csv_to_json(csv_file, output_folder)
    print(f"JSON files have been created in the '{output_folder}' folder.")
