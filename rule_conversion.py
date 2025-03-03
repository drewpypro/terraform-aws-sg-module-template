import pandas as pd
import os
import json
from typing import Dict, List, Any
import ipaddress

CONFIG = {
    "OUTPUT_DIR": "./sg_rules",
    "VALID_PROTOCOLS": ["tcp", "udp", "icmp"],
}

def validate_required_fields(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Check all required fields are present"""
    errors = []
    required_fields = ['RequestID', 'name', 'security_group_id', 'direction', 
                      'from_port', 'to_port', 'ip_protocol', ]
    
    for field in required_fields:
        missing_mask = df[field].isna() | (df[field].astype(str).str.strip() == '')
        if missing_mask.any():
            errors.extend([
                {"row": row, "error": f"Missing required field: {field}"} 
                for row in df[missing_mask].to_dict('records')
            ])
    return errors

def validate_field_values(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Check direction and protocol values are valid"""
    errors = []
    
    invalid_direction = ~df['direction'].str.lower().isin(['ingress', 'egress'])
    if invalid_direction.any():
        errors.extend([
            {"row": row, "error": "Direction must be either 'ingress' or 'egress'"} 
            for row in df[invalid_direction].to_dict('records')
        ])

    invalid_protocol = ~df['ip_protocol'].str.lower().isin(CONFIG['VALID_PROTOCOLS'])
    if invalid_protocol.any():
        errors.extend([
            {"row": row, "error": f"Protocol must be one of: {', '.join(CONFIG['VALID_PROTOCOLS'])}"} 
            for row in df[invalid_protocol].to_dict('records')
        ])

    return errors

def validate_ports(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Validate port ranges based on protocol:
    - TCP/UDP: ports must be 0-65535 and from_port <= to_port
    - ICMP: ports must be 0-255 (representing type/code)
    """
    validation_rules = {
        'tcp/udp': "TCP/UDP: ports must be 0-65535 and from_port <= to_port",
        'icmp': "ICMP: ports must be 0-255 (representing type/code)"
    }
    errors = []
    
    for _, row in df.iterrows():
        try:
            protocol = row['ip_protocol'].lower()
            from_port = int(row['from_port'])
            to_port = int(row['to_port'])
            
            if protocol == 'icmp':
                if not (0 <= from_port <= 255 and 0 <= to_port <= 255):
                    errors.append({
                        "row": row.to_dict(),
                        "error": f"Invalid ICMP ports: {from_port}, {to_port}. {validation_rules['icmp']}"
                    })
            else: 
                if not (0 <= from_port <= 65535 and 0 <= to_port <= 65535):
                    errors.append({
                        "row": row.to_dict(),
                        "error": f"Invalid port range: {from_port}, {to_port}. {validation_rules['tcp/udp']}"
                    })
                elif from_port > to_port:
                    errors.append({
                        "row": row.to_dict(),
                        "error": f"From port ({from_port}) cannot be greater than to port ({to_port})"
                    })
        except ValueError:
            errors.append({
                "row": row.to_dict(),
                "error": f"Port values must be integers, got from_port={row['from_port']}, to_port={row['to_port']}"
            })
    return errors

def validate_input_declarations(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Check that only one source (security group, CIDR IPv4, CIDR IPv6 or prefix_list_id) is specified per rule"""
    rule_conditions = [
        (df['referenced_security_group_id'].fillna('null') != 'null') & 
        (df['referenced_security_group_id'].fillna('null').str.lower() != 'null'),
        (df['cidr_ipv4'].fillna('null') != 'null') & 
        (df['cidr_ipv4'].fillna('null').str.lower() != 'null'),
        (df['cidr_ipv6'].fillna('null') != 'null') & 
        (df['cidr_ipv6'].fillna('null').str.lower() != 'null'),
        (df['prefix_list_id'].fillna('null') != 'null') & 
        (df['prefix_list_id'].fillna('null').str.lower() != 'null')
    ]
    
    multiple_inputs = sum(rule_conditions) > 1
    if multiple_inputs.any():
        return [
            {
                "row": row,
                "error": "Only one source (security group, CIDR IPv4, CIDR IPv6 or prefix_list_id) can be specified per rule"
            }
            for row in df[multiple_inputs].to_dict('records')
        ]
    return []

def validate_null_input(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Ensure that at least one input (security group, CIDR IPv4, CIDR IPv6 or prefix_list_id) is set per rule."""

    errors = []
    rule_conditions = [
        (df['referenced_security_group_id'].fillna('null').str.lower() != 'null'),
        (df['cidr_ipv4'].fillna('null').str.lower() != 'null'),
        (df['cidr_ipv6'].fillna('null').str.lower() != 'null'),
        (df['prefix_list_id'].fillna('null').str.lower() != 'null')
    ]

    # Sum up the number of non-null fields for each row
    missing_inputs = sum(rule_conditions) == 0
    if missing_inputs.any():
        return [
            {
                "row": row.to_dict(),
                "error": "At least one input (security group, CIDR IPv4, CIDR IPv6 or prefix_list_id) must be specified."
            }
            for _, row in df[missing_inputs].iterrows()
        ]

    return []



def validate_ip_addresses(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Check IP address formats and ensure proper CIDR notation for security group rules.
    IPv4: Must use /0 to /32
    IPv6: Must use /0 to /128
    """
    errors = []
    
    for _, row in df.iterrows():
        for ip_field, version in [('cidr_ipv4', 4), ('cidr_ipv6', 6)]:
            ip = row[ip_field]
            if pd.isna(ip) or str(ip).lower() == 'null':
                continue

            # Check for CIDR notation
            if '/' not in str(ip):
                errors.append({
                    "row": row.to_dict(),
                    "error": f"IP address {ip} must be in CIDR notation (e.g., x.x.x.x/32 for IPv4, x:x:x:x:x:x:x:x/128 for IPv6)"
                })
                continue
                
            try:
                ip_obj = ipaddress.ip_network(ip, strict=False)
                
                # Verify IP version
                if ip_obj.version != version:
                    errors.append({
                        "row": row.to_dict(),
                        "error": f"IP address {ip} must be a valid IPv{version} CIDR block"
                    })
                    continue

                # Verify prefix length
                max_prefix = 32 if version == 4 else 128
                if not (0 <= ip_obj.prefixlen <= max_prefix):
                    errors.append({
                        "row": row.to_dict(),
                        "error": f"IPv{version} CIDR {ip} must have a prefix length between 0 and {max_prefix}"
                    })
                    
            except ValueError as e:
                errors.append({
                    "row": row.to_dict(),
                    "error": f"Invalid CIDR block {ip}: Must be a valid IPv{version} CIDR notation"
                })
            except TypeError:
                errors.append({
                    "row": row.to_dict(),
                    "error": f"Invalid IP format: {ip} must be a string in CIDR notation"
                })
    return errors


def validate_prefix_lists(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Ensure prefix_list_id is only 's3' or 'dynamodb'."""
    errors = []
    valid_prefix_lists = [ "s3", "dynamodb", "null"]

    invalid_rows = ~df["prefix_list_id"].isin(valid_prefix_lists)

    if invalid_rows.any():
        errors.extend([
            {
                "row": row.to_dict(),
                "error": f"Invalid prefix_list_id: '{row['prefix_list_id']}'. "
                         f"Must be one of {', '.join(valid_prefix_lists)}."
            }
            for _, row in df[invalid_rows].iterrows()
        ])
    
    return errors

def check_duplicates(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Check for duplicate rules."""
    duplicate_mask = df.duplicated(subset=[
        'name', 'security_group_id', 'direction', 'from_port', 
        'to_port', 'ip_protocol', 'referenced_security_group_id',
        'cidr_ipv4', 'cidr_ipv6', 'prefix_list_id'
    ], keep=False)
    
    if duplicate_mask.any():
        return [
            {"row": row, "error": "Duplicate rule detected"}
            for row in df[duplicate_mask].to_dict('records')
        ]
    return []

def validate_rules(df: pd.DataFrame) -> Dict[str, List[Dict[str, Any]]]:
    """Main validation function that calls all validators in sequence"""
    issues = {}
    
    # 1. Required fields
    if field_errors := validate_required_fields(df):
        issues["missing_fields"] = field_errors

    # 2. Field values
    if value_errors := validate_field_values(df):
        issues["invalid_fields"] = value_errors

    # 3. Ports
    if port_errors := validate_ports(df):
        issues["port_validation"] = port_errors

    # 4. Source declarations
    if input_errors := validate_input_declarations(df):
        issues["multiple_input_declarations"] = input_errors
        
    # 5. IPs
    if ip_errors := validate_ip_addresses(df):
        issues["ip_validation"] = ip_errors

    # 6. Duplicates
    if duplicate_errors := check_duplicates(df):
        issues["duplicates"] = duplicate_errors

    # 6. Prefix Lists 
    if prefix_errors := validate_prefix_lists(df):
        issues["prefix_validation"] = prefix_errors

    # 7. Null input
    if invalid_input := validate_null_input(df):
        issues["invalid_input"] = invalid_input


    return issues

def read_existing_json(file_path: str) -> List[Dict[str, Any]]:
    """Read existing JSON file if it exists."""
    if os.path.exists(file_path):
        with open(file_path, "r") as jsonfile:
            try:
                return json.load(jsonfile)
            except json.JSONDecodeError:
                print(f"Warning: {file_path} is not a valid JSON. It will be overwritten.")
    return []

def rules_changed(existing_rules: List[Dict[str, Any]], new_rules: List[Dict[str, Any]]) -> bool:
    """Compare existing and new rules to determine if updates are needed."""
    return existing_rules != new_rules

def process_rules(input_file: str) -> None:
    """Main function to process and validate rules."""
    # Create output directory if it doesn't exist
    os.makedirs(CONFIG["OUTPUT_DIR"], exist_ok=True)
    
    # Read CSV file into pandas DataFrame and replace NaN with "null"
    df = pd.read_csv(input_file).fillna("null")
    
    # Validate rules
    issues = validate_rules(df)
    if issues:
        print("The following issues were found:")
        for issue_type, rows in issues.items():
            print(f"\n{issue_type.replace('_', ' ').title()}:")
            for item in rows:
                if isinstance(item, dict) and "error" in item:
                    print(f"Error: {item['error']}")
                    print(f"Row data: {item['row']}\n")
                else:
                    print(item)
        return
    
    # Process valid rules
    rules = {"ingress": {}, "egress": {}}
    
    # Group rules by direction and security group
    for direction in ["ingress", "egress"]:
        direction_df = df[df['direction'] == direction]
        for sg_name, group in direction_df.groupby('security_group_id'):
            rules[direction][sg_name] = group.to_dict('records')
    
    # Get current security groups from CSV
    all_security_groups = set(rules["ingress"].keys()).union(rules["egress"].keys())
    
    # Get existing security group files
    existing_files = set(f.replace('.json', '') for f in os.listdir(CONFIG["OUTPUT_DIR"]) 
                        if f.endswith('.json'))
    
    # Find security groups that need to be emptied
    to_empty = existing_files - all_security_groups
    
    # Handle security groups no longer in CSV
    if to_empty:
        print("\nThe following security groups are no longer in the CSV and will be emptied:")
        for sg in to_empty:
            output_file = os.path.join(CONFIG["OUTPUT_DIR"], f"{sg}.json")
            with open(output_file, "w") as jsonfile:
                json.dump([], jsonfile, indent=4)
            print(f"- Cleared rules for: {sg}")
    
    # Process current security groups
    changes_detected = False
    for sg_name in all_security_groups:
        # Combine ingress and egress rules for the security group
        combined_rules = (rules["ingress"].get(sg_name, []) + 
                         rules["egress"].get(sg_name, []))
        
        output_file = os.path.join(CONFIG["OUTPUT_DIR"], f"{sg_name}.json")
        
        # Read existing JSON rules for comparison
        existing_rules = read_existing_json(output_file)
        
        # Sort combined rules for consistency
        combined_rules_sorted = sorted(combined_rules, key=lambda x: (
            x["direction"], str(x["from_port"]), str(x["to_port"]), 
            x["ip_protocol"], str(x.get("referenced_security_group_id", "")),
            str(x.get("cidr_ipv4", "")), str(x.get("cidr_ipv6", ""))
        ))
        
        # Overwrite only if rules have changed
        if rules_changed(existing_rules, combined_rules_sorted):
            with open(output_file, "w") as jsonfile:
                json.dump(combined_rules_sorted, jsonfile, indent=4)
            print(f"Updated: {output_file}")
            changes_detected = True
        else:
            print(f"No changes: {output_file}")
    
    print(f"\nJSON files have been synchronized in {CONFIG['OUTPUT_DIR']}")
    
if __name__ == "__main__":
    process_rules("firewall_rules.csv")