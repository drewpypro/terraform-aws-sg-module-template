import csv
import json
from collections import defaultdict
from typing import Dict, List, Any
import os

def process_csv_to_json(csv_file: str) -> None:
    """
    Process CSV file and generate JSON files for each security group.
    """
    # Initialize data structure to hold rules by security group
    security_groups: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"rules": defaultdict(list)}
    )
    
    # Read CSV file
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row['name']
            
            # Create rule object, excluding null values
            rule = {}
            for key, value in row.items():
                if value not in ('null', '', None):
                    rule[key] = value
            
            # Determine direction and add to appropriate list
            direction = rule.pop('direction', None)
            if direction:
                security_groups[name]['rules'][direction].append(rule)
            
            # Store security_group_id if present
            if 'security_group_id' in rule:
                security_groups[name]['security_group_id'] = rule['security_group_id']
                
            # Store self_rule if present
            if 'self_rule' in rule:
                security_groups[name]['self_rule'] = rule['self_rule']

    # Generate JSON files
    os.makedirs('rulesets', exist_ok=True)
    for name, data in security_groups.items():
        filename = f"rulesets/{name}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

if __name__ == "__main__":
    process_csv_to_json("firewall_rules.csv")