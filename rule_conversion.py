import csv
import json

# Read the CSV and convert each rule to a JSON file
def csv_to_json(csv_filepath):
    with open(csv_filepath, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        rules_by_group = {}

        # Group rules by their security group name
        for row in csv_reader:
            group_name = row['name']
            if group_name not in rules_by_group:
                rules_by_group[group_name] = []

            # Remove fields with 'null' values for Terraform compatibility
            filtered_row = {key: value for key, value in row.items() if value.lower() != 'null'}
            rules_by_group[group_name].append(filtered_row)

        # Write each group's rules to a separate JSON file
        for group_name, rules in rules_by_group.items():
            with open(f"{group_name}.json", mode='w') as json_file:
                json.dump(rules, json_file, indent=4)

if __name__ == "__main__":
    csv_to_json('referenced_sg_rules.csv')
