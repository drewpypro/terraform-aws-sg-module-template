#!/bin/bash
output_file="prefix_lists.json"

echo "Fetching AWS Prefix List IDs..."
echo "{" > $output_file

for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do 
    echo "  \"$region\": {" >> $output_file
    aws ec2 describe-managed-prefix-lists --region $region \
        --query "PrefixLists[?PrefixListName=='com.amazonaws.${region}.s3' || PrefixListName=='com.amazonaws.${region}.dynamodb'].{Name: PrefixListName, ID: PrefixListId}" \
        --output json | jq -r 'map("\t\t\"\(.Name)\": \"\(.ID)\",") | .[]' >> $output_file
    echo "  }," >> $output_file
done

# Remove the last comma and close JSON
sed -i '$ s/,$//' $output_file
echo "}" >> $output_file

echo "Prefix lists saved to $output_file"
