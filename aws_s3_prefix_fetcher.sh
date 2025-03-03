#!/bin/bash
output_file="prefix_lists.json"

echo "Fetching AWS Prefix List IDs..."
echo "{" > $output_file

first_region=true
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    if [ "$first_region" = true ]; then
        first_region=false
    else
        echo "," >> $output_file  # Add a comma between regions
    fi

    echo "  \"$region\": {" >> $output_file

    # Fetch prefix lists for the region
    prefix_lists=$(aws ec2 describe-managed-prefix-lists --region "$region" \
        --query "PrefixLists[?PrefixListName=='com.amazonaws.${region}.s3' || PrefixListName=='com.amazonaws.${region}.dynamodb'].{Name: PrefixListName, ID: PrefixListId}" \
        --output json | jq -r 'map("    \"\(.Name)\": \"\(.ID)\"") | join(",\n")')

    echo -e "$prefix_lists" >> $output_file
    echo "  }" >> $output_file  # No comma here; handled above
done

echo "}" >> $output_file

echo "Prefix lists saved to $output_file"

# Ensure the final JSON is valid
jq . "$output_file" > /dev/null 2>&1 && echo "Valid JSON output." || echo "Error: JSON output is invalid!"
