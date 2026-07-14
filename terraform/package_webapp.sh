#!/usr/bin/env bash
# Run this from inside the terraform/ folder before `terraform apply`.
# Produces webapp.zip in this same folder, which Terraform then uploads
# to S3 and the EC2 instance downloads and deploys on first boot.
#
# Usage: bash package_webapp.sh /path/to/webapp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBAPP_DIR="${1:-../webapp}"
WEBAPP_DIR="$(cd "$WEBAPP_DIR" && pwd)"
BASENAME="$(basename "$WEBAPP_DIR")"
OUTPUT_ZIP="$SCRIPT_DIR/webapp.zip"

rm -f "$OUTPUT_ZIP"

# Zip so the archive contains a top-level "webapp/" folder, matching
# what user_data.sh.tpl expects after unzip. Excludes any local test
# artifacts (SQLite db, log files) so only source files are shipped.
cd "$(dirname "$WEBAPP_DIR")"
zip -r "$OUTPUT_ZIP" "$BASENAME" \
    -x "*.sqlite" \
    -x "*/logs/*.log" \
    -x "*.DS_Store"

echo "Created $OUTPUT_ZIP -- ready for terraform apply"
