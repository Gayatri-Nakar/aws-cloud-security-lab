#!/usr/bin/env bash
#
# Syncs all telemetry sources to S3. Intended to run via cron every few
# minutes so log data survives even if the instance becomes unstable or
# needs to be terminated early.
#
# Requires: AWS CLI installed, and an IAM instance role attached that
# grants only s3:PutObject on the target bucket (see project README).
#
# Example crontab entry (run every 5 minutes):
#   */5 * * * * /home/ubuntu/app/scripts/log_sync.sh >> /var/log/log_sync.log 2>&1

set -euo pipefail

BUCKET="s3://<LOG_BUCKET_NAME>"
INSTANCE_TAG="<INSTANCE_LABEL>"   # e.g. "misconfigured-01", used as an S3 key prefix

aws s3 sync /var/log/apache2/          "${BUCKET}/${INSTANCE_TAG}/apache2/"      --only-show-errors
aws s3 cp /var/log/auth.log            "${BUCKET}/${INSTANCE_TAG}/auth/auth.log" --only-show-errors
aws s3 sync /var/www/portal-data/logs/ "${BUCKET}/${INSTANCE_TAG}/app/"           --only-show-errors

echo "$(date -u +%FT%TZ) log_sync completed"
