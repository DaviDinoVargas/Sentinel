set -eu
export HOME=/tmp
mc alias set local http://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
for bucket in sentinel-evidence sentinel-evidence-test; do
  mc mb --with-lock --ignore-existing "local/$bucket" >/dev/null
  mc version enable "local/$bucket" >/dev/null
  mc anonymous set none "local/$bucket" >/dev/null
done
mc admin user add local "$SENTINEL_S3_USER" "$SENTINEL_S3_PASSWORD" >/dev/null
mc admin policy create local sentinel-evidence /setup/evidence-policy.json >/dev/null
mc admin policy attach local sentinel-evidence --user "$SENTINEL_S3_USER" >/dev/null
sed 's/sentinel-evidence/sentinel-evidence-test/g' /setup/evidence-policy.json > /tmp/test-policy.json
mc admin user add local "$SENTINEL_S3_TEST_USER" "$SENTINEL_S3_TEST_PASSWORD" >/dev/null
mc admin policy create local sentinel-evidence-test /tmp/test-policy.json >/dev/null
mc admin policy attach local sentinel-evidence-test --user "$SENTINEL_S3_TEST_USER" >/dev/null
