#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Optional: uncomment if you want to be strict about unset variables
# Pipe commands fail if any command in the pipe fails
set -o pipefail

# --- Configuration ---
LITEVAULT_URL="https://localhost:8443"
ROLE_NAME="readonly-app-role"
REQUEST_TOKEN="db-access-token" # Token with permission to read db/creds/{ROLE_NAME}
REVOKE_TOKEN="dev-root-token"   # Token with permission to delete db/leases/*

DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="devdb" # Should match MSSM_DEFAULT_DB_NAME in .env

# ANSI Color Codes
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_NC='\033[0m' # No Color

# --- Helper Functions ---
log_info() {
  echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1"
}

log_success() {
  echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_NC} $1"
}

log_warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_NC} $1"
}

log_error() {
  echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1" >&2
  exit 1
}

# --- Check Prerequisites ---
if ! command -v jq &> /dev/null; then
    log_error "'jq' command could not be found. Please install jq (e.g., brew install jq)."
fi
if ! command -v psql &> /dev/null; then
    log_error "'psql' command could not be found. Please install the PostgreSQL client."
fi
if ! command -v curl &> /dev/null; then
    log_error "'curl' command could not be found. Please install curl."
fi

# --- Main Script ---
log_info "Starting dynamic credential verification cycle..."

# 1. Request Dynamic Credentials
log_info "Requesting credentials for role '${ROLE_NAME}'..."
RESPONSE=$(curl -k -s -X GET \
  -H "X-Vault-Token: ${REQUEST_TOKEN}" \
  "${LITEVAULT_URL}/v1/db/creds/${ROLE_NAME}")

# Check if curl command was successful (basic check, doesn't guarantee valid JSON)
if [ $? -ne 0 ]; then
    log_error "curl command failed to request credentials."
fi

# Parse response using jq
LEASE_ID=$(echo "${RESPONSE}" | jq -r '.leaseId')
DB_USER=$(echo "${RESPONSE}" | jq -r '.username')
DB_PASSWORD=$(echo "${RESPONSE}" | jq -r '.password')

# Validate parsed values
if [[ -z "${LEASE_ID}" || "${LEASE_ID}" == "null" ]]; then
  log_error "Failed to parse leaseId from response: ${RESPONSE}"
fi
if [[ -z "${DB_USER}" || "${DB_USER}" == "null" ]]; then
  log_error "Failed to parse username from response: ${RESPONSE}"
fi
if [[ -z "${DB_PASSWORD}" || "${DB_PASSWORD}" == "null" ]]; then
  log_error "Failed to parse password from response: ${RESPONSE}"
fi

log_success "Credentials received:"
echo "  Lease ID:   ${LEASE_ID}"
echo "  Username:   ${DB_USER}"
# Avoid printing password directly in logs for security, uncomment if needed for debugging
# echo "  Password:   ${DB_PASSWORD}"
echo "  Password:   (received)"


# 2. Verify Login with New Credentials
log_info "Attempting login with dynamic user '${DB_USER}'..."
# Use PGPASSWORD environment variable for non-interactive login
export PGPASSWORD="${DB_PASSWORD}"
if psql -h "${DB_HOST}" -p "${DB_PORT}" -d "${DB_NAME}" -U "${DB_USER}" -c "\q" >/dev/null 2>&1; then
  log_success "Login successful for dynamic user '${DB_USER}'."
else
  # Unset PGPASSWORD before erroring out
  unset PGPASSWORD
  log_error "Login FAILED for dynamic user '${DB_USER}' (This should have worked)."
fi
# Unset PGPASSWORD after use
unset PGPASSWORD


# 3. Revoke the Lease
log_info "Revoking lease '${LEASE_ID}'..."
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "X-Vault-Token: ${REVOKE_TOKEN}" \
  "${LITEVAULT_URL}/v1/db/leases/${LEASE_ID}")

if [[ "${HTTP_STATUS}" -eq 204 ]]; then
  log_success "Lease '${LEASE_ID}' successfully revoked (HTTP Status: ${HTTP_STATUS})."
elif [[ "${HTTP_STATUS}" -eq 404 ]]; then
    log_warning "Lease '${LEASE_ID}' revocation returned HTTP 404. Lease might have already expired or been revoked."
else
  log_error "Failed to revoke lease '${LEASE_ID}'. HTTP Status: ${HTTP_STATUS}."
fi


# 4. Verify Login Fails After Revocation
log_info "Attempting login again with revoked user '${DB_USER}' (expecting failure)..."
export PGPASSWORD="${DB_PASSWORD}"
# We expect this command to fail, hence the '!' negation
if ! psql -h "${DB_HOST}" -p "${DB_PORT}" -d "${DB_NAME}" -U "${DB_USER}" -c "\q" >/dev/null 2>&1; then
  log_success "Login correctly failed for revoked user '${DB_USER}'."
else
  # Unset PGPASSWORD before erroring out
  unset PGPASSWORD
  log_error "Login SUCCEEDED for revoked user '${DB_USER}' (This should have failed!)."
fi
# Unset PGPASSWORD after use
unset PGPASSWORD


# --- Completion ---
log_success "Dynamic credential verification cycle completed successfully!"
exit 0
