#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Optional: uncomment if you want to be strict about unset variables
# Pipe commands fail if any command in the pipe fails
set -o pipefail

# --- Configuration ---
LITEVAULT_URL="https://localhost:8443"
KV_BASE_PATH="/v1/kv/data"
SECRET_PATH="myapp/password-pepper" # Path under myapp/ to use app-write-token permissions

# Use a token with R/W/D permissions on the chosen SECRET_PATH
# 'app-write-token' has R/W/D on 'kv/data/myapp/*' based on application-dev.yml
ACCESS_TOKEN="app-write-token"

# Secret details
SECRET_KEY="pepper"
# Generate a random pepper value for each run
SECRET_VALUE=$(openssl rand -hex 16)

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
if ! command -v curl &> /dev/null; then
    log_error "'curl' command could not be found. Please install curl."
fi
if ! command -v openssl &> /dev/null; then
    log_error "'openssl' command could not be found. Please install OpenSSL."
fi

# --- Main Script ---
log_info "Starting KV secret verification cycle..."
log_info "Using path: ${SECRET_PATH}"
log_info "Using token: ${ACCESS_TOKEN}"
log_info "Generated Secret Value (Pepper): ${SECRET_VALUE}"

# Construct JSON payload using jq
JSON_PAYLOAD=$(jq -n --arg key "$SECRET_KEY" --arg value "$SECRET_VALUE" '{($key): $value}')
log_info "JSON Payload for PUT: ${JSON_PAYLOAD}"

# 1. Write the Secret (PUT)
log_info "Attempting to write secret..."
HTTP_STATUS_PUT=$(curl -k -s -o /dev/null -w "%{http_code}" -X PUT \
  -H "X-Vault-Token: ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${JSON_PAYLOAD}" \
  "${LITEVAULT_URL}${KV_BASE_PATH}/${SECRET_PATH}")

if [[ "${HTTP_STATUS_PUT}" -eq 204 ]]; then
  log_success "Secret successfully written (HTTP Status: ${HTTP_STATUS_PUT})."
else
  log_error "Failed to write secret. HTTP Status: ${HTTP_STATUS_PUT}."
fi

# 2. Read the Secret and Verify Content (GET)
log_info "Attempting to read secret back..."
RESPONSE_GET=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X GET \
  -H "X-Vault-Token: ${ACCESS_TOKEN}" \
  "${LITEVAULT_URL}${KV_BASE_PATH}/${SECRET_PATH}")

# Extract body and status code
HTTP_STATUS_GET=$(echo "$RESPONSE_GET" | grep "HTTP_STATUS:" | cut -d':' -f2)
RESPONSE_BODY_GET=$(echo "$RESPONSE_GET" | sed '$d') # Remove last line (status code)

if [[ "${HTTP_STATUS_GET}" -ne 200 ]]; then
    log_error "Failed to read secret. HTTP Status: ${HTTP_STATUS_GET}. Body: ${RESPONSE_BODY_GET}"
fi

# Parse the read value using jq
READ_VALUE=$(echo "${RESPONSE_BODY_GET}" | jq -r --arg key "$SECRET_KEY" '.[$key]')

if [[ -z "${READ_VALUE}" || "${READ_VALUE}" == "null" ]]; then
    log_error "Failed to parse read value for key '${SECRET_KEY}' from response: ${RESPONSE_BODY_GET}"
fi

# Verify content
if [[ "${READ_VALUE}" == "${SECRET_VALUE}" ]]; then
    log_success "Read secret successfully and content matches!"
    log_info "  Read Value: ${READ_VALUE}"
else
    log_error "Content mismatch! Expected '${SECRET_VALUE}' but got '${READ_VALUE}'."
fi

# 3. Delete the Secret (DELETE)
log_info "Attempting to delete secret..."
HTTP_STATUS_DELETE=$(curl -k -s -o /dev/null -w "%{http_code}" -X DELETE \
  -H "X-Vault-Token: ${ACCESS_TOKEN}" \
  "${LITEVAULT_URL}${KV_BASE_PATH}/${SECRET_PATH}")

if [[ "${HTTP_STATUS_DELETE}" -eq 204 ]]; then
  log_success "Secret successfully deleted (HTTP Status: ${HTTP_STATUS_DELETE})."
else
  log_error "Failed to delete secret. HTTP Status: ${HTTP_STATUS_DELETE}."
fi

# 4. Verify Deletion by Attempting to Read Again (GET)
log_info "Attempting to read secret again (expecting 404 Not Found)..."
HTTP_STATUS_GET_AFTER_DELETE=$(curl -k -s -o /dev/null -w "%{http_code}" -X GET \
  -H "X-Vault-Token: ${ACCESS_TOKEN}" \
  "${LITEVAULT_URL}${KV_BASE_PATH}/${SECRET_PATH}")

if [[ "${HTTP_STATUS_GET_AFTER_DELETE}" -eq 404 ]]; then
  log_success "Read attempt correctly failed with HTTP 404 after deletion."
else
  log_error "Read attempt after deletion returned unexpected status: ${HTTP_STATUS_GET_AFTER_DELETE} (Expected 404)."
fi

# --- Completion ---
log_success "KV secret verification cycle completed successfully!"
exit 0
