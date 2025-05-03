#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Optional: uncomment if you want to be strict about unset variables
# Pipe commands fail if any command in the pipe fails
set -o pipefail

# --- Configuration ---
LITEVAULT_URL="https://localhost:8443"
JWT_BASE_PATH="/v1/jwt"

# Key name for signing and initial JWKS retrieval (must match application-dev.yml and policy)
SIGNING_KEY_NAME="api-signing-key-rsa"
# Token with permission to sign using SIGNING_KEY_NAME (jwt-signing-app-token has jwt/sign/api-signing-key-rsa)
SIGN_TOKEN="jwt-signing-app-token"

# Key name for rotation testing (must match application-dev.yml and policy)
ROTATION_KEY_NAME="internal-service-key-ec"
# Token with permission to rotate keys (dev-root-token has jwt/rotate/*)
ROTATE_TOKEN="dev-root-token"

# Sample claims for the JWT
JWT_CLAIMS=$(cat <<EOF
{
  "sub": "test-user-123",
  "iss": "lite-vault-test-script",
  "aud": "test-api",
  "exp": $(($(date +%s) + 3600)),
  "iat": $(date +%s),
  "customData": {
    "role": "tester",
    "verified": true
  }
}
EOF
)

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
if ! command -v date &> /dev/null; then
    log_error "'date' command could not be found (required for JWT expiry)."
fi


# --- Main Script ---
log_info "Starting JWT lifecycle verification..."

# 1. Sign a JWT (POST /sign/{keyName})
log_info "Attempting to sign JWT using key '${SIGNING_KEY_NAME}'..."
SIGN_RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
  -H "X-Vault-Token: ${SIGN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${JWT_CLAIMS}" \
  "${LITEVAULT_URL}${JWT_BASE_PATH}/sign/${SIGNING_KEY_NAME}")

# Extract body and status code
HTTP_STATUS_SIGN=$(echo "$SIGN_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
RESPONSE_BODY_SIGN=$(echo "$SIGN_RESPONSE" | sed '$d') # Remove last line (status code)

if [[ "${HTTP_STATUS_SIGN}" -ne 200 ]]; then
    log_error "Failed to sign JWT. HTTP Status: ${HTTP_STATUS_SIGN}. Body: ${RESPONSE_BODY_SIGN}"
fi

# Parse the signed JWT
SIGNED_JWT=$(echo "${RESPONSE_BODY_SIGN}" | jq -r '.jwt')

if [[ -z "${SIGNED_JWT}" || "${SIGNED_JWT}" == "null" ]]; then
    log_error "Failed to parse signed JWT from response: ${RESPONSE_BODY_SIGN}"
fi

log_success "JWT signed successfully using key '${SIGNING_KEY_NAME}'."
log_info "  Signed JWT: ${SIGNED_JWT:0:30}..." # Show beginning of JWT


# 2. Get JWKS for the signing key (GET /jwks/{keyName}) - Public Endpoint
log_info "Attempting to retrieve JWKS for signing key '${SIGNING_KEY_NAME}' (public)..."
JWKS_SIGN_RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X GET \
  "${LITEVAULT_URL}${JWT_BASE_PATH}/jwks/${SIGNING_KEY_NAME}")

# Extract body and status code
HTTP_STATUS_JWKS_SIGN=$(echo "$JWKS_SIGN_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
RESPONSE_BODY_JWKS_SIGN=$(echo "$JWKS_SIGN_RESPONSE" | sed '$d')

if [[ "${HTTP_STATUS_JWKS_SIGN}" -ne 200 ]]; then
    log_error "Failed to retrieve JWKS for signing key '${SIGNING_KEY_NAME}'. HTTP Status: ${HTTP_STATUS_JWKS_SIGN}. Body: ${RESPONSE_BODY_JWKS_SIGN}"
fi

# Basic validation: Check if response is valid JSON and has a 'keys' array
if ! echo "${RESPONSE_BODY_JWKS_SIGN}" | jq -e '.keys | type == "array"' > /dev/null; then
     log_error "Retrieved JWKS for signing key '${SIGNING_KEY_NAME}' is not valid JSON or missing 'keys' array: ${RESPONSE_BODY_JWKS_SIGN}"
fi

log_success "JWKS for signing key '${SIGNING_KEY_NAME}' retrieved successfully."
log_info "  JWKS Response (first key): $(echo "${RESPONSE_BODY_JWKS_SIGN}" | jq -c '.keys[0]')"


# 3. Get JWKS for the rotation key BEFORE rotation (GET /jwks/{keyName})
log_info "Attempting to retrieve JWKS for rotation key '${ROTATION_KEY_NAME}' BEFORE rotation..."
JWKS_BEFORE_RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X GET \
  "${LITEVAULT_URL}${JWT_BASE_PATH}/jwks/${ROTATION_KEY_NAME}")

HTTP_STATUS_JWKS_BEFORE=$(echo "$JWKS_BEFORE_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
RESPONSE_BODY_JWKS_BEFORE=$(echo "$JWKS_BEFORE_RESPONSE" | sed '$d')

if [[ "${HTTP_STATUS_JWKS_BEFORE}" -ne 200 ]]; then
    log_error "Failed to retrieve JWKS for rotation key '${ROTATION_KEY_NAME}' before rotation. HTTP Status: ${HTTP_STATUS_JWKS_BEFORE}. Body: ${RESPONSE_BODY_JWKS_BEFORE}"
fi

# Extract the Key ID (kid) from the first key in the set
KID_BEFORE=$(echo "${RESPONSE_BODY_JWKS_BEFORE}" | jq -r '.keys[0].kid')
if [[ -z "${KID_BEFORE}" || "${KID_BEFORE}" == "null" ]]; then
    log_error "Failed to parse 'kid' from JWKS before rotation: ${RESPONSE_BODY_JWKS_BEFORE}"
fi
log_success "JWKS for rotation key '${ROTATION_KEY_NAME}' retrieved successfully before rotation."
log_info "  Key ID (kid) before rotation: ${KID_BEFORE}"


# 4. Rotate the Key (POST /rotate/{keyName})
log_info "Attempting to rotate key '${ROTATION_KEY_NAME}'..."
HTTP_STATUS_ROTATE=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST \
  -H "X-Vault-Token: ${ROTATE_TOKEN}" \
  "${LITEVAULT_URL}${JWT_BASE_PATH}/rotate/${ROTATION_KEY_NAME}")

if [[ "${HTTP_STATUS_ROTATE}" -eq 204 ]]; then
  log_success "Key '${ROTATION_KEY_NAME}' rotation request successful (HTTP Status: ${HTTP_STATUS_ROTATE})."
else
  log_error "Failed to rotate key '${ROTATION_KEY_NAME}'. HTTP Status: ${HTTP_STATUS_ROTATE}."
fi

# Add a small delay to allow rotation process potentially finish if asynchronous (adjust if needed)
log_info "Waiting briefly after rotation request..."
sleep 2


# 5. Get JWKS for the rotation key AFTER rotation (GET /jwks/{keyName})
log_info "Attempting to retrieve JWKS for rotation key '${ROTATION_KEY_NAME}' AFTER rotation..."
JWKS_AFTER_RESPONSE=$(curl -k -s -w "\nHTTP_STATUS:%{http_code}" -X GET \
  "${LITEVAULT_URL}${JWT_BASE_PATH}/jwks/${ROTATION_KEY_NAME}")

HTTP_STATUS_JWKS_AFTER=$(echo "$JWKS_AFTER_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
RESPONSE_BODY_JWKS_AFTER=$(echo "$JWKS_AFTER_RESPONSE" | sed '$d')

if [[ "${HTTP_STATUS_JWKS_AFTER}" -ne 200 ]]; then
    log_error "Failed to retrieve JWKS for rotation key '${ROTATION_KEY_NAME}' after rotation. HTTP Status: ${HTTP_STATUS_JWKS_AFTER}. Body: ${RESPONSE_BODY_JWKS_AFTER}"
fi

# Extract the new Key ID (kid)
KID_AFTER=$(echo "${RESPONSE_BODY_JWKS_AFTER}" | jq -r '.keys[0].kid')
if [[ -z "${KID_AFTER}" || "${KID_AFTER}" == "null" ]]; then
    log_error "Failed to parse 'kid' from JWKS after rotation: ${RESPONSE_BODY_JWKS_AFTER}"
fi
log_success "JWKS for rotation key '${ROTATION_KEY_NAME}' retrieved successfully after rotation."
log_info "  Key ID (kid) after rotation: ${KID_AFTER}"


# 6. Verify Key ID Changed
log_info "Verifying if Key ID (kid) changed after rotation..."
if [[ "${KID_BEFORE}" != "${KID_AFTER}" ]]; then
    log_success "Key ID successfully changed after rotation ('${KID_BEFORE}' -> '${KID_AFTER}')."
else
    log_error "Key ID DID NOT change after rotation! Expected different kid, but got '${KID_AFTER}' both times."
fi


# --- Completion ---
log_success "JWT lifecycle verification cycle completed successfully!"
exit 0
