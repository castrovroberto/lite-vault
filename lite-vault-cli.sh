#!/bin/bash

# lite-vault-cli.sh
# An interactive script to test basic LiteVault API features.

# --- Default Configuration ---
DEFAULT_HOST="localhost"
DEFAULT_PORT="8443"
DEFAULT_PROTOCOL="https"

# --- Helper Functions ---
# (Keep the existing jq_exists, color functions: print_info, print_ok, print_fail, print_warn)
# Check if jq is installed
jq_exists() {
  command -v jq >/dev/null 2>&1
}

# Colors for output
COLOR_RESET='\033[0m'
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'

print_info() {
  echo -e "${COLOR_BLUE}INFO: $1${COLOR_RESET}"
}

print_ok() {
  echo -e "${COLOR_GREEN}OK:   $1${COLOR_RESET}"
}

print_fail() {
  echo -e "${COLOR_RED}FAIL: $1${COLOR_RESET}"
}

print_warn() {
  echo -e "${COLOR_YELLOW}WARN: $1${COLOR_RESET}"
}


# --- Global Variables ---
# These will be set by user input later
HOST=""
PORT=""
PROTOCOL=""
BASE_URL=""
CURL_OPTS=""
VAULT_TOKEN=""
INVALID_TOKEN="invalid-dummy-token-12345" # Keep this hardcoded for testing invalid case

# --- Core Request Function ---
# (Keep the existing make_request function - it's called by the test functions)
# Function to make requests and check status/basic content
# Usage: make_request <METHOD> <PATH> [EXPECTED_STATUS] [AUTH_TOKEN] [EXPECTED_JSON_QUERY (jq)] [EXPECTED_VALUE]
make_request() {
  local method="$1"
  local path="$2"
  local expected_status="${3:-200}"
  local token_type="$4" # Changed: Pass "VALID", "INVALID", or "" (for none)
  local jq_query="$5" # Optional: jq query string (e.g., '.status')
  local expected_value="$6" # Optional: Expected value for jq query

  local url="${BASE_URL}${path}"
  local headers=()
  local test_desc="[$method $path]"
  local current_token=""

  if [[ "$token_type" == "VALID" ]]; then
    current_token="$VAULT_TOKEN"
    if [[ -z "$current_token" ]]; then
        print_warn "$test_desc - Skipping test: VALID token requested but none provided."
        return 2 # Use a different return code for skipped
    fi
    headers+=("-H" "X-Vault-Token: $current_token")
    test_desc="$test_desc (Token: VALID)"
  elif [[ "$token_type" == "INVALID" ]]; then
      current_token="$INVALID_TOKEN"
      headers+=("-H" "X-Vault-Token: $current_token")
      test_desc="$test_desc (Token: INVALID)"
  else
      test_desc="$test_desc (Token: NONE)"
  fi

  print_info "Testing $test_desc - Expecting HTTP $expected_status"

  # Perform the request, capture status code and body
  # Use the globally set CURL_OPTS
  response=$(curl $CURL_OPTS -w "\nHTTP_STATUS:%{http_code}" -X "$method" "${headers[@]}" "$url")
  http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2)
  body=$(echo "$response" | sed '$d') # Remove last line (HTTP_STATUS)

  # Check Status Code
  if [[ "$http_status" -ne "$expected_status" ]]; then
    print_fail "$test_desc - Expected status $expected_status, got $http_status. Body: $body"
    return 1
  fi
  print_ok "$test_desc - Received expected status $http_status"

  # Optional JSON Check (if jq exists and query provided)
  if jq_exists && [[ -n "$jq_query" && -n "$expected_value" ]]; then
     actual_value=$(echo "$body" | jq -r "$jq_query" 2>/dev/null)
     # Handle null from jq which results in empty string
     if [[ -z "$actual_value" && "$expected_value" == "null" ]]; then
         actual_value="null" # Treat empty string as null if expected is null
     fi

     if [[ "$actual_value" == "$expected_value" ]]; then
       print_ok "$test_desc - JSON check passed: '$jq_query' is '$actual_value'."
     else
       # Check if jq failed to parse (e.g. non-json response)
       if ! echo "$body" | jq -e . > /dev/null 2>&1 && [[ -n "$body" ]]; then
            print_fail "$test_desc - JSON check failed: Response is not valid JSON. Body: $body"
       else
            print_fail "$test_desc - JSON check failed: Expected '$jq_query' to be '$expected_value', got '$actual_value'. Body: $body"
       fi
       return 1
     fi
  elif [[ -n "$jq_query" && -n "$expected_value" ]]; then
      print_warn "$test_desc - jq not found, skipping JSON value check for '$jq_query'."
      # Basic string check as fallback (less reliable for specific values)
      # Be careful with boolean/numeric values here
      if echo "$body" | grep -q "\"$expected_value\""; then # Basic check for string value presence
          print_ok "$test_desc - Basic check passed: Body seems to contain '$expected_value'."
      else
          print_fail "$test_desc - Basic check failed: Body does not seem to contain '$expected_value'. Body: $body"
          return 1
      fi
  fi

  return 0
}


# --- Individual Test Functions ---

test_root_endpoint() {
    print_info "--- Running Test: Root Endpoint (Public) ---"
    make_request "GET" "/" 200 "" '.message' "Welcome to LiteVault API"
    local result=$?
    echo "--- Test Complete ---"
    return $result
}

test_seal_status() {
    print_info "--- Running Test: Seal Status Endpoint (Public) ---"
    print_info "Testing [GET /sys/seal-status] - Expecting HTTP 200 and valid JSON"
    # We need to call curl directly here or adapt make_request to handle checks without specific expected values
    local url="${BASE_URL}/sys/seal-status"
    response=$(curl $CURL_OPTS -w "\nHTTP_STATUS:%{http_code}" -X GET "$url")
    http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2)
    body=$(echo "$response" | sed '$d')
    local result=0

    if [[ "$http_status" -ne 200 ]]; then
      print_fail "[GET /sys/seal-status] - Expected status 200, got $http_status. Body: $body"
      result=1
    else
      print_ok "[GET /sys/seal-status] - Received expected status 200"
      if jq_exists; then
        seal_status=$(echo "$body" | jq -r '.sealed' 2>/dev/null)
        if [[ "$seal_status" == "true" || "$seal_status" == "false" ]]; then
          print_ok "[GET /sys/seal-status] - JSON check passed: '.sealed' is '$seal_status'."
        else
          print_fail "[GET /sys/seal-status] - JSON check failed: Key '.sealed' not found or invalid value. Body: $body"
          result=1
        fi
      else
        print_warn "[GET /sys/seal-status] - jq not found, performing basic check."
        if echo "$body" | grep -q '"sealed":'; then
            print_ok "[GET /sys/seal-status] - Basic check passed: Body contains '\"sealed\":'."
        else
            print_fail "[GET /sys/seal-status] - Basic check failed: Body does not contain '\"sealed\":'. Body: $body"
            result=1
        fi
      fi
    fi
    echo "--- Test Complete ---"
    return $result
}

test_auth_no_token() {
    print_info "--- Running Test: Authentication (No Token) ---"
    local protected_path="/v1/kv/some/nonexistent/path" # Using a hypothetical protected path
    print_info "Attempting access to protected path: $protected_path"
    # Expect 401 (Unauthorized) or 403 (Forbidden) depending on Spring Security config
    make_request "GET" "$protected_path" 401 ""
    local result=$?
    if [[ $result -ne 0 ]]; then
        print_warn "Retrying $protected_path without token, checking for 403..."
        make_request "GET" "$protected_path" 403 ""
        result=$?
        if [[ $result -ne 0 ]]; then
             print_fail "Access without token did not return 401 or 403."
        fi
    fi
    echo "--- Test Complete ---"
    return $result
}

test_auth_invalid_token() {
    print_info "--- Running Test: Authentication (Invalid Token) ---"
    local protected_path="/v1/kv/some/nonexistent/path"
    print_info "Attempting access to protected path: $protected_path"
    # Expect 403 (Forbidden) or 401 (Unauthorized)
    make_request "GET" "$protected_path" 403 "INVALID"
    local result=$?
     if [[ $result -ne 0 ]]; then
        print_warn "Retrying $protected_path with invalid token, checking for 401..."
        make_request "GET" "$protected_path" 401 "INVALID"
        result=$?
        if [[ $result -ne 0 ]]; then
             print_fail "Access with invalid token did not return 403 or 401."
        fi
    fi
    echo "--- Test Complete ---"
    return $result
}

test_auth_valid_token() {
    print_info "--- Running Test: Authentication (Valid Token) ---"
    local protected_path="/v1/kv/some/nonexistent/path"
    print_info "Attempting access to protected path: $protected_path"
    # Expect 404 Not Found because the path doesn't exist, but auth should pass
    make_request "GET" "$protected_path" 404 "VALID"
    local result=$?
    # make_request already handles the warning if token is missing
    echo "--- Test Complete ---"
    return $result
}

run_all_tests() {
    print_info "*** Running ALL Available Tests ***"
    local overall_result=0
    test_root_endpoint || overall_result=1
    test_seal_status || overall_result=1
    test_auth_no_token || overall_result=1
    test_auth_invalid_token || overall_result=1
    test_auth_valid_token # Don't fail script if token wasn't provided (make_request handles skip)

    echo # Extra newline
    if [[ $overall_result -eq 0 ]]; then
        print_ok "*** ALL Tests Passed (or skipped gracefully) ***"
    else
        print_fail "*** Some Tests FAILED ***"
    fi
    return $overall_result
}


# --- Main Execution ---

clear
print_info "Welcome to the Interactive LiteVault API Tester"
echo

# 1. Get Configuration from User
print_info "Please enter connection details:"
read -p "Enter Host [$DEFAULT_HOST]: " HOST
HOST=${HOST:-$DEFAULT_HOST} # Use default if input is empty

read -p "Enter Port [$DEFAULT_PORT]: " PORT
PORT=${PORT:-$DEFAULT_PORT}

read -p "Enter Protocol (http/https) [$DEFAULT_PROTOCOL]: " PROTOCOL
PROTOCOL=${PROTOCOL:-$DEFAULT_PROTOCOL}

BASE_URL="${PROTOCOL}://${HOST}:${PORT}"
CURL_OPTS="-s" # Start with silent

if [[ "$PROTOCOL" == "https" ]]; then
    read -p "Use insecure flag (-k) for self-signed certs? (y/N): " insecure_choice
    if [[ "$insecure_choice" =~ ^[Yy]$ ]]; then
        CURL_OPTS="-k -s"
        print_warn "Using curl with -k (insecure) flag for testing."
    else
        CURL_OPTS="-s"
    fi
else
    CURL_OPTS="-s" # No -k needed for http
fi

echo # Newline
read -sp "Enter VALID Vault Token (X-Vault-Token) if required, otherwise leave blank: " VAULT_TOKEN
echo # Add a newline after secret input
if [[ -z "$VAULT_TOKEN" ]]; then
    print_warn "No VALID Vault Token provided. Tests requiring a valid token will be skipped or may fail if auth is enabled."
else
    print_info "Valid Vault Token provided."
fi
echo

# Check for jq
if ! jq_exists; then
    print_warn "jq command not found. JSON validation will be basic string checks."
fi
echo

# 2. Display Menu and Run Tests
print_info "Target Vault: ${BASE_URL}"
echo

PS3=$'\n'"Select an option: " # Prompt for the select command
options=(
    "Test Root Endpoint (/)"
    "Test Seal Status (/sys/seal-status)"
    "Test Auth - No Token (Protected Path)"
    "Test Auth - Invalid Token (Protected Path)"
    "Test Auth - Valid Token (Protected Path)"
    "Run All Tests"
    "Reconfigure Connection"
    "Quit"
)

while true; do
    select opt in "${options[@]}"; do
        case $opt in
            "Test Root Endpoint (/)")
                test_root_endpoint
                break # Break inner select loop, outer while loop continues
                ;;
            "Test Seal Status (/sys/seal-status)")
                test_seal_status
                break
                ;;
            "Test Auth - No Token (Protected Path)")
                test_auth_no_token
                break
                ;;
            "Test Auth - Invalid Token (Protected Path)")
                test_auth_invalid_token
                break
                ;;
            "Test Auth - Valid Token (Protected Path)")
                test_auth_valid_token
                break
                ;;
            "Run All Tests")
                run_all_tests
                break
                ;;
            "Reconfigure Connection")
                # Jump back to the configuration section - easiest way is to exit and suggest re-running
                # Or we could wrap the config part in a function and call it again.
                # For simplicity here, let's just inform the user.
                # A more complex script might use functions heavily.
                print_info "Please restart the script to reconfigure."
                # Alternatively, wrap config section in function and call here.
                break
                ;;
            "Quit")
                print_info "Exiting."
                exit 0
                ;;
            *)
                echo "Invalid option $REPLY. Please try again."
                # No break here, PS3 prompt will redisplay
                ;;
        esac
    done
    # After a test runs (or invalid input), the menu prompt (PS3) will show again
    # because the 'select' command loops internally until 'break' or 'exit'.
done
