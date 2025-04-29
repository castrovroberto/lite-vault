#!/bin/bash

# lite-vault-cli.sh
# An interactive script to test basic LiteVault API features.

# --- Default Configuration ---
DEFAULT_HOST="localhost"
DEFAULT_PORT="8443"
DEFAULT_PROTOCOL="https"

# --- Helper Functions ---
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
HOST=""
PORT=""
PROTOCOL=""
BASE_URL=""
CURL_OPTS=""
VAULT_TOKEN=""
INVALID_TOKEN="invalid-dummy-token-12345"

# --- Test Statistics ---
tests_run=0
tests_passed=0
tests_failed=0
tests_skipped=0

reset_stats() {
    tests_run=0
    tests_passed=0
    tests_failed=0
    tests_skipped=0
}

# --- Core Request Function ---
# Function to make requests and check status/basic content
# Usage: make_request <METHOD> <PATH> [EXPECTED_STATUS] [TOKEN_TYPE] [JQ_QUERY] [EXPECTED_VALUE] [BODY_DATA]
# TOKEN_TYPE: "VALID", "INVALID", or "" (for none)
# Returns: 0 on pass, 1 on fail, 2 on skip
make_request() {
  local method="$1"
  local path="$2"
  local expected_status="${3:-200}"
  local token_type="$4" # "VALID", "INVALID", ""
  local jq_query="$5" # Optional: jq query string (e.g., '.status')
  local expected_value="$6" # Optional: Expected value for jq query
  local body_data="$7" # Optional: Request body data

  local url="${BASE_URL}${path}"
  local headers=()
  local curl_data_opts=()
  local test_desc="[$method $path]"
  local current_token=""

  ((tests_run++)) # Increment tests run counter

  # --- Token Handling ---
  if [[ "$token_type" == "VALID" ]]; then
    current_token="$VAULT_TOKEN"
    if [[ -z "$current_token" ]]; then
        print_warn "$test_desc - Skipping test: VALID token requested but none provided."
        ((tests_skipped++))
        return 2 # Skipped
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

  # --- Body Data Handling ---
  if [[ -n "$body_data" ]]; then
      headers+=("-H" "Content-Type: application/json")
      curl_data_opts+=("-d" "$body_data")
      test_desc="$test_desc (Body: Present)"
  fi

  print_info "Testing $test_desc - Expecting HTTP $expected_status"

  # --- Perform Request ---
  response=$(curl $CURL_OPTS -w "\nHTTP_STATUS:%{http_code}" -X "$method" "${headers[@]}" "${curl_data_opts[@]}" "$url")
  http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2)
  body=$(echo "$response" | sed '$d') # Remove last line (HTTP_STATUS)

  # --- Check Status Code ---
  if [[ "$http_status" -ne "$expected_status" ]]; then
    print_fail "$test_desc - Expected status $expected_status, got $http_status. Body: $body"
    ((tests_failed++))
    return 1 # Fail
  fi
  print_ok "$test_desc - Received expected status $http_status"

  # --- Optional JSON Check ---
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
       ((tests_failed++))
       return 1 # Fail
     fi
  elif [[ -n "$jq_query" && -n "$expected_value" ]]; then
      # jq not found, try basic check
      print_warn "$test_desc - jq not found, skipping specific JSON value check for '$jq_query'. Performing basic check."
      # Basic string check as fallback (less reliable for specific values)
      if echo "$body" | grep -q "\"$expected_value\""; then # Basic check for string value presence
          print_ok "$test_desc - Basic check passed: Body seems to contain '$expected_value'."
      else
          print_fail "$test_desc - Basic check failed: Body does not seem to contain '$expected_value'. Body: $body"
          ((tests_failed++))
          return 1 # Fail
      fi
  fi

  # If all checks passed
  ((tests_passed++))
  return 0 # Pass
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
    ((tests_run++))
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

    if [[ $result -eq 0 ]]; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo "--- Test Complete ---"
    return $result
}

test_auth_no_token() {
    print_info "--- Running Test: Authentication (No Token) ---"
    local protected_path="/v1/kv/data/auth-test/no-token"
    print_info "Attempting access to protected path: $protected_path"
    ((tests_run++))
    # Expect 401 (Unauthorized) or 403 (Forbidden)
    make_request "GET" "$protected_path" 401 "" > /dev/null # Suppress make_request output for this check
    local result=$?
    if [[ $result -ne 0 ]]; then
        print_warn "Retrying $protected_path without token, checking for 403..."
        make_request "GET" "$protected_path" 403 "" > /dev/null
        result=$?
    fi

    if [[ $result -eq 0 ]]; then
        print_ok "[GET $protected_path] (No Token) - Received expected 401 or 403 status."
        ((tests_passed++))
    else
        print_fail "[GET $protected_path] (No Token) - Access without token did not return 401 or 403."
        ((tests_failed++))
    fi
    echo "--- Test Complete ---"
    return $result
}

test_auth_invalid_token() {
    print_info "--- Running Test: Authentication (Invalid Token) ---"
    local protected_path="/v1/kv/data/auth-test/invalid-token"
    print_info "Attempting access to protected path: $protected_path"
    ((tests_run++))
    # Expect 403 (Forbidden) or 401 (Unauthorized)
    make_request "GET" "$protected_path" 403 "INVALID" > /dev/null
    local result=$?
     if [[ $result -ne 0 ]]; then
        print_warn "Retrying $protected_path with invalid token, checking for 401..."
        make_request "GET" "$protected_path" 401 "INVALID" > /dev/null
        result=$?
    fi

    if [[ $result -eq 0 ]]; then
        print_ok "[GET $protected_path] (Invalid Token) - Received expected 403 or 401 status."
        ((tests_passed++))
    else
        print_fail "[GET $protected_path] (Invalid Token) - Access with invalid token did not return 403 or 401."
        ((tests_failed++))
    fi
    echo "--- Test Complete ---"
    return $result
}

test_auth_valid_token() {
    print_info "--- Running Test: Authentication (Valid Token) ---"
    local protected_path="/v1/kv/data/auth-test/valid-token"
    print_info "Attempting access to protected path: $protected_path"
    # Expect 404 Not Found because the path doesn't exist, but auth should pass
    # make_request handles the skip if token is missing and increments stats
    make_request "GET" "$protected_path" 404 "VALID"
    local result=$?
    echo "--- Test Complete ---"
    return $result
}

# --- NEW KV CRUD Test Function ---
test_kv_crud() {
    print_info "--- Running Test: KV CRUD Operations ---"
    local test_path="/v1/kv/data/test/cli/secret1"
    # Ensure JSON is properly quoted for the shell
    local test_data='{"user":"test-user","pass":"s3cr3t!","value":"123"}'
    local overall_result=0

    # 1. Write Secret (Valid Token) - Expect 204
    print_info "Step 1: Writing secret to $test_path"
    make_request "PUT" "$test_path" 204 "VALID" "" "" "$test_data" || { overall_result=1; echo "--- Test Failed ---"; return 1; }

    # 2. Read Secret (Valid Token) - Expect 200 and check content
    print_info "Step 2: Reading secret from $test_path"
    make_request "GET" "$test_path" 200 "VALID" '.user' 'test-user' || { overall_result=1; echo "--- Test Failed ---"; return 1; }
    make_request "GET" "$test_path" 200 "VALID" '.pass' 's3cr3t!' || { overall_result=1; echo "--- Test Failed ---"; return 1; }

    # 3. Delete Secret (Valid Token) - Expect 204
    print_info "Step 3: Deleting secret from $test_path"
    make_request "DELETE" "$test_path" 204 "VALID" || { overall_result=1; echo "--- Test Failed ---"; return 1; }

    # 4. Read Secret After Delete (Valid Token) - Expect 404
    print_info "Step 4: Reading secret after delete from $test_path"
    make_request "GET" "$test_path" 404 "VALID" || { overall_result=1; echo "--- Test Failed ---"; return 1; }

    # 5. Attempt Write (No Token) - Expect 401 or 403
    print_info "Step 5: Attempting write with NO token to $test_path"
    ((tests_run++)) # Manual increment for this specific auth check
    make_request "PUT" "$test_path" 401 "" "" "" "$test_data" > /dev/null
    local result_no_token=$?
    if [[ $result_no_token -ne 0 ]]; then
        make_request "PUT" "$test_path" 403 "" "" "" "$test_data" > /dev/null
        result_no_token=$?
    fi
    if [[ $result_no_token -eq 0 ]]; then
        print_ok "[PUT $test_path] (No Token) - Received expected 401 or 403 status."
        ((tests_passed++))
    else
        print_fail "[PUT $test_path] (No Token) - Write without token did not return 401 or 403."
        ((tests_failed++))
        overall_result=1
    fi

    # 6. Attempt Read (Invalid Token) - Expect 401 or 403
    print_info "Step 6: Attempting read with INVALID token from $test_path"
    ((tests_run++)) # Manual increment
    make_request "GET" "$test_path" 403 "INVALID" > /dev/null
    local result_invalid_token=$?
    if [[ $result_invalid_token -ne 0 ]]; then
        make_request "GET" "$test_path" 401 "INVALID" > /dev/null
        result_invalid_token=$?
    fi
     if [[ $result_invalid_token -eq 0 ]]; then
        print_ok "[GET $test_path] (Invalid Token) - Received expected 403 or 401 status."
        ((tests_passed++))
    else
        print_fail "[GET $test_path] (Invalid Token) - Read with invalid token did not return 403 or 401."
        ((tests_failed++))
        overall_result=1
    fi

    # If we got here and overall_result is still 0, the main sequence passed
    if [[ $overall_result -eq 0 ]]; then
        print_ok "KV CRUD sequence completed successfully."
    fi

    echo "--- Test Complete ---"
    return $overall_result
}


run_all_tests() {
    print_info "*** Running ALL Available Tests ***"
    reset_stats # Reset counters before running all tests
    local overall_result=0

    test_root_endpoint || overall_result=1
    test_seal_status || overall_result=1
    test_auth_no_token || overall_result=1
    test_auth_invalid_token || overall_result=1
    test_auth_valid_token # Don't fail script if token wasn't provided
    test_kv_crud || overall_result=1 # Run the new KV tests

    echo # Extra newline
    print_info "*** Test Summary ***"
    print_info "Total Tests Run:    $tests_run"
    print_ok   "Tests Passed:     $tests_passed"
    print_fail "Tests Failed:     $tests_failed"
    print_warn "Tests Skipped:    $tests_skipped"
    echo

    if [[ $tests_failed -eq 0 ]]; then
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
HOST=${HOST:-$DEFAULT_HOST}

read -p "Enter Port [$DEFAULT_PORT]: " PORT
PORT=${PORT:-$DEFAULT_PORT}

read -p "Enter Protocol (http/https) [$DEFAULT_PROTOCOL]: " PROTOCOL
PROTOCOL=${PROTOCOL:-$DEFAULT_PROTOCOL}

BASE_URL="${PROTOCOL}://${HOST}:${PORT}"
CURL_OPTS="-s"

if [[ "$PROTOCOL" == "https" ]]; then
    read -p "Use insecure flag (-k) for self-signed certs? (y/N): " insecure_choice
    if [[ "$insecure_choice" =~ ^[Yy]$ ]]; then
        CURL_OPTS="-k -s"
        print_warn "Using curl with -k (insecure) flag for testing."
    else
        CURL_OPTS="-s"
    fi
else
    CURL_OPTS="-s"
fi

echo
read -sp "Enter VALID Vault Token (X-Vault-Token) if required, otherwise leave blank: " VAULT_TOKEN
echo
if [[ -z "$VAULT_TOKEN" ]]; then
    print_warn "No VALID Vault Token provided. Tests requiring a valid token will be skipped or may fail if auth is enabled."
else
    print_info "Valid Vault Token provided."
fi
echo

if ! jq_exists; then
    print_warn "jq command not found. JSON validation will be basic string checks."
fi
echo

# 2. Display Menu and Run Tests
print_info "Target Vault: ${BASE_URL}"
echo

PS3=$'\n'"Select an option: "
options=(
    "Test Root Endpoint (/)"
    "Test Seal Status (/sys/seal-status)"
    "Test Auth - No Token (Protected Path)"
    "Test Auth - Invalid Token (Protected Path)"
    "Test Auth - Valid Token (Protected Path)"
    "Test KV CRUD Operations" # <-- New Option
    "Run All Tests"
    "Reconfigure Connection"
    "Quit"
)

while true; do
    select opt in "${options[@]}"; do
        case $opt in
            "Test Root Endpoint (/)")
                reset_stats; test_root_endpoint; print_info "Ran 1 test group."
                break
                ;;
            "Test Seal Status (/sys/seal-status)")
                reset_stats; test_seal_status; print_info "Ran 1 test group."
                break
                ;;
            "Test Auth - No Token (Protected Path)")
                reset_stats; test_auth_no_token; print_info "Ran 1 test group."
                break
                ;;
            "Test Auth - Invalid Token (Protected Path)")
                reset_stats; test_auth_invalid_token; print_info "Ran 1 test group."
                break
                ;;
            "Test Auth - Valid Token (Protected Path)")
                reset_stats; test_auth_valid_token; print_info "Ran 1 test group."
                break
                ;;
            "Test KV CRUD Operations") # <-- New Case
                reset_stats; test_kv_crud; print_info "Ran 1 test group."
                break
                ;;
            "Run All Tests")
                run_all_tests # This function already handles stats and summary
                break
                ;;
            "Reconfigure Connection")
                print_info "Please restart the script to reconfigure."
                break
                ;;
            "Quit")
                print_info "Exiting."
                exit 0
                ;;
            *)
                echo "Invalid option $REPLY. Please try again."
                ;;
        esac
    done
done
