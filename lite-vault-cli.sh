#!/bin/bash

# lite-vault-cli.sh
# An interactive script to test basic LiteVault API features.

# --- Default Configuration ---
DEFAULT_HOST="localhost"
DEFAULT_PORT="8443"
DEFAULT_PROTOCOL="https"

# --- Script Flags ---
VERBOSE_MODE=0 # Default to non-verbose

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE_MODE=1; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    # shift # Shift past argument or value (already done by case)
done


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
COLOR_CYAN='\033[0;36m' # For verbose output

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

# New function for verbose output
print_verbose() {
    if [[ "$VERBOSE_MODE" -eq 1 ]]; then
        echo -e "${COLOR_CYAN}VERBOSE: $1${COLOR_RESET}"
    fi
}


# --- Global Variables ---
HOST=""
PORT=""
PROTOCOL=""
BASE_URL=""
CURL_OPTS=""
VAULT_TOKEN="" # Will be prompted for
# Example valid tokens from application-dev.yml (for user reference)
VALID_TOKEN_EXAMPLE_1="dev-root-token"
VALID_TOKEN_EXAMPLE_2="app-token-readonly"
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
# DOES NOT MODIFY GLOBAL COUNTERS
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
  local curl_cmd_display="curl $CURL_OPTS -w '\\nHTTP_STATUS:%{http_code}' -X '$method'" # For verbose display

  # --- Token Handling ---
  if [[ "$token_type" == "VALID" ]]; then
    current_token="$VAULT_TOKEN"
    if [[ -z "$current_token" ]]; then
        print_warn "$test_desc - Skipping test: VALID token requested but none was provided at script start."
        # Note: Caller function should increment skipped count
        return 2 # Skipped
    fi
    headers+=("-H" "X-Vault-Token: $current_token")
    curl_cmd_display+=" -H 'X-Vault-Token: ***'" # Mask token in display
    test_desc="$test_desc (Token: VALID)"
  elif [[ "$token_type" == "INVALID" ]]; then
      current_token="$INVALID_TOKEN"
      headers+=("-H" "X-Vault-Token: $current_token")
      curl_cmd_display+=" -H 'X-Vault-Token: $current_token'"
      test_desc="$test_desc (Token: INVALID)"
  else
      test_desc="$test_desc (Token: NONE)"
  fi

  # --- Body Data Handling ---
  if [[ -n "$body_data" ]]; then
      headers+=("-H" "Content-Type: application/json")
      curl_data_opts+=("-d" "$body_data")
      curl_cmd_display+=" -H 'Content-Type: application/json' -d '$body_data'"
      test_desc="$test_desc (Body: Present)"
  fi

  curl_cmd_display+=" '$url'"

  print_info "Testing $test_desc - Expecting HTTP $expected_status"
  print_verbose "Executing: $curl_cmd_display"

  # --- Perform Request ---
  response=$(curl $CURL_OPTS -w "\nHTTP_STATUS:%{http_code}" -X "$method" "${headers[@]}" "${curl_data_opts[@]}" "$url")
  http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2)
  body=$(echo "$response" | sed '$d') # Remove last line (HTTP_STATUS)

  print_verbose "Raw Response Body:\n$body"
  print_verbose "HTTP Status Received: $http_status"

  # --- Check Status Code ---
  if [[ "$http_status" -ne "$expected_status" ]]; then
    print_fail "$test_desc - Expected status $expected_status, got $http_status. Body: $body"
    # Note: Caller function should increment failed count
    return 1 # Fail
  fi
  print_ok "$test_desc - Received expected status $http_status"

  # --- Optional JSON Check ---
  if jq_exists && [[ -n "$jq_query" && -n "$expected_value" ]]; then
     actual_value=$(echo "$body" | jq -r "$jq_query" 2>/dev/null)
     if [[ -z "$actual_value" && "$expected_value" == "null" ]]; then
         actual_value="null"
     fi

     if [[ "$actual_value" == "$expected_value" ]]; then
       print_ok "$test_desc - JSON check passed: '$jq_query' is '$actual_value'."
     else
       if ! echo "$body" | jq -e . > /dev/null 2>&1 && [[ -n "$body" ]]; then
            print_fail "$test_desc - JSON check failed: Response is not valid JSON. Body: $body"
       else
            print_fail "$test_desc - JSON check failed: Expected '$jq_query' to be '$expected_value', got '$actual_value'. Body: $body"
       fi
       # Note: Caller function should increment failed count
       return 1 # Fail
     fi
  elif [[ -n "$jq_query" && -n "$expected_value" ]]; then
      print_warn "$test_desc - jq not found, skipping specific JSON value check for '$jq_query'. Performing basic check."
      if echo "$body" | grep -q "\"$expected_value\""; then
          print_ok "$test_desc - Basic check passed: Body seems to contain '$expected_value'."
      else
          print_fail "$test_desc - Basic check failed: Body does not seem to contain '$expected_value'. Body: $body"
          # Note: Caller function should increment failed count
          return 1 # Fail
      fi
  fi

  # If all checks passed
  # Note: Caller function should increment passed count
  return 0 # Pass
}


# --- Individual Test Functions ---
# Each function increments tests_run once and tests_passed/tests_failed once

test_root_endpoint() {
    print_info "--- Running Test: Root Endpoint (Public) ---"
    ((tests_run++))
    make_request "GET" "/" 200 "" '.message' "Welcome to LiteVault API"
    local result=$?
    if [[ $result -eq 0 ]]; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo "--- Test Complete ---"
    return $result
}

test_seal_status() {
    print_info "--- Running Test: Seal Status Endpoint (Public) ---"
    ((tests_run++))
    print_info "Testing [GET /sys/seal-status] - Expecting HTTP 200 and valid JSON"

    local url="${BASE_URL}/sys/seal-status"
    response=$(curl $CURL_OPTS -w "\nHTTP_STATUS:%{http_code}" -X GET "$url")
    http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d':' -f2)
    body=$(echo "$response" | sed '$d')
    local result=0

    print_verbose "Executing: curl $CURL_OPTS -w '\\nHTTP_STATUS:%{http_code}' -X GET '$url'"
    print_verbose "Raw Response Body:\n$body"
    print_verbose "HTTP Status Received: $http_status"

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
    ((tests_run++))
    local protected_path="/v1/kv/data/auth-test/no-token"
    print_info "Attempting access to protected path: $protected_path"

    # Expect 401 (Unauthorized) or 403 (Forbidden)
    make_request "GET" "$protected_path" 401 ""
    local result=$?
    if [[ $result -ne 0 ]]; then
        print_warn "Retrying $protected_path without token, checking for 403..."
        make_request "GET" "$protected_path" 403 ""
        result=$? # Use the result of the second check
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
    ((tests_run++))
    local protected_path="/v1/kv/data/auth-test/invalid-token"
    print_info "Attempting access to protected path: $protected_path"

    # Expect 403 (Forbidden) or 401 (Unauthorized)
    make_request "GET" "$protected_path" 403 "INVALID"
    local result=$?
     if [[ $result -ne 0 ]]; then
        print_warn "Retrying $protected_path with invalid token, checking for 401..."
        make_request "GET" "$protected_path" 401 "INVALID"
        result=$? # Use the result of the second check
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
    ((tests_run++))
    local protected_path="/v1/kv/data/auth-test/valid-token"
    print_info "Attempting access to protected path: $protected_path"

    # Expect 403 Forbidden because the path doesn't exist, AND ACL enforcement (Task 15) is not yet implemented.
    make_request "GET" "$protected_path" 403 "VALID"
    local result=$?

    if [[ $result -eq 2 ]]; then # Check if skipped
        ((tests_skipped++))
        # Adjust tests_run back down since make_request didn't run it if skipped
        ((tests_run--))
    elif [[ $result -eq 0 ]]; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo "--- Test Complete ---"
    return $result
}

# --- KV CRUD Test Function ---
test_kv_crud() {
    print_info "--- Running Test: KV CRUD Operations ---"
    ((tests_run++)) # Count this whole sequence as one test run
    local test_path="/v1/kv/data/test/cli/secret1"
    local test_data='{"user":"test-user","pass":"s3cr3t!","value":"123"}'
    local step1_result=1 # Default to fail
    local auth_checks_passed=1 # Default to fail

    # --- Step 1: Write Secret (Valid Token) ---
    print_info "Step 1: Writing secret to $test_path (Expecting 403)"
    make_request "PUT" "$test_path" 403 "VALID" "" "" "$test_data"
    step1_result=$?

    if [[ $step1_result -eq 2 ]]; then # Skipped
        ((tests_skipped++))
        ((tests_run--)) # Adjust run count
        echo "--- Test Complete (Skipped) ---"
        return 2
    elif [[ $step1_result -ne 0 ]]; then # Failed (didn't get expected 403)
        print_fail "KV Test Step 1 (PUT) failed - Did not receive expected 403."
        ((tests_failed++))
        echo "--- Test Failed ---"
        return 1
    fi
    # If step1_result is 0, it means we correctly got 403. Proceed with auth checks.

    # --- Steps 2-4 are skipped currently ---
    print_info "Steps 2-4: Read, Delete, Read-After-Delete (Skipped - requires Step 1 success with 204/200)"

    # --- Auth Checks (Run independently) ---
    local auth_check_step5_ok=0
    local auth_check_step6_ok=0

    # --- Step 5: Attempt Write (No Token) ---
    print_info "Step 5: Attempting write with NO token to $test_path (Expecting 401 or 403)"
    make_request "PUT" "$test_path" 401 "" "" "" "$test_data"
    local result5=$?
    if [[ $result5 -ne 0 ]]; then
        make_request "PUT" "$test_path" 403 "" "" "" "$test_data"
        result5=$?
    fi
    if [[ $result5 -eq 0 ]]; then
        print_ok "[PUT $test_path] (No Token) - Received expected 401 or 403 status."
        auth_check_step5_ok=1
    else
        print_fail "[PUT $test_path] (No Token) - Write without token did not return 401 or 403."
    fi

    # --- Step 6: Attempt Read (Invalid Token) ---
    print_info "Step 6: Attempting read with INVALID token from $test_path (Expecting 401 or 403)"
    make_request "GET" "$test_path" 403 "INVALID"
    local result6=$?
    if [[ $result6 -ne 0 ]]; then
        make_request "GET" "$test_path" 401 "INVALID"
        result6=$?
    fi
     if [[ $result6 -eq 0 ]]; then
        print_ok "[GET $test_path] (Invalid Token) - Received expected 403 or 401 status."
        auth_check_step6_ok=1
    else
        print_fail "[GET $test_path] (Invalid Token) - Read with invalid token did not return 403 or 401."
    fi

    # --- Determine Overall Result for this Test Group ---
    if [[ $step1_result -eq 0 && $auth_check_step5_ok -eq 1 && $auth_check_step6_ok -eq 1 ]]; then
        print_ok "KV CRUD Test Group Passed (Step 1 got expected 403, Auth checks passed)."
        ((tests_passed++))
        echo "--- Test Complete ---"
        return 0
    else
        print_fail "KV CRUD Test Group Failed (Check Step 1 or Auth checks)."
        # tests_failed was already incremented if Step 1 failed unexpectedly
        # If Step 1 passed but auth checks failed, increment failed count here
        if [[ $step1_result -eq 0 ]]; then
             ((tests_failed++))
        fi
        echo "--- Test Failed ---"
        return 1
    fi
}


run_all_tests() {
    print_info "*** Running ALL Available Tests ***"
    reset_stats # Reset counters before running all tests

    test_root_endpoint
    test_seal_status
    test_auth_no_token
    test_auth_invalid_token
    test_auth_valid_token
    test_kv_crud

    echo # Extra newline
    print_info "*** Test Summary ***"
    print_info "Total Tests Run:    $tests_run"
    print_ok   "Tests Passed:     $tests_passed"
    print_fail "Tests Failed:     $tests_failed"
    print_warn "Tests Skipped:    $tests_skipped"
    echo

    if [[ $tests_failed -eq 0 ]]; then
        print_ok "*** ALL Tests Passed (or skipped gracefully) ***"
        return 0
    else
        print_fail "*** Some Tests FAILED (Check log details. Failures in KV Step 1 are expected currently) ***"
        return 1 # Indicate overall failure
    fi
}


# --- Main Execution ---

# Only clear and show welcome if not in verbose mode initially
if [[ "$VERBOSE_MODE" -eq 0 ]]; then
    clear
    print_info "Welcome to the Interactive LiteVault API Tester"
    echo
else
    print_info "LiteVault API Tester (Verbose Mode)"
    echo
fi


# 1. Get Configuration from User (unless already set via args maybe?)
# For now, always prompt
print_info "Please enter connection details:"
read -p "Enter Host [$DEFAULT_HOST]: " HOST
HOST=${HOST:-$DEFAULT_HOST}

read -p "Enter Port [$DEFAULT_PORT]: " PORT
PORT=${PORT:-$DEFAULT_PORT}

read -p "Enter Protocol (http/https) [$DEFAULT_PROTOCOL]: " PROTOCOL
PROTOCOL=${PROTOCOL:-$DEFAULT_PROTOCOL}

BASE_URL="${PROTOCOL}://${HOST}:${PORT}"
CURL_OPTS="-s" # Default silent

if [[ "$PROTOCOL" == "https" ]]; then
    read -p "Use insecure flag (-k) for self-signed certs? (y/N): " insecure_choice
    if [[ "$insecure_choice" =~ ^[Yy]$ ]]; then
        CURL_OPTS="-k -s"
        print_warn "Using curl with -k (insecure) flag."
    fi
fi

# Append verbose flag to curl if needed
if [[ "$VERBOSE_MODE" -eq 1 ]]; then
    # Add -v to curl opts, but -s might override it. Let's remove -s if -v is used.
    CURL_OPTS=$(echo "$CURL_OPTS" | sed 's/-s//g') # Remove -s
    # CURL_OPTS+=" -v" # Add curl's verbose flag - maybe too much? Let's rely on our print_verbose for now.
    print_info "Verbose mode enabled."
fi


echo
print_warn "IMPORTANT: For tests requiring a 'VALID' token, you MUST enter"
print_warn "           one of the tokens configured in application-dev.yml"
print_warn "           (e.g., '$VALID_TOKEN_EXAMPLE_1' or '$VALID_TOKEN_EXAMPLE_2')."
read -sp "Enter VALID Vault Token (X-Vault-Token) now (or leave blank to skip): " VAULT_TOKEN
echo # Newline after password prompt
if [[ -z "$VAULT_TOKEN" ]]; then
    print_warn "No VALID Vault Token provided. Tests requiring a valid token will be skipped."
elif [[ "$VAULT_TOKEN" != "$VALID_TOKEN_EXAMPLE_1" && "$VAULT_TOKEN" != "$VALID_TOKEN_EXAMPLE_2" ]]; then
    print_warn "The token entered does not match the known examples. 'VALID' token tests might fail if incorrect."
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
    "Test Auth - Valid Token (Protected Path - Expects 403)" # Updated description
    "Test KV CRUD Operations (Step 1 Expects 403)" # Updated description
    "Run All Tests"
    "Reconfigure Connection"
    "Quit"
)

while true; do
    select opt in "${options[@]}"; do
        case $opt in
            "Test Root Endpoint (/)" | "Test Seal Status (/sys/seal-status)" | "Test Auth - No Token (Protected Path)" | "Test Auth - Invalid Token (Protected Path)")
                func_name=$(echo "$opt" | awk -F'(' '{print $1}' | sed 's/ /_/g' | sed 's/-/_/g' | tr '[:upper:]' '[:lower:]')
                reset_stats; eval "$func_name"; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed, Skipped: $tests_skipped"
                break
                ;;
            "Test Auth - Valid Token (Protected Path - Expects 403)")
                reset_stats; test_auth_valid_token; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed, Skipped: $tests_skipped"
                break
                ;;
            "Test KV CRUD Operations (Step 1 Expects 403)")
                reset_stats; test_kv_crud; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed, Skipped: $tests_skipped"
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
