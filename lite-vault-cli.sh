#!/bin/bash

# lite-vault-cli.sh
# An interactive script to test basic LiteVault API features, including policy enforcement.

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
# VAULT_TOKEN="" # No longer prompted for, using specific tokens below

# --- Specific Tokens for Policy Testing (from application-dev.yml) ---
ROOT_TOKEN="dev-root-token"
READONLY_TOKEN="app-token-readonly" # Has kv-read-only policy (kv/data/* READ/LIST)
MYAPP_WRITE_TOKEN="app-write-token" # Has myapp-read-only & myapp-write-delete (myapp/* READ/LIST/WRITE/DELETE)
NOACCESS_TOKEN="no-access-token" # Has non-existent-policy
INVALID_TOKEN="invalid-dummy-token-12345" # A token not in config at all

# --- Test Statistics ---
tests_run=0
tests_passed=0
tests_failed=0
tests_skipped=0 # Keep skipped count for potential future use (e.g., unmet dependencies)

reset_stats() {
    tests_run=0
    tests_passed=0
    tests_failed=0
    tests_skipped=0
}

# --- Core Request Function ---
# Function to make requests and check status/basic content
# Usage: make_request <METHOD> <PATH> [EXPECTED_STATUS] [TOKEN] [JQ_QUERY] [EXPECTED_VALUE] [BODY_DATA]
# TOKEN: Literal token string, "INVALID", or "" (for none)
# Returns: 0 on pass, 1 on fail
# DOES NOT MODIFY GLOBAL COUNTERS
make_request() {
  local method="$1"
  local path="$2"
  local expected_status="${3:-200}"
  local token_arg="$4" # Literal token string, "INVALID", ""
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
  if [[ "$token_arg" == "INVALID" ]]; then
      current_token="$INVALID_TOKEN"
      headers+=("-H" "X-Vault-Token: $current_token")
      curl_cmd_display+=" -H 'X-Vault-Token: $current_token'"
      test_desc="$test_desc (Token: INVALID)"
  elif [[ -n "$token_arg" ]]; then # Treat non-empty, non-"INVALID" as a literal token
      current_token="$token_arg"
      headers+=("-H" "X-Vault-Token: $current_token")
      curl_cmd_display+=" -H 'X-Vault-Token: ***'" # Mask token in display
      test_desc="$test_desc (Token: Provided)"
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
     # Handle jq returning empty string for null values correctly
     if [[ -z "$actual_value" || "$actual_value" == "null" ]] && [[ "$expected_value" == "null" ]]; then
         actual_value="null" # Normalize for comparison
     fi

     if [[ "$actual_value" == "$expected_value" ]]; then
       print_ok "$test_desc - JSON check passed: '$jq_query' is '$actual_value'."
     else
       # Check if the body was valid JSON at all before complaining about the value
       if ! echo "$body" | jq -e . > /dev/null 2>&1 && [[ -n "$body" ]]; then
            print_fail "$test_desc - JSON check failed: Response is not valid JSON. Body: $body"
       else
            print_fail "$test_desc - JSON check failed: Expected '$jq_query' to be '$expected_value', got '$actual_value'. Body: $body"
       fi
       # Note: Caller function should increment failed count
       return 1 # Fail
     fi
  elif [[ -n "$jq_query" && -n "$expected_value" ]]; then
      # jq not found, do basic check if query/value were provided
      print_warn "$test_desc - jq not found, skipping specific JSON value check for '$jq_query'. Performing basic check."
      # Basic check: does the body contain the expected value as a substring (crude)
      if echo "$body" | grep -q "$expected_value"; then
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

    # Expect 401 (Unauthorized) or 403 (Forbidden) - Spring Security might return 401 first if no auth at all
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

    # Expect 403 (Forbidden) - StaticTokenAuthFilter runs, finds no match, proceeds, PolicyEnforcementFilter denies
    # Or potentially 401 if Spring Security ExceptionTranslationFilter handles it earlier based on config. Let's check 403 first.
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

# Renamed from test_auth_valid_token
test_auth_root_token_nonexistent_path() {
    print_info "--- Running Test: Auth (Root Token, Non-Existent Path) ---"
    ((tests_run++))
    local protected_path="/v1/kv/data/auth-test/non-existent"
    print_info "Attempting access to non-existent path: $protected_path with Root Token"

    # Expect 404 Not Found. Root policy grants access, but KV engine won't find the path.
    make_request "GET" "$protected_path" 404 "$ROOT_TOKEN"
    local result=$?

    if [[ $result -eq 0 ]]; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo "--- Test Complete ---"
    return $result
}

# Renamed from test_kv_crud
test_kv_crud_root_token() {
    print_info "--- Running Test: KV CRUD Operations (Root Token) ---"
    ((tests_run++)) # Count this whole sequence as one test run
    local test_path="/v1/kv/data/test/cli/root-crud"
    local test_data='{"user":"root-test","pass":"s3cr3t!"}'
    local final_result=0 # Assume pass initially

    # --- Step 1: Write Secret (Root Token) ---
    print_info "Step 1: Writing secret to $test_path (Root Token - Expecting 204)"
    make_request "PUT" "$test_path" 204 "$ROOT_TOKEN" "" "" "$test_data"
    if [[ $? -ne 0 ]]; then final_result=1; fi

    # --- Step 2: Read Secret (Root Token) ---
    if [[ $final_result -eq 0 ]]; then
      print_info "Step 2: Reading secret from $test_path (Root Token - Expecting 200)"
      make_request "GET" "$test_path" 200 "$ROOT_TOKEN" '.user' 'root-test'
      if [[ $? -ne 0 ]]; then final_result=1; fi
    else
      print_warn "Skipping KV Read test due to previous step failure."
    fi

    # --- Step 3: Delete Secret (Root Token) ---
     if [[ $final_result -eq 0 ]]; then
      print_info "Step 3: Deleting secret at $test_path (Root Token - Expecting 204)"
      make_request "DELETE" "$test_path" 204 "$ROOT_TOKEN"
      if [[ $? -ne 0 ]]; then final_result=1; fi
    else
      print_warn "Skipping KV Delete test due to previous step failure."
    fi

    # --- Step 4: Read Secret After Delete (Root Token) ---
    if [[ $final_result -eq 0 ]]; then
      print_info "Step 4: Reading secret after delete from $test_path (Root Token - Expecting 404)"
      make_request "GET" "$test_path" 404 "$ROOT_TOKEN"
      if [[ $? -ne 0 ]]; then final_result=1; fi
    else
      print_warn "Skipping KV Read-After-Delete test due to previous step failure."
    fi

    # --- Determine Overall Result for this Test Group ---
    if [[ $final_result -eq 0 ]]; then
        print_ok "KV CRUD Test Group (Root Token) Passed."
        ((tests_passed++))
        echo "--- Test Complete ---"
        return 0
    else
        print_fail "KV CRUD Test Group (Root Token) Failed (Check logs for specific step failure)."
        ((tests_failed++))
        echo "--- Test Failed ---"
        return 1
    fi
}

# NEW Test Function for Policy Enforcement
test_policy_enforcement() {
    print_info "--- Running Test: Policy Enforcement ---"
    ((tests_run++)) # Count this whole sequence as one test run

    local myapp_path="/v1/kv/data/myapp/policy-test"
    local other_path="/v1/kv/data/other/policy-test"
    local test_data='{"policy":"check"}'
    local final_result=0 # Assume pass initially

    # --- Test Cases ---
    # Token             Method  Path         Expected Status   Permissions Check
    # ----------------- ------- ------------ ---------------   ------------------------------------------------
    # Root Token (Full Access)
    print_info "Testing Root Token..."
    make_request "PUT"    "$myapp_path" 204 "$ROOT_TOKEN" "" "" "$test_data" || final_result=1
    make_request "GET"    "$myapp_path" 200 "$ROOT_TOKEN" '.policy' 'check' || final_result=1
    make_request "PUT"    "$other_path" 204 "$ROOT_TOKEN" "" "" "$test_data" || final_result=1
    make_request "GET"    "$other_path" 200 "$ROOT_TOKEN" '.policy' 'check' || final_result=1
    make_request "DELETE" "$myapp_path" 204 "$ROOT_TOKEN" || final_result=1
    make_request "DELETE" "$other_path" 204 "$ROOT_TOKEN" || final_result=1
    make_request "GET"    "$myapp_path" 404 "$ROOT_TOKEN" || final_result=1 # Check deleted
    make_request "GET"    "$other_path" 404 "$ROOT_TOKEN" || final_result=1 # Check deleted

    # ReadOnly Token (kv-read-only policy: kv/data/* READ/LIST)
    print_info "Testing ReadOnly Token..."
    make_request "PUT"    "$myapp_path" 403 "$READONLY_TOKEN" "" "" "$test_data" || final_result=1 # Write Denied
    make_request "PUT"    "$other_path" 403 "$READONLY_TOKEN" "" "" "$test_data" || final_result=1 # Write Denied
    # Need to ensure something exists to read first (use root token)
    make_request "PUT"    "$myapp_path" 204 "$ROOT_TOKEN" "" "" "$test_data" > /dev/null # Setup for read
    make_request "GET"    "$myapp_path" 200 "$READONLY_TOKEN" '.policy' 'check' || final_result=1 # Read Allowed
    make_request "DELETE" "$myapp_path" 403 "$READONLY_TOKEN" || final_result=1 # Delete Denied
    # Cleanup
    make_request "DELETE" "$myapp_path" 204 "$ROOT_TOKEN" > /dev/null

    # MyApp Write Token (myapp-read-only, myapp-write-delete: myapp/* READ/LIST/WRITE/DELETE)
    print_info "Testing MyApp Write Token..."
    make_request "PUT"    "$myapp_path" 204 "$MYAPP_WRITE_TOKEN" "" "" "$test_data" || final_result=1 # Write Allowed (myapp)
    make_request "GET"    "$myapp_path" 200 "$MYAPP_WRITE_TOKEN" '.policy' 'check' || final_result=1 # Read Allowed (myapp)
    make_request "PUT"    "$other_path" 403 "$MYAPP_WRITE_TOKEN" "" "" "$test_data" || final_result=1 # Write Denied (other)
    make_request "GET"    "$other_path" 403 "$MYAPP_WRITE_TOKEN" || final_result=1 # Read Denied (other)
    make_request "DELETE" "$myapp_path" 204 "$MYAPP_WRITE_TOKEN" || final_result=1 # Delete Allowed (myapp)
    make_request "GET"    "$myapp_path" 404 "$MYAPP_WRITE_TOKEN" || final_result=1 # Check deleted

    # No Access Token (non-existent-policy)
    print_info "Testing No Access Token..."
    make_request "PUT"    "$myapp_path" 403 "$NOACCESS_TOKEN" "" "" "$test_data" || final_result=1 # Write Denied
    make_request "GET"    "$myapp_path" 403 "$NOACCESS_TOKEN" || final_result=1 # Read Denied
    make_request "DELETE" "$myapp_path" 403 "$NOACCESS_TOKEN" || final_result=1 # Delete Denied

    # --- Determine Overall Result ---
    if [[ $final_result -eq 0 ]]; then
        print_ok "Policy Enforcement Test Group Passed."
        ((tests_passed++))
        echo "--- Test Complete ---"
        return 0
    else
        print_fail "Policy Enforcement Test Group Failed (Check logs for specific step failure)."
        ((tests_failed++))
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
    test_auth_root_token_nonexistent_path # Renamed test
    test_kv_crud_root_token             # Renamed test
    test_policy_enforcement             # New test

    echo # Extra newline
    print_info "*** Test Summary ***"
    print_info "Total Test Groups Run: $tests_run"
    print_ok   "Test Groups Passed:  $tests_passed"
    print_fail "Test Groups Failed:  $tests_failed"
    # print_warn "Tests Skipped:     $tests_skipped" # Can uncomment if skipping logic is added
    echo

    if [[ $tests_failed -eq 0 ]]; then
        print_ok "*** ALL Test Groups Passed ***"
        return 0
    else
        print_fail "*** Some Test Groups FAILED (Check log details) ***"
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


# 1. Get Configuration from User
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
    CURL_OPTS=$(echo "$CURL_OPTS" | sed 's/-s//g') # Remove -s if verbose
    print_info "Verbose mode enabled (script output only, not curl -v)."
fi


echo
# Removed the prompt for VAULT_TOKEN
print_info "NOTE: Policy tests use specific tokens (e.g., '$ROOT_TOKEN', '$READONLY_TOKEN') hardcoded in the script."
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
    "Test Auth - Root Token (Non-Existent Path - Expects 404)" # Updated description
    "Test KV CRUD - Root Token (Expects Success)" # Updated description
    "Test Policy Enforcement (Multiple Tokens/Paths)" # New Test
    "Run All Tests"
    "Reconfigure Connection"
    "Quit"
)

while true; do
    select opt in "${options[@]}"; do
        case $opt in
            "Test Root Endpoint (/)" | "Test Seal Status (/sys/seal-status)" | "Test Auth - No Token (Protected Path)" | "Test Auth - Invalid Token (Protected Path)")
                func_name=$(echo "$opt" | awk -F'(' '{print $1}' | sed 's/ /_/g' | sed 's/-/_/g' | tr '[:upper:]' '[:lower:]')
                reset_stats; eval "$func_name"; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed"
                break
                ;;
            "Test Auth - Root Token (Non-Existent Path - Expects 404)")
                reset_stats; test_auth_root_token_nonexistent_path; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed"
                break
                ;;
            "Test KV CRUD - Root Token (Expects Success)")
                reset_stats; test_kv_crud_root_token; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed"
                break
                ;;
            "Test Policy Enforcement (Multiple Tokens/Paths)")
                reset_stats; test_policy_enforcement; print_info "Ran 1 test group. Passed: $tests_passed, Failed: $tests_failed"
                break
                ;;
            "Run All Tests")
                run_all_tests # This function already handles stats and summary
                break
                ;;
            "Reconfigure Connection")
                print_info "Please restart the script to reconfigure."
                # Or could re-run the config section, but restart is simpler
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
