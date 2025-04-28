#!/bin/bash

# Default values (primarily for 'dev' environment)
DEFAULT_ENV="dev"
DEFAULT_ALIAS="litevault-dev"
DEFAULT_KEYSTORE_FILE="./src/main/resources/dev-keystore.p12"
DEFAULT_VALIDITY=365 # days
DEFAULT_CN="localhost"
DEFAULT_OU="Development"
DEFAULT_O="LiteVault"
DEFAULT_L="City"
DEFAULT_ST="State"
DEFAULT_C="US"
DEFAULT_KEY_ALG="RSA"
DEFAULT_KEY_SIZE=2048
DEFAULT_STORE_TYPE="PKCS12"

# --- Function to display help ---
usage() {
  echo "Usage: $0 [-e <env>] [-f <keystore_file>] [-a <alias>] [-d <days>] [-p <password>] [-cn <common_name>] [-ou <org_unit>] [-o <org>] [-l <locality>] [-st <state>] [-c <country>] [-h]"
  echo "  Generates a PKCS12 keystore with a self-signed certificate."
  echo ""
  echo "  Options:"
  echo "    -e <env>          : Environment name (e.g., dev, staging, prod). Affects defaults if not overridden. (Default: $DEFAULT_ENV)"
  echo "    -f <keystore_file>: Path to the output keystore file. (Default depends on env, e.g., $DEFAULT_KEYSTORE_FILE for dev)"
  echo "    -a <alias>        : Alias for the key entry. (Default depends on env, e.g., $DEFAULT_ALIAS for dev)"
  echo "    -d <days>         : Validity period in days. (Default: $DEFAULT_VALIDITY)"
  echo "    -p <password>     : Keystore and key password. **WARNING: Insecure!** Use KEYSTORE_PASSWORD env var instead if possible."
  echo "    -cn <common_name> : Certificate Common Name (e.g., hostname). (Default: $DEFAULT_CN for dev)"
  echo "    -ou <org_unit>    : Organizational Unit. (Default: $DEFAULT_OU)"
  echo "    -o <org>          : Organization. (Default: $DEFAULT_O)"
  echo "    -l <locality>     : Locality/City. (Default: $DEFAULT_L)"
  echo "    -st <state>       : State/Province. (Default: $DEFAULT_ST)"
  echo "    -c <country>      : Country Code (2 letters). (Default: $DEFAULT_C)"
  echo "    -h                : Display this help message."
  echo ""
  echo "  Password Handling:"
  echo "    1. Uses KEYSTORE_PASSWORD environment variable if set."
  echo "    2. Uses password from -p argument if provided (INSECURE)."
  echo "    3. Prompts for password securely if neither is set."
  echo ""
  exit 1
}

# --- Initialize variables with defaults ---
ENV_NAME="$DEFAULT_ENV"
KEYSTORE_FILE="" # Will be set based on env or flag
ALIAS=""         # Will be set based on env or flag
VALIDITY="$DEFAULT_VALIDITY"
PASSWORD_ARG=""
CN=""            # Will be set based on env or flag
OU="$DEFAULT_OU"
O="$DEFAULT_O"
L="$DEFAULT_L"
ST="$DEFAULT_ST"
C="$DEFAULT_C"

# --- Parse Command Line Arguments ---
while getopts "e:f:a:d:p:cn:ou:o:l:st:c:h" opt; do
  case $opt in
    e) ENV_NAME="$OPTARG" ;;
    f) KEYSTORE_FILE="$OPTARG" ;;
    a) ALIAS="$OPTARG" ;;
    d) VALIDITY="$OPTARG" ;;
    p) PASSWORD_ARG="$OPTARG" ;;
    cn) CN="$OPTARG" ;;
    ou) OU="$OPTARG" ;;
    o) O="$OPTARG" ;;
    l) L="$OPTARG" ;;
    st) ST="$OPTARG" ;;
    c) C="$OPTARG" ;;
    h) usage ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
  esac
done
shift $((OPTIND-1))

# --- Set Environment-Specific Defaults if not overridden by flags ---
# Convert env name to lowercase for comparison
ENV_LOWER=$(echo "$ENV_NAME" | tr '[:upper:]' '[:lower:]')

if [[ -z "$ALIAS" ]]; then
  ALIAS="litevault-$ENV_LOWER"
fi

if [[ -z "$KEYSTORE_FILE" ]]; then
  # Place in src/main/resources only for dev, otherwise place outside source tree
  if [[ "$ENV_LOWER" == "dev" ]]; then
    KEYSTORE_FILE="./src/main/resources/${ENV_LOWER}-keystore.p12"
  else
    # Suggest placing outside source control for non-dev
    KEYSTORE_FILE="./${ENV_LOWER}-keystore.p12"
    echo "Warning: Defaulting keystore location for '$ENV_NAME' to '$KEYSTORE_FILE'. Consider using -f to specify a secure location outside the source tree."
  fi
fi

if [[ -z "$CN" ]]; then
  if [[ "$ENV_LOWER" == "dev" ]]; then
    CN="$DEFAULT_CN" # localhost for dev
  else
    # Prompt or require CN for non-dev environments
    read -p "Enter Common Name (CN) (e.g., vault.yourdomain.com) for environment '$ENV_NAME': " CN
    if [[ -z "$CN" ]]; then
      echo "Error: Common Name (-cn) is required for non-dev environments." >&2
      exit 1
    fi
  fi
fi

# Adjust OU based on environment if not overridden
if [[ "$OU" == "$DEFAULT_OU" && "$ENV_LOWER" != "dev" ]]; then
    OU=$(echo "$ENV_NAME" | awk '{print toupper(substr($0,1,1))tolower(substr($0,2))}') # Capitalize env name
fi

# Adjust validity for non-dev if using default
if [[ "$VALIDITY" == "$DEFAULT_VALIDITY" && "$ENV_LOWER" != "dev" ]]; then
    VALIDITY=730 # e.g., 2 years for non-dev
    echo "Info: Defaulting validity for '$ENV_NAME' to $VALIDITY days."
fi


# --- Determine Password ---
PASSWORD=""
if [[ -n "$KEYSTORE_PASSWORD" ]]; then
  echo "Using password from KEYSTORE_PASSWORD environment variable."
  PASSWORD="$KEYSTORE_PASSWORD"
elif [[ -n "$PASSWORD_ARG" ]]; then
  echo "WARNING: Using password provided via -p argument. This is insecure!" >&2
  PASSWORD="$PASSWORD_ARG"
else
  echo "KEYSTORE_PASSWORD environment variable not set, and -p not used."
  # Prompt securely
  while true; do
    read -s -p "Enter keystore password: " PWD1
    echo
    read -s -p "Confirm keystore password: " PWD2
    echo
    if [[ "$PWD1" == "$PWD2" ]]; then
      if [[ -z "$PWD1" ]]; then
        echo "Password cannot be empty. Please try again."
      else
        PASSWORD="$PWD1"
        break
      fi
    else
      echo "Passwords do not match. Please try again."
    fi
  done
fi

if [[ -z "$PASSWORD" ]]; then
  echo "Error: Failed to obtain a password." >&2
  exit 1
fi

# --- Construct Distinguished Name (DN) ---
DN="CN=$CN, OU=$OU, O=$O, L=$L, ST=$ST, C=$C"

# --- Ensure output directory exists ---
KEYSTORE_DIR=$(dirname "$KEYSTORE_FILE")
if [[ ! -d "$KEYSTORE_DIR" ]]; then
  echo "Creating directory: $KEYSTORE_DIR"
  mkdir -p "$KEYSTORE_DIR"
  if [[ $? -ne 0 ]]; then
    echo "Error: Failed to create directory $KEYSTORE_DIR" >&2
    exit 1
  fi
fi

# --- Display parameters and confirm ---
echo "--------------------------------------------------"
echo "Generating Keystore with the following parameters:"
echo "  Environment (-e) : $ENV_NAME"
echo "  Keystore File (-f): $KEYSTORE_FILE"
echo "  Alias (-a)       : $ALIAS"
echo "  Validity (-d)    : $VALIDITY days"
echo "  DN               : $DN"
echo "  Password Source  : $( [[ -n "$KEYSTORE_PASSWORD" ]] && echo "Env Var" || ( [[ -n "$PASSWORD_ARG" ]] && echo "Argument (Insecure)" || echo "Prompt" ) )"
echo "--------------------------------------------------"
read -p "Proceed? (y/N): " CONFIRM
CONFIRM_LOWER=$(echo "$CONFIRM" | tr '[:upper:]' '[:lower:]')
if [[ "$CONFIRM_LOWER" != "y" ]]; then
  echo "Aborted."
  exit 0
fi


# --- Execute keytool command ---
echo "Running keytool..."
keytool -genkeypair \
        -alias "$ALIAS" \
        -keyalg "$DEFAULT_KEY_ALG" \
        -keysize "$DEFAULT_KEY_SIZE" \
        -storetype "$DEFAULT_STORE_TYPE" \
        -keystore "$KEYSTORE_FILE" \
        -validity "$VALIDITY" \
        -storepass "$PASSWORD" \
        -keypass "$PASSWORD" \
        -dname "$DN"

# --- Check result ---
if [[ $? -eq 0 ]]; then
  echo "--------------------------------------------------"
  echo "SUCCESS: Keystore generated successfully at:"
  echo "  $KEYSTORE_FILE"
  echo ""
  echo "IMPORTANT:"
  echo "  - Secure this keystore file appropriately."
  echo "  - Ensure the application uses the correct password (ideally via environment variable)."
  echo "  - For non-dev environments, ensure '$KEYSTORE_FILE' is NOT committed to version control."
  echo "--------------------------------------------------"
else
  echo "--------------------------------------------------"
  echo "ERROR: keytool command failed." >&2
  echo "--------------------------------------------------"
  exit 1
fi

exit 0