#!/usr/bin/env bash
#
# REMnux Installer (Next Generation)
#
# A wrapper script for Cast that provides a familiar interface for
# installing and upgrading the REMnux distribution.
#
# To rename this script, change SCRIPT_NAME in the Configuration section.
#
# https://REMnux.org
#

set -euo pipefail

#############################################################################
# Configuration
#############################################################################

SCRIPT_NAME="remnux-ng"
SCRIPT_VERSION="1.0.0"
CAST_VERSION="v1.0.0"
# IMPORTANT: When updating CAST_VERSION, also update CAST_DEB_SHA256_* checksums below

# Expected SHA256 checksums (from checksums.txt for v1.0.0)
CAST_DEB_SHA256_AMD64="8d73856e4eef8a66d305861c6c81c763e5a3eea121a0f492ddf7caa11084a280"
CAST_DEB_SHA256_ARM64="c3212e562ce3d5120b24b9fa3d2e3b3a8e1869a96d2351cd1b7344c037b8ba9f"

# GitHub base URL for Cast releases
CAST_GITHUB_BASE_URL="https://github.com/ekristen/cast/releases/download"

# Fallback base URL (leave empty to disable fallback)
# Example: "https://remnux.org/files"
CAST_FALLBACK_BASE_URL=""

# Installation path (where dpkg installs cast)
CAST_BIN="/usr/bin/cast"

# Valid modes for REMnux installation
VALID_MODES=("dedicated" "addon" "cloud")

# Legacy config file (for migration from old remnux-cli)
LEGACY_CONFIG_FILE="/etc/remnux-config"

# Disable Cast telemetry/checkpoint functionality
export CHECKPOINT_DISABLE=1

#############################################################################
# Global variables
#############################################################################

COMMAND=""
MODE=""
USER_SPECIFIED=""
VERSION_REQUESTED=""
SKIP_CHECKSUM=false

#############################################################################
# Helper functions
#############################################################################

get_system_arch() {
    # Detect system architecture and return the Cast package architecture name
    local arch
    arch=$(uname -m)
    
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            log_error "Unsupported architecture: ${arch}"
            log_error "Supported architectures: x86_64 (amd64), aarch64 (arm64)"
            exit 1
            ;;
    esac
}

get_cast_deb_url() {
    # Construct the primary download URL for the Cast .deb package
    local arch="$1"
    echo "${CAST_GITHUB_BASE_URL}/${CAST_VERSION}/cast-${CAST_VERSION}-linux-${arch}.deb"
}

get_cast_deb_fallback_url() {
    # Construct the fallback download URL for the Cast .deb package
    local arch="$1"
    if [[ -n "${CAST_FALLBACK_BASE_URL:-}" ]]; then
        echo "${CAST_FALLBACK_BASE_URL}/cast-${CAST_VERSION}-linux-${arch}.deb"
    else
        echo ""
    fi
}

get_cast_deb_sha256() {
    # Return the expected SHA256 checksum for the given architecture
    local arch="$1"
    case "$arch" in
        amd64)
            echo "$CAST_DEB_SHA256_AMD64"
            ;;
        arm64)
            echo "$CAST_DEB_SHA256_ARM64"
            ;;
        *)
            log_error "No checksum available for architecture: ${arch}"
            exit 1
            ;;
    esac
}

log_info() {
    echo "> $*"
}

log_error() {
    echo "ERROR: $*" >&2
}

log_warn() {
    echo "WARNING: $*" >&2
}

log_detail() {
    echo ">> $*"
}

show_usage() {
    cat << EOF
Usage:
  ${SCRIPT_NAME} install [--mode=<mode>] [--user=<user>] [--version=<version>]
  ${SCRIPT_NAME} upgrade [--mode=<mode>] [--user=<user>] [--version=<version>]
  ${SCRIPT_NAME} results
  ${SCRIPT_NAME} debug
  ${SCRIPT_NAME} -h | --help

Commands:
  install         Install or upgrade REMnux on this system
  upgrade         Alias for install
  results         Show results from the last installation/upgrade
  debug           Show version and debug information

Options:
  --mode=<mode>       Installation mode: dedicated, addon, or cloud
                      (default: dedicated)
  --user=<user>       User for REMnux configuration
                      (default: current sudo user)
  --version=<version> Specific version to install (e.g., v2024.1)
  --skip-checksum     Skip SHA256 checksum verification (not recommended)
  -h, --help          Show this help message

Examples:
  sudo ${SCRIPT_NAME} install
  sudo ${SCRIPT_NAME} install --mode=addon
  sudo ${SCRIPT_NAME} install --mode=cloud --user=remnux
  sudo ${SCRIPT_NAME} upgrade

For more information, visit https://docs.remnux.org
EOF
}

#############################################################################
# Validation functions
#############################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with root privileges."
        echo ""
        echo "Please run: sudo $0 $*"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine operating system. /etc/os-release not found."
        exit 1
    fi

    # shellcheck source=/dev/null
    source /etc/os-release

    if [[ "${ID:-}" != "ubuntu" ]]; then
        log_error "This script only supports Ubuntu. Detected: ${ID:-unknown}"
        exit 1
    fi

    local version="${VERSION_ID:-}"
    if [[ "$version" != "20.04" && "$version" != "24.04" ]]; then
        log_error "Unsupported Ubuntu version: ${version}"
        log_error "Supported versions: 20.04 (Focal), 24.04 (Noble)"
        exit 1
    fi

    log_detail "Detected Ubuntu ${version}"
}

validate_mode() {
    local mode="$1"
    for valid_mode in "${VALID_MODES[@]}"; do
        if [[ "$mode" == "$valid_mode" ]]; then
            return 0
        fi
    done
    log_error "Invalid mode: ${mode}"
    log_error "Valid modes are: ${VALID_MODES[*]}"
    exit 1
}

#############################################################################
# Cast management functions
#############################################################################

get_cast_path() {
    if [[ -x "$CAST_BIN" ]]; then
        echo "$CAST_BIN"
    else
        echo ""
    fi
}

get_installed_cast_version() {
    local cast_path
    cast_path=$(get_cast_path)
    
    if [[ -z "$cast_path" ]]; then
        echo ""
        return
    fi

    # Cast outputs version like "cast version v1.0.0" or similar
    local version_output
    version_output=$("$cast_path" --version 2>/dev/null || true)
    
    # Extract version number (looking for vX.Y.Z pattern)
    if [[ "$version_output" =~ v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        echo "${BASH_REMATCH[0]}"
    else
        echo ""
    fi
}

version_compare() {
    # Compare two version strings (without 'v' prefix)
    # Returns: 0 if equal, 1 if first > second, 2 if first < second
    local v1="${1#v}"
    local v2="${2#v}"

    if [[ "$v1" == "$v2" ]]; then
        return 0
    fi

    local IFS=.
    local i
    # shellcheck disable=SC2206
    local ver1=($v1)
    # shellcheck disable=SC2206
    local ver2=($v2)

    # Fill empty positions with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=${#ver2[@]}; i<${#ver1[@]}; i++)); do
        ver2[i]=0
    done

    for ((i=0; i<${#ver1[@]}; i++)); do
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 2
        fi
    done

    return 0
}

verify_checksum() {
    local file="$1"
    local expected="$2"

    if [[ "$SKIP_CHECKSUM" == "true" ]]; then
        log_warn "Skipping checksum verification (--skip-checksum specified)"
        return 0
    fi

    log_info "Verifying SHA256 checksum..."
    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')

    if [[ "$actual" != "$expected" ]]; then
        log_error "Checksum verification failed!"
        log_error "Expected: ${expected}"
        log_error "Actual:   ${actual}"
        log_error ""
        log_error "The downloaded file may be corrupted or tampered with."
        log_error "Use --skip-checksum to bypass this check (not recommended)."
        return 1
    fi

    log_detail "Checksum verified successfully"
}

download_file() {
    local url="$1"
    local dest="$2"

    log_detail "Downloading from: ${url}"
    
    if ! curl -fsSL -o "$dest" "$url"; then
        log_error "Failed to download from: ${url}"
        return 1
    fi
}

install_cast_from_deb() {
    local deb_file="$1"

    log_info "Installing Cast from Debian package..."
    if ! dpkg -i "$deb_file" >/dev/null; then
        log_error "Failed to install Cast Debian package"
        return 1
    fi
}

ensure_cast_installed() {
    local installed_version
    installed_version=$(get_installed_cast_version)

    if [[ -n "$installed_version" ]]; then
        log_detail "Found Cast ${installed_version}"
        
        # Compare versions
        local cmp_result=0
        version_compare "$installed_version" "$CAST_VERSION" || cmp_result=$?
        
        case $cmp_result in
            0)
                log_info "Cast ${CAST_VERSION} is already installed"
                return 0
                ;;
            1)
                log_info "Installed Cast ${installed_version} is newer than expected ${CAST_VERSION}"
                return 0
                ;;
            2)
                log_info "Upgrading Cast from ${installed_version} to ${CAST_VERSION}..."
                ;;
        esac
    else
        log_info "Cast not found, installing ${CAST_VERSION}..."
    fi

    # Detect system architecture
    local arch
    arch=$(get_system_arch)
    log_detail "Detected architecture: ${arch}"

    # Get architecture-specific URL and checksum
    local cast_deb_url
    local cast_deb_sha256
    cast_deb_url=$(get_cast_deb_url "$arch")
    cast_deb_sha256=$(get_cast_deb_sha256 "$arch")

    # Create temp directory for downloads
    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Cleanup function
    cleanup_tmp() {
        rm -rf "$tmp_dir"
    }

    # Try primary URL (Debian package)
    local deb_file="${tmp_dir}/cast.deb"
    log_info "Downloading Cast ${CAST_VERSION} for ${arch}..."
    
    if download_file "$cast_deb_url" "$deb_file"; then
        if verify_checksum "$deb_file" "$cast_deb_sha256"; then
            if install_cast_from_deb "$deb_file"; then
                cleanup_tmp
                log_info "Cast ${CAST_VERSION} installed successfully"
                return 0
            fi
        fi
    fi

    log_warn "Primary download failed, trying fallback..."

    # Try fallback URL (Debian package) if configured
    local cast_deb_fallback_url
    cast_deb_fallback_url=$(get_cast_deb_fallback_url "$arch")
    
    if [[ -n "$cast_deb_fallback_url" ]]; then
        local fallback_deb="${tmp_dir}/cast-fallback.deb"
        
        if download_file "$cast_deb_fallback_url" "$fallback_deb"; then
            if verify_checksum "$fallback_deb" "$cast_deb_sha256"; then
                if install_cast_from_deb "$fallback_deb"; then
                    cleanup_tmp
                    log_info "Cast ${CAST_VERSION} installed successfully (from fallback)"
                    return 0
                fi
            fi
        fi
    else
        log_detail "No fallback URL configured"
    fi

    cleanup_tmp
    log_error "Failed to download and install Cast"
    log_error "Please check your network connection and try again."
    exit 1
}

#############################################################################
# Legacy configuration migration
#############################################################################

get_legacy_mode() {
    if [[ -f "$LEGACY_CONFIG_FILE" ]]; then
        # Parse YAML-style config: mode: dedicated
        # Handles "mode: dedicated" and "mode:dedicated", with optional leading whitespace
        local mode
        mode=$(grep -E "^[[:space:]]*mode:" "$LEGACY_CONFIG_FILE" 2>/dev/null | sed -n 's/^[[:space:]]*mode:[[:space:]]*//p' || true)
        if [[ -n "$mode" ]]; then
            echo "$mode"
            return
        fi
    fi
    echo ""
}

get_legacy_user() {
    if [[ -f "$LEGACY_CONFIG_FILE" ]]; then
        local user
        user=$(grep -E "^[[:space:]]*user:" "$LEGACY_CONFIG_FILE" 2>/dev/null | sed -n 's/^[[:space:]]*user:[[:space:]]*//p' || true)
        if [[ -n "$user" ]]; then
            echo "$user"
            return
        fi
    fi
    echo ""
}

#############################################################################
# Command implementations
#############################################################################

cmd_install() {
    log_info "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
    
    check_os
    ensure_cast_installed

    local cast_path
    cast_path=$(get_cast_path)

    # Build Cast command arguments
    local cast_args=("install" "remnux")

    # Handle mode
    if [[ -n "$MODE" ]]; then
        validate_mode "$MODE"
        cast_args+=("--mode=${MODE}")
    else
        # Check for legacy mode from old remnux-cli config
        local legacy_mode
        legacy_mode=$(get_legacy_mode)
        if [[ -n "$legacy_mode" ]]; then
            log_info "Using mode from previous installation: ${legacy_mode}"
            cast_args+=("--mode=${legacy_mode}")
        fi
    fi

    # Handle user
    local target_user=""
    if [[ -n "$USER_SPECIFIED" ]]; then
        target_user="$USER_SPECIFIED"
    elif [[ -n "${SUDO_USER:-}" ]]; then
        target_user="$SUDO_USER"
    else
        # Check for legacy user
        local legacy_user
        legacy_user=$(get_legacy_user)
        if [[ -n "$legacy_user" ]]; then
            target_user="$legacy_user"
        fi
    fi

    if [[ -n "$target_user" ]]; then
        cast_args+=("--user=${target_user}")
    else
        log_error "Cannot determine target user."
        log_error "Please specify a user with --user=<username>"
        log_error "Example: sudo ${SCRIPT_NAME} install --user=remnux"
        exit 1
    fi

    # Handle version
    if [[ -n "$VERSION_REQUESTED" ]]; then
        # Cast uses distro@version syntax
        cast_args[1]="remnux@${VERSION_REQUESTED}"
    fi

    log_detail "Executing: ${cast_path} ${cast_args[*]}"
    
    # Execute Cast
    exec "$cast_path" "${cast_args[@]}"
}

cmd_results() {
    local cast_log_dir="/var/cache/cast/installer/logs"
    local results_file="${cast_log_dir}/results.yaml"
    local saltstack_log="${cast_log_dir}/saltstack.log"

    echo "=== REMnux Installation Results ==="
    echo ""

    if [[ ! -d "$cast_log_dir" ]]; then
        echo "No installation logs found."
        echo "REMnux may not have been installed yet, or logs have been cleaned up."
        return 0
    fi

    if [[ -f "$results_file" ]]; then
        echo "Results file: ${results_file}"
        echo ""

        # Count successes and failures from results.yaml
        # The file is YAML with structure like: local: { state_id: { result: true/false, ... } }
        local success_count
        local failure_count
        success_count=$(grep -c "result: true" "$results_file" 2>/dev/null) || success_count=0
        failure_count=$(grep -c "result: false" "$results_file" 2>/dev/null) || failure_count=0

        echo "Summary:"
        echo "  Successful states: ${success_count}"
        echo "  Failed states: ${failure_count}"
        echo ""

        if [[ "$failure_count" -gt 0 ]]; then
            echo "WARNING: Some states failed during installation."
            echo ""
            echo "To see failure details, examine the log files:"
            echo "  ${results_file}"
            echo "  ${saltstack_log}"
            echo ""
            echo "In saltstack.log, look for lines containing [ERROR] or states"
            echo "marked with 'result: false'. The first failure is usually the root cause."
        else
            echo "Installation completed successfully!"
            echo ""
            echo "Please reboot to make sure all settings take effect."
        fi
    else
        echo "Results file not found: ${results_file}"
        echo ""
        echo "This could mean:"
        echo "  - REMnux installation has not been run yet"
        echo "  - The installation is still in progress"
        echo "  - Logs have been cleaned up"
    fi

    echo ""
    echo "Log files location: ${cast_log_dir}"
    if [[ -f "$saltstack_log" ]]; then
        echo "  saltstack.log: $(wc -l < "$saltstack_log") lines"
        echo ""
        echo "To view the last 20 lines of the saltstack log:"
        echo "  tail -20 ${saltstack_log}"
    fi
}

cmd_debug() {
    echo "=== REMnux Debug Information ==="
    echo ""
    
    if [[ $EUID -ne 0 ]]; then
        log_warn "Running debug as non-root user."
        log_warn "Some information (like Cast state in /root) may be inaccessible."
        log_warn "For full debug info, run: sudo $0 debug"
        echo ""
    fi

    echo "Script version: ${SCRIPT_NAME} ${SCRIPT_VERSION}"
    echo "Expected Cast version: ${CAST_VERSION}"
    echo ""
    
    # Show architecture info
    local arch
    arch=$(get_system_arch 2>/dev/null || echo "unknown")
    echo "System architecture: $(uname -m) (${arch})"
    if [[ "$arch" != "unknown" ]]; then
        echo "Cast download URL: $(get_cast_deb_url "$arch")"
    fi
    echo ""
    
    local cast_path
    cast_path=$(get_cast_path)
    
    echo "Cast binary path: ${cast_path:-not found}"
    if [[ -n "$cast_path" ]]; then
        echo "Cast installed version: $(get_installed_cast_version)"
    fi
    echo ""
    
    echo "Current user: $(whoami)"
    echo "SUDO_USER: ${SUDO_USER:-not set}"
    echo ""
    
    if [[ -f /etc/os-release ]]; then
        echo "Operating System:"
        grep -E "^(NAME|VERSION|ID|VERSION_ID)=" /etc/os-release | sed 's/^/  /'
    fi
    echo ""
    
    if [[ -f "$LEGACY_CONFIG_FILE" ]]; then
        echo "Legacy config (${LEGACY_CONFIG_FILE}):"
        sed 's/^/  /' "$LEGACY_CONFIG_FILE"
    else
        echo "Legacy config: not found"
    fi
    echo ""

    # Check for Cast state file (YAML) in root's config directory since we run as sudo
    local cast_state_file="/root/.config/cast/state.yaml"
    
    if [[ -f "$cast_state_file" ]]; then
        echo "Cast state file: ${cast_state_file}"
        echo "  exists: yes"
        echo ""
        echo "Cast state content:"
        
        # Simple parsing of the YAML structure
        # Structure is usually:
        # installations:
        #   remnux:
        #     distro_name: remnux
        #     version: v2024.1
        #     mode: dedicated
        
        local mode user version
        # Extract values for 'remnux' entry
        # We look for the block starting with "remnux:", then grab indented keys
        # The awk command handles variable indentation (spaces/tabs)
        # Logic: Find "remnux:", set flag. Once flag is set, find "mode:" or "version:" and print.
        mode=$(awk '/^[[:space:]]*remnux:/ {found=1} found && /^[[:space:]]*mode:/ {print $2; exit}' "$cast_state_file" | tr -d '"') || mode=""
        version=$(awk '/^[[:space:]]*remnux:/ {found=1} found && /^[[:space:]]*version:/ {print $2; exit}' "$cast_state_file" | tr -d '"') || version=""
        
        echo "  mode: ${mode:-not found}"
        echo "  version: ${version:-not found}"
    else
        echo "Cast state file: ${cast_state_file}"
        echo "  exists: no (REMnux not yet installed via Cast or run as different user)"
    fi

    # Check for installed versions in remnux_salt-states
    local version_dir="/var/cache/cast/remnux_salt-states"
    if [[ -d "$version_dir" ]]; then
        echo ""
        echo "Installed versions (cached in /var/cache/cast):"
        ls -1 "$version_dir" 2>/dev/null | grep -v '^\.' | sed 's/^/  /' || echo "  (none)"
    fi

    # Check last result time
    local results_file="/var/cache/cast/installer/logs/results.yaml"
    if [[ -f "$results_file" ]]; then
        echo ""
        echo "Last installation run:"
        # Use stat for portable modification time (Linux syntax)
        if command -v stat >/dev/null; then
            stat -c "  Date: %y" "$results_file" 2>/dev/null || echo "  Date: unknown"
        fi
    fi
}

#############################################################################
# Argument parsing
#############################################################################

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            install|upgrade|results|debug)
                COMMAND="$1"
                shift
                ;;
            --mode=*)
                MODE="${1#*=}"
                shift
                ;;
            --mode)
                if [[ -z "${2:-}" ]]; then
                    log_error "--mode requires a value"
                    exit 1
                fi
                MODE="$2"
                shift 2
                ;;
            --user=*)
                USER_SPECIFIED="${1#*=}"
                shift
                ;;
            --user)
                if [[ -z "${2:-}" ]]; then
                    log_error "--user requires a value"
                    exit 1
                fi
                USER_SPECIFIED="$2"
                shift 2
                ;;
            --version=*)
                VERSION_REQUESTED="${1#*=}"
                shift
                ;;
            --version)
                # Check if next arg looks like a version or another flag
                if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
                    VERSION_REQUESTED="$2"
                    shift 2
                else
                    # Just --version alone means show debug info
                    COMMAND="debug"
                    shift
                fi
                ;;
            --skip-checksum)
                SKIP_CHECKSUM=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -v)
                cmd_debug
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo ""
                show_usage
                exit 1
                ;;
        esac
    done
}

#############################################################################
# Main
#############################################################################

main() {
    parse_args "$@"

    if [[ -z "$COMMAND" ]]; then
        show_usage
        exit 1
    fi

    # Commands that don't require root
    case "$COMMAND" in
        debug)
            cmd_debug
            exit 0
            ;;
        results)
            cmd_results
            exit 0
            ;;
    esac

    # Commands that require root
    check_root "$@"

    case "$COMMAND" in
        install|upgrade)
            cmd_install
            ;;
        *)
            log_error "Unknown command: ${COMMAND}"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
