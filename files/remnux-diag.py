#!/usr/bin/env python3
"""
REMnux Salt State Diagnostic Tool

Analyzes salt-states results to identify root causes of failures and their
cascading effects. Helps diagnose issues from 'remnux upgrade' or 'remnux install'.

Usage:
    remnux-diag.py [<results.yaml> | <directory>] [--log <saltstack.log>]

File locations (checked in order if not specified):
    1. /var/cache/cast/installer/logs/results.yaml
    2. ./results.yaml (current directory)
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

# Try to use PyYAML, fall back to basic parsing if not available
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Default paths to check for results file
DEFAULT_RESULTS_PATHS = [
    Path("/var/cache/cast/installer/logs/results.yaml"),
    Path("results.yaml"),
]

# Log file name to look for alongside results
LOG_FILENAME = "saltstack.log"

# Display formatting
REPORT_WIDTH = 35  # Width for separators
TEXT_WRAP_WIDTH = 78  # Width for word-wrapped error text


# ============================================================================
# Error Category Definitions
# ============================================================================

# Path patterns for context-aware missing file/directory hints
MISSING_PATH_HINTS = {
    r"/opt/[^/]+/lib/python[0-9.]+/site-packages/": (
        "Package installed but expected file not found. "
        "The package structure may have changed."
    ),
    r"/usr/local/src/remnux/[^/]+": (
        "Source directory missing. A prior download or extract step may have failed."
    ),
    r"/opt/[^/]+/bin/": (
        "Virtualenv binary missing. Check if virtualenv creation succeeded."
    ),
    r"/home/[^/]+/\.": (
        "User config file missing. May need to be created or copied from a template."
    ),
}

ERROR_CATEGORIES = {
    "network": {
        "name": "Network/DNS Issue",
        "patterns": [
            r"Temporary failure in name resolution",
            r"Connection timed out",
            r"Could not connect to",
            r"Failed to open TCP connection",
            r"Network is unreachable",
            r"Name or service not known",
            r"getaddrinfo.*failed",
            r"curl.*Recv failure",
            r"Unable to fetch some archives",
            r"fatal: unable to access",
            r"Could not resolve host",
        ],
        "hint": "Check network connectivity and DNS. Try: ping google.com",
    },
    "download": {
        "name": "Download Failed",
        "patterns": [
            r"Failed to cache https?://",
            r"Failed to fetch https?://",
            r"404 Not Found",
            r"403 Forbidden",
            r"HTTP Error \d+",
            r"No matching distribution found",
        ],
        "hint": "Resource unavailable or URL changed. Check if the source is accessible.",
    },
    "missing_file": {
        "name": "Missing File/Directory",
        "patterns": [
            r"Desired working directory",
            r"is not available",
            r"No such file or directory",
            r"Source file .* not found",
            r"does not exist",
            r"File not found",
        ],
        "hint": "Required file/directory missing. May be caused by a prior failure.",
    },
    "package": {
        "name": "Package Installation Failed",
        "patterns": [
            r"Unable to locate package",
            r"Package .* has no installation candidate",
            r"dpkg.*error",
            r"apt-get.*failed",
            r"E: Unable to",
            r"Depends:.*but it is not",
            r"unmet dependencies",
            r"Problem encountered installing package",
            r"Couldn't find any package by regex",
        ],
        "hint": "Try: sudo apt-get update && sudo apt-get -f install",
    },
    "permission": {
        "name": "Permission Denied",
        "patterns": [
            r"Permission denied",
            r"Operation not permitted",
            r"Access denied",
            r"EACCES",
        ],
        "hint": "Check file permissions. Ensure running with appropriate privileges.",
    },
    "pip": {
        "name": "Python/Pip Issue",
        "patterns": [
            r"pip.*failed",
            r"Could not install packages",
            r"Failed building wheel",
            r"ModuleNotFoundError",
            r"ImportError",
            r"error: subprocess-exited-with-error",
            r"Failed to install packages:",
            r"InvalidVersion",
            r"Invalid version:",
            r"pip\._vendor\.packaging",
            r"ResolutionImpossible",
        ],
        "hint": "Python package installation failed. Check pip logs for details.",
        "specific_hints": {
            "InvalidVersion": "A package has a non-PEP-440 version string ('{bad_version}'). "
                             "Try: pip install --upgrade pip setuptools packaging",
            "ResolutionImpossible": "Dependency conflict - packages have incompatible version requirements.",
        },
    },
    "git": {
        "name": "Git Clone/Fetch Failed",
        "patterns": [
            r"git clone.*failed",
            r"fatal: early EOF",
            r"fetch-pack.*unexpected disconnect",
            r"RPC failed",
            r"Could not read from remote repository",
            r"Failed to check remote refs",
        ],
        "hint": "Git operation failed. Check network and repository availability.",
    },
    "gem": {
        "name": "Ruby Gem Issue",
        "patterns": [
            r"gem.*failed",
            r"Could not find a valid gem",
            r"ERROR:.*gem",
            r"Gem::.*Error",
            r"/gem\.py",
            r"states/gem\.py",
            r"modules/gem\.py",
        ],
        "hint": "Ruby gem installation failed. Check rubygems.org availability.",
    },
    "npm": {
        "name": "NPM/Node Issue",
        "patterns": [
            r"npm.*ERR!",
            r"Error installing.*git\+https://",
            r"npm install.*failed",
        ],
        "hint": "Node.js package installation failed. Check npm and network access.",
    },
    "command": {
        "name": "Command Execution Failed",
        "patterns": [
            r"Command .* failed with return code",
            r"non-zero exit status",
        ],
        "hint": "Shell command failed. Check the error details above.",
    },
}


# Patterns that indicate critical issues even in "successful" states
# These catch cases where a command returns exit code 0 but actually failed
CRITICAL_WARNING_PATTERNS = {
    "dns": {
        "name": "DNS Resolution Failures",
        "patterns": [
            r"Temporary failure resolving",
            r"Could not resolve host",
            r"Name or service not known",
            r"getaddrinfo.*failed",
        ],
        "impact": "Network operations and package downloads may fail",
    },
    "apt_fetch": {
        "name": "APT Repository Fetch Failures",
        "patterns": [
            r"W: Failed to fetch",
            r"W: Some index files failed to download",
            r"Err:\d+\s+https?://",
        ],
        "impact": "Package installation may fail due to outdated/missing package lists",
    },
    "network": {
        "name": "Network Connectivity Issues",
        "patterns": [
            r"Connection refused",
            r"Connection timed out",
            r"Network is unreachable",
        ],
        "impact": "Downloads and remote operations may fail",
    },
    "cpan": {
        "name": "CPAN Module Installation Failed",
        "patterns": [
            r"Could not expand \[",
            r"couldn't find a matching namespace",
            r"Skipping .* because I couldn't find",
        ],
        "impact": "Perl modules may not be installed despite successful state",
    },
}


# ============================================================================
# YAML Parsing (with fallback for systems without PyYAML)
# ============================================================================

def parse_yaml_fallback(content: str) -> dict:
    """
    Basic YAML parser for the results.yaml format.
    Handles the specific structure of Salt state results files.
    """
    result = {"local": {}}
    current_key = None
    current_entry = {}

    lines = content.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]

        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('#'):
            i += 1
            continue

        # Detect top-level 'local:' key
        if line == "local:":
            i += 1
            continue

        # Handle YAML complex key format: "  ? key_part1\n    key_part2\n  : ..."
        if line.startswith("  ? "):
            if current_key:
                result["local"][current_key] = current_entry
            # Collect the complex key (may span multiple lines)
            key_parts = [line[4:]]  # Remove "  ? "
            i += 1
            while i < len(lines):
                next_line = lines[i]
                if next_line.startswith("    ") and not next_line.startswith("     "):
                    # Continuation of key
                    key_parts.append(next_line.strip())
                    i += 1
                elif next_line.startswith("  : "):
                    # End of complex key, start of value
                    current_key = " ".join(key_parts).strip()
                    current_entry = {}
                    # The line after ": " might have field data
                    rest = next_line[4:]  # Remove "  : "
                    if rest.strip():
                        # Parse inline field like "  : __id__: value"
                        field_match = re.match(r"(\w+):\s*(.*)", rest.strip())
                        if field_match:
                            fkey, fval = field_match.groups()
                            current_entry[fkey] = fval.strip("'\"")
                    i += 1
                    break
                else:
                    # Unexpected format, skip
                    i += 1
                    break
            continue

        # Detect state entry key (2-space indent, ends with :)
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            if current_key:
                result["local"][current_key] = current_entry
            current_key = line.strip().rstrip(":")
            current_entry = {}
            i += 1
            continue

        # Parse entry fields (4-space indent)
        if line.startswith("    ") and not line.startswith("      "):
            match = re.match(r"    (\w+):\s*(.*)", line)
            if match:
                key, value = match.groups()

                # Handle multi-line values (block scalar, nested dict, or quoted continuation)
                if value.strip() == "" or value.strip() in ["|", ">", "|-", ">-"]:
                    i += 1
                    # Check if this is a nested dict (first line has "key: value" format)
                    if i < len(lines) and lines[i].startswith("      "):
                        first_nested = lines[i].strip()
                        # Match keys with word chars, hyphens, or underscores
                        if re.match(r'[\w-]+:\s*', first_nested):
                            # Parse as nested dict
                            nested_dict = {}
                            while i < len(lines) and lines[i].startswith("      "):
                                nested_line = lines[i].strip()
                                nested_match = re.match(r"([\w-]+):\s*(.*)", nested_line)
                                if nested_match:
                                    nkey, nval = nested_match.groups()
                                    # Handle quoted multi-line values in nested dict
                                    if nval.startswith("'") and not nval.endswith("'"):
                                        # Multi-line quoted value
                                        nval_parts = [nval[1:]]  # Remove opening quote
                                        i += 1
                                        while i < len(lines):
                                            cont = lines[i]
                                            if cont.startswith("        "):
                                                stripped = cont.strip()
                                                if stripped.endswith("'"):
                                                    nval_parts.append(stripped[:-1])
                                                    i += 1
                                                    break
                                                nval_parts.append(stripped)
                                                i += 1
                                            else:
                                                break
                                        nested_dict[nkey] = " ".join(nval_parts)
                                    else:
                                        # Simple value - strip quotes
                                        nested_dict[nkey] = nval.strip("'\"")
                                        i += 1
                                else:
                                    i += 1
                            current_entry[key] = nested_dict
                            continue
                    # Fall back to joining as string
                    multi_value = []
                    while i < len(lines) and (lines[i].startswith("      ") or lines[i].strip() == ""):
                        if lines[i].strip():
                            multi_value.append(lines[i].strip())
                        i += 1
                    current_entry[key] = " ".join(multi_value)
                    continue
                elif (value.startswith('"') and not value.endswith('"')) or (value.startswith("'") and not value.endswith("'")):
                    multi_value = [value.lstrip("'\"")]
                    i += 1
                    while i < len(lines):
                        cont_line = lines[i]
                        if cont_line.startswith("      "):
                            stripped = cont_line.strip().rstrip("\\").rstrip()
                            if stripped.endswith('"') or stripped.endswith("'"):
                                multi_value.append(stripped[:-1])
                                i += 1
                                break
                            multi_value.append(stripped)
                            i += 1
                        else:
                            break
                    full_value = " ".join(multi_value)
                    full_value = full_value.replace("\\n", "\n").replace('\\"', '"')
                    current_entry[key] = full_value
                    continue
                elif value.startswith("'") and value.endswith("'"):
                    current_entry[key] = value[1:-1]
                elif value.startswith('"') and value.endswith('"'):
                    current_entry[key] = value[1:-1]
                elif value == "true":
                    current_entry[key] = True
                elif value == "false":
                    current_entry[key] = False
                elif value in ("null", "~"):
                    current_entry[key] = None
                elif value == "{}":
                    current_entry[key] = {}
                else:
                    # Try parsing as number, fall back to string
                    try:
                        current_entry[key] = float(value) if "." in value else int(value)
                    except (ValueError, OverflowError):
                        current_entry[key] = value.strip("'\"")

        i += 1

    if current_key:
        result["local"][current_key] = current_entry

    return result


def load_results(filepath: Path) -> dict:
    """
    Load and parse the results.yaml file.
    Raises PermissionError if file cannot be read due to permissions.
    """
    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except PermissionError:
        raise PermissionError(f"Cannot read {filepath} - permission denied")

    if HAS_YAML:
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            print(f"Warning: YAML parsing error, using fallback parser: {e}", file=sys.stderr)
            return parse_yaml_fallback(content)
    return parse_yaml_fallback(content)


# ============================================================================
# Failure Analysis
# ============================================================================

class FailedState:
    """Represents a failed salt state with parsed metadata."""

    def __init__(self, key: str, data: dict):
        self.key = key
        self.data = data
        self.state_id = data.get("__id__", key)
        self.sls_file = data.get("__sls__", "unknown")
        self.comment = str(data.get("comment", ""))
        self.name = data.get("name", "")
        self.run_num = data.get("__run_num__", 0)

        # Extract stderr/retcode from changes dict (for cmd.run states)
        changes = data.get("changes", {})
        if isinstance(changes, dict):
            self.stderr = str(changes.get("stderr", "")) if changes.get("stderr") else ""
            self.retcode = changes.get("retcode")
        else:
            self.stderr = ""
            self.retcode = None

        # Parse state type from key (format: type_|-id_|-name_|-function)
        parts = key.split("_|-")
        self.state_type = parts[0] if parts else "unknown"

        # Determine if this is a cascade failure
        self.is_cascade = "One or more requisite failed:" in self.comment

        # Extract failed requisites
        self.failed_requisites = []
        if self.is_cascade:
            match = re.search(r"One or more requisite failed:\s*(.+)", self.comment, re.DOTALL)
            if match:
                reqs = match.group(1).replace("\n", " ").strip()
                self.failed_requisites = [r.strip() for r in reqs.split(",")]

        self.category = self._categorize()

    def _categorize(self) -> Optional[str]:
        """Determine error category based on comment content and context."""
        if self.is_cascade:
            return None

        # Match against error patterns using BOTH comment and stderr
        search_text = f"{self.comment} {self.stderr}"
        for cat_id, cat_info in ERROR_CATEGORIES.items():
            for pattern in cat_info["patterns"]:
                if re.search(pattern, search_text, re.IGNORECASE):
                    return cat_id

        # Fallback: infer from sls file path
        sls = self.sls_file.lower()
        if ".rubygems." in sls:
            return "gem"
        if ".python3-packages." in sls:
            return "pip"
        if ".node-packages." in sls:
            return "npm"
        if ".perl-packages." in sls:
            return "command"

        return "unknown"

    @property
    def tool_name(self) -> str:
        """Extract human-readable tool name from sls file."""
        if not self.sls_file:
            return "unknown"
        parts = self.sls_file.split(".")
        return parts[-1] if len(parts) >= 2 else self.sls_file

    @property
    def short_id(self) -> str:
        """Get shortened state ID for display."""
        short = self.state_id
        for prefix in ("remnux-", "remnux_"):
            if short.startswith(prefix):
                return short[len(prefix):]
        return short


def analyze_failures(results: dict) -> tuple[list[FailedState], list[FailedState]]:
    """Analyze results and return (root_causes, cascade_failures)."""
    local = results.get("local", {})

    root_causes = []
    cascades = []

    for key, data in local.items():
        # Skip malformed entries
        if not isinstance(data, dict):
            continue
        if data.get("result") is False:
            failed = FailedState(key, data)
            (cascades if failed.is_cascade else root_causes).append(failed)

    # Sort by execution order
    root_causes.sort(key=lambda x: x.run_num)
    cascades.sort(key=lambda x: x.run_num)

    return root_causes, cascades


def build_cascade_tree(root_causes: list[FailedState],
                       cascades: list[FailedState]) -> dict[str, list[FailedState]]:
    """Build mapping from root cause state_id to cascade failures it caused."""
    tree = defaultdict(list)

    for cascade in cascades:
        for req in cascade.failed_requisites:
            parts = req.rsplit(".", 1)
            req_id = parts[-1] if parts else req

            for rc in root_causes:
                if rc.state_id == req_id or req.endswith(rc.state_id):
                    tree[rc.state_id].append(cascade)
                    break

    return tree


# ============================================================================
# Enhanced Analysis: Predecessor States, Skipped States, Context
# ============================================================================

def find_succeeded_predecessors(failed_state: FailedState, results: dict) -> list[dict]:
    """
    Find states in the same SLS file that succeeded and might be related.
    Returns list of dicts with state info.
    """
    predecessors = []
    local = results.get("local", {})

    for key, data in local.items():
        if not isinstance(data, dict):
            continue
        if data.get("__sls__") != failed_state.sls_file:
            continue
        if data.get("result") is not True:
            continue
        # Only include states that ran before the failed state
        if data.get("__run_num__", 0) >= failed_state.run_num:
            continue

        # Parse state type from key
        parts = key.split("_|-")
        state_type = parts[0] if parts else "unknown"

        predecessors.append({
            "state_id": data.get("__id__", key),
            "state_type": state_type,
            "name": data.get("name", ""),
            "run_num": data.get("__run_num__", 0),
        })

    return predecessors


def find_skipped_states(failed_state: FailedState, results: dict) -> list[dict]:
    """
    Find states in the same SLS file that were skipped (unless/onlyif conditions).
    These might explain why a resource is missing.
    """
    skipped = []
    local = results.get("local", {})

    for key, data in local.items():
        if not isinstance(data, dict):
            continue
        if data.get("__sls__") != failed_state.sls_file:
            continue

        comment = str(data.get("comment", ""))
        # Check for skipped conditions
        # Note: "onlyif condition is true" means the state RUNS (condition passed)
        # Only "onlyif condition is false" and "unless condition is true" indicate skipping
        if any(skip_indicator in comment for skip_indicator in [
            "unless condition is true",
            "onlyif condition is false",
        ]):
            parts = key.split("_|-")
            state_type = parts[0] if parts else "unknown"
            skipped.append({
                "state_id": data.get("__id__", key),
                "state_type": state_type,
                "name": data.get("name", ""),
                "comment": comment,
            })

    return skipped


def get_enhanced_hint(failed_state: FailedState, results: dict) -> Optional[str]:
    """
    Generate an enhanced hint based on predecessor state analysis.
    Returns a more specific hint if pattern is detected, else None.
    """
    # Check both comment and stderr for error indicators
    search_text = f"{failed_state.comment} {failed_state.stderr}"

    # Check if this is a missing file/directory error
    # Salt-specific patterns handle truncated comments that may not include the full message
    is_missing_error = any(p in search_text for p in [
        "does not exist", "not available", "No such file",
        "Source file", "not found", "File not found",
        "Local file source",  # Salt: truncated "Local file source ... does not exist"
        "Desired working directory"  # Salt: truncated "Desired working directory ... is not available"
    ])

    if not is_missing_error:
        return None

    # Extract path from error message
    path_match = re.search(r'["\']?(/[^\s"\']+)["\']?', search_text)
    if not path_match:
        return None
    missing_path = path_match.group(1)

    # Check for context-aware path hints
    for pattern, hint in MISSING_PATH_HINTS.items():
        if re.search(pattern, missing_path):
            # Check if a related predecessor succeeded
            predecessors = find_succeeded_predecessors(failed_state, results)

            # Look for pip/virtualenv states that succeeded
            for pred in predecessors:
                if pred["state_type"] in ("pip", "virtualenv"):
                    return (f"{hint}\n"
                            f"    Note: {pred['state_type']}.{pred['state_id']} succeeded, "
                            f"suggesting the package/virtualenv exists but internal structure changed.")

            return hint

    # Check for skipped states that might explain the missing resource
    skipped = find_skipped_states(failed_state, results)
    if skipped:
        skipped_names = [s["state_id"] for s in skipped[:3]]
        return (f"Required file/directory missing. "
                f"Note: These related states were skipped: {', '.join(skipped_names)}")

    return None


def group_root_causes_by_category(root_causes: list[FailedState]) -> dict[str, list[FailedState]]:
    """Group root causes by their error category for summarized display."""
    groups = defaultdict(list)
    for rc in root_causes:
        category = rc.category or "unknown"
        groups[category].append(rc)
    return groups


def map_warnings_to_root_causes(warnings: list['SuccessfulStateWarning'],
                                 root_causes: list[FailedState]) -> dict[str, list[str]]:
    """
    Map warning types to specific root causes they likely caused.
    Returns dict of warning_type -> list of affected tool names.
    """
    # Map warning types to related error categories
    warning_to_categories = {
        "dns": ["network", "download", "git"],
        "apt_fetch": ["package"],
        "network": ["network", "download", "git"],
        "cpan": ["command"],
    }

    mapping = defaultdict(list)

    # Get unique warning types present
    warning_types = {w.warning_type for w in warnings}

    for warn_type in warning_types:
        related_categories = warning_to_categories.get(warn_type, [])
        for rc in root_causes:
            if rc.category in related_categories:
                if rc.tool_name not in mapping[warn_type]:
                    mapping[warn_type].append(rc.tool_name)

    return dict(mapping)


# ============================================================================
# Successful State Warning Analysis
# ============================================================================

class SuccessfulStateWarning:
    """Represents a warning found in a successful state's output."""

    def __init__(self, key: str, data: dict, warning_type: str, matches: list[str]):
        self.key = key
        self.data = data
        self.state_id = data.get("__id__", key)
        self.sls_file = data.get("__sls__", "unknown")
        self.warning_type = warning_type
        self.matches = matches  # Actual matched warning text
        self.run_num = data.get("__run_num__", 0)

        # Get retcode from changes if available
        changes = data.get("changes", {})
        if isinstance(changes, dict):
            self.retcode = changes.get("retcode")
        else:
            self.retcode = None

    @property
    def tool_name(self) -> str:
        """Extract human-readable tool name from sls file."""
        if not self.sls_file:
            return "unknown"
        parts = self.sls_file.split(".")
        return parts[-1] if len(parts) >= 2 else self.sls_file

    @property
    def warning_name(self) -> str:
        """Get human-readable warning category name."""
        return CRITICAL_WARNING_PATTERNS.get(self.warning_type, {}).get("name", self.warning_type)

    @property
    def impact(self) -> str:
        """Get impact description for this warning type."""
        return CRITICAL_WARNING_PATTERNS.get(self.warning_type, {}).get("impact", "")


def analyze_successful_state_warnings(results: dict) -> list[SuccessfulStateWarning]:
    """
    Scan successful states for critical warning patterns.
    These are states that "succeeded" but contain errors in stdout/stderr.
    """
    local = results.get("local", {})
    warnings_found = []

    for key, data in local.items():
        # Skip malformed entries
        if not isinstance(data, dict):
            continue

        # Only check successful states
        if data.get("result") is not True:
            continue

        # Get text to search (stdout, stderr from changes dict)
        changes = data.get("changes", {})
        if not isinstance(changes, dict):
            continue

        search_text = ""
        stdout = changes.get("stdout", "")
        stderr = changes.get("stderr", "")
        if stdout:
            search_text += str(stdout) + "\n"
        if stderr:
            search_text += str(stderr)

        if not search_text.strip():
            continue

        # Check each warning pattern category
        for warn_type, warn_info in CRITICAL_WARNING_PATTERNS.items():
            matches = []
            for pattern in warn_info["patterns"]:
                # Extract context for each match
                for match in re.finditer(pattern, search_text, re.IGNORECASE):
                    # Get the line containing the match
                    start = search_text.rfind('\n', 0, match.start()) + 1
                    end = search_text.find('\n', match.end())
                    if end == -1:
                        end = len(search_text)
                    line = search_text[start:end].strip()
                    if line and line not in matches:
                        matches.append(line)

            if matches:
                warnings_found.append(
                    SuccessfulStateWarning(key, data, warn_type, matches[:10])  # Limit matches
                )

    # Sort by execution order
    warnings_found.sort(key=lambda x: x.run_num)

    return warnings_found


def count_potentially_affected_failures(warnings: list[SuccessfulStateWarning],
                                        root_causes: list[FailedState],
                                        cascades: list[FailedState]) -> int:
    """
    Estimate how many failures might be caused by warnings in successful states.
    This is a heuristic based on matching warning types to error categories.
    Only counts root causes since cascades don't have categories assigned.
    """
    if not warnings:
        return 0

    # Map warning types to related error categories
    # DNS/network failures can cause downloads to fail, which causes missing files
    warning_to_error_categories = {
        "dns": ["network", "download", "git", "missing_file"],
        "apt_fetch": ["package"],
        "network": ["network", "download", "git", "missing_file"],
        "cpan": ["command"],
    }

    affected_categories = set()
    for w in warnings:
        affected_categories.update(warning_to_error_categories.get(w.warning_type, []))

    # Count root cause failures in affected categories
    # (Cascades don't have categories assigned - they return None)
    count = 0
    for rc in root_causes:
        if rc.category in affected_categories:
            count += 1

    return count


# ============================================================================
# Output Formatting
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"  # Better than yellow for readability
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        for attr in ("RED", "ORANGE", "GREEN", "CYAN", "BLUE", "BOLD", "DIM", "RESET"):
            setattr(cls, attr, "")


def clean_text(text: str) -> str:
    """Clean up text by removing escape sequences and normalizing whitespace."""
    text = text.replace("\\n", " ")
    text = re.sub(r"\\\s*", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


class TracebackParser:
    """Extracts structured information from Python tracebacks."""

    # Pattern to match the final exception line in a traceback
    # Uses word boundary to correctly capture exception name after module path
    EXCEPTION_PATTERN = re.compile(
        r"^(?:(?P<module>[\w._]+)\.)?\b(?P<exception>[A-Z]\w*(?:Error|Exception|Warning|Version|Failure|Impossible)):\s*(?P<message>.+)$",
        re.MULTILINE
    )

    # Patterns to extract specific problematic values from exception messages
    VALUE_PATTERNS = [
        # pip InvalidVersion: Invalid version: '0.1.36ubuntu1'
        # Requires quotes to avoid matching f-string template in source code
        (r"Invalid version:\s*['\"]([^'\"]+)['\"]", "bad_version"),
        # ModuleNotFoundError: No module named 'foo'
        (r"No module named\s*['\"]([^'\"]+)['\"]", "missing_module"),
        # FileNotFoundError: [Errno 2] No such file or directory: '/path'
        (r"No such file or directory:\s*['\"]([^'\"]+)['\"]", "missing_file"),
        # PermissionError: [Errno 13] Permission denied: '/path'
        (r"Permission denied:\s*['\"]([^'\"]+)['\"]", "permission_denied_path"),
        # Package not found patterns
        (r"Could not find a version that satisfies.*from\s+(\S+)", "missing_package"),
        (r"No matching distribution found for\s+(\S+)", "missing_package"),
    ]

    @classmethod
    def parse(cls, text: str) -> dict:
        """
        Parse text containing a traceback and extract structured information.
        Returns dict with keys: exception_type, module, message, extracted_values, short_summary
        """
        result = {
            "exception_type": None,
            "module": None,
            "message": None,
            "extracted_values": {},
            "short_summary": None,
        }

        if not text:
            return result

        try:
            # Find the exception line (search entire text for exception pattern)
            match = cls.EXCEPTION_PATTERN.search(text)
            if match:
                result["module"] = match.group("module")
                result["exception_type"] = match.group("exception")
                result["message"] = match.group("message").strip()

                # Extract specific values from the message
                for pattern, value_name in cls.VALUE_PATTERNS:
                    value_match = re.search(pattern, text, re.IGNORECASE)
                    if value_match:
                        result["extracted_values"][value_name] = value_match.group(1)

                # Create short summary
                result["short_summary"] = cls._create_summary(result)
        except (re.error, AttributeError, IndexError):
            # If regex fails or groups are missing, return empty result
            pass

        return result

    @classmethod
    def _create_summary(cls, parsed: dict) -> Optional[str]:
        """Create a human-readable short summary of the exception."""
        exc_type = parsed.get("exception_type")
        values = parsed.get("extracted_values", {})

        if exc_type == "InvalidVersion" and "bad_version" in values:
            return f"Package version '{values['bad_version']}' is not PEP-440 compliant"
        if exc_type == "ModuleNotFoundError" and "missing_module" in values:
            return f"Python module '{values['missing_module']}' not installed"
        if "missing_file" in values:
            return f"File not found: {values['missing_file']}"
        if exc_type == "ResolutionImpossible":
            return "Package dependency conflict"

        # Fallback to exception type and message
        if exc_type and parsed.get("message"):
            msg = parsed["message"]
            if len(msg) > 80:
                msg = msg[:77] + "..."
            return f"{exc_type}: {msg}"

        return None


def format_category(category: Optional[str]) -> str:
    """Format error category for display."""
    if not category:
        return ""
    if category == "unknown":
        return f"{Colors.DIM}[Unknown Error]{Colors.RESET}"
    cat_info = ERROR_CATEGORIES.get(category, {})
    name = cat_info.get("name", category.title())
    return f"{Colors.BLUE}[{name}]{Colors.RESET}"


def format_hint(category: Optional[str], exception_type: str = None,
                extracted_values: dict = None) -> str:
    """
    Get the hint for an error category, with optional specific hint override.
    If exception_type matches a specific_hints entry, use that instead.
    Extracted values are interpolated into the hint.
    """
    if not category or category == "unknown":
        return ""

    cat_info = ERROR_CATEGORIES.get(category, {})

    # Check for specific hint based on exception type
    if exception_type and "specific_hints" in cat_info:
        specific_hint = cat_info["specific_hints"].get(exception_type)
        if specific_hint:
            # Interpolate extracted values
            if extracted_values:
                try:
                    return specific_hint.format(**extracted_values)
                except KeyError:
                    # If a placeholder is missing, use the template as-is
                    return specific_hint
            return specific_hint

    return cat_info.get("hint", "")


def _print_wrapped_error(text: str, max_len: int = 500):
    """Print error text with word wrapping."""
    error_text = clean_text(text)
    if len(error_text) > max_len:
        error_text = error_text[:max_len] + "..."
    # Simple word wrap at ~74 chars with 4-space indent
    words = error_text.split()
    current_line = ""
    indent = "    "
    for word in words:
        if not current_line:
            current_line = word
        elif len(indent) + len(current_line) + 1 + len(word) > TEXT_WRAP_WIDTH:
            print(indent + current_line)
            current_line = word
        else:
            current_line += " " + word
    if current_line:
        print(indent + current_line)


def print_report(root_causes: list[FailedState],
                 cascades: list[FailedState],
                 cascade_tree: dict[str, list[FailedState]],
                 log_parser: Optional['LogParser'] = None,
                 has_warnings: bool = False,
                 results: dict = None):
    """Print diagnostic report with cascade trees and log details."""
    if not root_causes and not cascades:
        if not has_warnings:
            print(f"\n{Colors.GREEN}✓ All states completed successfully!{Colors.RESET}\n")
        return

    # Header
    print(f"\n{Colors.BOLD}{'═' * REPORT_WIDTH}{Colors.RESET}")
    print(f"{Colors.BOLD}REMnux Salt State Diagnostic Report{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * REPORT_WIDTH}{Colors.RESET}\n")

    print(f"{Colors.RED}✗ {len(root_causes)} root cause failure(s){Colors.RESET} → "
          f"{Colors.ORANGE}{len(cascades)} cascaded failure(s){Colors.RESET}\n")

    # Group root causes by category for summary if many failures
    if len(root_causes) > 5:
        groups = group_root_causes_by_category(root_causes)
        # Check if any category has multiple failures
        multi_category = {cat: rcs for cat, rcs in groups.items() if len(rcs) > 2}
        if multi_category:
            print(f"{Colors.DIM}Category summary:{Colors.RESET}")
            for cat, rcs in sorted(multi_category.items(), key=lambda x: len(x[1]), reverse=True):
                cat_name = ERROR_CATEGORIES.get(cat, {}).get("name", cat.title())
                tools = ", ".join(rc.tool_name for rc in rcs[:5])
                if len(rcs) > 5:
                    tools += f", ... (+{len(rcs) - 5} more)"
                print(f"  • {cat_name}: {len(rcs)} failures ({tools})")
            print()

    for i, rc in enumerate(root_causes, 1):
        cat_display = format_category(rc.category)
        cascade_failures = cascade_tree.get(rc.state_id, [])

        print(f"{Colors.BOLD}[{i}/{len(root_causes)}] {rc.tool_name}{Colors.RESET} {cat_display}")
        print(f"{Colors.DIM}    State: {rc.state_id}{Colors.RESET}")
        print(f"{Colors.DIM}    File:  {rc.sls_file}{Colors.RESET}")

        # Get detailed error from log if available
        log_context = log_parser.get_error_context(rc) if log_parser else None

        # Track exception type and extracted values for hints
        exception_type = None
        extracted_values = {}

        if log_context:
            # Extract traceback info for hints
            if log_context.get("traceback_info"):
                exception_type = log_context["traceback_info"].get("exception_type")
            extracted_values = log_context.get("extracted_values", {})

            # Display error from log
            error_text = log_context.get("error_text")
            if error_text:
                print(f"\n    {Colors.RED}Error (from log):{Colors.RESET}")
                for line in error_text.split('\n'):
                    print(f"    {line}")
            else:
                # Fallback to comment
                print(f"\n    {Colors.RED}Error:{Colors.RESET}")
                _print_wrapped_error(rc.comment)
        else:
            # No log context - use comment and stderr from results.yaml
            print(f"\n    {Colors.RED}Error:{Colors.RESET}")

            # Prefer stderr if it contains error indicators (E:, ERROR, etc.)
            stderr_has_error = rc.stderr and any(
                indicator in rc.stderr for indicator in ('E: ', 'ERROR', 'Error:', 'error:', 'failed')
            )
            if stderr_has_error:
                _print_wrapped_error(rc.stderr)
            else:
                _print_wrapped_error(rc.comment)

        # Generate hint - try enhanced hint first, then standard hint
        hint = None
        if results:
            hint = get_enhanced_hint(rc, results)
        if not hint:
            hint = format_hint(rc.category, exception_type, extracted_values)
        if hint:
            print(f"\n    {Colors.CYAN}Hint: {hint}{Colors.RESET}")

        if cascade_failures:
            print(f"\n    {Colors.ORANGE}Cascaded failures ({len(cascade_failures)}):{Colors.RESET}")
            by_tool = defaultdict(list)
            for cf in cascade_failures:
                by_tool[cf.tool_name].append(cf)
            for tool, failures in sorted(by_tool.items()):
                if len(failures) == 1:
                    print(f"      └─ {tool}: {failures[0].short_id}")
                else:
                    print(f"      └─ {tool}: {len(failures)} states affected")

        print(f"\n{Colors.DIM}{'─' * REPORT_WIDTH}{Colors.RESET}\n")

    # Orphan cascades with improved summary for large sets
    linked = {c.state_id for lst in cascade_tree.values() for c in lst}
    orphans = [c for c in cascades if c.state_id not in linked]
    if orphans:
        print(f"{Colors.ORANGE}Additional cascade failures (indirect):{Colors.RESET}")

        # Group by SLS category for better summary when many orphans
        if len(orphans) > 15:
            by_category = defaultdict(list)
            for orphan in orphans:
                parts = orphan.sls_file.split(".")
                category = parts[1] if len(parts) > 1 else "other"
                by_category[category].append(orphan)

            for category, items in sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True):
                if len(items) > 3:
                    sample = ", ".join(i.tool_name for i in items[:3])
                    print(f"  • {category}: {len(items)} states ({sample}, ...)")
                else:
                    for item in items:
                        print(f"  • {item.tool_name}: {item.short_id}")
        else:
            for orphan in orphans[:10]:
                print(f"  • {orphan.tool_name}: {orphan.short_id}")
            if len(orphans) > 10:
                print(f"  ... and {len(orphans) - 10} more")
        print()


def print_warnings_section(warnings: list[SuccessfulStateWarning],
                           num_failures: int,
                           potentially_affected: int,
                           root_causes: list[FailedState] = None):
    """Print section about warnings found in successful states."""
    if not warnings:
        return

    # Deduplicate warnings by type (show one example per type)
    by_type: dict[str, list[SuccessfulStateWarning]] = defaultdict(list)
    for w in warnings:
        by_type[w.warning_type].append(w)

    # Map warnings to affected root causes
    warning_to_root_causes = {}
    if root_causes:
        warning_to_root_causes = map_warnings_to_root_causes(warnings, root_causes)

    print(f"\n{Colors.BOLD}{'═' * REPORT_WIDTH}{Colors.RESET}")
    print(f"{Colors.BOLD}Warnings in Successful States{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * REPORT_WIDTH}{Colors.RESET}\n")

    print(f"{Colors.ORANGE}⚠ Found {len(warnings)} state(s) that succeeded but contain error indicators.{Colors.RESET}")
    if potentially_affected > 0:
        print(f"{Colors.DIM}  These may have caused up to {potentially_affected} of the {num_failures} failures above.{Colors.RESET}")
    print()

    for warn_type, warns in sorted(by_type.items()):
        # Pick the first warning of this type as representative
        representative = warns[0]
        warn_info = CRITICAL_WARNING_PATTERNS.get(warn_type, {})

        print(f"{Colors.ORANGE}[{warn_info.get('name', warn_type)}]{Colors.RESET}")
        print(f"{Colors.DIM}    State: {representative.state_id}{Colors.RESET}")
        if representative.retcode is not None:
            print(f"{Colors.DIM}    Exit code: {representative.retcode} (success){Colors.RESET}")

        # Show sample of matched warnings
        print(f"\n    {Colors.ORANGE}Detected issues:{Colors.RESET}")
        shown = set()
        for w in warns:
            for match in w.matches[:3]:  # Limit per warning
                # Truncate long matches
                display = match if len(match) <= 70 else match[:67] + "..."
                if display not in shown:
                    print(f"      • {display}")
                    shown.add(display)
                if len(shown) >= 5:  # Max 5 unique examples per type
                    break
            if len(shown) >= 5:
                break

        # Count additional warnings not shown
        total_matches = sum(len(w.matches) for w in warns)
        if total_matches > len(shown):
            print(f"      {Colors.DIM}... and {total_matches - len(shown)} more{Colors.RESET}")

        # Show impact
        impact = warn_info.get("impact", "")
        if impact:
            print(f"\n    {Colors.CYAN}Impact: {impact}{Colors.RESET}")

        # Show affected root causes for this warning type
        affected = warning_to_root_causes.get(warn_type, [])
        if affected:
            tools_list = ", ".join(affected[:5])
            if len(affected) > 5:
                tools_list += f", ... (+{len(affected) - 5} more)"
            print(f"\n    {Colors.RED}Likely affected: {tools_list}{Colors.RESET}")

        if len(warns) > 1:
            print(f"\n    {Colors.DIM}({len(warns)} states affected by this issue){Colors.RESET}")

        print(f"\n{Colors.DIM}{'─' * REPORT_WIDTH}{Colors.RESET}\n")


# ============================================================================
# Log File Parsing
# ============================================================================

class LogParser:
    """Parses saltstack.log to extract error context for failed states."""

    def __init__(self, log_path: Optional[Path]):
        self.content = ""
        self.state_sections: dict[str, str] = {}
        self.load_error: Optional[str] = None

        if log_path and log_path.exists():
            try:
                self.content = log_path.read_text(encoding='utf-8', errors='replace')
                self._index_states()
            except PermissionError:
                self.load_error = f"Cannot read {log_path} - permission denied"
            except (OSError, IOError) as e:
                self.load_error = f"Cannot read {log_path}: {e}"

    def _index_states(self):
        """Build index of state names to their log sections."""
        pattern = r"# \[INFO\s*\] Running state \[([^\]]+)\].*?# \[INFO\s*\] Completed state \[\1\]"
        for match in re.finditer(pattern, self.content, re.DOTALL):
            self.state_sections[match.group(1)] = match.group(0)

    def get_error_context(self, state: FailedState) -> Optional[dict]:
        """
        Extract error context for a failed state.
        Returns dict with: error_text, traceback_info, extracted_values
        """
        if not self.content:
            return None

        # Find section
        section = self.state_sections.get(state.name)
        if not section:
            for key, sec in self.state_sections.items():
                if state.state_id in key or state.name in key:
                    section = sec
                    break

        if not section:
            return None

        result = {
            "error_text": None,
            "traceback_info": None,
            "extracted_values": {},
        }

        # Check for tracebacks and parse them
        traceback_match = re.search(
            r'Traceback \(most recent call last\):.*?(?=\n#\s*\[|\n\n|$)',
            section,
            re.DOTALL
        )
        if traceback_match:
            tb_text = traceback_match.group(0)
            result["traceback_info"] = TracebackParser.parse(tb_text)
            result["extracted_values"].update(
                result["traceback_info"].get("extracted_values", {})
            )

        # Extract ERROR lines with continuations
        errors = []
        lines = section.split('\n')
        skip_patterns = {'stdout:', 'stderr:', 'retcode: 1', 'retcode: 2',
                         'retcode: 100', 'retcode: 128'}
        i = 0
        while i < len(lines):
            line = lines[i]
            if '# [ERROR' in line:
                error_text = re.sub(r'^#\s*\[ERROR\s*\]\s*', '', line).strip()
                if error_text in skip_patterns:
                    i += 1
                    continue

                # Collect continuation lines
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if next_line.startswith('# [') or not next_line.strip():
                        break
                    error_text += " " + next_line.strip()
                    j += 1

                if error_text:
                    errors.append(error_text)
            i += 1

        # Use traceback summary if available, otherwise use error lines
        if result["traceback_info"] and result["traceback_info"].get("short_summary"):
            result["error_text"] = result["traceback_info"]["short_summary"]
        elif errors:
            # Prioritize non-traceback error lines for display
            useful = [e for e in errors if 'Traceback' not in e and 'File "/' not in e]
            display_errors = useful if useful else errors

            # Deduplicate and limit
            seen = set()
            unique = []
            for err in display_errors:
                key = err[:80]
                if key not in seen:
                    seen.add(key)
                    unique.append(err)

            result["error_text"] = self._format_errors(unique[:2])

        return result if (result["error_text"] or result["traceback_info"]) else None

    def _format_errors(self, errors: list[str]) -> str:
        """Format error messages for display."""
        formatted = []
        for err in errors:
            err = re.sub(r'^(stdout|stderr):\s*', '', err)
            if len(err) > 300:
                err = err[:300] + "..."
            formatted.append(err)
        return "\n".join(formatted)


# ============================================================================
# Main Entry Point
# ============================================================================

def check_file_readable(path: Path) -> tuple[bool, Optional[str]]:
    """
    Check if a file exists and is readable.
    Returns (is_readable, error_message).
    """
    if not path.exists():
        return False, None  # Not found, no error
    if not path.is_file():
        return False, f"Not a regular file: {path}"
    if not os.access(path, os.R_OK):
        return False, f"Permission denied: {path}"
    return True, None


def find_results_file(specified: Optional[str]) -> tuple[Optional[Path], Optional[str]]:
    """
    Find the results file, checking multiple locations if needed.
    If specified is a directory, look for results.yaml in that directory.
    Returns (path, error_message). Error is set if file exists but isn't readable.
    """
    if specified:
        path = Path(specified)
        
        # If it's a directory, look for results.yaml inside it
        if path.is_dir():
            for name in ("results.yaml", "results.yml"):
                candidate = path / name
                readable, error = check_file_readable(candidate)
                if error:
                    return None, error
                if readable:
                    return candidate, None
            # Directory exists but no results file found inside
            return None, None
        
        # It's a file path
        readable, error = check_file_readable(path)
        if error:
            return None, error
        return (path, None) if readable else (None, None)

    for path in DEFAULT_RESULTS_PATHS:
        readable, error = check_file_readable(path)
        if error:
            return None, error  # File exists but not readable
        if readable:
            return path, None

    return None, None


def find_log_file(results_path: Path, specified: Optional[str]) -> tuple[Optional[Path], Optional[str]]:
    """
    Find the saltstack.log file.
    Returns (path, error_message). Error is set if file exists but isn't readable.
    """
    if specified:
        path = Path(specified)
        readable, error = check_file_readable(path)
        if error:
            return None, error
        return (path, None) if readable else (None, None)

    # Look in same directory as results file
    auto_log = results_path.parent / LOG_FILENAME
    readable, error = check_file_readable(auto_log)
    if readable:
        return auto_log, None
    # Don't report error for auto-detected files, just skip them

    # Also check current directory
    cwd_log = Path(LOG_FILENAME)
    readable, error = check_file_readable(cwd_log)
    if readable:
        return cwd_log, None

    return None, None


def print_permission_hint():
    """Print a hint about running with sudo."""
    print(f"{Colors.DIM}Hint: Log files may require elevated privileges. "
          f"Try: sudo {Path(sys.argv[0]).name} ...{Colors.RESET}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Diagnose REMnux salt-state installation failures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default path
  %(prog)s /path/to/logs/               # Specify directory containing logs
  %(prog)s /path/to/results.yaml        # Specify results file directly
  %(prog)s --log /path/to/saltstack.log # Specify log file location
        """
    )

    parser.add_argument(
        "results_file",
        nargs="?",
        help="Path to results.yaml or directory containing it (default: /var/cache/cast/installer/logs/)"
    )

    parser.add_argument(
        "--log", "-l",
        type=str,
        metavar="FILE",
        help="Path to saltstack.log for additional error context"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    # Disable colors if requested or not a TTY
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Find results file
    results_path, results_error = find_results_file(args.results_file)

    if results_error:
        # File exists but not readable (permission issue)
        print(f"{Colors.RED}Error:{Colors.RESET} {results_error}", file=sys.stderr)
        print_permission_hint()
        sys.exit(1)

    if not results_path:
        # File not found
        if args.results_file and Path(args.results_file).is_dir():
            print(f"{Colors.RED}Error:{Colors.RESET} No results.yaml found in directory: {args.results_file}")
        else:
            searched = args.results_file or ", ".join(str(p) for p in DEFAULT_RESULTS_PATHS)
            print(f"{Colors.RED}Error:{Colors.RESET} Results file not found: {searched}")
        sys.exit(1)

    # Find log file
    log_path, log_error = find_log_file(results_path, args.log)

    if log_error:
        # Explicitly specified log file has permission issue
        print(f"{Colors.ORANGE}Warning:{Colors.RESET} {log_error}", file=sys.stderr)
        print_permission_hint()
        log_path = None
    elif args.log and not log_path:
        # Explicitly specified log file not found
        print(f"{Colors.ORANGE}Warning:{Colors.RESET} Log file not found: {args.log}",
              file=sys.stderr)

    # Load and parse results
    try:
        results = load_results(results_path)
    except PermissionError as e:
        print(f"{Colors.RED}Error:{Colors.RESET} {e}", file=sys.stderr)
        print_permission_hint()
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Error:{Colors.RESET} Failed to parse results file: {e}")
        sys.exit(1)

    if not results or "local" not in results:
        print(f"{Colors.RED}Error:{Colors.RESET} Invalid results file format")
        sys.exit(1)

    # Initialize log parser
    log_parser = None
    if log_path:
        log_parser = LogParser(log_path)
        if log_parser.load_error:
            print(f"{Colors.ORANGE}Warning:{Colors.RESET} {log_parser.load_error}",
                  file=sys.stderr)
            log_parser = None

    # Analyze failures and warnings
    root_causes, cascades = analyze_failures(results)
    cascade_tree = build_cascade_tree(root_causes, cascades)
    successful_warnings = analyze_successful_state_warnings(results)

    # Print main report (pass has_warnings to suppress misleading success message)
    print_report(root_causes, cascades, cascade_tree, log_parser,
                 has_warnings=bool(successful_warnings), results=results)

    # Print warnings section if there are hidden issues in successful states
    if successful_warnings:
        num_failures = len(root_causes) + len(cascades)
        potentially_affected = count_potentially_affected_failures(
            successful_warnings, root_causes, cascades
        )
        print_warnings_section(successful_warnings, num_failures, potentially_affected,
                               root_causes=root_causes)

        # If no failures but warnings exist, show a qualified success message
        if not root_causes and not cascades:
            print(f"{Colors.ORANGE}⚠ All states completed, but some contain warnings "
                  f"that may indicate issues.{Colors.RESET}\n")

    sys.exit(1 if root_causes else 0)


if __name__ == "__main__":
    main()

