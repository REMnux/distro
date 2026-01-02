#!/usr/bin/env python3
"""
REMnux Salt State Diagnostic Tool

Analyzes salt-states results to identify root causes of failures and their
cascading effects. Helps diagnose issues from 'remnux upgrade' or 'remnux install'.

Usage:
    remnux-diag.py [results.yaml] [--log saltstack.log]

File locations (checked in order if not specified):
    1. /var/cache/cast/installer/logs/results.yaml
    2. ./results.yaml (current directory)
"""

import argparse
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


# ============================================================================
# Error Category Definitions
# ============================================================================

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
        ],
        "hint": "Python package installation failed. Check pip logs for details.",
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
        "hint": "Shell command failed. Run with -v for more details.",
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

                # Handle multi-line values (block scalar or quoted with continuation)
                if value.strip() == "" or value.strip() in ["|", ">", "|-", ">-"]:
                    multi_value = []
                    i += 1
                    while i < len(lines) and (lines[i].startswith("      ") or lines[i].strip() == ""):
                        if lines[i].strip():
                            multi_value.append(lines[i].strip())
                        i += 1
                    current_entry[key] = " ".join(multi_value)
                    continue
                elif value.startswith('"') or (value.startswith("'") and not value.endswith("'")):
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
                elif value == "true":
                    current_entry[key] = True
                elif value == "false":
                    current_entry[key] = False
                elif value in ("null", "~"):
                    current_entry[key] = None
                elif value == "{}":
                    current_entry[key] = {}
                else:
                    try:
                        current_entry[key] = float(value) if "." in value else int(value)
                    except ValueError:
                        current_entry[key] = value.strip("'\"")

        i += 1

    if current_key:
        result["local"][current_key] = current_entry

    return result


def load_results(filepath: Path) -> dict:
    """Load and parse the results.yaml file."""
    content = filepath.read_text(encoding='utf-8', errors='replace')

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

        # Match against error patterns
        for cat_id, cat_info in ERROR_CATEGORIES.items():
            for pattern in cat_info["patterns"]:
                if re.search(pattern, self.comment, re.IGNORECASE):
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


def format_category(category: Optional[str]) -> str:
    """Format error category for display."""
    if not category:
        return ""
    if category == "unknown":
        return f"{Colors.DIM}[Unknown Error]{Colors.RESET}"
    cat_info = ERROR_CATEGORIES.get(category, {})
    name = cat_info.get("name", category.title())
    return f"{Colors.BLUE}[{name}]{Colors.RESET}"


def format_hint(category: Optional[str]) -> str:
    """Get the hint for an error category."""
    if not category or category == "unknown":
        return ""
    return ERROR_CATEGORIES.get(category, {}).get("hint", "")


def print_report(root_causes: list[FailedState],
                 cascades: list[FailedState],
                 cascade_tree: dict[str, list[FailedState]],
                 log_parser: Optional['LogParser'] = None):
    """Print diagnostic report with cascade trees and log details."""
    if not root_causes and not cascades:
        print(f"\n{Colors.GREEN}✓ All states completed successfully!{Colors.RESET}\n")
        return

    # Header
    print(f"\n{Colors.BOLD}{'═' * 78}{Colors.RESET}")
    print(f"{Colors.BOLD}REMnux Salt State Diagnostic Report{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 78}{Colors.RESET}\n")

    print(f"{Colors.RED}✗ {len(root_causes)} root cause failure(s){Colors.RESET} → "
          f"{Colors.ORANGE}{len(cascades)} cascaded failure(s){Colors.RESET}\n")

    for i, rc in enumerate(root_causes, 1):
        cat_display = format_category(rc.category)
        cascade_failures = cascade_tree.get(rc.state_id, [])

        print(f"{Colors.BOLD}[{i}/{len(root_causes)}] {rc.tool_name}{Colors.RESET} {cat_display}")
        print(f"{Colors.DIM}    State: {rc.state_id}{Colors.RESET}")
        print(f"{Colors.DIM}    File:  {rc.sls_file}{Colors.RESET}")

        # Get detailed error from log if available
        log_error = log_parser.get_error_context(rc) if log_parser else None

        if log_error:
            print(f"\n    {Colors.RED}Error (from log):{Colors.RESET}")
            for line in log_error.split('\n'):
                print(f"    {line}")
        else:
            print(f"\n    {Colors.RED}Error:{Colors.RESET}")
            error_text = clean_text(rc.comment)
            if len(error_text) > 500:
                error_text = error_text[:500] + "..."
            # Simple word wrap at ~74 chars
            words = error_text.split()
            current = "    "
            for word in words:
                if len(current) + len(word) + 1 > 78:
                    print(current)
                    current = "    " + word
                else:
                    current += (" " + word) if current.strip() else ("    " + word)
            if current.strip():
                print(current)

        hint = format_hint(rc.category)
        if hint:
            print(f"\n    {Colors.CYAN}💡 {hint}{Colors.RESET}")

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

        print(f"\n{Colors.DIM}{'─' * 78}{Colors.RESET}\n")

    # Orphan cascades
    linked = {c.state_id for lst in cascade_tree.values() for c in lst}
    orphans = [c for c in cascades if c.state_id not in linked]
    if orphans:
        print(f"{Colors.ORANGE}Additional cascade failures (indirect):{Colors.RESET}")
        for orphan in orphans[:10]:
            print(f"  • {orphan.tool_name}: {orphan.short_id}")
        if len(orphans) > 10:
            print(f"  ... and {len(orphans) - 10} more")
        print()


# ============================================================================
# Log File Parsing
# ============================================================================

class LogParser:
    """Parses saltstack.log to extract error context for failed states."""

    def __init__(self, log_path: Optional[Path]):
        self.content = ""
        self.state_sections: dict[str, str] = {}

        if log_path and log_path.exists():
            try:
                self.content = log_path.read_text(encoding='utf-8', errors='replace')
                self._index_states()
            except (OSError, IOError):
                pass

    def _index_states(self):
        """Build index of state names to their log sections."""
        pattern = r"# \[INFO\s*\] Running state \[([^\]]+)\].*?# \[INFO\s*\] Completed state \[\1\]"
        for match in re.finditer(pattern, self.content, re.DOTALL):
            self.state_sections[match.group(1)] = match.group(0)

    def get_error_context(self, state: FailedState) -> Optional[str]:
        """Extract concise error context for a failed state."""
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

        if not errors:
            return None

        # Prioritize non-traceback errors
        useful = [e for e in errors if 'Traceback' not in e and 'File "/' not in e]
        errors = useful if useful else errors

        # Deduplicate and limit
        seen = set()
        unique = []
        for err in errors:
            key = err[:80]
            if key not in seen:
                seen.add(key)
                unique.append(err)

        return self._format_errors(unique[:2])

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

def find_results_file(specified: Optional[str]) -> Optional[Path]:
    """Find the results file, checking multiple locations if needed."""
    if specified:
        path = Path(specified)
        return path if path.exists() else None

    for path in DEFAULT_RESULTS_PATHS:
        if path.exists():
            return path
    return None


def find_log_file(results_path: Path, specified: Optional[str]) -> Optional[Path]:
    """Find the saltstack.log file."""
    if specified:
        path = Path(specified)
        return path if path.exists() else None

    # Look in same directory as results file
    auto_log = results_path.parent / LOG_FILENAME
    if auto_log.exists():
        return auto_log

    # Also check current directory
    cwd_log = Path(LOG_FILENAME)
    if cwd_log.exists():
        return cwd_log

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Diagnose REMnux salt-state installation failures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default path
  %(prog)s /path/to/results.yaml        # Specify results file
  %(prog)s --log /path/to/saltstack.log # Specify log file location
        """
    )

    parser.add_argument(
        "results_file",
        nargs="?",
        help="Path to results.yaml (default: /var/cache/cast/installer/logs/results.yaml)"
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
    results_path = find_results_file(args.results_file)
    if not results_path:
        searched = args.results_file or ", ".join(str(p) for p in DEFAULT_RESULTS_PATHS)
        print(f"{Colors.RED}Error:{Colors.RESET} Results file not found: {searched}")
        sys.exit(1)

    # Find log file
    log_path = find_log_file(results_path, args.log)
    if args.log and not log_path:
        print(f"{Colors.ORANGE}Warning:{Colors.RESET} Log file not found: {args.log}",
              file=sys.stderr)

    # Load and parse results
    try:
        results = load_results(results_path)
    except Exception as e:
        print(f"{Colors.RED}Error:{Colors.RESET} Failed to parse results file: {e}")
        sys.exit(1)

    if not results or "local" not in results:
        print(f"{Colors.RED}Error:{Colors.RESET} Invalid results file format")
        sys.exit(1)

    # Initialize log parser
    log_parser = LogParser(log_path) if log_path else None

    # Analyze and report
    root_causes, cascades = analyze_failures(results)
    cascade_tree = build_cascade_tree(root_causes, cascades)
    print_report(root_causes, cascades, cascade_tree, log_parser)

    sys.exit(1 if root_causes else 0)


if __name__ == "__main__":
    main()

