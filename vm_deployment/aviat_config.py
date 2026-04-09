#!/usr/bin/env python3
"""
Aviat Radio Configuration Tool - SSH Backend
Batch credential & SNMP configuration for firmware 6.1.0 upgrades

Tested on: Aviat WTM4200 series

Usage:
    python aviat_config.py --ip 10.0.1.100
    python aviat_config.py --file radios.txt
    python aviat_config.py --ip 10.0.1.100 --tasks password
    python aviat_config.py --ip 10.0.1.100 --tasks snmp
    python aviat_config.py --ip 10.0.1.100 --tasks all
"""

import argparse
import sys
import time
import re
import csv
import json
import subprocess
import socket
import shutil
import ipaddress
import requests
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import warnings
try:
    import paramiko
    # Suppress TripleDES warnings from paramiko/cryptography
    warnings.filterwarnings("ignore", category=UserWarning, module='paramiko')
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    print("Error: paramiko not installed. Run: pip install paramiko")
    sys.exit(1)

try:
    import websockets.sync.client as ws_client
except Exception:
    ws_client = None

UPTIME_CHECK_TIMEOUT = int(os.getenv("AVIAT_UPTIME_CHECK_TIMEOUT", "5"))
LOGIN_TIMEOUT = int(os.getenv("AVIAT_WEB_LOGIN_TIMEOUT", "10"))


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Created once at module level to avoid tuple allocation on every function call.
_TRANSIENT_CLI_MARKERS = (
    "socket is closed",
    "not connected",
    "connection reset",
    "broken pipe",
    "timeout",
    "timed out",
    "channel closed",
    "connection refused",
    "eof",
)
_TRANSIENT_PROCESSING_MARKERS = (
    "unable to connect to port 22",
    "unable to connect",
    "connection failed",
    "connection timeout",
    "authentication failed",
    "ssh error",
    "device did not recover",
    "no existing session",
)


def _clean_cli_output(text: str) -> str:
    """Normalize CLI output so parsers are resilient to pager/ANSI noise."""
    if not text:
        return ""
    text = _ANSI_RE.sub("", text)
    # Remove pager artifacts that break command chaining and parsing.
    text = text.replace("--More--", "")
    text = text.replace("(END)", "")
    # Remove non-printable control chars but preserve line structure.
    text = _CTRL_RE.sub("", text)
    return text


# ============================================================================
# CONFIGURATION - Edit these values as needed
# ============================================================================

@dataclass
class Config:
    # Default credentials to login with
    default_username: str = os.getenv("AVIAT_USER", "admin")
    default_password: str = os.getenv("AVIAT_PASS", "admin")
    
    # New password to set
    new_password: str = os.getenv("AVIAT_NEW_PASS", "Fr3knL@zr!")
    
    # SNMP settings
    snmp_mode: str = os.getenv("SNMP_MODE", "v2c-only")
    snmp_community: str = os.getenv("SNMP_COMMUNITY", "FBZ1yYdphf")
    
    # SSH settings
    ssh_port: int = int(os.getenv("SSH_PORT", "22"))
    ssh_timeout: int = 30
    command_timeout: int = 10
    ssh_retries: int = int(os.getenv("SSH_RETRIES", "2"))
    
    # Parallel execution
    max_workers: int = int(os.getenv("MAX_WORKERS", "100"))
    
    # Tool Port
    port: int = int(os.getenv("PORT", "5001"))

    # Firmware settings
    firmware_base_uri: str = os.getenv(
        "AVIAT_FIRMWARE_BASE_URI", "http://143.55.35.76/updates"
    )
    firmware_baseline_uri: str = os.getenv(
        "AVIAT_FIRMWARE_BASELINE_URI",
        "http://143.55.35.76/updates/wtm4100-2.11.11.18.6069.swpack",
    )
    firmware_final_uri: str = os.getenv(
        "AVIAT_FIRMWARE_FINAL_URI",
        "http://192.168.11.118:8000/api/aviat/firmware/wtm4100-6.2.4.12.59373.swpack",
    )
    firmware_baseline_version: str = os.getenv("AVIAT_BASELINE_VERSION", "2.11.11")
    firmware_final_version: str = os.getenv("AVIAT_FINAL_VERSION", "6.2.4")
    firmware_activation_time: str = os.getenv("AVIAT_ACTIVATION_TIME", "02:00")
    firmware_activate_now: bool = os.getenv("AVIAT_ACTIVATE_NOW", "false").lower() in (
        "1",
        "true",
        "yes",
    )

    # SOP checks
    sop_checks_path: str = os.getenv("AVIAT_SOP_CHECKS_PATH", "")
    buffer_queue_limit: int = int(os.getenv("AVIAT_BUFFER_QUEUE_LIMIT", "2500"))

    # Firmware reconnect
    firmware_reconnect_timeout: int = int(os.getenv("AVIAT_RECONNECT_TIMEOUT", "900"))
    firmware_reconnect_interval: int = int(os.getenv("AVIAT_RECONNECT_INTERVAL", "10"))
    firmware_ping_timeout: int = int(os.getenv("AVIAT_PING_TIMEOUT", "3900"))
    firmware_ping_payload: int = int(os.getenv("AVIAT_PING_PAYLOAD", "1400"))
    firmware_post_activation_wait: int = int(os.getenv("AVIAT_POST_ACTIVATION_WAIT", "3900"))
    firmware_ping_check_interval: int = int(os.getenv("AVIAT_PING_CHECK_INTERVAL", "60"))
    firmware_ping_max_wait: int = int(os.getenv("AVIAT_PING_MAX_WAIT", "3600"))
    # Allow devices to complete long reboot/bootup before first reachability probe.
    firmware_first_check_delay: int = int(os.getenv("AVIAT_FIRST_CHECK_DELAY", "900"))
    reboot_initial_delay: int = int(os.getenv("AVIAT_REBOOT_INITIAL_DELAY", "900"))
    sop_recheck_attempts: int = int(os.getenv("AVIAT_SOP_RECHECK_ATTEMPTS", "3"))
    sop_recheck_delay: int = int(os.getenv("AVIAT_SOP_RECHECK_DELAY", "3"))


CONFIG = Config()


# ============================================================================
# SSH CONNECTION HANDLER
# ============================================================================

@dataclass
class RadioResult:
    """Result of configuring a single radio"""
    ip: str
    success: bool = False
    status: str = "completed"
    password_changed: bool = False
    snmp_configured: bool = False
    buffer_configured: bool = False
    firmware_downloaded: bool = False
    firmware_downloaded_version: Optional[str] = None
    firmware_scheduled: bool = False
    firmware_activated: bool = False
    sop_checked: bool = False
    sop_passed: bool = False
    sop_results: List[Dict[str, Any]] = field(default_factory=list)
    subnet_ok: Optional[bool] = None
    subnet_actual: Optional[str] = None
    license_ok: Optional[bool] = None
    license_detail: Optional[str] = None
    stp_ok: Optional[bool] = None
    stp_detail: Optional[str] = None
    target_version: Optional[str] = None
    firmware_version_before: Optional[str] = None
    firmware_version_after: Optional[str] = None
    error: Optional[str] = None
    output: List[str] = field(default_factory=list)
    duration: float = 0.0


class AviatSSHClient:
    """SSH client for Aviat WTM radio configuration"""
    
    def __init__(self, ip: str, username: str, password: str, port: int = 22):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client: Optional[paramiko.SSHClient] = None
        self.shell = None
        self.output_buffer = []
        
    def connect(self) -> bool:
        """Establish SSH connection"""
        last_error = None
        retries = max(0, CONFIG.ssh_retries)
        for attempt in range(retries + 1):
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                self.client.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=CONFIG.ssh_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )

                # Get interactive shell
                self.shell = self.client.invoke_shell(width=200, height=50)
                self.shell.settimeout(CONFIG.command_timeout)

                # Wait for initial prompt and clear buffer
                time.sleep(2)
                self._read_until_prompt()

                return True
            except paramiko.AuthenticationException:
                raise Exception("Authentication failed - check credentials")
            except (paramiko.SSHException, TimeoutError) as e:
                last_error = e
            except Exception as e:
                last_error = e
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
        if isinstance(last_error, paramiko.SSHException):
            raise Exception(f"SSH error: {last_error}")
        if isinstance(last_error, TimeoutError):
            raise Exception("Connection timeout")
        raise Exception(f"Connection failed: {last_error}")
    
    def _read_until_prompt(self, timeout: float = 5.0, prompt_patterns: List[str] = None) -> str:
        """Read output until we see a prompt or timeout"""
        if prompt_patterns is None:
            prompt_patterns = ['#', '>', ':', ']']
        
        output = ""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.shell.recv_ready():
                chunk = self.shell.recv(4096).decode('utf-8', errors='ignore')
                clean_chunk = _clean_cli_output(chunk)
                output += chunk
                self.output_buffer.append(chunk)

                # Handle paged output automatically so commands are not truncated.
                if "--More--" in clean_chunk or "(END)" in clean_chunk:
                    try:
                        self.shell.send(" ")
                    except Exception:
                        pass
                
                # Check if we hit a prompt
                stripped = output.strip()
                if stripped and any(stripped.endswith(p) for p in prompt_patterns):
                    # Give a tiny bit more time for any trailing output
                    time.sleep(0.1)
                    if self.shell.recv_ready():
                        chunk = self.shell.recv(4096).decode('utf-8', errors='ignore')
                        output += chunk
                        self.output_buffer.append(chunk)
                    break
            else:
                time.sleep(0.1)
                
        return output
    
    def send_command(self, command: str, wait_for: List[str] = None, timeout: float = 5.0) -> str:
        """Send a command and wait for response, stripping the echo if present"""
        if not self.shell:
            raise Exception("Not connected")
        
        if wait_for is None:
            wait_for = ['#', '>', ':', ']']
            
        # Clear any pending output first
        if self.shell.recv_ready():
            self.shell.recv(4096)
            
        self.shell.send(command + "\n")
        
        # We wait for the prompt
        output = self._read_until_prompt(timeout=timeout, prompt_patterns=wait_for)
        clean_output = _clean_cli_output(output)

        # Strip command echo from first matching line.
        if command:
            lines = clean_output.splitlines()
            removed = False
            filtered = []
            for line in lines:
                normalized = line.strip()
                if not removed and normalized:
                    # Handles both "show x" and "HOST# show x"
                    if normalized == command or normalized.endswith(f"# {command}") or normalized.endswith(f"> {command}"):
                        removed = True
                        continue
                filtered.append(line)
            clean_output = "\n".join(filtered)

        return clean_output.strip("\r\n")
    
    def send_password(self, password: str, timeout: float = 3.0) -> str:
        """Send a password (no echo expected)"""
        if not self.shell:
            raise Exception("Not connected")
            
        self.shell.send(password + "\n")
        time.sleep(0.5)
        return self._read_until_prompt(timeout=timeout)
    
    def close(self):
        """Close SSH connection"""
        if self.shell:
            try:
                self.shell.close()
            except:
                pass
        if self.client:
            try:
                self.client.close()
            except:
                pass
    
    def get_full_output(self) -> str:
        """Get all captured output"""
        return "".join(self.output_buffer)


# ============================================================================
# CONFIGURATION TASKS
# ============================================================================

def exit_config_mode(client: 'AviatSSHClient'):
    try:
        client.send_command("exit")
    except Exception:
        pass

def change_password(client: AviatSSHClient, callback=None) -> Tuple[bool, str]:
    """
    Change admin password on the radio.
    
    Based on Aviat WTM CLI:
    - Method 1: Use 'change-password' command (for changing own password)
    - Method 2: Use 'user admin password' in config mode (may not work for self)
    """
    log(f"  [{client.ip}] Changing admin password...", "info", callback=callback)
    
    try:
        # First, try the change-password command at root level
        # This is the recommended way to change your own password
        log(f"  [{client.ip}]   Trying 'change-password' command...", "info", callback=callback)
        
        output = client.send_command("change-password", wait_for=[':', '#', '>'])
        log(f"  [{client.ip}]   > change-password", "info", callback=callback)

        # Check if it's asking for current/old password
        lowered = output.lower()
        if 'current' in lowered or 'old' in lowered or 'password' in lowered:
            # Send current password
            output = client.send_password(CONFIG.default_password)
            log(f"  [{client.ip}]   > [current password]")

            # Send new password
            lowered = output.lower()
            if 'new' in lowered or 'password' in lowered:
                output = client.send_password(CONFIG.new_password)
                log(f"  [{client.ip}]   > [new password]")

                # Confirm new password
                lowered = output.lower()
                if 'confirm' in lowered or 'again' in lowered or 'retype' in lowered or 'password' in lowered:
                    output = client.send_password(CONFIG.new_password)
                    log(f"  [{client.ip}]   > [confirm password]")

            # Check for success
            time.sleep(1)
            final_output = client._read_until_prompt(timeout=3)
            final_lower = final_output.lower()

            if 'success' in final_lower or 'changed' in final_lower:
                log(f"  [{client.ip}] [OK] Password changed via change-password", "success")
                return True, "Password changed successfully"
            elif 'error' in final_lower or 'fail' in final_lower or 'invalid' in final_lower:
                log(f"  [{client.ip}]   change-password method failed, trying config mode...", "warning")
            else:
                # Might have worked, continue
                log(f"  [{client.ip}] [OK] Password change commands sent", "success")
                return True, "Password change commands sent"
        
        # If change-password didn't work or isn't available, try config terminal method
        log(f"  [{client.ip}]   Trying config terminal method...")
        
        # Enter config mode
        output = client.send_command("config terminal")
        log(f"  [{client.ip}]   > config terminal")
        
        if 'config' not in output.lower() and '#' not in output:
            # Try alternative
            output = client.send_command("configure terminal")
            log(f"  [{client.ip}]   > configure terminal")
        
        # Set password using user command
        # This sends: user admin password
        # Then waits for (<string>): prompt and sends the password
        output = client.send_command("user admin password", wait_for=[':', '#', '>'])
        log(f"  [{client.ip}]   > user admin password")
        lowered = output.lower()
        if ':' in output or 'string' in lowered:
            # It's prompting for the password
            output = client.send_password(CONFIG.new_password)
            log(f"  [{client.ip}]   > [new password entered]")
            lowered = output.lower()

        # Commit the changes
        output = client.send_command("commit", wait_for=['#', '>', '[', ':'], timeout=10)
        log(f"  [{client.ip}]   > commit")
        lowered = output.lower()

        # Check if commit asks for confirmation
        if '[' in output or 'yes' in lowered or 'confirm' in lowered:
            output = client.send_command("yes")
            log(f"  [{client.ip}]   > yes")
            lowered = output.lower()

        # Check for the specific error about using change-password
        if 'change-password' in lowered and 'please use' in lowered:
            log(f"  [{client.ip}]   ! Config method blocked - password must be changed via change-password", "warning")
            # Exit config mode
            client.send_command("exit")
            return False, "Use change-password command - cannot change own password via config"

        # Exit config mode
        exit_config_mode(client)
        log(f"  [{client.ip}]   > exit")

        # Check for errors
        if 'error' in lowered or 'invalid' in lowered or 'abort' in lowered:
            return False, f"Password change may have failed: {output[-200:]}"
        
        log(f"  [{client.ip}] [OK] Password change commands sent", "success")
        return True, "Password change commands sent"
        
    except Exception as e:
        log(f"  [{client.ip}] [FAIL] Password change error: {e}", "error")
        return False, str(e)


def configure_snmp(client: AviatSSHClient, callback=None) -> Tuple[bool, str]:
    """
    Configure SNMP settings on the radio.
    
    Based on Aviat WTM CLI (in config terminal mode):
    - snmp v2c-only
    - snmp community <string>
    - commit
    """
    log(f"  [{client.ip}] Configuring SNMP...", "info", callback=callback)
    
    try:
        # Enter config mode
        output = client.send_command("config terminal")
        log(f"  [{client.ip}]   > config terminal", "info", callback=callback)

        if 'config' not in output.lower() and '#' not in output:
            output = client.send_command("configure terminal")
            log(f"  [{client.ip}]   > configure terminal", "info", callback=callback)
        
        # Set SNMP mode
        output = client.send_command(f"snmp {CONFIG.snmp_mode}")
        log(f"  [{client.ip}]   > snmp {CONFIG.snmp_mode}", "info", callback=callback)
        lowered = output.lower()
        if 'invalid' in lowered or 'error' in lowered:
            log(f"  [{client.ip}]   ! Warning: SNMP mode command may have issue", "warning", callback=callback)

        # Set SNMP community
        output = client.send_command(f"snmp community {CONFIG.snmp_community}")
        log(f"  [{client.ip}]   > snmp community {CONFIG.snmp_community}", "info", callback=callback)
        lowered = output.lower()
        if 'invalid' in lowered or 'error' in lowered:
            log(f"  [{client.ip}]   ! Warning: SNMP community command may have issue", "warning", callback=callback)
        
        # Commit changes
        output = client.send_command("commit", wait_for=['#', '>', '[', ':'], timeout=10)
        log(f"  [{client.ip}]   > commit", "info", callback=callback)
        
        # Handle confirmation prompt if any
        lowered = output.lower()
        if '[' in output or 'yes' in lowered or 'confirm' in lowered:
            output = client.send_command("yes")
            log(f"  [{client.ip}]   > yes", "info", callback=callback)
            lowered = output.lower()

        # Exit config mode
        exit_config_mode(client)
        log(f"  [{client.ip}]   > exit", "info", callback=callback)

        # Check for errors
        if 'error' in lowered and 'abort' in lowered:
            return False, f"SNMP config may have failed: {output[-200:]}"
        
        log(f"  [{client.ip}] [OK] SNMP configured", "success")
        return True, "SNMP configured successfully"
        
    except Exception as e:
        log(f"  [{client.ip}] [FAIL] SNMP configuration error: {e}", "error")
        return False, str(e)

def configure_buffer(client: AviatSSHClient, callback=None) -> Tuple[bool, str]:
    """
    Configure QoS buffer settings on the radio.
    Equivalent to the aviatqos.sh script.
    
    Logic:
    - Must be firmware 6.x
    - Must be PRIMARY (10g2) not PARTNER (10g1)
    - Sets ExternalBuffersize and queue-limit 2500
    """
    log(f"  [{client.ip}] Running Buffer script logic...", "info", callback=callback)

    try:
        # 1. Check firmware version
        output = client.send_command("show version")
        log(f"  [{client.ip}]   Checking version...", "info", callback=callback)
        
        version_match = re.search(r'Version\s+:\s+(\d+)\.', output)
        if not version_match:
            # Try alternative pattern
            version_match = re.search(r'([Vv]ersion|[Rr]elease)\s+(\d+)\.', output)
            
        if version_match:
            major_version = version_match.group(2) if len(version_match.groups()) > 1 else version_match.group(1)
            log(f"  [{client.ip}]   Detected version {major_version}.x", "info", callback=callback)
            # The script only runs on 6.x
            if major_version != "6":
                msg = f"Skipping: Version {major_version}.x (needs 6.x)"
                log(f"  [{client.ip}]   {msg}", "warning", callback=callback)
                return True, msg
        
        # 2. Partner detection using partner-device config (match bash script)
        log(f"  [{client.ip}]   Checking Partner/Primary status...", "info", callback=callback)
        partner_output = client.send_command("show running-config partner-device")
        partner_lower = partner_output.lower()
        if "partner-device" in partner_lower:
            if "connection interface 10g1" in partner_lower:
                msg = "Skipping: Detected as PARTNER radio (10g1 connected)"
                log(f"  [{client.ip}]   {msg}", "warning", callback=callback)
                return True, msg
            if "connection interface 10g2" in partner_lower:
                log(f"  [{client.ip}]   [OK] Detected as PRIMARY radio (10g2)", "info", callback=callback)
            else:
                log(f"  [{client.ip}]   [OK] partner-device present; treating as PRIMARY/standalone", "info", callback=callback)
        elif "syntax error" in partner_lower:
            log(f"  [{client.ip}]   [OK] partner-device check not supported; treating as standalone", "info", callback=callback)
        else:
            log(f"  [{client.ip}]   [OK] Radio is PRIMARY. Proceeding...", "info", callback=callback)

        # 3. Check if already correct (Safety Lock-in)
        # Bash script says: Skips radios where queue-limit is already correct
        check_config = client.send_command(
            "show running-config qos-default-policy ExternalBufferSize"
        )
        if re.search(
            rf"queue-size\s+queue-limit\s+{CONFIG.buffer_queue_limit}\s+kbytes",
            check_config,
            re.I,
        ):
            msg = f"Skipping: Queue-limit is already {CONFIG.buffer_queue_limit} kbytes"
            log(f"  [{client.ip}]   {msg}", "success", callback=callback)
            return True, msg

        # 4. Apply Buffer Configuration (single-line command, matching bash script)
        log(f"  [{client.ip}]   Applying QoS Buffer settings...", "info", callback=callback)
        out_config = client.send_command("config")
        log(f"  [{client.ip}]   > config", "info", callback=callback)
        out_config_lower = out_config.lower()
        if "syntax error" in out_config_lower or "invalid" in out_config_lower:
            log(f"  [{client.ip}]   [FAIL] Command rejected: {out_config.strip()}", "error", callback=callback)
            exit_config_mode(client)
            return False, "Configuration failed: config command rejected"

        line_cmd = (
            f"qos-default-policy ExternalBufferSize traffic-classes 0 "
            f"queue-size queue-limit {CONFIG.buffer_queue_limit} kbytes"
        )
        out_line = client.send_command(line_cmd)
        log(f"  [{client.ip}]   > {line_cmd}", "info", callback=callback)
        out_line_lower = out_line.lower()
        if "syntax error" in out_line_lower or "invalid" in out_line_lower:
            log(f"  [{client.ip}]   [FAIL] Command rejected: {out_line.strip()}", "error", callback=callback)
            client.send_command("rollback")
            exit_config_mode(client)
            return False, "Configuration failed: queue-limit command rejected"
        # Commit changes
        output = client.send_command("commit", wait_for=['#', '>', '[', ':'], timeout=10)
        log(f"  [{client.ip}]   > commit", "info", callback=callback)
        lowered = output.lower()
        if '[' in output or 'yes' in lowered or 'confirm' in lowered:
            output = client.send_command("yes")
            log(f"  [{client.ip}]   > yes", "info", callback=callback)
            lowered = output.lower()
        
        # Exit config mode
        exit_config_mode(client)

        verify_output = client.send_command(
            "show running-config qos-default-policy ExternalBufferSize"
        )
        if not re.search(
            rf"queue-size\s+queue-limit\s+{CONFIG.buffer_queue_limit}\s+kbytes",
            verify_output,
            re.I,
        ):
            log(
                f"  [{client.ip}]   [FAIL] Verification failed for queue-limit {CONFIG.buffer_queue_limit}",
                "warning",
                callback=callback,
            )
            return False, "Verification failed for queue-limit"

        log(f"  [{client.ip}] [OK] Buffer script applied", "success", callback=callback)
        return True, "Buffer configured successfully"
        
    except Exception as e:
        exit_config_mode(client)
        log(f"  [{client.ip}] [FAIL] Buffer configuration error: {e}", "error", callback=callback)
        return False, str(e)


def _is_plausible_version(parts: List[str]) -> bool:
    # Aviat versions are small (e.g., 2.11.11, 6.1.0). Filter IP-like tokens.
    # Generator lets any() short-circuit without building an intermediate list.
    try:
        return not any(int(p) > 50 for p in parts)
    except (ValueError, TypeError):
        return False


def _parse_version(version_output: str) -> Optional[str]:
    version_output = _clean_cli_output(version_output or "")
    patterns = [
        r"(?:Version|Release)\s*:?\s*([0-9]+(?:\.[0-9]+){1,})",
        r"\b([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)",
        r"\b([0-9]+\.[0-9]+\.[0-9]+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, version_output, re.I)
        if match:
            parts = match.group(1).split(".")
            if _is_plausible_version(parts[:3]):
                return ".".join(parts[:3])
    return None

def _parse_active_version(version_output: str) -> Optional[str]:
    version_output = _clean_cli_output(version_output or "")
    patterns = [
        r"software-status\s+active-version\s+([0-9]+(?:\.[0-9]+){1,})",
        r"active-version\s+([0-9]+(?:\.[0-9]+){1,})",
        r"(?:active\s+(?:software\s+)?version|current\s+software\s+version)\s*[:=]?\s*([0-9]+(?:\.[0-9]+){1,})",
        r"Active\s+Version\s*:\s*([0-9]+(?:\.[0-9]+){1,})",
        r"Active\s+Version\s*:\s*([0-9]+(?:\.[0-9]+){1,})\([^)]+\)",
    ]
    for pattern in patterns:
        match = re.search(pattern, version_output, re.I)
        if match:
            parts = match.group(1).split(".")
            if _is_plausible_version(parts[:3]):
                return ".".join(parts[:3])

    table_match = re.search(
        r"^\s*\S+\s+([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)\s+([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)",
        version_output,
        re.I | re.M,
    )
    if table_match:
        parts = table_match.group(1).split(".")
        if _is_plausible_version(parts[:3]):
            return ".".join(parts[:3])

    return None

def _parse_inactive_version(version_output: str) -> Optional[str]:
    version_output = _clean_cli_output(version_output or "")
    patterns = [
        r"software-status\s+inactive-version\s+([0-9]+(?:\.[0-9]+){1,})",
        r"inactive-version\s+([0-9]+(?:\.[0-9]+){1,})",
        r"(?:inactive\s+(?:software\s+)?version)\s*[:=]?\s*([0-9]+(?:\.[0-9]+){1,})",
        r"Inactive\s+Version\s*:\s*([0-9]+(?:\.[0-9]+){1,})",
        r"Inactive\s+Version\s*:\s*([0-9]+(?:\.[0-9]+){1,})\([^)]+\)",
    ]
    for pattern in patterns:
        match = re.search(pattern, version_output, re.I)
        if match:
            parts = match.group(1).split(".")
            if _is_plausible_version(parts[:3]):
                return ".".join(parts[:3])

    table_match = re.search(
        r"^\s*\S+\s+([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)\s+([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)",
        version_output,
        re.I | re.M,
    )
    if table_match:
        return table_match.group(2)

    return None


def _parse_versions_from_status(version_output: str) -> Tuple[Optional[str], Optional[str]]:
    version_output = _clean_cli_output(version_output or "")
    active = _parse_active_version(version_output)
    inactive = _parse_inactive_version(version_output)
    if active or inactive:
        return active, inactive

    table_match = re.search(
        r"^\s*\S+\s+([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)\s+([0-9]+\.[0-9]+\.[0-9]+)\([^)]+\)",
        version_output,
        re.I | re.M,
    )
    if table_match:
        active_parts = table_match.group(1).split(".")
        inactive_parts = table_match.group(2).split(".")
        active = ".".join(active_parts[:3]) if _is_plausible_version(active_parts[:3]) else None
        inactive = ".".join(inactive_parts[:3]) if _is_plausible_version(inactive_parts[:3]) else None
        if active or inactive:
            return active, inactive

    return None, None


def _is_invalid_output(output: str) -> bool:
    output = _clean_cli_output(output or "")
    if not output or not output.strip():
        return True
    lowered = output.lower()
    if (
        "invalid input" in lowered
        or "syntax error" in lowered
        or "unknown element" in lowered
    ):
        return True
    stripped = re.sub(r"\s+", " ", lowered).strip()
    return stripped in ("% no entries found.", "no entries found.", "no entries found")


def _extract_version_from_text(text: str) -> Optional[str]:
    text = _clean_cli_output(text or "")
    if not text:
        return None
    match = re.search(r"([0-9]+(?:\.[0-9]+){1,3})", text)
    if not match:
        return None
    parts = match.group(1).split(".")[:3]
    if _is_plausible_version(parts):
        return ".".join(parts)
    return None


def _is_ip_like_version(version: Optional[str], ip: Optional[str]) -> bool:
    if not version or not ip:
        return False
    return ip.startswith(f"{version}.")

def _version_tuple(version: Optional[str]) -> Tuple[int, int, int]:
    if not version:
        return (0, 0, 0)
    parts = [int(p) for p in re.findall(r"\d+", version)]
    parts = (parts + [0, 0, 0])[:3]
    return tuple(parts)


def _requested_target_version(maintenance_params: Optional[Dict[str, Any]]) -> Optional[str]:
    target = str((maintenance_params or {}).get("firmware_target") or "final").strip().lower()
    if target == "baseline":
        return CONFIG.firmware_baseline_version
    if target == "final":
        return CONFIG.firmware_final_version
    return None

def _is_transient_cli_error(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return any(marker in text for marker in _TRANSIENT_CLI_MARKERS)

def _is_transient_processing_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout, EOFError, ConnectionError)):
        return True
    if _is_transient_cli_error(exc):
        return True
    text = str(exc or "").lower()
    return any(marker in text for marker in _TRANSIENT_PROCESSING_MARKERS)


def get_firmware_version(client: AviatSSHClient, callback=None) -> Optional[str]:
    log(f"  [{client.ip}] Checking firmware version...", "info", callback=callback)
    commands = [
        "show software-status",
        "show software-status active-version",
        "show software-status status",
        "show software-status loading-uri",
        "show software status",
        "show version",
    ]
    version = None
    last_output = ""
    # Post-reboot radios can briefly return "% No entries found." before
    # software-status repopulates; allow a longer settle window.
    retries = 8
    for attempt in range(retries + 1):
        for command in commands:
            try:
                output = client.send_command(command)
            except Exception as exc:
                # Reboots can close CLI channels briefly; treat as transient and retry.
                if _is_transient_cli_error(exc):
                    output = ""
                else:
                    raise
            last_output = output
            if _is_invalid_output(output):
                continue
            active, _inactive = _parse_versions_from_status(output)
            version = active or _parse_version(output)
            if version and _is_ip_like_version(version, client.ip):
                version = None
            if version and version != "0.0.0":
                break
        if version and version != "0.0.0":
            break
        if attempt < retries:
            log(f"  [{client.ip}] Firmware version not ready; retrying...", "warning", callback=callback)
            time.sleep(5)
    if version and version != "0.0.0":
        log(f"  [{client.ip}] Detected firmware {version}", "info", callback=callback)
        return version
    tail = (last_output or "").strip().replace("\r", "")[-160:]
    if tail:
        log(f"  [{client.ip}] Firmware parse output tail: {tail}", "warning", callback=callback)
    log(
        f"  [{client.ip}] Firmware version temporarily unavailable; will retry or defer verification.",
        "warning",
        callback=callback,
    )
    return None


def get_inactive_firmware_version(client: AviatSSHClient, callback=None) -> Optional[str]:
    log(f"  [{client.ip}] Checking inactive firmware version...", "info", callback=callback)
    commands = [
        "show software-status",
        "show software-status inactive-version",
        "show software-status status",
        "show software status",
    ]
    version = None
    last_output = ""
    load_ok = False
    retries = 3
    for attempt in range(retries):
        for command in commands:
            try:
                output = client.send_command(command)
            except Exception as exc:
                if _is_transient_cli_error(exc):
                    output = ""
                else:
                    raise
            output = _clean_cli_output(output)
            last_output = output
            if re.search(r"\bloadok\b", output, re.I):
                load_ok = True
            # Try parsing even if output appears noisy/partial.
            _active, inactive = _parse_versions_from_status(output)
            version = inactive or _parse_inactive_version(output)
            if version:
                break
        if version:
            break
        if attempt < retries - 1:
            time.sleep(1)
    if not load_ok and last_output and re.search(r"\bloadok\b", last_output, re.I):
        load_ok = True
    if not version and load_ok:
        try:
            loading_output = client.send_command("show software-status loading-uri")
            if not _is_invalid_output(loading_output):
                version = _extract_version_from_text(loading_output)
        except Exception:
            pass
    if version:
        log(f"  [{client.ip}] Inactive firmware {version}", "info", callback=callback)
    else:
        if load_ok:
            log(f"  [{client.ip}] Inactive firmware loadOk detected", "info", callback=callback)
            return "loadOk"
        tail = (last_output or "").strip().replace("\r", "")[-160:]
        if tail:
            log(f"  [{client.ip}] Inactive parse output tail: {tail}", "warning", callback=callback)
        log(
            f"  [{client.ip}] Inactive firmware version temporarily unavailable.",
            "warning",
            callback=callback,
        )
    return version


def get_uptime_days(client: AviatSSHClient, callback=None) -> Optional[int]:
    def _web_get_uptime_seconds() -> Optional[int]:
        try:
            if ws_client is None:
                return None
            session = requests.Session()
            login_req = session.post(
                f"http://{client.ip}/wtmlogin",
                data={"username": client.username or "admin", "password": client.password},
                timeout=LOGIN_TIMEOUT,
            )
            if login_req.status_code != 200:
                return None
            sesh = login_req.cookies.get("sesh")
            if not sesh:
                return None
            with ws_client.connect(
                f"ws://{client.ip}/ie10fix",
                additional_headers={"cookie": f"sesh={sesh}"},
                subprotocols=["aurora_channel"],
            ) as ws:
                ws.send(
                    """{"token":"%s","message":{"command":6,"data":{"token":"%s"}}}"""
                    % (sesh.split("-")[0], sesh)
                )
                ws.send(bytes.fromhex("0100000001") + b"""{"key":"system_status_1","pluginId":52,"channelId":1}""")
                t = time.monotonic()
                while time.monotonic() - t < UPTIME_CHECK_TIMEOUT:
                    msg = ws.recv()
                    if not isinstance(msg, bytes):
                        continue
                    uptime = re.match(br"4\x00\x01\x00\x01(\d+)$", msg)
                    if not uptime:
                        continue
                    try:
                        return int(uptime.group(1))
                    except Exception:
                        return None
        except Exception:
            return None
        return None

    def _parse_uptime_days(output: str) -> Optional[int]:
        if not output:
            return None
        # Explicit "X day(s)" in uptime line.
        match = re.search(r"(?:uptime\s*[:=]?\s*|up\s+)(\d+)\s+day", output, re.I)
        if match:
            return int(match.group(1))
        # "Up Time: d:hh:mm:ss" or "Up Time: hh:mm:ss"
        up_line = re.search(r"(?:uptime|up time|system up time)\s*[:=]?\s*([0-9: ]+)", output, re.I)
        if up_line:
            raw = up_line.group(1).strip()
            parts = [p for p in re.split(r"\s*:\s*", raw) if p]
            try:
                nums = [int(p) for p in parts]
                if len(nums) == 4:
                    d, h, m, s = nums
                    return int(d + (h / 24) + (m / 1440) + (s / 86400))
                if len(nums) == 3:
                    h, m, s = nums
                    return int((h / 24) + (m / 1440) + (s / 86400))
            except Exception:
                pass
        # "X days, Y hours, Z minutes"
        long_match = re.search(r"(\d+)\s+day(?:s)?[, ]+\s*(\d+)\s+hour", output, re.I)
        if long_match:
            d = int(long_match.group(1))
            return d
        # Parse active-rx-time field
        rc_match = re.search(r"active-rx-time\s*[:=]?\s*([^\r\n]+)", output, re.I)
        if rc_match:
            value = rc_match.group(1).strip()
            day_match = re.search(r"(\d+)\s+day", value, re.I)
            if day_match:
                return int(day_match.group(1))
            if value.isdigit():
                seconds = int(value)
                return seconds // 86400
            if ":" in value:
                parts = [p for p in value.split(":") if p.strip()]
                try:
                    nums = [int(p) for p in parts]
                    if len(nums) == 4:
                        d, h, m, s = nums
                        return int(d + (h / 24) + (m / 1440) + (s / 86400))
                    if len(nums) == 3:
                        h, m, s = nums
                        return int((h / 24) + (m / 1440) + (s / 86400))
                except Exception:
                    pass
        return None

    commands = [
        "show uptime",
        "show system uptime",
        "show system status",
        "show system information",
        "show system",
        "show status",
        "show version",
        "show radio-carrier status",
    ]

    # Try twice to handle transient CLI output quirks.
    for _ in range(2):
        for cmd in commands:
            try:
                output = client.send_command(cmd)
            except Exception:
                continue
            if _is_invalid_output(output):
                continue
            days = _parse_uptime_days(output)
            if days is not None:
                log(f"  [{client.ip}] Uptime days: {days}", "info", callback=callback)
                return days
        time.sleep(0.2)

    # Final fallback: web UI uptime (works on 2.11.x devices).
    web_seconds = _web_get_uptime_seconds()
    if web_seconds is not None:
        days = int(web_seconds // 86400)
        log(f"  [{client.ip}] Uptime days: {days}", "info", callback=callback)
        return days

    log(f"  [{client.ip}] Uptime days: unknown", "warning", callback=callback)
    return None


def _first_valid_output(client: AviatSSHClient, commands: List[str]) -> str:
    def _looks_like_prompt_only(text: str) -> bool:
        cleaned = _clean_cli_output(text or "").strip()
        if not cleaned:
            return True
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        return len(lines) == 1 and bool(re.search(r"[#>]\s*$", lines[0]))

    for command in commands:
        output = client.send_command(command)
        lowered = output.lower()
        if "syntax error" in lowered or "invalid" in lowered:
            continue
        if output.strip() and not _looks_like_prompt_only(output):
            return output
    return ""


def _get_snmp_output(client: AviatSSHClient) -> str:
    commands = [
        "show running-config | include snmp",
        "show running-config snmp",
        "show running-config | include SNMP",
        "show running-config",
    ]
    outputs: List[str] = []
    for command in commands:
        output = client.send_command(command)
        lowered = output.lower()
        if "syntax error" in lowered or "invalid" in lowered:
            continue
        cleaned = _clean_cli_output(output or "").strip()
        if not cleaned:
            continue
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        if len(lines) == 1 and re.search(r"[#>]\s*$", lines[0]):
            continue
        outputs.append(output)
        combined = "\n".join(outputs)
        mode_ok, comm_ok = _check_snmp_output(combined)
        if mode_ok and comm_ok:
            return combined
    return "\n".join(outputs)


def _check_snmp_output(snmp_output: str) -> Tuple[bool, bool]:
    """Check SNMP mode and community in a config dump.

    Compiles the two dynamic patterns once per call and returns
    (mode_ok, community_ok) so callers don't duplicate regex logic.
    """
    mode_pat = re.compile(rf"\bsnmp\s+{re.escape(CONFIG.snmp_mode)}\b", re.I)
    comm_pat = re.compile(
        rf"\bsnmp\s+community\s+{re.escape(CONFIG.snmp_community)}\b", re.I
    )
    return mode_pat.search(snmp_output) is not None, comm_pat.search(snmp_output) is not None


def _get_buffer_output(client: AviatSSHClient) -> str:
    return _first_valid_output(
        client,
        [
            "show running-config qos-default-policy ExternalBufferSize | include queue-limit",
            "show running-config qos-default-policy ExternalBufferSize",
            "show running-config",
        ],
    )


def _get_subnet_output(client: AviatSSHClient) -> str:
    command = os.getenv("AVIAT_SUBNET_COMMAND", "show interface vlan1 | begin subnet")
    return _first_valid_output(
        client,
        [
            command,
            "show interface Vlan1 | begin subnet",
            "show interface vlan1 | begin subnet",
            "show running-config interface Vlan1",
            "show running-config interface vlan1",
            "show interface Vlan1",
            "show interface vlan1",
            "show interface",
        ],
    )


def check_subnet_mask(client: AviatSSHClient) -> Tuple[Optional[bool], str]:
    expected = os.getenv("AVIAT_EXPECTED_MASK", "255.255.255.248")
    output = _get_subnet_output(client)
    if not output:
        return None, "No output"

    # Prefer explicit mask entries when available.
    match = re.search(r"(?:subnet\s+mask|subnet-mask|mask)\s*[:=]?\s*([0-9.]+)", output, re.I)
    actual = match.group(1) if match else None

    # Fallback for UI/CLI variants that expose only CIDR (e.g. 10.249.73.67/29).
    if not actual:
        cidr = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/(\d{1,2})\b", output)
        if cidr:
            try:
                prefix = int(cidr.group(1))
                actual = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False).netmask)
            except Exception:
                actual = None

    # Running-config often exposes IPv4 address + prefix-length instead of dotted mask.
    if not actual:
        prefix = re.search(r"\bprefix-length\s+(\d{1,2})\b", output, re.I)
        if prefix:
            try:
                actual = str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix.group(1))}", strict=False).netmask)
            except Exception:
                actual = None

    if not actual:
        return None, "Mask not found"
    return actual == expected, actual


def check_license_bundles(client: AviatSSHClient) -> Tuple[Optional[bool], str]:
    output = _first_valid_output(
        client,
        ["show licensing bundles", "show licensing", "show licensing licenses"],
    )
    if not output:
        return None, "No output"
    bundles: List[str] = []
    header_markers = {
        "bundle",
        "bundles",
        "entity",
        "name",
        "installed",
        "licenses",
        "license",
        "features",
        "serial",
        "numbers",
    }
    token_re = re.compile(r"\b[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+\b")

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered in header_markers:
            continue
        if re.match(r"^[=\-]{3,}$", line):
            continue

        # Extract bundle tokens from table-style or sentence-style outputs.
        for token in token_re.findall(line.upper()):
            if token == "TRIAL":
                continue
            # Keep likely bundle names only.
            if token.startswith(("WZ", "WZF", "WZL", "WZE", "WZM", "WZH", "WZC")):
                bundles.append(token)

    if bundles:
        return True, ", ".join(sorted(set(bundles)))
    if "trial" in output.lower():
        return False, "trial"
    return None, "Unknown"


def check_stp_disabled(client: AviatSSHClient) -> Tuple[Optional[bool], str]:
    expected = os.getenv("AVIAT_STP_EXPECTED", "disabled").lower()
    output = _first_valid_output(
        client,
        [
            "show spanning-tree",
            "show running-config | include spanning-tree",
            "show running-config | include spanning",
        ],
    )
    if not output:
        return None, "No output"
    lowered = output.lower()
    if "no entries found" in lowered:
        return True, "disabled"
    if expected in ("disabled", "shutdown", "off"):
        if (
            "shutdown" in lowered
            or "disabled" in lowered
            or "off" in lowered
            or "administrative-status down" in lowered
        ):
            return True, "disabled"
        if "enabled" in lowered or "forwarding" in lowered or "administrative-status up" in lowered:
            return False, "enabled"
    return None, "Unknown"


def trigger_firmware_download(
    client: AviatSSHClient,
    uri: str,
    activation_time: Optional[str],
    activate_now: bool,
    activation_mode: str,
    callback=None,
) -> Tuple[bool, str]:
    def _software_status_text() -> str:
        try:
            return client.send_command("show software-status status", timeout=10) or ""
        except Exception:
            return ""

    def _software_state_from_text(text: str) -> str:
        lowered_text = (text or "").lower()
        match = re.search(r"software-status status\s+([a-z]+)", lowered_text)
        if match:
            return match.group(1)
        if "loading started" in lowered_text:
            return "load"
        if "automatic activation" in lowered_text:
            return "load"
        return "unknown"

    def _send_load(in_config_mode: bool) -> str:
        if in_config_mode:
            config_output = client.send_command("config terminal", wait_for=['#', '>'], timeout=10)
            log(f"  [{client.ip}]   > config terminal", "info", callback=callback)
            if "invalid input" in (config_output or "").lower():
                client.send_command("configure terminal", wait_for=['#', '>'], timeout=10)
                log(f"  [{client.ip}]   > configure terminal", "info", callback=callback)
        try:
            output = client.send_command(command, timeout=20)
            log(f"  [{client.ip}]   > {command}", "info", callback=callback)
            return output
        finally:
            if in_config_mode:
                exit_config_mode(client)

    if activation_mode in ("manual", "scheduled"):
        command = f"software load uri {uri} force"
    elif activate_now:
        command = f"software load uri {uri} force activation-immediately"
    elif activation_time:
        command = f"software load uri {uri} force activation-time {activation_time}"
    else:
        command = f"software load uri {uri} force"

    log(f"  [{client.ip}] Triggering firmware download...", "info", callback=callback)
    status_before = _software_status_text()
    if re.search(r"software-status status\s+(rollbackerror|loaderror)", status_before, re.I):
        try:
            client.send_command("config terminal", wait_for=['#', '>'], timeout=10)
            log(f"  [{client.ip}]   > config terminal", "info", callback=callback)
            client.send_command("software abort", timeout=8)
            log(f"  [{client.ip}]   > software abort", "info", callback=callback)
        finally:
            exit_config_mode(client)

    output = _send_load(in_config_mode=False)
    lowered = (output or "").lower()
    if "syntax error" in lowered or "invalid input" in lowered:
        output = _send_load(in_config_mode=True)
        lowered = (output or "").lower()

    if "loading started" not in lowered and "automatic activation" not in lowered:
        state_now = _software_state_from_text(_software_status_text())
        if state_now not in {"prepareload", "load", "activate", "commit"}:
            return False, f"Firmware download failed: {(output or '').strip()[-200:]}"
    return True, "Firmware download started"


def _next_activation_datetime(activation_time: str) -> datetime:
    hour, minute = [int(x) for x in activation_time.split(":")]
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def wait_until_activation(
    activation_time: str,
    callback=None,
    should_abort: Optional[callable] = None,
) -> bool:
    target = _next_activation_datetime(activation_time)
    log(
        f"Waiting until {target.strftime('%Y-%m-%d %H:%M')} for activation window.",
        "info",
        callback=callback,
    )
    while datetime.now() < target:
        if should_abort and should_abort():
            return False
        time.sleep(10)
    return True


def _restart_device_after_activation(client: AviatSSHClient, callback=None) -> Tuple[bool, str]:
    """Explicitly restart the radio after activation so inactive firmware becomes active."""
    log(f"  [{client.ip}] Restarting device to apply activated firmware...", "info", callback=callback)
    try:
        output = client.send_command(
            "restart",
            # Avoid ':' prompt matching here; it can appear in normal output lines.
            wait_for=['#', '>', ']', '?', '[no,yes]'],
            timeout=15,
        )
        log(f"  [{client.ip}]   > restart", "info", callback=callback)
        lowered = (output or "").lower()
        if "are you sure" in lowered or "[no,yes]" in lowered:
            try:
                confirm = client.send_command("yes", wait_for=['#', '>', ':', ']', '?'], timeout=12)
                output = (output or "") + "\n" + (confirm or "")
            except Exception:
                # Connection often drops immediately after confirmation; treat as expected reboot start.
                return True, "Firmware activated; restart initiated"
        if "invalid input" in lowered or "syntax error" in lowered:
            return False, f"Restart command rejected: {(output or '').strip()[-200:]}"
        return True, "Firmware activated; restart initiated"
    except Exception as exc:
        # SSH session may drop instantly when restart is accepted.
        text = str(exc).lower()
        if any(k in text for k in ("socket", "closed", "reset", "eof", "timed out", "timeout")):
            return True, "Firmware activated; restart initiated"
        return False, f"Restart failed: {exc}"


def activate_firmware(client: AviatSSHClient, callback=None) -> Tuple[bool, str]:
    def _software_status_text() -> str:
        try:
            return client.send_command("show software-status status", timeout=10) or ""
        except Exception:
            return ""

    def _software_state_from_text(text: str) -> str:
        lowered_text = (text or "").lower()
        if "software-status status" in lowered_text:
            if re.search(r"\bactivate\b", lowered_text):
                return "activate"
            if re.search(r"\brollback\b", lowered_text):
                return "rollback"
            if re.search(r"\bload\b", lowered_text):
                return "load"
            if re.search(r"\bidle\b", lowered_text):
                return "idle"
        if "resp activating new software now" in lowered_text:
            return "activate"
        if "resp ok" in lowered_text and "rollback" in lowered_text:
            return "rollback"
        if "loading started" in lowered_text:
            return "load"
        return "unknown"

    log(f"  [{client.ip}] Activating firmware...", "info", callback=callback)
    try:
        config_output = client.send_command("config terminal", wait_for=['#', '>'], timeout=10)
        log(f"  [{client.ip}]   > config terminal", "info", callback=callback)
        if "invalid input" in (config_output or "").lower():
            client.send_command("configure terminal", wait_for=['#', '>'], timeout=10)
            log(f"  [{client.ip}]   > configure terminal", "info", callback=callback)

        # Avoid ':' prompt matching here; it can terminate reads too early.
        output = client.send_command("software activate", wait_for=['#', '>', ']', '?', '[no,yes]'], timeout=20)
        log(f"  [{client.ip}]   > software activate", "info", callback=callback)
        lowered = (output or "").lower()
        if "are you sure" in lowered or "[no,yes]" in lowered or "proceed" in lowered:
            confirm = client.send_command("yes", wait_for=['#', '>', ']', '?'], timeout=20)
            output = (output or "") + "\n" + (confirm or "")
            lowered = output.lower()
        if "no software ready to activate" in lowered:
            status_output = ""
            try:
                exit_config_mode(client)
                status_output = client.send_command("show software-status", timeout=10)
                status_lowered = (status_output or "").lower()
                if "software-status status activate" in status_lowered:
                    return _restart_device_after_activation(client, callback=callback)
            except Exception:
                pass
            try:
                active_version, inactive_version = _parse_versions_from_status(status_output or "")
            except Exception:
                active_version, inactive_version = (None, None)

            # For activate-now flows, if device is not final and direct activation is not ready,
            # force the automatic activation load path to avoid dead-end "no software ready".
            if _version_tuple(active_version) < _version_tuple(CONFIG.firmware_final_version):
                try:
                    client.send_command("config terminal", wait_for=['#', '>'], timeout=10)
                    client.send_command("software abort", timeout=8)
                except Exception:
                    pass
                finally:
                    exit_config_mode(client)
                cmd = f"software load uri {CONFIG.firmware_final_uri} force activation-immediately"
                out = client.send_command(cmd, timeout=20)
                out_lowered = (out or "").lower()
                if "loading started" in out_lowered:
                    log(f"  [{client.ip}]   > {cmd}", "info", callback=callback)
                    # Confirm radio really entered an operation state before marking as loading.
                    time.sleep(2)
                    status_now = _software_status_text()
                    state_now = _software_state_from_text(status_now)
                    if state_now in ("load", "activate"):
                        return True, f"Activation fallback: automatic activation {state_now} started"
                    tail = (status_now or "").strip().replace("\r", "")[-200:]
                    return False, f"Activation fallback did not enter load/activate state: {tail or 'no status'}"
                tail = (out or "").strip().replace("\r", "")[-200:]
                return False, f"Firmware activation fallback failed: {tail}"

            return False, "Firmware activation failed: no software ready to activate"

        exit_config_mode(client)
        if re.search(r"\b(activat(ing|ion)|scheduled|reboot|restarting)\b", lowered) or "resp activating" in lowered:
            return _restart_device_after_activation(client, callback=callback)
        # Some radios return minimal/no text; verify operation state before failing.
        status_now = _software_status_text()
        state_now = _software_state_from_text(status_now)
        if state_now == "activate":
            return _restart_device_after_activation(client, callback=callback)
        if state_now == "load":
            return True, "Activation accepted; software load in progress"
        if not (output or "").strip():
            return _restart_device_after_activation(client, callback=callback)
        tail = (output or "").strip().replace("\r", "")[-200:]
        return False, f"Firmware activation failed: {tail}"
    finally:
        exit_config_mode(client)


def rollback_firmware(client: AviatSSHClient, callback=None) -> Tuple[bool, str]:
    def _software_status_text() -> str:
        try:
            return client.send_command("show software-status status", timeout=10) or ""
        except Exception:
            return ""

    log(f"  [{client.ip}] Rolling back firmware...", "info", callback=callback)
    try:
        config_output = client.send_command("config terminal", wait_for=['#', '>'], timeout=10)
        log(f"  [{client.ip}]   > config terminal", "info", callback=callback)
        if "invalid input" in (config_output or "").lower():
            client.send_command("configure terminal", wait_for=['#', '>'], timeout=10)
            log(f"  [{client.ip}]   > configure terminal", "info", callback=callback)

        output = client.send_command("software rollback", wait_for=['#', '>', ']', '?', '[no,yes]'], timeout=20)
        log(f"  [{client.ip}]   > software rollback", "info", callback=callback)
        lowered = (output or "").lower()
        if "are you sure" in lowered or "[no,yes]" in lowered or "proceed" in lowered:
            confirm = client.send_command("yes", wait_for=['#', '>', ']', '?'], timeout=20)
            output = (output or "") + "\n" + (confirm or "")
            lowered = output.lower()
        exit_config_mode(client)

        status_now = _software_status_text()
        status_lowered = (status_now or "").lower()
        if "software-status status rollback" in status_lowered:
            return True, "Firmware rollback started"
        if "resp ok" in lowered or "rollback" in lowered or "reboot" in lowered or "restarting" in lowered:
            return True, "Firmware rollback started"
        tail = (output or status_now or "").strip().replace("\r", "")[-200:]
        return False, f"Firmware rollback failed: {tail or 'no status'}"
    finally:
        exit_config_mode(client)


def _load_sop_checks() -> List[Dict[str, Any]]:
    path = CONFIG.sop_checks_path
    if not path:
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _evaluate_sop(client: AviatSSHClient, callback=None) -> Tuple[bool, List[Dict[str, Any]]]:
    results: List[Dict[str, Any]] = []
    checks = _load_sop_checks()

    version = get_firmware_version(client, callback=callback)
    version_ok = _version_tuple(version) >= _version_tuple(CONFIG.firmware_final_version)
    results.append(
        {
            "name": "Firmware version",
            "expected": f">= {CONFIG.firmware_final_version}",
            "actual": version or "unknown",
            "pass": version_ok,
        }
    )

    snmp_output = _get_snmp_output(client)
    snmp_mode_ok, snmp_comm_ok = _check_snmp_output(snmp_output)
    results.append(
        {
            "name": "SNMP mode",
            "expected": CONFIG.snmp_mode,
            "actual": "found" if snmp_mode_ok else "missing",
            "pass": snmp_mode_ok,
        }
    )
    results.append(
        {
            "name": "SNMP community",
            "expected": CONFIG.snmp_community,
            "actual": "found" if snmp_comm_ok else "missing",
            "pass": snmp_comm_ok,
        }
    )

    buffer_output = _get_buffer_output(client)
    buffer_ok = re.search(
        rf"queue-size\s+queue-limit\s+{CONFIG.buffer_queue_limit}\s+kbytes",
        buffer_output,
        re.I,
    ) is not None
    results.append(
        {
            "name": "Buffer queue-limit",
            "expected": str(CONFIG.buffer_queue_limit),
            "actual": "found" if buffer_ok else "missing",
            "pass": buffer_ok,
        }
    )

    expected_mask = os.getenv("AVIAT_EXPECTED_MASK", "255.255.255.248")
    subnet_ok, subnet_actual = check_subnet_mask(client)
    results.append(
        {
            "name": "Subnet mask",
            "expected": expected_mask,
            "actual": subnet_actual or "unknown",
            "pass": subnet_ok is True,
        }
    )

    for check in checks:
        name = check.get("name", "SOP check")
        command = check.get("command")
        pattern = check.get("expect_regex")
        if not command or not pattern:
            continue
        output = client.send_command(command)
        passed = re.search(pattern, output, re.I) is not None
        results.append(
            {
                "name": name,
                "expected": pattern,
                "actual": "matched" if passed else "missing",
                "pass": passed,
            }
        )

    passed_all = all(item.get("pass") for item in results) if results else True
    return passed_all, results


def run_sop_checks(client: AviatSSHClient, callback=None) -> Tuple[bool, List[Dict[str, Any]]]:
    def _is_hard_sop_failure(item: Dict[str, Any]) -> bool:
        name = str(item.get("name") or "").strip().lower()
        # Subnet is an advisory precheck and should not mark overall upgrade failed.
        return bool(item.get("pass") is False and name != "subnet mask")

    attempts = max(1, CONFIG.sop_recheck_attempts)
    delay = max(0, CONFIG.sop_recheck_delay)
    last_results: List[Dict[str, Any]] = []
    for attempt in range(1, attempts + 1):
        passed, results = _evaluate_sop(client, callback=callback)
        last_results = results
        passed = not any(_is_hard_sop_failure(item) for item in results)
        if passed:
            break
        if attempt < attempts and delay:
            log(
                f"  [{client.ip}] SOP recheck attempt {attempt}/{attempts} failed; retrying in {delay}s...",
                "warning",
                callback=callback,
            )
            time.sleep(delay)

    passed_all = not any(_is_hard_sop_failure(item) for item in last_results) if last_results else True
    for item in last_results:
        log(
            f"  [{client.ip}] SOP check - {item['name']}: {'PASS' if item['pass'] else 'FAIL'}",
            "success" if item["pass"] else "warning",
            callback=callback,
        )
    return passed_all, last_results


def wait_for_reconnect(
    ip: str,
    username: str,
    password: str,
    callback=None,
) -> AviatSSHClient:
    timeout = CONFIG.firmware_reconnect_timeout
    interval = CONFIG.firmware_reconnect_interval
    start = time.time()
    while time.time() - start < timeout:
        try:
            client = AviatSSHClient(ip, username=username, password=password, port=CONFIG.ssh_port)
            client.connect()
            log(f"[{ip}] Reconnected after firmware activation", "success", callback=callback)
            return client
        except Exception:
            time.sleep(interval)
    raise TimeoutError("Timed out waiting for device to reconnect after firmware activation.")




def check_device_status(ip: str, callback=None) -> Dict[str, Any]:
    result = {
        "ip": ip,
        "reachable": False,
        "firmware": None,
        "snmp_ok": False,
        "buffer_ok": False,
        "subnet_ok": None,
        "subnet_actual": None,
        "license_ok": None,
        "license_detail": None,
        "stp_ok": None,
        "stp_detail": None,
        "error": None,
    }
    try:
        sock = socket.create_connection((ip, CONFIG.ssh_port), timeout=3)
        sock.close()
    except Exception as exc:
        result["error"] = f"tcp-probe failed: {exc}"
        return result
    client = None
    try:
        try:
            client = AviatSSHClient(ip, username=CONFIG.default_username, password=CONFIG.new_password)
            client.connect()
        except Exception:
            client = AviatSSHClient(ip, username=CONFIG.default_username, password=CONFIG.default_password)
            client.connect()
        result["reachable"] = True
        version = get_firmware_version(client, callback=callback)
        result["firmware"] = version
        snmp_output = _get_snmp_output(client)
        snmp_mode_ok, snmp_comm_ok = _check_snmp_output(snmp_output)
        result["snmp_ok"] = snmp_mode_ok and snmp_comm_ok
        buffer_output = _get_buffer_output(client)
        result["buffer_ok"] = re.search(
            rf"queue-size\s+queue-limit\s+{CONFIG.buffer_queue_limit}\s+kbytes",
            buffer_output,
            re.I,
        ) is not None
        subnet_ok, subnet_actual = check_subnet_mask(client)
        result["subnet_ok"] = subnet_ok
        result["subnet_actual"] = subnet_actual
        license_ok, license_detail = check_license_bundles(client)
        result["license_ok"] = license_ok
        result["license_detail"] = license_detail
        stp_ok, stp_detail = check_stp_disabled(client)
        result["stp_ok"] = stp_ok
        result["stp_detail"] = stp_detail
    except Exception as e:
        result["error"] = str(e)
    finally:
        if client:
            client.close()
    return result

def wait_for_ping(
    ip: str,
    timeout: int,
    payload_size: int = 1400,
    callback=None,
) -> bool:
    """Wait for ICMP ping to succeed for up to timeout seconds."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            result = _run_ping(ip, payload_size=payload_size, timeout_seconds=1)
            if result.returncode == 0:
                log(f"[{ip}] Ping successful; device online.", "info", callback=callback)
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def wait_after_activation(callback=None):
    wait_seconds = CONFIG.firmware_post_activation_wait
    if wait_seconds <= 0:
        return
    log(
        f"Waiting {wait_seconds // 60} minutes after activation before reconnect checks...",
        "info",
        callback=callback,
    )
    time.sleep(wait_seconds)


def _run_ping(ip: str, payload_size: int, timeout_seconds: int) -> subprocess.CompletedProcess:
    if os.name == "nt":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(max(1, int(timeout_seconds)) * 1000),
            "-l",
            str(payload_size),
            ip,
        ]
    else:
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            str(max(1, int(timeout_seconds))),
            "-s",
            str(payload_size),
            ip,
        ]
    return subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def wait_for_device_ready(
    ip: str,
    callback=None,
    payload_size: Optional[int] = None,
    check_interval: Optional[int] = None,
    max_wait: Optional[int] = None,
    initial_delay: int = 0,
) -> bool:
    """Poll with ICMP ping every N minutes until reachable or max wait reached."""
    payload = payload_size if payload_size is not None else CONFIG.firmware_ping_payload
    interval = check_interval if check_interval is not None else CONFIG.firmware_ping_check_interval
    max_wait_seconds = max_wait if max_wait is not None else CONFIG.firmware_ping_max_wait
    if initial_delay > 0:
        log(
            f"[{ip}] Waiting {initial_delay // 60} min before first availability check...",
            "info",
            callback=callback,
        )
        time.sleep(initial_delay)
    start = time.time()
    attempt = 1
    ping_available = shutil.which("ping") is not None
    if not ping_available:
        log(
            f"[{ip}] Ping binary not available; using TCP probe on port {CONFIG.ssh_port}.",
            "warning",
            callback=callback,
        )
    while time.time() - start < max_wait_seconds:
        reachable = False
        try:
            if ping_available:
                result = _run_ping(ip, payload_size=payload, timeout_seconds=2)
                if result.returncode == 0:
                    reachable = True
        except Exception:
            pass
        if not reachable:
            try:
                with socket.create_connection((ip, CONFIG.ssh_port), timeout=2):
                    reachable = True
            except Exception:
                reachable = False
        if reachable:
            log(
                f"[{ip}] Device reachable after reboot; continuing.",
                "success",
                callback=callback,
            )
            return True
        remaining = max_wait_seconds - int(time.time() - start)
        next_check = (datetime.now() + timedelta(seconds=interval)).strftime("%H:%M")
        log(
            f"[{ip}] Availability check {attempt} failed; retrying in {interval // 60} min (next at {next_check}, remaining {max(0, remaining) // 60} min).",
            "info",
            callback=callback,
        )
        attempt += 1
        time.sleep(interval)
    log(
        f"[{ip}] Ping did not recover within {max_wait_seconds // 60} minutes.",
        "error",
        callback=callback,
    )
    return False


def wait_for_device_ready_and_reconnect(
    ip: str,
    username: str,
    password: str,
    fallback_password: Optional[str] = None,
    callback=None,
    payload_size: Optional[int] = None,
    check_interval: Optional[int] = None,
    max_wait: Optional[int] = None,
    initial_delay: int = 0,
) -> Optional[AviatSSHClient]:
    """Wait for reachability, then wait until SSH login succeeds."""
    payload = payload_size if payload_size is not None else CONFIG.firmware_ping_payload
    interval = check_interval if check_interval is not None else CONFIG.firmware_ping_check_interval
    max_wait_seconds = max_wait if max_wait is not None else CONFIG.firmware_ping_max_wait
    if initial_delay > 0:
        log(
            f"[{ip}] Waiting {initial_delay // 60} min before first availability check...",
            "info",
            callback=callback,
        )
        time.sleep(initial_delay)
    start = time.time()
    attempt = 1
    ping_available = shutil.which("ping") is not None
    if not ping_available:
        log(
            f"[{ip}] Ping binary not available; using TCP probe on port {CONFIG.ssh_port}.",
            "warning",
            callback=callback,
        )
    while time.time() - start < max_wait_seconds:
        reachable = False
        try:
            if ping_available:
                result = _run_ping(ip, payload_size=payload, timeout_seconds=2)
                if result.returncode == 0:
                    reachable = True
        except Exception:
            pass
        if not reachable:
            try:
                with socket.create_connection((ip, CONFIG.ssh_port), timeout=2):
                    reachable = True
            except Exception:
                reachable = False
        if reachable:
            candidates = [(username, password)]
            if fallback_password and fallback_password != password:
                candidates.append((username, fallback_password))
            for user, pwd in candidates:
                try:
                    client = AviatSSHClient(ip, username=user, password=pwd, port=CONFIG.ssh_port)
                    client.connect()
                    log(f"[{ip}] Device reachable after reboot; continuing.", "success", callback=callback)
                    return client
                except Exception:
                    continue
            log(
                f"[{ip}] Reachable but SSH not ready; retrying in {interval // 60} min.",
                "warning",
                callback=callback,
            )
        else:
            remaining = max_wait_seconds - int(time.time() - start)
            next_check = (datetime.now() + timedelta(seconds=interval)).strftime("%H:%M")
            log(
                f"[{ip}] Availability check {attempt} failed; retrying in {interval // 60} min (next at {next_check}, remaining {max(0, remaining) // 60} min).",
                "info",
                callback=callback,
            )
            attempt += 1
        time.sleep(interval)
    log(
        f"[{ip}] Device did not recover within {max_wait_seconds // 60} minutes.",
        "error",
        callback=callback,
    )
    return None


# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_radio(
    ip: str,
    tasks: List[str],
    callback=None,
    maintenance_params: Optional[Dict[str, Any]] = None,
    should_abort: Optional[callable] = None,
) -> RadioResult:
    """Process a single radio with core maintenance tasks"""
    result = RadioResult(ip=ip)
    stages = []
    def stage(label: str):
        stages.append(label)
    client = None
    maintenance_params = maintenance_params or {}
    firmware_target = maintenance_params.get("firmware_target", "final")
    firmware_uri_override = maintenance_params.get("firmware_uri")
    result.target_version = _requested_target_version(maintenance_params)
    activation_time = maintenance_params.get("activation_time")
    if activation_time == "":
        activation_time = None
    activation_mode = maintenance_params.get("activation_mode", "scheduled")
    activate_now = maintenance_params.get("activate_now")
    if activate_now is None:
        activate_now = CONFIG.firmware_activate_now
    
    def abort_if_needed():
        if should_abort and should_abort():
            result.error = "Aborted"
            log(f"[{ip}] Aborted by operator", "warning", callback=callback)
            return True
        return False

    try:
        start_time = time.time()
        task_set = frozenset(tasks)
        _has_all = "all" in task_set

        def _task(*names: str) -> bool:
            """True if any of `names` or 'all' is in the task set."""
            return _has_all or any(n in task_set for n in names)

        log(f"[{ip}] Connecting...", "info", callback=callback)
        # Always try new password first, then fall back to default.
        try:
            client = AviatSSHClient(ip, username=CONFIG.default_username, password=CONFIG.new_password)
            client.connect()
            log(f"[{ip}] Connected with new password", "success", callback=callback)
            login_username = CONFIG.default_username
            login_password = CONFIG.new_password
            stage("CONNECTED(new)")
        except Exception:
            log(f"[{ip}] Retrying with default password...", "info", callback=callback)
            client = AviatSSHClient(ip, username=CONFIG.default_username, password=CONFIG.default_password)
            client.connect()
            log(f"[{ip}] Connected with default password", "success", callback=callback)
            login_username = CONFIG.default_username
            login_password = CONFIG.default_password
            stage("CONNECTED(default)")

        if _task("firmware", "sop"):
            result.firmware_version_before = get_firmware_version(client, callback=callback)

        # Always collect precheck health for queue/UI visibility.
        try:
            subnet_ok, subnet_actual = check_subnet_mask(client)
            result.subnet_ok = subnet_ok
            result.subnet_actual = subnet_actual
            if subnet_ok is False:
                log(
                    f"[{ip}] Subnet mask mismatch: expected {os.getenv('AVIAT_EXPECTED_MASK', '255.255.255.248')}, got {subnet_actual}",
                    "warning",
                    callback=callback,
                )
        except Exception:
            result.subnet_ok = None
            result.subnet_actual = None

        try:
            license_ok, license_detail = check_license_bundles(client)
            result.license_ok = license_ok
            result.license_detail = license_detail
        except Exception:
            result.license_ok = None
            result.license_detail = None

        try:
            stp_ok, stp_detail = check_stp_disabled(client)
            result.stp_ok = stp_ok
            result.stp_detail = stp_detail
        except Exception:
            result.stp_ok = None
            result.stp_detail = None

        # Precheck + reboot gate: block upgrade path but keep radio in queue (not failed queue).
        if any(t in tasks for t in ("firmware", "activate", "all")):
            precheck_issues = []
            if result.subnet_ok is False:
                expected_mask = os.getenv("AVIAT_EXPECTED_MASK", "255.255.255.248")
                precheck_issues.append(
                    f"NEEDS /29 ({expected_mask}); device reports {result.subnet_actual or 'unknown'}"
                )
                stage("PRECHECK_SUBNET_FAIL")
            if result.stp_ok is False:
                precheck_issues.append(f"STP ENABLED ({result.stp_detail or 'disable STP before upgrade'})")
                stage("PRECHECK_STP_FAIL")
            if result.license_ok is False:
                precheck_issues.append(f"LICENSE ISSUE ({result.license_detail or 'required license missing'})")
                stage("PRECHECK_LICENSE_FAIL")

            try:
                uptime_days = get_uptime_days(client, callback=callback)
            except Exception as err:
                log(f"[{ip}] Uptime check failed (ignored): {err}", "warning", callback=callback)
                uptime_days = None
            reboot_needed = uptime_days is not None and uptime_days > 250
            if reboot_needed:
                stage("REBOOT_REQUIRED")
                log(
                    f"[{ip}] Uptime {uptime_days} days exceeds 250; reboot required before upgrade.",
                    "warning",
                    callback=callback,
                )
            else:
                stage("UPTIME_OK")

            if precheck_issues or reboot_needed:
                result.status = "reboot_required" if reboot_needed else "precheck_failed"
                result.success = True
                messages = []
                if reboot_needed:
                    messages.append(f"REBOOT REQUIRED ({uptime_days} days)")
                messages.extend(precheck_issues)
                result.error = "Precheck blocked upgrade: " + "; ".join(messages)
                log(f"[{ip}] {result.error}", "warning", callback=callback)
                log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "warning", callback=callback)
                return result

        # 0. Firmware download / scheduling
        if _task("firmware"):
            if abort_if_needed():
                return result
            current_version = result.firmware_version_before
            inactive_version = get_inactive_firmware_version(client, callback=callback)
            inactive_version = (inactive_version or "").strip()
            inactive_target = _parse_version(inactive_version) or inactive_version
            ready_versions = {
                CONFIG.firmware_baseline_version,
                CONFIG.firmware_final_version,
            }
            if (
                firmware_target != "baseline"
                and _version_tuple(current_version) >= _version_tuple(CONFIG.firmware_final_version)
            ):
                log(
                    f"[{ip}] Active firmware {current_version} already final; skipping download.",
                    "info",
                    callback=callback,
                )
                result.firmware_downloaded = True
                result.firmware_activated = True
                result.firmware_version_after = current_version
                stage("FIRMWARE_SKIP_FINAL")
            elif inactive_version.lower() == "loadok" and activation_mode in ("scheduled", "manual"):
                log(
                    f"[{ip}] Inactive firmware loadOk detected; skipping download.",
                    "info",
                    callback=callback,
                )
                result.firmware_downloaded = True
                result.firmware_downloaded_version = inactive_version
                if activation_mode == "scheduled":
                    result.firmware_scheduled = True
                    result.status = "scheduled"
                    result.success = True
                    stage("FIRMWARE_INACTIVE_READY")
                    stage("SCHEDULED")
                else:
                    result.status = "manual"
                    result.success = True
                    stage("MANUAL_ACTIVATION")
                log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                return result
            elif inactive_version in ready_versions and activation_mode == "scheduled":
                log(
                    f"[{ip}] Inactive firmware {inactive_version} already loaded; skipping download.",
                    "info",
                    callback=callback,
                )
                result.firmware_downloaded = True
                result.firmware_scheduled = True
                result.firmware_downloaded_version = inactive_version
                result.status = "scheduled"
                result.success = True
                stage("FIRMWARE_INACTIVE_READY")
                stage("SCHEDULED")
                log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                return result
            baseline_needed = _version_tuple(current_version) < _version_tuple(
                CONFIG.firmware_baseline_version
            )
            already_baseline = (
                not firmware_uri_override
                and firmware_target == "baseline"
                and _version_tuple(current_version)
                == _version_tuple(CONFIG.firmware_baseline_version)
            )
            already_final = (
                not firmware_uri_override
                and firmware_target != "baseline"
                and _version_tuple(current_version)
                >= _version_tuple(CONFIG.firmware_final_version)
            )
            firmware_was_triggered = False
            if already_final or already_baseline:
                log(
                    f"[{ip}] Firmware already at {current_version}; skipping download.",
                    "info",
                    callback=callback,
                )
                result.firmware_downloaded = True
                result.firmware_activated = True
                result.firmware_version_after = current_version
                stage("FIRMWARE_SKIP_TARGET")
            else:
                if firmware_uri_override:
                    steps = [("override", firmware_uri_override)]
                elif baseline_needed:
                    steps = [
                        ("baseline", CONFIG.firmware_baseline_uri),
                        ("final", CONFIG.firmware_final_uri),
                    ]
                else:
                    steps = [
                        (
                            firmware_target,
                            CONFIG.firmware_baseline_uri
                            if firmware_target == "baseline"
                            else CONFIG.firmware_final_uri,
                        )
                    ]

                for index, (step_name, uri) in enumerate(steps):
                    if abort_if_needed():
                        return result
                    if baseline_needed and step_name == "final" and not activate_now:
                        log(
                            f"[{ip}] Baseline scheduled. Run final upgrade after baseline activation.",
                            "warning",
                            callback=callback,
                        )
                        break
                    if step_name == "baseline":
                        version = CONFIG.firmware_baseline_version
                    elif step_name == "final":
                        version = CONFIG.firmware_final_version
                    else:
                        version = None
                    firmware_was_triggered = True
                    stage(f"FIRMWARE_TRIGGER_{step_name}")
                    success, msg = trigger_firmware_download(
                        client,
                        uri,
                        activation_time if not activate_now else None,
                        activate_now,
                        activation_mode,
                        callback=callback,
                    )
                    result.firmware_downloaded = result.firmware_downloaded or success
                    if success:
                        result.firmware_downloaded_version = version
                    result.firmware_scheduled = result.firmware_scheduled or bool(
                        success and activation_time and not activate_now
                    )
                    result.firmware_activated = result.firmware_activated or bool(
                        success and activate_now
                    )
                    if not success and "software operation already in progress" in str(msg or "").lower():
                        result.status = "loading"
                        result.success = True
                        stage("FIRMWARE_ALREADY_LOADING")
                        log(
                            f"[{ip}] Firmware operation already in progress; deferring remaining tasks until load completes.",
                            "warning",
                            callback=callback,
                        )
                        log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                        return result
                    if not success and not result.error:
                        result.error = msg
                        break
                    if (
                        success
                        and activate_now
                        and baseline_needed
                        and step_name == "baseline"
                        and index < len(steps) - 1
                    ):
                        try:
                            client.close()
                        except Exception:
                            pass
                        client = wait_for_device_ready_and_reconnect(
                            ip,
                            username=login_username,
                            password=login_password,
                            fallback_password=CONFIG.default_password,
                            callback=callback,
                            initial_delay=CONFIG.firmware_first_check_delay,
                        )
                        if not client:
                            result.error = "Device did not recover within 60 minutes after baseline activation"
                            return result
                        current_version = get_firmware_version(client, callback=callback)
                        result.firmware_version_after = current_version
                        if _version_tuple(current_version) < _version_tuple(
                            CONFIG.firmware_baseline_version
                        ):
                            result.error = "Baseline firmware not detected after activation reboot"
                            return result
                        stage("BASELINE_ACTIVE")

                if firmware_was_triggered and activation_mode == "manual":
                    log(
                        f"[{ip}] Firmware download complete. Manual activation required.",
                        "warning",
                        callback=callback,
                    )
                    result.status = "manual"
                    result.success = True
                    stage("MANUAL_ACTIVATION")
                    log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                    return result

                if firmware_was_triggered and activation_mode == "scheduled":
                    log(
                        f"[{ip}] Firmware download complete. Added to loading queue.",
                        "warning",
                        callback=callback,
                    )
                    result.status = "loading"
                    result.success = True
                    stage("LOADING")
                    log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                    return result

                if firmware_was_triggered and activation_mode == "immediate" and not result.error:
                    client.close()
                    client = wait_for_device_ready_and_reconnect(
                        ip,
                        username=login_username,
                        password=login_password,
                        fallback_password=CONFIG.default_password,
                        callback=callback,
                        initial_delay=CONFIG.firmware_first_check_delay,
                    )
                    if not client:
                        result.error = "Device did not recover within 60 minutes after activation"
                        return result
                    current_version = get_firmware_version(client, callback=callback)
                    result.firmware_version_after = current_version
                    if not current_version:
                        log(
                            f"[{ip}] Firmware version unavailable after reboot; keeping radio in loading queue for deferred verification.",
                            "warning",
                            callback=callback,
                        )
                        result.status = "pending_verify"
                        result.success = True
                        stage("VERSION_DEFERRED")
                        log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                        return result

            if baseline_needed and result.firmware_activated:
                current_version = get_firmware_version(client, callback=callback)
                if not current_version:
                    log(
                        f"[{ip}] Firmware version unavailable after activation reboot; deferring verification.",
                        "warning",
                        callback=callback,
                    )
                    result.status = "pending_verify"
                    result.success = True
                    stage("VERSION_DEFERRED")
                    log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                    return result
                if _version_tuple(current_version) < _version_tuple(
                    CONFIG.firmware_final_version
                ):
                    log(
                        f"[{ip}] Final firmware not detected; stopping remaining tasks.",
                        "warning",
                        callback=callback,
                    )
                    result.error = "Final firmware not detected after activation"
                    return result

        # Activation-only step for scheduled queue
        if _task("activate"):
            if abort_if_needed():
                return result
            current_version = get_firmware_version(client, callback=callback)
            result.firmware_version_before = current_version
            if _version_tuple(current_version) >= _version_tuple(
                CONFIG.firmware_final_version
            ):
                log(
                    f"[{ip}] Firmware already at {current_version}; skipping activation.",
                    "info",
                    callback=callback,
                )
                result.firmware_activated = True
                result.firmware_version_after = current_version
                stage("ACTIVATE_SKIP_FINAL")
            else:
                # Uptime gating handled earlier; no reboot here.
                success, msg = activate_firmware(client, callback=callback)
                result.firmware_activated = success
                if not success and not result.error:
                    result.error = msg
                    return result
                if isinstance(msg, str) and msg.lower().startswith("activation fallback:"):
                    msg_lower = msg.lower()
                    if "load" in msg_lower:
                        result.status = "loading"
                        result.success = True
                        stage("ACTIVATE_FALLBACK_LOAD")
                        return result
                stage("ACTIVATE")
                client.close()
                client = wait_for_device_ready_and_reconnect(
                    ip,
                    username=login_username,
                    password=login_password,
                    fallback_password=CONFIG.default_password,
                    callback=callback,
                    initial_delay=CONFIG.firmware_first_check_delay,
                )
                if not client:
                    result.error = "Device did not recover within 60 minutes after activation"
                    return result
                current_version = get_firmware_version(client, callback=callback)
                if not current_version:
                    log(
                        f"[{ip}] Firmware version unavailable after activation reboot; deferring verification.",
                        "warning",
                        callback=callback,
                    )
                    result.status = "pending_verify"
                    result.success = True
                    stage("VERSION_DEFERRED")
                    log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
                    return result
                if _version_tuple(current_version) < _version_tuple(
                    CONFIG.firmware_final_version
                ):
                    inactive_after_activate = get_inactive_firmware_version(client, callback=callback)
                    inactive_after_activate = (inactive_after_activate or "").strip()
                    if _version_tuple(inactive_after_activate) >= _version_tuple(
                        CONFIG.firmware_final_version
                    ):
                        # Final is already loaded in inactive slot; do not re-download and
                        # do not move to loading queue. Keep in deferred verification/scheduled.
                        log(
                            f"[{ip}] Final firmware already present as inactive ({inactive_after_activate}); awaiting reboot/version flip.",
                            "warning",
                            callback=callback,
                        )
                        result.firmware_scheduled = True
                        result.status = "pending_verify"
                        result.success = True
                        stage("ACTIVATE_DEFERRED")
                        return result
                    if _version_tuple(current_version) >= _version_tuple(
                        CONFIG.firmware_baseline_version
                    ):
                        log(
                            f"[{ip}] Baseline active; scheduling final firmware download.",
                            "warning",
                            callback=callback,
                        )
                        success, msg = trigger_firmware_download(
                            client,
                            CONFIG.firmware_final_uri,
                            activation_time,
                            False,
                            "scheduled",
                            callback=callback,
                        )
                        result.firmware_downloaded = result.firmware_downloaded or success
                        result.firmware_scheduled = result.firmware_scheduled or success
                        if success:
                            result.firmware_downloaded_version = CONFIG.firmware_final_version
                        result.status = "loading"
                        result.success = True
                        return result
                    result.error = "Final firmware not detected after activation"
                    return result
        
        # 1. Change Credentials
        if _task("password"):
            if login_password == CONFIG.new_password:
                log(
                    f"[{ip}] Skipping password change (already using new password).",
                    "info",
                    callback=callback,
                )
                result.password_changed = True
                stage("PASSWORD_SKIP")
            else:
                if abort_if_needed():
                    return result
                success, msg = change_password(client, callback=callback)
                result.password_changed = success
                if not success:
                    result.error = msg
                stage("PASSWORD_SET" if success else "PASSWORD_FAIL")

        # 2. Configure SNMP
        if _task("snmp"):
            if abort_if_needed():
                return result
            success, msg = configure_snmp(client, callback=callback)
            result.snmp_configured = success
            if not success and not result.error:
                result.error = msg
            stage("SNMP_SET" if success else "SNMP_FAIL")

        # 3. Run Buffer Script
        if _task("buffer"):
            if abort_if_needed():
                return result
            success, msg = configure_buffer(client, callback=callback)
            result.buffer_configured = success
            if not success and not result.error: result.error = msg
            stage("BUFFER_SET" if success else "BUFFER_SKIP_OR_FAIL")

        # 4. SOP checks (skip until firmware final is active)
        if _task("sop"):
            if abort_if_needed():
                return result
            if result.status in ("loading", "scheduled", "manual"):
                log(
                    f"[{ip}] Skipping SOP checks while firmware is {result.status}.",
                    "warning",
                    callback=callback,
                )
                result.sop_checked = False
                result.sop_passed = True
                fw_for_sop = None
                stage("SOP_SKIP_LOADING")
            else:
                fw_for_sop = result.firmware_version_after or result.firmware_version_before
            if fw_for_sop and _version_tuple(fw_for_sop) < _version_tuple(CONFIG.firmware_final_version):
                log(
                    f"[{ip}] Skipping SOP checks until firmware {CONFIG.firmware_final_version}+ is active.",
                    "warning",
                    callback=callback,
                )
                result.sop_checked = False
                result.sop_passed = True
                stage("SOP_SKIP_FW")
            else:
                if fw_for_sop is not None:
                    passed, results = run_sop_checks(client, callback=callback)
                    result.sop_checked = True
                    result.sop_passed = passed
                    result.sop_results = results
                    if not passed and not result.error:
                        result.error = "SOP checks failed"
                    stage("SOP_OK" if passed else "SOP_FAIL")

        if _task("firmware", "sop"):
            result.firmware_version_after = get_firmware_version(client, callback=callback)
            
        # Overall success check
        result.success = True
        if _task("firmware") and not (
            result.firmware_downloaded
            or result.firmware_activated
            or result.firmware_scheduled
            or result.status in ("loading", "scheduled", "manual", "pending_verify", "reboot_pending")
        ):
            result.success = False
        if _task("password") and not result.password_changed:
            result.success = False
        if _task("snmp") and not result.snmp_configured:
            result.success = False
        if _task("buffer") and not result.buffer_configured:
            result.success = False
        if _task("sop") and result.sop_checked and not result.sop_passed:
            result.success = False
            
        result.output = client.output_buffer
        
    except Exception as e:
        result.error = str(e)
        upgrade_related = any(t in tasks for t in ("firmware", "activate", "all", "sop"))
        if upgrade_related and _is_transient_processing_error(e):
            # During activation/reboot windows, transient SSH/CLI errors are expected.
            # Keep radios in deferred queue states instead of hard-failing them.
            if result.status not in (
                "loading",
                "scheduled",
                "manual",
                "pending_verify",
                "reboot_required",
                "reboot_pending",
                "rebooting",
                "precheck_failed",
            ):
                result.status = "pending_verify"
            result.success = True
            stage("DEFERRED_TRANSIENT")
            log(
                f"[{ip}] Transient device state during upgrade ({e}); deferring verification.",
                "warning",
                callback=callback,
            )
        else:
            log(f"[{ip}] ERROR: {e}", "error", callback=callback)
        
    finally:
        if client:
            client.close()
        result.duration = time.time() - start_time
        
    status = "SUCCESS" if result.success else "FAILED"
    log(f"[{ip}] {status} (took {result.duration:.1f}s)", "success" if result.success else "error", callback=callback)
    if stages:
        log(f"[{ip}] WORKFLOW: " + " -> ".join(stages), "info", callback=callback)
    
    return result


def process_radios_parallel(
    ips: List[str],
    tasks: List[str],
    maintenance_params: Optional[Dict[str, Any]] = None,
    should_abort: Optional[callable] = None,
    callback=None,
    max_workers: Optional[int] = None,
) -> List[RadioResult]:
    """Process multiple radios in parallel"""
    results = []
    worker_count = max_workers if max_workers is not None else CONFIG.max_workers
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                process_radio,
                ip,
                tasks,
                callback,
                maintenance_params,
                should_abort,
            ): ip
            for ip in ips
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            
    return results
def process_radios_sequential(
    ips: List[str],
    tasks: List[str],
    maintenance_params: Optional[Dict[str, Any]] = None,
    should_abort: Optional[callable] = None,
) -> List[RadioResult]:
    """Process multiple radios one by one"""
    results = []
    for ip in ips:
        result = process_radio(ip, tasks, None, maintenance_params, should_abort)
        results.append(result)
    return results


# ============================================================================
# LOGGING & OUTPUT
# ============================================================================

LOG_COLORS = {
    "info": "\033[0m",      # Default
    "success": "\033[92m",  # Green
    "warning": "\033[93m",  # Yellow
    "error": "\033[91m",    # Red
    "reset": "\033[0m",
}

def log(message: str, level: str = "info", callback=None):
    """Print colored log message and optionally call a callback"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = LOG_COLORS.get(level, LOG_COLORS["info"])
    reset = LOG_COLORS["reset"]
    formatted_msg = f"[{timestamp}] {message}"
    print(f"{color}{formatted_msg}{reset}")
    if callback:
        callback(formatted_msg, level)


def print_summary(results: List[RadioResult]):
    """Print summary of results"""
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    total = len(results)
    success = sum(1 for r in results if r.success)
    failed = total - success
    
    pwd_changed = sum(1 for r in results if r.password_changed)
    snmp_configured = sum(1 for r in results if r.snmp_configured)
    firmware_downloaded = sum(1 for r in results if r.firmware_downloaded)
    sop_passed = sum(1 for r in results if r.sop_passed)
    
    print(f"Total radios:      {total}")
    print(f"Successful:        {success}")
    print(f"Failed:            {failed}")
    print(f"Firmware started:  {firmware_downloaded}")
    print(f"Passwords changed: {pwd_changed}")
    print(f"SNMP configured:   {snmp_configured}")
    print(f"SOP passed:        {sop_passed}")
    print()
    
    if failed > 0:
        print("Failed radios:")
        for r in results:
            if not r.success:
                print(f"  - {r.ip}: {r.error or 'Unknown error'}")
    
    print("=" * 60)


def export_results(results: List[RadioResult], filename: str):
    """Export results to CSV"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'IP',
            'Success',
            'Firmware Started',
            'Firmware Scheduled',
            'Firmware Activated',
            'Password Changed',
            'SNMP Configured',
            'Buffer Configured',
            'SOP Passed',
            'Error',
            'Duration',
        ])
        
        for r in results:
            writer.writerow([
                r.ip,
                r.success,
                r.firmware_downloaded,
                r.firmware_scheduled,
                r.firmware_activated,
                r.password_changed,
                r.snmp_configured,
                r.buffer_configured,
                r.sop_passed,
                r.error or '',
                f"{r.duration:.1f}s"
            ])
    
    log(f"Results exported to {filename}", "success")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def load_ips_from_file(filename: str) -> List[str]:
    """Load IP addresses from file (one per line or comma-separated)"""
    ips = []
    
    with open(filename, 'r') as f:
        for line in f:
            # Handle comma-separated and newline-separated
            for ip in line.strip().split(','):
                ip = ip.strip()
                if ip and not ip.startswith('#'):
                    ips.append(ip)
                    
    return ips


def interactive_mode():
    """Run in interactive mode"""
    print("\n" + "=" * 60)
    print("AVIAT RADIO CONFIGURATION TOOL")
    print("For WTM4200 series with firmware 6.1.0+")
    print("=" * 60)
    print("Tasks: firmware, password, SNMP, buffer, SOP")
    print(f"Default login: {CONFIG.default_username}/{CONFIG.default_password}")
    print(f"New password:  {CONFIG.default_username}/{CONFIG.new_password}")
    print(f"SNMP Mode:     {CONFIG.snmp_mode}")
    print(f"SNMP Community: {CONFIG.snmp_community}")
    print("=" * 60)
    
    # Get IPs
    print("\nEnter radio IP addresses (comma or newline separated).")
    print("Type 'done' when finished:\n")
    
    ips = []
    while True:
        line = input("> ").strip()
        if line.lower() == 'done':
            break
        if line.lower() == 'quit' or line.lower() == 'exit':
            print("Exiting.")
            return
        for ip in line.split(','):
            ip = ip.strip()
            if ip:
                ips.append(ip)
                print(f"  Added: {ip}")
    
    if not ips:
        print("No IPs entered. Exiting.")
        return
    
    # Select tasks
    print(f"\nTasks to execute on {len(ips)} radio(s):")
    print("  Enter comma-separated tasks: firmware,password,snmp,buffer,sop")
    print("  Or type 'all' to run everything.")
    choice = input("\nSelect tasks [all]: ").strip()
    if not choice:
        choice = "all"
    tasks = [t.strip() for t in choice.split(",") if t.strip()]
    
    # Confirm
    print(f"\nReady to configure {len(ips)} radio(s).")
    print(f"Tasks: {', '.join(tasks)}")
    confirm = input("Proceed? [y/N]: ").strip().lower()
    
    if confirm != 'y':
        print("Aborted.")
        return
    
    # Process
    print("\n" + "-" * 60)
    results = process_radios_sequential(ips, tasks)
    print_summary(results)
    
    # Export option
    export = input("\nExport results to CSV? [y/N]: ").strip().lower()
    if export == 'y':
        filename = f"aviat_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        export_results(results, filename)


def main():
    parser = argparse.ArgumentParser(
        description="Aviat Radio Configuration Tool - SSH Backend (WTM4200 series)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aviat_config.py --ip 10.0.1.100
  python aviat_config.py --ip 10.0.1.100,10.0.1.101,10.0.1.102
  python aviat_config.py --file radios.txt
  python aviat_config.py --ip 10.0.1.100 --tasks password
  python aviat_config.py --ip 10.0.1.100 --tasks snmp
  python aviat_config.py --file radios.txt --parallel --export results.csv
        """
    )
    
    parser.add_argument('--ip', '-i', help='Single IP or comma-separated list of IPs')
    parser.add_argument('--file', '-f', help='File containing IP addresses')
    parser.add_argument(
        '--tasks',
        '-t',
        default='all',
        help='Tasks to execute (comma-separated: firmware,password,snmp,buffer,sop,all)',
    )
    parser.add_argument('--parallel', '-p', action='store_true',
                        help='Process radios in parallel')
    parser.add_argument('--workers', '-w', type=int, default=5,
                        help='Number of parallel workers (default: 5)')
    parser.add_argument('--export', '-e', help='Export results to CSV file')
    parser.add_argument('--interactive', action='store_true',
                        help='Run in interactive mode')
    
    # Configuration overrides
    parser.add_argument('--username', default=CONFIG.default_username,
                        help=f'Login username (default: {CONFIG.default_username})')
    parser.add_argument('--password', default=CONFIG.default_password,
                        help=f'Login password (default: {CONFIG.default_password})')
    parser.add_argument('--new-password', default=CONFIG.new_password,
                        help='New password to set')
    parser.add_argument('--snmp-mode', default=CONFIG.snmp_mode,
                        help=f'SNMP mode (default: {CONFIG.snmp_mode})')
    parser.add_argument('--snmp-community', default=CONFIG.snmp_community,
                        help=f'SNMP community (default: {CONFIG.snmp_community})')
    parser.add_argument('--port', type=int, default=CONFIG.ssh_port,
                        help=f'SSH port (default: {CONFIG.ssh_port})')
    parser.add_argument(
        '--firmware-target',
        choices=['baseline', 'final'],
        default='final',
        help='Firmware target (default: final)',
    )
    parser.add_argument('--firmware-uri', help='Override firmware URI')
    parser.add_argument(
        '--activation-time',
        help='Activation time (HH:MM) for scheduled upgrade',
    )
    parser.add_argument(
        '--activate-now',
        action='store_true',
        help='Activate firmware immediately after download',
    )
    parser.add_argument(
        '--activation-mode',
        choices=['scheduled', 'immediate', 'manual'],
        default='scheduled',
        help='Activation mode (default: scheduled)',
    )
    parser.add_argument('--sop-checks', help='Path to SOP checks JSON file')
    
    args = parser.parse_args()
    
    # Update config from args
    CONFIG.default_username = args.username
    CONFIG.default_password = args.password
    CONFIG.new_password = args.new_password
    CONFIG.snmp_mode = args.snmp_mode
    CONFIG.snmp_community = args.snmp_community
    CONFIG.ssh_port = args.port
    CONFIG.max_workers = args.workers
    if args.sop_checks:
        CONFIG.sop_checks_path = args.sop_checks
    
    # Interactive mode
    if args.interactive or (not args.ip and not args.file):
        interactive_mode()
        return
    
    # Collect IPs
    ips = []
    
    if args.ip:
        ips.extend([ip.strip() for ip in args.ip.split(',') if ip.strip()])
        
    if args.file:
        try:
            ips.extend(load_ips_from_file(args.file))
        except FileNotFoundError:
            log(f"File not found: {args.file}", "error")
            sys.exit(1)
    
    if not ips:
        log("No IP addresses provided", "error")
        sys.exit(1)
    
    # Remove duplicates while preserving order
    ips = list(dict.fromkeys(ips))
    
    # Print header
    print("\n" + "=" * 60)
    print("AVIAT RADIO CONFIGURATION TOOL")
    print("For WTM4200 series with firmware 6.1.0+")
    print("=" * 60)
    print(f"Radios:        {len(ips)}")
    print(f"Tasks:         {args.tasks}")
    print(f"Firmware URI:  {args.firmware_uri or args.firmware_target}")
    if args.activation_time:
        print(f"Activation:    {args.activation_time} ({'now' if args.activate_now else 'scheduled'})")
    else:
        print(f"Activation:    {'now' if args.activate_now else 'scheduled'}")
    print(f"Mode:          {'Parallel' if args.parallel else 'Sequential'}")
    print(f"Login:         {CONFIG.default_username}/{CONFIG.default_password}")
    print(f"New password:  {CONFIG.new_password}")
    print(f"SNMP:          {CONFIG.snmp_mode} / {CONFIG.snmp_community}")
    print("=" * 60 + "\n")
    
    # Process
    tasks = [t.strip() for t in args.tasks.split(",") if t.strip()] or ["all"]
    maintenance_params = {
        "firmware_target": args.firmware_target,
        "firmware_uri": args.firmware_uri,
        "activation_time": args.activation_time,
        "activate_now": args.activate_now if args.activate_now else None,
        "activation_mode": args.activation_mode,
    }
    
    if args.parallel:
        results = process_radios_parallel(ips, tasks, maintenance_params)
    else:
        results = process_radios_sequential(ips, tasks, maintenance_params)
    
    # Summary
    print_summary(results)
    
    # Export
    if args.export:
        export_results(results, args.export)
    
    # Exit code
    failed = sum(1 for r in results if not r.success)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
