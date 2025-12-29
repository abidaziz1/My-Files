"""
Channel Hopper Module - Dual Band Support (2.4GHz + 5GHz) - FIXED
Handles automated channel hopping across both frequency bands
"""

import subprocess
import threading
import time
import re
from typing import List, Optional, Callable, Dict
from loguru import logger


class ChannelHopper:
    """
    Manages channel hopping for WiFi monitoring with dual-band support.
    
    Supports both 2.4GHz (channels 1-14) and 5GHz (channels 36-165) bands.
    Uses intelligent interleaving to efficiently cover both bands.
    """
    
    def __init__(
        self,
        interface: str,
        hop_interval: float = 0.5,
        channel_list: Optional[List[int]] = None
    ):
        """
        Initialize the channel hopper.
        
        Args:
            interface: Wireless interface name (e.g., 'wlan0')
            hop_interval: Time in seconds between channel switches
            channel_list: Optional list of specific channels to hop
        """
        self.interface = interface
        self.hop_interval = hop_interval
        self._stop_event = threading.Event()
        self._hop_thread: Optional[threading.Thread] = None
        self._channel_callbacks: List[Callable] = []
        self.current_channel: Optional[int] = None
        
        # Detect supported channels
        self.channels_24 = self._get_supported_channels_24()
        self.channels_5 = self._get_supported_channels_5()
        
        # Use custom list or interleaved default
        if channel_list:
            self.all_channels = channel_list
        else:
            self.all_channels = self._interleave_channels(
                self.channels_24, 
                self.channels_5
            )
        
        logger.info(f"ChannelHopper initialized for {interface}")
        logger.info(f"2.4GHz channels ({len(self.channels_24)}): {self.channels_24}")
        logger.info(f"5GHz channels ({len(self.channels_5)}): {self.channels_5}")
        logger.info(f"Will hop across {len(self.all_channels)} channels")
    
    def _get_supported_channels_24(self) -> List[int]:
        """
        Get supported 2.4GHz channels (1-14).
        
        Returns:
            List of supported 2.4GHz channel numbers
        """
        try:
            result = subprocess.run(
                ["iw", "phy", "phy0", "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.warning("Could not detect 2.4GHz channels, using default")
                return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
            
            channels = []
            in_24ghz_section = False
            
            for line in result.stdout.split('\n'):
                # Detect Band 1 (2.4GHz) - more reliable than looking for frequency ranges
                if 'Band 1:' in line:
                    in_24ghz_section = True
                    logger.debug("Detected Band 1 (2.4GHz) section")
                elif 'Band 2:' in line or 'Band 3:' in line or 'Band 4:' in line:
                    in_24ghz_section = False
                
                # Extract channels from lines like "* 2412.0 MHz [1] (30.0 dBm)"
                if in_24ghz_section and 'MHz' in line and '[' in line:
                    # Match frequency in 2.4GHz range (2400-2500 MHz)
                    freq_match = re.search(r'(\d{4})\.\d MHz', line)
                    chan_match = re.search(r'\[(\d+)\]', line)
                    
                    if freq_match and chan_match:
                        freq = int(freq_match.group(1))
                        channel = int(chan_match.group(1))
                        
                        # Verify it's in 2.4GHz range and not disabled
                        if 2400 <= freq <= 2500 and 1 <= channel <= 14:
                            if 'disabled' not in line.lower():
                                channels.append(channel)
                                logger.debug(f"Found 2.4GHz channel {channel} at {freq} MHz")
            
            if channels:
                logger.info(f"Detected {len(channels)} active 2.4GHz channels")
                return sorted(set(channels))
            else:
                logger.warning("No 2.4GHz channels detected, using defaults")
                return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
                
        except Exception as e:
            logger.error(f"Error detecting 2.4GHz channels: {e}")
            return [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    
    def _get_supported_channels_5(self) -> List[int]:
        """
        Get supported 5GHz channels (36-165).
        
        Returns:
            List of supported 5GHz channel numbers
        """
        try:
            result = subprocess.run(
                ["iw", "phy", "phy0", "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.warning("Could not detect 5GHz channels")
                return []
            
            channels = []
            in_5ghz_section = False
            
            for line in result.stdout.split('\n'):
                # Detect Band 2 (5GHz) - Band 1 is 2.4GHz, Band 2 is 5GHz
                if 'Band 2:' in line:
                    in_5ghz_section = True
                    logger.debug("Detected Band 2 (5GHz) section")
                elif 'Band 3:' in line or 'Band 4:' in line:
                    in_5ghz_section = False
                
                # Extract channels from lines like "* 5180.0 MHz [36] (23.0 dBm)"
                if in_5ghz_section and 'MHz' in line and '[' in line:
                    # Match frequency in 5GHz range (5000-6000 MHz)
                    freq_match = re.search(r'(\d{4})\.\d MHz', line)
                    chan_match = re.search(r'\[(\d+)\]', line)
                    
                    if freq_match and chan_match:
                        freq = int(freq_match.group(1))
                        channel = int(chan_match.group(1))
                        
                        # Verify it's in 5GHz range and not disabled
                        if 5000 <= freq <= 6000 and 36 <= channel <= 165:
                            if 'disabled' not in line.lower():
                                channels.append(channel)
                                logger.debug(f"Found 5GHz channel {channel} at {freq} MHz")
            
            if channels:
                logger.info(f"Detected {len(channels)} active 5GHz channels")
                return sorted(set(channels))
            else:
                logger.warning("No 5GHz channels detected - adapter may not support 5GHz")
                return []
                
        except Exception as e:
            logger.error(f"Error detecting 5GHz channels: {e}")
            return []
    
    def _interleave_channels(
        self, 
        channels_24: List[int], 
        channels_5: List[int]
    ) -> List[int]:
        """
        Interleave 2.4GHz and 5GHz channels for efficient scanning.
        
        Strategy: Alternate between bands to catch traffic on both quickly.
        Example: [1, 36, 6, 44, 11, 149, ...]
        
        Args:
            channels_24: List of 2.4GHz channels
            channels_5: List of 5GHz channels
            
        Returns:
            Interleaved channel list
        """
        interleaved = []
        max_len = max(len(channels_24), len(channels_5))
        
        for i in range(max_len):
            if i < len(channels_24):
                interleaved.append(channels_24[i])
            if i < len(channels_5):
                interleaved.append(channels_5[i])
        
        return interleaved
    
    def set_channel(self, channel: int) -> bool:
        """
        Set the wireless interface to a specific channel.
        
        Args:
            channel: Channel number to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine frequency from channel
            if 1 <= channel <= 14:
                # 2.4GHz: Channel to frequency conversion
                freq = 2407 + (channel * 5)
            elif 36 <= channel <= 165:
                # 5GHz: Channel to frequency conversion
                freq = 5000 + (channel * 5)
            else:
                logger.error(f"Invalid channel: {channel}")
                return False
            
            # Set using iw
            result = subprocess.run(
                ["iw", "dev", self.interface, "set", "freq", str(freq)],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                self.current_channel = channel
                
                # Notify callbacks
                for callback in self._channel_callbacks:
                    try:
                        callback(channel)
                    except Exception as e:
                        logger.error(f"Channel callback error: {e}")
                
                return True
            else:
                logger.error(f"Failed to set channel {channel}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error setting channel {channel}: {e}")
            return False
    
    def register_callback(self, callback: Callable[[int], None]) -> None:
        """
        Register a callback to be notified on channel changes.
        
        Args:
            callback: Function that takes channel number as argument
        """
        self._channel_callbacks.append(callback)
    
    def _hop_loop(self) -> None:
        """Internal method - continuous channel hopping loop"""
        logger.info("Channel hopping started")
        
        while not self._stop_event.is_set():
            for channel in self.all_channels:
                if self._stop_event.is_set():
                    break
                
                self.set_channel(channel)
                if channel >= 36:
                    time.sleep(self.hop_interval*2)
                else:
                    time.sleep(self.hop_interval)
        
        logger.info("Channel hopping stopped")
    
    def start(self) -> None:
        """Start channel hopping in background thread"""
        if self._hop_thread and self._hop_thread.is_alive():
            logger.warning("Channel hopping already running")
            return
        
        self._stop_event.clear()
        self._hop_thread = threading.Thread(target=self._hop_loop, daemon=True)
        self._hop_thread.start()
        logger.info("Channel hopper started")
    
    def stop(self) -> None:
        """Stop channel hopping"""
        if not self._hop_thread or not self._hop_thread.is_alive():
            logger.warning("Channel hopping not running")
            return
        
        logger.info("Stopping channel hopper...")
        self._stop_event.set()
        
        if self._hop_thread:
            self._hop_thread.join(timeout=5)
        
        logger.info("Channel hopper stopped")
    
    def is_running(self) -> bool:
        """Check if channel hopping is active"""
        return self._hop_thread is not None and self._hop_thread.is_alive()
    
    def get_stats(self) -> Dict:
        """Get channel hopper statistics"""
        return {
            'interface': self.interface,
            'current_channel': self.current_channel,
            'hop_interval': self.hop_interval,
            'total_channels': len(self.all_channels),
            'channels_24ghz': len(self.channels_24),
            'channels_5ghz': len(self.channels_5),
            'is_running': self.is_running()
        }


if __name__ == "__main__":
    # Test the channel hopper
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python channel_hopper.py <interface>")
        print("Example: python channel_hopper.py wlan0")
        sys.exit(1)
    
    interface = sys.argv[1]
    
    print(f"\n{'='*60}")
    print(f"Channel Hopper Test - Interface: {interface}")
    print(f"{'='*60}\n")
    
    hopper = ChannelHopper(interface, hop_interval=1.0)
    
    print(f"\nDetected Channels:")
    print(f"  2.4GHz: {hopper.channels_24}")
    print(f"  5GHz: {hopper.channels_5}")
    print(f"  Total: {len(hopper.all_channels)} channels\n")
    
    # Test channel setting
    print("Testing channel setting...")
    if hopper.channels_24:
        ch = hopper.channels_24[0]
        print(f"  Testing 2.4GHz channel {ch}...", end=" ")
        if hopper.set_channel(ch):
            print("✓")
        else:
            print("✗")
    
    if hopper.channels_5:
        ch = hopper.channels_5[0]
        print(f"  Testing 5GHz channel {ch}...", end=" ")
        if hopper.set_channel(ch):
            print("✓")
        else:
            print("✗ (adapter may not support 5GHz)")
    
    print("\nChannel hopper test complete!")
