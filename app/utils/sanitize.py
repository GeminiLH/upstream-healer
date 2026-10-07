"""
Data sanitization utilities for privacy protection.
"""
import re
from typing import Optional


# Regular expressions for network identifiers
IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_ADDRESS = re.compile(
    r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b"
)


def sanitize_mac_address(mac: str) -> str:
    """
    Sanitize a MAC address by masking the last 3 octets.
    
    Args:
        mac: The MAC address string
        
    Returns:
        Sanitized MAC address (e.g., "AA:BB:CC:DD:EE:FF" -> "AA:BB:CC:*:*:*")
    """
    if not mac:
        return ""
    
    # Normalize MAC format to use colons
    normalized_mac = mac.replace("-", ":").replace(".", ":")
    
    # Split into octets and mask the last three
    octets = normalized_mac.split(":")
    if len(octets) >= 3:
        # Mask last 3 octets, keep first 3
        octets[3:] = ["*"] * (len(octets) - 3)
    
    return ":".join(octets)


def sanitize_ip_address(ip: str) -> str:
    """
    Sanitize an IP address by masking the last octet.
    
    Args:
        ip: The IP address string
        
    Returns:
        Sanitized IP address (e.g., "192.168.1.100" -> "192.168.1.*")
    """
    if not ip:
        return ""
        
    # Split into octets and mask the last one
    octets = ip.split(".")
    if len(octets) >= 4:
        octets[3] = "*"
    
    return ".".join(octets)


def sanitize_message_text(text: str, preserve_names: bool = True) -> str:
    """
    Sanitize message text by removing or masking network identifiers.
    
    Args:
        text: The text to sanitize
        preserve_names: Whether to preserve hostnames (if they don't contain IPs/MACs)
        
    Returns:
        Sanitized text with sensitive data masked
    """
    if not text:
        return ""
        
    # First, mask MAC addresses
    sanitized = MAC_ADDRESS.sub(lambda m: sanitize_mac_address(m.group()), text)
    
    # Then, mask IP addresses  
    sanitized = IP_ADDRESS.sub(lambda m: sanitize_ip_address(m.group()), sanitized)
    
    # Clean up extra spaces from masking
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    
    return sanitized


def sanitize_email_content(message: str, details: str = "") -> tuple[str, str]:
    """
    Sanitize email message and details content.
    
    Args:
        message: Main email message
        details: Additional details
        
    Returns:
        Tuple of (sanitized_message, sanitized_details)
    """
    sanitized_message = sanitize_message_text(message)
    sanitized_details = sanitize_message_text(details) if details else ""
    
    return sanitized_message, sanitized_details