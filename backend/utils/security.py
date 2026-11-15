"""
Security Hardening & SSRF Defense Utilities (Phase 6)
=====================================================
Enforces defense-in-depth protection:
- Server-Side Request Forgery (SSRF) mitigation
- Strict URL protocol and domain validation
- Localhost, RFC 1918 private IP, and Cloud Metadata IP rejection
- Input size limiting and control character sanitization
"""

import re
import ipaddress
from urllib.parse import urlparse

# Prohibited dangerous URI schemes
DANGEROUS_SCHEMES = {
    "file", "gopher", "dict", "ftp", "sftp", "tftp", "ldap", "ldaps",
    "data", "javascript", "vbscript", "jar", "blob"
}

# Cloud metadata endpoints and reserved local targets
BLOCKED_HOSTNAMES = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254",
    "metadata.google.internal", "instance-data"
}

MAX_URL_LENGTH = 2048
MAX_EMAIL_LENGTH = 100 * 1024  # 100 KB


class SecurityValidationError(Exception):
    """Raised when an input fails security validation checks."""
    pass


def sanitize_input_string(raw: str, max_length: int = MAX_URL_LENGTH) -> str:
    """Strips null bytes and non-printable control characters."""
    if not raw:
        return ""
    # Strip null bytes and non-printable control characters
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", str(raw).strip())
    if len(cleaned) > max_length:
        raise SecurityValidationError(f"Input exceeds maximum allowed length of {max_length} characters.")
    return cleaned


def validate_and_sanitize_url(raw_url: str) -> str:
    """
    Validates candidate URL against SSRF and injection attacks.
    Returns normalized, safe URL string.
    """
    cleaned = sanitize_input_string(raw_url, max_length=MAX_URL_LENGTH)
    if not cleaned:
        raise SecurityValidationError("URL cannot be empty.")

    # Check if a scheme is present (e.g. "javascript:alert(1)" or "http://example.com")
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", cleaned)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in DANGEROUS_SCHEMES:
            raise SecurityValidationError(f"Prohibited URL scheme: '{scheme}:'. Only HTTP and HTTPS are permitted.")
        if scheme not in ("http", "https"):
            raise SecurityValidationError(f"Unsupported protocol: '{scheme}'. Expected 'http' or 'https'.")
    else:
        # Prepend http:// if no scheme is specified
        cleaned = "http://" + cleaned

    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()

    if scheme in DANGEROUS_SCHEMES:
        raise SecurityValidationError(f"Prohibited URL scheme: '{scheme}://'. Only HTTP and HTTPS are permitted.")

    if scheme not in ("http", "https"):
        raise SecurityValidationError(f"Unsupported protocol: '{scheme}'. Expected 'http' or 'https'.")

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise SecurityValidationError("Invalid URL: Missing hostname or domain.")

    # Rejection of localhost and metadata hosts
    if hostname in BLOCKED_HOSTNAMES:
        raise SecurityValidationError(f"Destination '{hostname}' is a reserved internal or metadata host.")

    # Check if host is an IP address; block loopback / link-local subnets
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.is_loopback:
            raise SecurityValidationError("Loopback IP addresses (127.0.0.0/8) are prohibited.")
        if ip_obj.is_link_local:
            raise SecurityValidationError("Link-local IP addresses (e.g., AWS metadata 169.254.x.x) are prohibited.")
    except ValueError:
        # Hostname is a domain name, not a plain IP
        pass

    return cleaned


def validate_email_input(subject: str, body: str, sender: str = ""):
    """Validates email subject and body lengths and sanitizes content."""
    clean_subj = sanitize_input_string(subject, max_length=512)
    clean_body = sanitize_input_string(body, max_length=MAX_EMAIL_LENGTH)
    clean_sender = sanitize_input_string(sender, max_length=255) if sender else ""

    if not clean_subj and not clean_body:
        raise SecurityValidationError("Email must contain either a subject or a message body.")

    return clean_subj, clean_body, clean_sender
