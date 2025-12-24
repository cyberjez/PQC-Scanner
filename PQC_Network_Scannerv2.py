#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, List, Tuple
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import shutil
import os
import sys
import time
import random

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import re


# IDS-Safe Throttling Modes Configuration
THROTTLING_MODES = {
    "Normal": {
        "name": "Normal (No Throttling)",
        "description": "Full speed scanning - may trigger IDS alerts",
        "delay_min": 0.0,
        "delay_max": 0.0,
        "jitter": 0.0,
        "adaptive": False
    },
    "Slow": {
        "name": "Slow (Conservative)",
        "description": "Fixed 2-5 second delays between scans",
        "delay_min": 2.0,
        "delay_max": 5.0,
        "jitter": 0.5,
        "adaptive": False
    },
    "Stealth": {
        "name": "Stealth (Very Slow)",
        "description": "Random 5-15 second delays for maximum stealth",
        "delay_min": 5.0,
        "delay_max": 15.0,
        "jitter": 2.0,
        "adaptive": False
    },
    "Random": {
        "name": "Random (Variable)",
        "description": "Randomized 1-10 second delays to appear organic",
        "delay_min": 1.0,
        "delay_max": 10.0,
        "jitter": 3.0,
        "adaptive": False
    },
    "Adaptive": {
        "name": "Adaptive (Smart)",
        "description": "Adjusts timing based on responses (slow start)",
        "delay_min": 1.0,
        "delay_max": 8.0,
        "jitter": 2.0,
        "adaptive": True
    }
}


# ============================================================================
# SCAN PROFILES DOCUMENTATION
# ============================================================================
# Three pre-configured scan profiles are available for different operational
# scenarios. Each profile automatically configures thread count, rate limiting,
# and timing jitter parameters.
#
# AGGRESSIVE PROFILE:
# - Use Case: Internal networks with no IDS/IPS, time-critical assessments
# - Parameters: 200 threads, 100 req/s, 0.0s jitter, IDS-safe disabled
# - Characteristics:
#   * Maximum scan speed - completes large network scans quickly
#   * High resource utilization on scanning host
#   * WILL trigger IDS/IPS alerts and may be blocked
#   * Suitable for authorized testing in controlled environments only
#   * Risk: May overwhelm target systems or network infrastructure
#
# BALANCED PROFILE (DEFAULT):
# - Use Case: General-purpose scanning, moderate stealth requirements
# - Parameters: 50 threads, 20 req/s, 0.05s jitter, IDS-safe disabled
# - Characteristics:
#   * Good balance between speed and stealth
#   * Moderate resource usage
#   * May trigger some IDS alerts but less aggressive than full-speed scan
#   * Reasonable for routine security assessments in trusted environments
#   * Suitable for most enterprise scanning scenarios
#
# IDS-SAFE PROFILE:
# - Use Case: Sensitive networks, environments with active IDS/IPS monitoring
# - Parameters: 10 threads, 3 req/s, 0.2s jitter, IDS-safe enabled
# - Characteristics:
#   * Maximum stealth - designed to evade detection
#   * Low resource utilization and minimal network impact
#   * Significantly longer scan duration (10-50x slower than Aggressive)
#   * Timing randomization makes traffic appear more organic
#   * Best for: Red team operations, external assessments, monitored networks
#   * Note: Advanced behavioral IDS may still detect patterns
#
# CUSTOMIZATION:
# After selecting a profile, users can manually adjust any parameter without
# changing the profile selection. Profile presets are only reapplied when
# explicitly selecting a different profile from the dropdown.
# ============================================================================


# ============================================================================
# IDS-SAFE MODE DOCUMENTATION
# ============================================================================
# IDS-safe mode is designed to reduce the likelihood of triggering Intrusion
# Detection Systems (IDS) and Intrusion Prevention Systems (IPS) during
# network scanning operations.
#
# PURPOSE:
# - Avoid detection by signature-based IDS/IPS that monitor for rapid
#   connection attempts or port scanning patterns
# - Reduce alert fatigue for security teams by blending scan traffic with
#   normal network activity
# - Enable stealthy reconnaissance in sensitive environments where aggressive
#   scanning may be flagged or blocked
#
# HOW IT WORKS:
# The RateLimiter class enforces two key mechanisms:
#
# 1. RATE PACING:
#    - Limits the maximum number of connection attempts per second
#    - Enforces a minimum time interval between successive operations
#    - Thread-safe implementation ensures rate limits are respected even
#      when using parallel scanning threads
#    - Typical IDS-safe rates: 1-10 requests/second (vs. 100+ without limiting)
#
# 2. TIMING JITTER:
#    - Adds random variance to connection timing (± jitter seconds)
#    - Prevents predictable, fixed-interval patterns that IDS can detect
#    - Makes scan traffic appear more "organic" and less automated
#    - Randomization breaks timing signatures used by behavioral IDS
#
# USAGE RECOMMENDATIONS:
# - Standard stealth: 5 req/s with 0.1s jitter
# - High stealth: 1-2 req/s with 0.5-1.0s jitter
# - Paranoid mode: <1 req/s with 2-5s jitter
# - Use fewer parallel threads (5-10) when IDS-safe mode is enabled
#
# TRADE-OFFS:
# - Significantly increases scan duration
# - May still be detected by advanced behavioral analysis
# - Not a substitute for proper authorization and compliance
# ============================================================================


class RateLimiter:
    """Rate limiter for IDS-safe scanning with jitter support.
    
    Enforces maximum request rate and adds timing jitter to reduce IDS/IPS
    detection probability during network scanning operations.
    """
    def __init__(self, max_rate: float, jitter: float = 0.0):
        """
        Args:
            max_rate: Maximum requests per second (e.g., 5.0 for 5 req/s)
            jitter: Random jitter in seconds to add/subtract from delay (e.g., 0.1)
        """
        self.max_rate = max_rate
        self.jitter = jitter
        self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_call = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Block until enough time has passed to respect the rate limit."""
        with self.lock:
            now = time.time()
            time_since_last = now - self.last_call
            
            # Calculate delay with jitter
            delay = self.min_interval
            if self.jitter > 0:
                jitter_amount = random.uniform(-self.jitter, self.jitter)
                delay = max(0, delay + jitter_amount)
            
            # Wait if needed
            if time_since_last < delay:
                time.sleep(delay - time_since_last)
            
            self.last_call = time.time()


# Canonical OID Registry for Post-Quantum Cryptography
PQC_SIGNATURE_OIDS = {
    # NIST Round 3 - Dilithium (ML-DSA)
    "1.3.6.1.4.1.2.267.7.4.4": "Dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5": "Dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7": "Dilithium5",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",  # NIST standardized
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    
    # NIST Round 3 - Falcon
    "1.3.9999.3.1": "Falcon-512",
    "1.3.9999.3.4": "Falcon-1024",
    "1.3.6.1.4.1.2.267.8.4.4": "Falcon-512",
    "1.3.6.1.4.1.2.267.8.8.8": "Falcon-1024",
    
    # NIST Round 3 - SPHINCS+
    "1.3.9999.6.4.1": "SPHINCS+-SHA256-128f",
    "1.3.9999.6.4.4": "SPHINCS+-SHA256-128s",
    "1.3.9999.6.5.1": "SPHINCS+-SHA256-192f",
    "1.3.9999.6.5.4": "SPHINCS+-SHA256-192s",
    "1.3.9999.6.6.1": "SPHINCS+-SHA256-256f",
    "1.3.9999.6.6.4": "SPHINCS+-SHA256-256s",
    
    # Experimental/Draft OIDs
    "1.3.9999": "Experimental PQC",
    "1.3.6.1.4.1.22554": "PQC Experimental (OpenQuantumSafe)",
}

PQC_KEM_OIDS = {
    # NIST Round 3 - Kyber (ML-KEM)
    "1.3.6.1.4.1.2.267.1.1.1": "Kyber512",
    "1.3.6.1.4.1.2.267.1.1.2": "Kyber768",
    "1.3.6.1.4.1.2.267.1.1.3": "Kyber1024",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",  # NIST standardized
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    
    # Hybrid KEMs
    "1.3.9999.99.1": "X25519-Kyber512",
    "1.3.9999.99.2": "X25519-Kyber768",
    "1.3.9999.99.3": "P-256-Kyber512",
    "1.2.840.10045.3.1.7.1": "secp256r1-Kyber768",  # Hybrid ECDH+Kyber
    
    # Experimental
    "1.3.6.1.4.1.22554.5": "Kyber (OpenQuantumSafe)",
}

PQC_EXTENSION_OIDS = {
    # Certificate extensions indicating PQC support
    "1.3.6.1.5.5.7.1.35": "PQC Certificate Extension",
    "1.3.6.1.4.1.2.267.12": "Composite Key Extension",
    "2.16.840.1.114027.80.8.1": "PQC Algorithm Identifier",
}


@dataclass
class CertAnalysis:
    host: str
    hostname: Optional[str]
    device_type: Optional[str]
    port: int
    success: bool
    error: Optional[str]
    algo_family: Optional[str]
    key_size: Optional[int]
    quantum_vulnerable: Optional[bool]
    severity: Optional[str]
    comment: Optional[str]
    pqc_ready: Optional[bool] = False
    pqc_details: Optional[str] = None
    chain_length: Optional[int] = None
    chain_details: Optional[List[dict]] = None


def fetch_cert_chain_openssl(host: str, port: int, timeout: float = 1.5) -> Optional[List[bytes]]:
    """Use OpenSSL command-line tool to retrieve the full certificate chain."""
    # Check if openssl is available
    if not shutil.which('openssl'):
        return None
    
    try:
        # Run openssl s_client to get the full certificate chain
        cmd = [
            'openssl', 's_client',
            '-connect', f'{host}:{port}',
            '-showcerts',
            '-servername', host
        ]
        
        result = subprocess.run(
            cmd,
            input=b'',
            capture_output=True,
            timeout=timeout
        )
        
        output = result.stdout.decode('utf-8', errors='ignore')
        
        # Extract all certificates from the output
        cert_chain = []
        cert_blocks = re.findall(
            r'-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----',
            output,
            re.DOTALL
        )
        
        for cert_pem in cert_blocks:
            # Reconstruct PEM format and convert to DER
            pem_cert = f"-----BEGIN CERTIFICATE-----\n{cert_pem}\n-----END CERTIFICATE-----"
            try:
                cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
                cert_chain.append(cert.public_bytes(encoding=x509.Encoding.DER))
            except:
                continue
        
        return cert_chain if cert_chain else None
        
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, Exception):
        return None


def fetch_server_certificate(host: str, port: int, timeout: float = 1.5) -> Tuple[List[bytes], Optional[str], Optional[str], Optional[List[str]]]:
    """Fetch the entire DER-encoded certificate chain from a TLS server and negotiated cipher/protocol info.
    Returns: (cert_chain, cipher, protocol_version, supported_groups)
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    conn = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(conn, server_hostname=host)
    
    # Get the full certificate chain in DER format
    cert_chain = []
    try:
        # Get peer certificate chain (returns list of DER-encoded certs)
        # Note: getpeercert_chain() is not available in standard ssl, so we use a workaround
        der_cert = sock.getpeercert(binary_form=True)
        cert_chain.append(der_cert)
        
        # Try to get the full chain using the underlying socket
        # This is a best-effort approach - we'll get what we can
        try:
            # Get the SSL object's certificate chain if available
            import ssl as ssl_module
            if hasattr(sock, '_sslobj'):
                # Try to extract additional certificates from the connection
                # This is implementation-specific and may not work on all systems
                sslobj = sock._sslobj
                
                # Attempt to get the peer certificate chain using internal methods
                if hasattr(sslobj, 'get_unverified_chain'):
                    chain_certs = sslobj.get_unverified_chain()
                    for cert in chain_certs[1:]:  # Skip leaf (already added)
                        cert_chain.append(cert)
                elif hasattr(sslobj, 'getpeercertchain'):
                    chain_certs = sslobj.getpeercertchain()
                    if chain_certs:
                        for cert in chain_certs[1:]:
                            cert_chain.append(cert)
        except:
            pass
        
        # Skip OpenSSL fallback for speed (subprocess is slow)
        # Uncomment below if full chain is critical:
        # if len(cert_chain) <= 1:
        #     openssl_chain = fetch_cert_chain_openssl(host, port, timeout)
        #     if openssl_chain and len(openssl_chain) > len(cert_chain):
        #         cert_chain = openssl_chain
    except Exception as e:
        # If we can't get the chain, at least try to get the leaf
        try:
            der_cert = sock.getpeercert(binary_form=True)
            cert_chain.append(der_cert)
        except:
            pass
    
    # Try to get negotiated cipher, protocol version, and protocol info
    cipher = None
    protocol_version = None
    supported_groups = None
    try:
        cipher = sock.cipher()  # Returns (cipher_name, protocol_version, secret_bits)
        # Get protocol version
        protocol_version = sock.version()  # Returns string like 'TLSv1.2', 'TLSv1.3'
        # Note: TLS supported_groups not directly accessible via standard ssl module
    except:
        pass
    
    sock.close()
    return cert_chain, cipher, protocol_version, supported_groups


def detect_pqc_hybrid_features(cert: x509.Certificate, cipher_info: Optional[Tuple]) -> Tuple[bool, Optional[str]]:
    """
    Detect PQC/hybrid features in certificate or TLS handshake using canonical OID registry.
    Returns (is_pqc_ready, details_string)
    """
    pqc_indicators = []
    
    # 1. Check certificate signature algorithm OID against registry
    sig_algo = cert.signature_algorithm_oid.dotted_string
    sig_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else sig_algo
    
    # Check against canonical signature OID registry
    if sig_algo in PQC_SIGNATURE_OIDS:
        pqc_indicators.append(f"PQC signature: {PQC_SIGNATURE_OIDS[sig_algo]} ({sig_algo})")
    else:
        # Fallback to pattern matching for partial OID matches
        for oid_prefix, algo_name in PQC_SIGNATURE_OIDS.items():
            if sig_algo.startswith(oid_prefix):
                pqc_indicators.append(f"PQC signature: {algo_name} (matched {oid_prefix}*)")
                break
    
    # Also check signature algorithm name for keywords
    sig_algo_lower = str(sig_name).lower()
    pqc_keywords = ['dilithium', 'falcon', 'sphincs', 'ml-dsa', 'mldsa']
    if not pqc_indicators:  # Only if not already detected via OID
        for keyword in pqc_keywords:
            if keyword in sig_algo_lower:
                pqc_indicators.append(f"PQC signature keyword: {sig_name}")
                break
    
    # 2. Check public key algorithm for PQC (check for KEM OIDs in key structure)
    try:
        pub_key = cert.public_key()
        pub_key_type = type(pub_key).__name__.lower()
        
        # Check if public key OID is in our registry (may require deep inspection)
        pqc_key_keywords = ['kyber', 'mlkem', 'dilithium', 'mldsa', 'falcon', 'sphincs']
        for keyword in pqc_key_keywords:
            if keyword in pub_key_type:
                pqc_indicators.append(f"PQC public key: {type(pub_key).__name__}")
                break
    except:
        pass
    
    # 3. Check certificate extensions against OID registries
    try:
        for ext in cert.extensions:
            ext_oid = ext.oid.dotted_string
            ext_name = ext.oid._name if hasattr(ext.oid, '_name') else ext_oid
            
            # Check against PQC extension OID registry
            if ext_oid in PQC_EXTENSION_OIDS:
                pqc_indicators.append(f"PQC extension: {PQC_EXTENSION_OIDS[ext_oid]} ({ext_oid})")
            # Check against KEM OIDs (might be in extensions)
            elif ext_oid in PQC_KEM_OIDS:
                pqc_indicators.append(f"PQC KEM in extension: {PQC_KEM_OIDS[ext_oid]} ({ext_oid})")
            # Check against signature OIDs
            elif ext_oid in PQC_SIGNATURE_OIDS:
                pqc_indicators.append(f"PQC signature in extension: {PQC_SIGNATURE_OIDS[ext_oid]} ({ext_oid})")
            # Fallback to experimental OID detection
            elif ext_oid.startswith('1.3.9999') or ext_oid.startswith('1.3.6.1.4.1.22554'):
                pqc_indicators.append(f"Experimental PQC extension: {ext_name} ({ext_oid})")
    except:
        pass
    
    # 4. Check Subject Alternative Names for experimental markers
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                dns_name = name.value.lower()
                if 'pqc' in dns_name or 'quantum' in dns_name or 'hybrid' in dns_name:
                    pqc_indicators.append(f"PQC marker in SAN: {name.value}")
    except:
        pass
    
    # 5. Check cipher suite for hybrid key exchange (X25519+Kyber)
    if cipher_info:
        cipher_name = cipher_info[0] if isinstance(cipher_info, tuple) else str(cipher_info)
        cipher_lower = cipher_name.lower()
        
        # Hybrid KEX patterns (check against KEM OID names)
        hybrid_keywords = ['kyber', 'mlkem', 'x25519kyber', 'x25519_kyber', 'x25519-kyber', 'hybrid']
        for keyword in hybrid_keywords:
            if keyword in cipher_lower:
                pqc_indicators.append(f"Hybrid KEX in cipher: {cipher_name}")
                break
                break
    
    # 6. Check certificate issuer/subject for PQC test markers
    try:
        issuer_str = cert.issuer.rfc4514_string().lower()
        subject_str = cert.subject.rfc4514_string().lower()
        
        for cert_field in [issuer_str, subject_str]:
            if any(marker in cert_field for marker in ['pqc', 'post-quantum', 'dilithium', 'kyber']):
                pqc_indicators.append("PQC marker in cert DN")
                break
    except:
        pass
    
    is_pqc_ready = len(pqc_indicators) > 0
    details = '; '.join(pqc_indicators) if pqc_indicators else None
    
    return is_pqc_ready, details


def analyze_cert_chain(cert_chain_der: List[bytes], cipher_info: Optional[Tuple]) -> Tuple[List[dict], bool, Optional[str]]:
    """Analyze all certificates in the chain and detect PQC features.
    Returns (chain_details, any_pqc_ready, pqc_summary)
    """
    chain_details = []
    any_pqc = False
    pqc_findings = []
    
    for idx, der_cert in enumerate(cert_chain_der):
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            public_key = cert.public_key()
            
            # Determine cert type in chain
            if idx == 0:
                cert_type = "Leaf"
            elif idx == len(cert_chain_der) - 1:
                cert_type = "Root"
            else:
                cert_type = f"Intermediate-{idx}"
            
            # Analyze key type
            algo_family = None
            key_size = None
            quantum_vuln = None
            
            if isinstance(public_key, rsa.RSAPublicKey):
                algo_family = "RSA"
                key_size = public_key.key_size
                quantum_vuln = True
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                algo_family = "EC"
                key_size = public_key.curve.key_size
                quantum_vuln = True
            else:
                algo_family = type(public_key).__name__
                quantum_vuln = None
            
            # Check for PQC features (only on leaf cert for cipher, all certs for signatures)
            pqc_ready, pqc_details = detect_pqc_hybrid_features(
                cert, 
                cipher_info if idx == 0 else None
            )
            
            if pqc_ready:
                any_pqc = True
                pqc_findings.append(f"{cert_type}: {pqc_details}")
            
            # Get subject for identification
            try:
                subject = cert.subject.rfc4514_string()
            except:
                subject = "Unknown"
            
            chain_details.append({
                'position': cert_type,
                'subject': subject,
                'algo_family': algo_family,
                'key_size': key_size,
                'quantum_vulnerable': quantum_vuln,
                'pqc_ready': pqc_ready,
                'pqc_details': pqc_details
            })
            
        except Exception as e:
            chain_details.append({
                'position': f'Cert-{idx}',
                'error': str(e)
            })
    
    pqc_summary = '; '.join(pqc_findings) if pqc_findings else None
    return chain_details, any_pqc, pqc_summary


def apply_throttling(mode_config: dict, scan_count: int = 0, error_count: int = 0):
    """Apply IDS-safe throttling delay based on selected mode.
    
    Args:
        mode_config: Throttling configuration dictionary
        scan_count: Number of scans completed (for adaptive mode)
        error_count: Number of errors encountered (for adaptive mode)
    """
    if mode_config["delay_min"] == 0 and mode_config["delay_max"] == 0:
        return  # No throttling
    
    # Calculate base delay
    base_delay = random.uniform(mode_config["delay_min"], mode_config["delay_max"])
    
    # Add jitter for more organic timing
    if mode_config["jitter"] > 0:
        jitter = random.uniform(-mode_config["jitter"], mode_config["jitter"])
        base_delay = max(0.1, base_delay + jitter)  # Ensure minimum 0.1s delay
    
    # Adaptive throttling - adjust based on scan behavior
    if mode_config["adaptive"]:
        # Start slower (first 10 scans)
        if scan_count < 10:
            base_delay *= 1.5
        # Slow down if encountering errors (possible IDS detection)
        if error_count > 0 and scan_count > 0:
            error_ratio = error_count / scan_count
            if error_ratio > 0.2:  # More than 20% errors
                base_delay *= 2.0  # Double the delay
    
    time.sleep(base_delay)


def is_port_open(host: str, port: int, timeout: float = 0.3, rate_limiter=None) -> bool:
    """Check if a port is open on the host."""
    try:
        if rate_limiter:
            rate_limiter.wait()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def identify_device(ip: str, cert: Optional[x509.Certificate] = None) -> Tuple[Optional[str], Optional[str]]:
    """Enhanced device identification using DNS, certificate, and pattern matching.
    Returns (hostname, device_type)
    """
    hostname = None
    device_type = None
    
    # 1. Try reverse DNS lookup
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except:
        pass
    
    # 2. Extract name from certificate CN or SAN
    cert_name = None
    if cert:
        try:
            # Try Common Name (CN) first
            cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attr:
                cert_name = cn_attr[0].value
                if not hostname or len(cert_name) > len(hostname):
                    hostname = cert_name
        except:
            pass
        
        try:
            # Try Subject Alternative Names
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_name = name.value
                    # Prefer non-wildcard, non-generic names
                    if not san_name.startswith('*') and '.' in san_name:
                        if not hostname or (len(san_name) < len(hostname) and 'localhost' not in san_name):
                            hostname = san_name
                            break
        except:
            pass
    
    # 3. Detect device type from hostname patterns
    if hostname:
        hostname_lower = hostname.lower()
        
        # Network infrastructure devices
        if any(pattern in hostname_lower for pattern in ['router', 'rtr', 'gateway', 'gw']):
            device_type = 'Router'
        elif any(pattern in hostname_lower for pattern in ['switch', 'sw']):
            device_type = 'Switch'
        elif any(pattern in hostname_lower for pattern in ['firewall', 'fw', 'fortigate', 'palo', 'checkpoint', 'asa']):
            device_type = 'Firewall'
        elif any(pattern in hostname_lower for pattern in ['vpn', 'ssl-vpn']):
            device_type = 'VPN Gateway'
        elif any(pattern in hostname_lower for pattern in ['lb', 'loadbalancer', 'load-balancer', 'f5', 'bigip']):
            device_type = 'Load Balancer'
        
        # Servers
        elif any(pattern in hostname_lower for pattern in ['web', 'www', 'http', 'nginx', 'apache']):
            device_type = 'Web Server'
        elif any(pattern in hostname_lower for pattern in ['mail', 'smtp', 'exchange', 'postfix']):
            device_type = 'Mail Server'
        elif any(pattern in hostname_lower for pattern in ['db', 'database', 'sql', 'mysql', 'postgres', 'oracle']):
            device_type = 'Database Server'
        elif any(pattern in hostname_lower for pattern in ['api', 'rest']):
            device_type = 'API Server'
        elif any(pattern in hostname_lower for pattern in ['app', 'application']):
            device_type = 'Application Server'
        
        # Management/Monitoring
        elif any(pattern in hostname_lower for pattern in ['vcenter', 'esxi', 'vmware']):
            device_type = 'Virtualization'
        elif any(pattern in hostname_lower for pattern in ['idrac', 'ilo', 'ipmi', 'bmc']):
            device_type = 'BMC/IPMI'
        elif any(pattern in hostname_lower for pattern in ['monitor', 'nagios', 'zabbix', 'prometheus']):
            device_type = 'Monitoring'
        
        # Storage
        elif any(pattern in hostname_lower for pattern in ['nas', 'san', 'storage', 'netapp']):
            device_type = 'Storage Device'
        
        # Generic server if no specific type found
        elif any(pattern in hostname_lower for pattern in ['server', 'srv', 'host']):
            device_type = 'Server'
        
        # Default for domains
        elif hostname_lower.count('.') >= 2:
            device_type = 'Network Host'
    
    return hostname, device_type


def resolve_hostname(ip: str) -> Optional[str]:
    """Simple hostname resolution for backwards compatibility."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None


def analyze_certificate(host: str, port: int, throttle_config: Optional[dict] = None, scan_stats: Optional[dict] = None, rate_limiter=None) -> CertAnalysis:
    """Analyze certificate with optional IDS-safe throttling.
    
    Args:
        host: Target IP/hostname
        port: Target port
        throttle_config: Optional throttling mode configuration
        scan_stats: Optional dict with 'count' and 'errors' for adaptive throttling
        rate_limiter: Optional rate limiter for controlling scan rate
    """
    # Apply throttling delay before scanning
    if throttle_config:
        scan_count = scan_stats.get('count', 0) if scan_stats else 0
        error_count = scan_stats.get('errors', 0) if scan_stats else 0
        apply_throttling(throttle_config, scan_count, error_count)
    
    # Initial hostname resolution
    hostname = resolve_hostname(host)
    device_type = None
    
    try:
        if rate_limiter:
            rate_limiter.wait()
        cert_chain_der, cipher_info, protocol_version, _ = fetch_server_certificate(host, port)
    except Exception as e:
        return CertAnalysis(
            host=host, hostname=hostname, device_type=device_type, port=port, success=False, error=str(e),
            algo_family=None, key_size=None, quantum_vulnerable=None,
            severity=None, comment=None, pqc_ready=False, pqc_details=None,
            chain_length=None, chain_details=None,
        )

    if not cert_chain_der:
        return CertAnalysis(
            host=host, hostname=hostname, device_type=device_type, port=port, success=False, error="No certificates retrieved",
            algo_family=None, key_size=None, quantum_vulnerable=None,
            severity=None, comment=None, pqc_ready=False, pqc_details=None,
            chain_length=0, chain_details=None,
        )

    try:
        # Analyze the full certificate chain
        chain_details, chain_pqc_ready, chain_pqc_summary = analyze_cert_chain(cert_chain_der, cipher_info)
        
        # Analyze the leaf certificate (first in chain)
        der_cert = cert_chain_der[0]
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        public_key = cert.public_key()
        
        # Enhanced device identification using certificate
        hostname, device_type = identify_device(host, cert)

        algo_family = None
        key_size = None
        quantum_vulnerable = None
        severity = None
        comment = None
        
        # Classify TLS protocol version risk
        protocol_risk = None
        protocol_comment = ""
        if protocol_version:
            if protocol_version in ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                protocol_risk = "High"
                protocol_comment = f"{protocol_version}: Deprecated protocol, vulnerable to attacks (BEAST, POODLE). "
            elif protocol_version == 'TLSv1.2':
                # Check if RSA key exchange is used (not PFS)
                if cipher_info:
                    cipher_name = cipher_info[0] if isinstance(cipher_info, tuple) else str(cipher_info)
                    if 'RSA' in cipher_name and 'ECDHE' not in cipher_name and 'DHE' not in cipher_name:
                        protocol_risk = "High"
                        protocol_comment = f"{protocol_version} with RSA key exchange: No Perfect Forward Secrecy (PFS). "
                    else:
                        protocol_comment = f"{protocol_version} with PFS. "
                else:
                    protocol_comment = f"{protocol_version}. "
            elif protocol_version == 'TLSv1.3':
                protocol_comment = f"{protocol_version}: Always provides Perfect Forward Secrecy (PFS). "
        
        # Detect PQC/hybrid features on leaf
        pqc_ready, pqc_details = detect_pqc_hybrid_features(cert, cipher_info)
        
        # Override with chain-wide PQC detection
        if chain_pqc_ready:
            pqc_ready = True
            pqc_details = chain_pqc_summary if chain_pqc_summary else pqc_details

        if isinstance(public_key, rsa.RSAPublicKey):
            algo_family = "RSA"
            key_size = public_key.key_size
            quantum_vulnerable = True

            if key_size < 2048:
                severity = "High"
                comment = f"{protocol_comment}RSA-{key_size} is weak even against classical attacks and fully exposed to future quantum (Shor's algorithm)."
            elif key_size < 4096:
                severity = "High"
                comment = f"{protocol_comment}RSA-{key_size} is considered strong classically today but fails rapidly once scalable quantum factoring is available."
            else:
                severity = "Medium"
                comment = f"{protocol_comment}RSA-{key_size} marginally improves classical resistance, but remains fundamentally breakable by Shor's algorithm."
            
            # Elevate severity if protocol risk detected
            if protocol_risk == "High":
                severity = "High"
            
            # Adjust if PQC/hybrid detected
            if pqc_ready:
                # Distinguish between hybrid and pure PQC
                is_hybrid = any(keyword in pqc_details.lower() for keyword in ['hybrid', 'x25519', 'rsa', 'ec', 'ecdh', 'p-256', 'secp']) if pqc_details else False
                
                if is_hybrid:
                    severity = "Medium"
                    comment += f" HOWEVER: Hybrid PQC features detected - {pqc_details}. Provides quantum resistance via PQC component."
                else:
                    severity = "Low"
                    comment += f" HOWEVER: Pure PQC features detected - {pqc_details}. Fully quantum-resistant."

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algo_family = "EC"
            key_size = public_key.curve.key_size
            quantum_vulnerable = True
            severity = "High"
            comment = f"{protocol_comment}Elliptic Curve cryptography (approx. {key_size}-bit strength) is directly broken by quantum discrete log attacks."
            
            # Elevate severity if protocol risk detected (though EC is already High)
            if protocol_risk == "High":
                severity = "High"
            
            # Adjust if PQC/hybrid detected
            if pqc_ready:
                # Distinguish between hybrid and pure PQC
                is_hybrid = any(keyword in pqc_details.lower() for keyword in ['hybrid', 'x25519', 'rsa', 'ec', 'ecdh', 'p-256', 'secp']) if pqc_details else False
                
                if is_hybrid:
                    severity = "Medium"
                    comment += f" HOWEVER: Hybrid PQC features detected - {pqc_details}. Provides quantum resistance via PQC component."
                else:
                    severity = "Low"
                    comment += f" HOWEVER: Pure PQC features detected - {pqc_details}. Fully quantum-resistant."

        else:
            algo_family = type(public_key).__name__
            
            # Check if this is actually a PQC key type
            if pqc_ready:
                quantum_vulnerable = False
                # Distinguish between hybrid and pure PQC
                is_hybrid = any(keyword in pqc_details.lower() for keyword in ['hybrid', 'x25519', 'rsa', 'ec', 'ecdh', 'p-256', 'secp']) if pqc_details else False
                
                if is_hybrid:
                    severity = "Medium"
                    comment = f"Hybrid PQC certificate detected: {pqc_details}. Provides quantum resistance via PQC component."
                else:
                    severity = "Low"
                    comment = f"Pure PQC certificate detected: {pqc_details}. Fully quantum-resistant as currently understood."
            else:
                quantum_vulnerable = None
                severity = "Informational"
                comment = "Non-RSA/EC key detected. Manual review required to determine quantum posture and conformance with NIST PQC guidance."
        
        # Add chain information to comment
        if len(cert_chain_der) > 1:
            chain_summary = f" Certificate chain has {len(cert_chain_der)} certificates."
            # Check for mixed key types in chain
            chain_algos = set(c.get('algo_family') for c in chain_details if 'algo_family' in c)
            if len(chain_algos) > 1:
                chain_summary += f" Mixed key types in chain: {', '.join(chain_algos)}."
            comment = (comment or "") + chain_summary

        return CertAnalysis(
            host=host, hostname=hostname, device_type=device_type, port=port, success=True, error=None,
            algo_family=algo_family, key_size=key_size,
            quantum_vulnerable=quantum_vulnerable, severity=severity,
            comment=comment, pqc_ready=pqc_ready, pqc_details=pqc_details,
            chain_length=len(cert_chain_der), chain_details=chain_details,
        )

    except Exception as e:
        return CertAnalysis(
            host=host, hostname=hostname, device_type=device_type, port=port, success=False,
            error=f"Certificate parse error: {e}",
            algo_family=None, key_size=None, quantum_vulnerable=None,
            severity=None, comment=None, pqc_ready=False, pqc_details=None,
            chain_length=len(cert_chain_der) if cert_chain_der else 0, chain_details=None,
        )


def parse_ip_range(ip_input: str) -> List[str]:
    """Parse IP range input and return list of IP addresses."""
    try:
        # Handle CIDR notation (e.g., 192.168.1.0/24)
        if '/' in ip_input:
            network = ipaddress.ip_network(ip_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        
        # Handle IP range (e.g., 192.168.1.1-192.168.1.10)
        elif '-' in ip_input:
            start_ip, end_ip = ip_input.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            ips = []
            current = start
            while current <= end:
                ips.append(str(current))
                current = ipaddress.ip_address(int(current) + 1)
            return ips
        
        # Single IP
        else:
            ipaddress.ip_address(ip_input.strip())
            return [ip_input.strip()]
    except Exception as e:
        raise ValueError(f"Invalid IP format: {e}")


def parse_port_range(port_input: str) -> List[int]:
    """Parse port range input."""
    ports = []
    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def format_report(results: List[CertAnalysis]) -> str:
    """Generate a formatted report string."""
    output = "=" * 70 + "\n"
    output += "QUANTUM READINESS NETWORK SCAN & TLS CERTIFICATES\n"
    output += "=" * 70 + "\n\n"

    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    error_count = 0
    total_vulnerable = 0
    pqc_ready_count = 0

    for r in results:
        # Display IP and hostname (if resolved)
        target_info = f"{r.host}:{r.port}"
        if r.hostname:
            target_info += f" ({r.hostname})"
        if r.device_type:
            target_info += f" [{r.device_type}]"
        output += f"Target: {target_info}\n"
        if not r.success:
            output += "  Status      : ERROR\n"
            output += f"  Detail      : {r.error}\n\n"
            error_count += 1
            continue

        output += "  Status      : OK\n"
        output += f"  Key family  : {r.algo_family}\n"
        if r.key_size:
            output += f"  Key size    : {r.key_size} bits\n"
        
        # Display certificate chain information
        if r.chain_length and r.chain_length > 1:
            output += f"  Chain length: {r.chain_length} certificates\n"
            if r.chain_details:
                output += "  Chain info  :\n"
                for cert_info in r.chain_details:
                    if 'error' in cert_info:
                        output += f"    - {cert_info.get('position', 'Unknown')}: Error parsing\n"
                    else:
                        pos = cert_info.get('position', 'Unknown')
                        algo = cert_info.get('algo_family', 'Unknown')
                        key_sz = cert_info.get('key_size', 'N/A')
                        vuln = cert_info.get('quantum_vulnerable', None)
                        vuln_str = "âš ï¸ Quantum-vulnerable" if vuln else "âœ“ Quantum-safe" if vuln is False else "?"
                        
                        output += f"    - {pos}: {algo}"
                        if key_sz != 'N/A':
                            output += f"-{key_sz}"
                        output += f" ({vuln_str})\n"
                        
                        # Show PQC features if present
                        if cert_info.get('pqc_ready'):
                            output += f"      PQC: {cert_info.get('pqc_details', 'detected')}\n"
        
        if r.quantum_vulnerable is True:
            output += "  Quantum risk: VULNERABLE (pre-quantum algorithm)\n"
            total_vulnerable += 1
        elif r.quantum_vulnerable is False:
            output += "  Quantum risk: Not vulnerable (as currently understood)\n"
        else:
            output += "  Quantum risk: UNKNOWN (manual review required)\n"
        
        # Display PQC readiness
        if r.pqc_ready:
            output += "  PQC Ready   : YES âœ“\n"
            output += f"  PQC Details : {r.pqc_details}\n"
            pqc_ready_count += 1

        if r.severity:
            output += f"  Severity    : {r.severity}\n"
            if r.severity == "High":
                high_count += 1
            elif r.severity == "Medium":
                medium_count += 1
            elif r.severity == "Low":
                low_count += 1
            else:
                info_count += 1

        if r.comment:
            output += f"  Commentary  : {r.comment}\n"

        output += "\n"

    # Summary section
    output += "=" * 70 + "\n"
    output += "SUMMARY\n"
    output += "=" * 70 + "\n"
    total = len(results)

    output += f"Total targets assessed     : {total}\n"
    output += f" - High risk (quantum)     : {high_count}\n"
    output += f" - Medium risk (quantum)   : {medium_count}\n"
    output += f" - Low risk (PQC/hybrid)   : {low_count}\n"
    output += f" - Informational/Other     : {info_count}\n"
    output += f" - Errors / unreachable    : {error_count}\n"
    output += f" - PQC-ready endpoints     : {pqc_ready_count}\n\n"

    if pqc_ready_count > 0:
        output += "PQC/HYBRID DETECTION\n"
        output += "--------------------\n"
        output += (
            f"Found {pqc_ready_count} endpoint(s) with PQC or hybrid cryptography features.\n"
            "These may include:\n"
            "  â€¢ X25519+Kyber (ML-KEM) hybrid key exchange\n"
            "  â€¢ Dilithium (ML-DSA) signatures\n"
            "  â€¢ Experimental PQC certificates (OpenSSL 3.2+)\n\n"
            "Note: Early PQC deployments are experimental. Verify implementations\n"
            "align with final NIST standards and your security requirements.\n\n"
        )

    if total_vulnerable > 0:
        output += "QUANTUM RISK SUMMARY\n"
        output += "--------------------\n"
        output += (
            "Finding: One or more endpoints rely on RSA/ECC, which are "
            "susceptible to Shor-style quantum attacks once a fault-tolerant "
            "quantum computer is available.\n\n"
        )
        output += (
            "Impact: Confidential data protected by these keys may be subject "
            "to 'harvest now, decrypt later' risk â€“ adversaries can record "
            "encrypted traffic today and decrypt it in the future.\n\n"
        )
        output += "Recommendations:\n"
        output += "  1. Establish a crypto inventory and crypto-agility strategy.\n"
        output += "  2. Track NIST PQC standardisation (e.g., Kyber (ML-KEM), Dilithium (ML-DSA)).\n"
        output += "  3. Plan migration away from RSA/ECC for long-lived data.\n"
        output += "  4. Consider hybrid approaches (classical + PQC) during transition.\n"
        output += "  5. Align remediation with your internal risk framework and regulations.\n"
    else:
        output += "QUANTUM RISK SUMMARY\n"
        output += "--------------------\n"
        output += (
            "No clearly quantum-vulnerable RSA/ECC keys detected in the "
            "assessed certificates. This does NOT guarantee overall quantum safety.\n"
        )

    return output


# --- GUI Implementation ---
class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PQC Network Scanner 2.0 - Professional Edition")
        self.root.geometry("1200x750")
        self.root.configure(bg='#f5f5f5')
        # Prevent window from shrinking and set minimum size
        self.root.minsize(1200, 700)
        # Set window icon (optional - will use default if no icon)
        try:
            self.root.iconbitmap(default='shield.ico')
        except:
            pass
        self.scan_cancelled = False
        self.max_workers = 20  # Number of parallel threads

        # Header (fixed at top, not scrollable) - Professional gradient design
        header_frame = tk.Frame(root, bg='#1a237e', height=90)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        # Text container
        text_container = tk.Frame(header_frame, bg='#1a237e')
        text_container.pack(expand=True, fill='both', pady=5)
        
        # Main title with icon
        title_frame = tk.Frame(text_container, bg='#1a237e')
        title_frame.pack(expand=True)
        
        header_label = tk.Label(title_frame, text="🛡️ PQC Network Scanner 2.0", 
                                font=("Segoe UI", 18, "bold"), fg="#ffffff", bg='#1a237e', anchor='center')
        header_label.pack()

        subtitle = tk.Label(text_container, text="Post-Quantum Cryptography Assessment Platform", 
                           font=("Segoe UI", 9), fg="#90caf9", bg='#1a237e', anchor='center')
        subtitle.pack(pady=(0, 5))
        
        version_label = tk.Label(text_container, text="Enterprise Edition | v2.0.0", 
                           font=("Segoe UI", 8), fg="#7986cb", bg='#1a237e', anchor='center')
        version_label.pack()

        # Create main canvas with scrollbar for all content
        main_canvas = tk.Canvas(root, bg='#f5f5f5', highlightthickness=0)
        scrollbar = tk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
        scrollable_frame = tk.Frame(main_canvas, bg='#f5f5f5')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )

        canvas_window = main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make scrollable_frame expand to canvas width
        def _configure_canvas(event):
            canvas_width = event.width
            main_canvas.itemconfig(canvas_window, width=canvas_width)
        main_canvas.bind('<Configure>', _configure_canvas)

        # Pack canvas and scrollbar
        scrollbar.pack(side="right", fill="y")
        main_canvas.pack(side="left", fill="both", expand=True)

        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Input frame (now inside scrollable_frame) - Modern card design
        input_frame = tk.LabelFrame(scrollable_frame, text="⚙️ Network Scan Configuration", 
                                   font=("Segoe UI", 10, "bold"),
                                   bg='#ffffff', fg='#1a237e', padx=20, pady=15,
                                   relief=tk.FLAT, bd=2, highlightbackground='#e0e0e0',
                                   highlightthickness=1)
        input_frame.pack(padx=25, pady=10, fill='both', expand=True)
        
        # Configure grid to expand column 1 (where inputs are)
        input_frame.grid_columnconfigure(1, weight=1)
        input_frame.grid_columnconfigure(0, minsize=200)

        # IP Range input with icon
        tk.Label(input_frame, text="🌐 IP Range (CIDR, range, or single IP):", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=0, column=0, sticky='w', pady=5)
        
        self.ip_entry = tk.Entry(input_frame, width=60, font=("Segoe UI", 9),
                                relief=tk.SOLID, bd=1, highlightbackground='#9fa8da',
                                highlightcolor='#3f51b5', highlightthickness=1)
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')

        tk.Label(input_frame, text="💡 Examples: 192.168.1.0/24, 10.0.0.1-10.0.0.50, 172.16.0.10", 
                font=("Segoe UI", 7), bg='#ffffff', fg='#757575').grid(row=1, column=1, sticky='w', padx=10)

        # Port input with icon
        tk.Label(input_frame, text="🔌 Ports (comma-separated or range):", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=2, column=0, sticky='w', pady=5)
        
        self.port_entry = tk.Entry(input_frame, width=60, font=("Segoe UI", 9),
                                   relief=tk.SOLID, bd=1, highlightbackground='#9fa8da',
                                   highlightcolor='#3f51b5', highlightthickness=1)
        self.port_entry.insert(0, "443,8443")
        self.port_entry.grid(row=2, column=1, padx=10, pady=5, sticky='ew')

        tk.Label(input_frame, text="💡 Examples: 443,8443,10443 or 443-445", 
                font=("Segoe UI", 7), bg='#ffffff', fg='#757575').grid(row=3, column=1, sticky='w', padx=10)

        # Options
        self.check_open_var = tk.BooleanVar(value=True)
        tk.Checkbutton(input_frame, text="⚡ Only scan open ports (faster)", 
                      variable=self.check_open_var, bg='#ffffff', fg='#424242',
                      font=("Segoe UI", 9), selectcolor='#ffffff',
                      activebackground='#ffffff').grid(row=4, column=1, sticky='w', padx=10, pady=5)

        # Throttling mode selection
        tk.Label(input_frame, text="🕐 IDS-Safe Throttling Mode:", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=5, column=0, sticky='w', pady=5)
        
        self.throttle_mode_var = tk.StringVar(value="Normal")
        throttle_combo = ttk.Combobox(input_frame, textvariable=self.throttle_mode_var,
                                     values=list(THROTTLING_MODES.keys()),
                                     width=15, font=("Segoe UI", 9), state='readonly')
        throttle_combo.grid(row=5, column=1, padx=10, pady=5, sticky='w')
        throttle_combo.bind('<<ComboboxSelected>>', self.update_throttle_description)
        
        self.throttle_desc_label = tk.Label(input_frame, 
                text=THROTTLING_MODES["Normal"]["description"], 
                font=("Segoe UI", 8), bg='#ffffff', fg='#757575', wraplength=400, justify='left')
        self.throttle_desc_label.grid(row=6, column=1, sticky='w', padx=10)

        # Scan Profile selection
        tk.Label(input_frame, text="📊 Scan Profile:", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=7, column=0, sticky='w', pady=5)
        
        self.scan_profile_var = tk.StringVar(value="Balanced")
        profile_combo = ttk.Combobox(input_frame, textvariable=self.scan_profile_var,
                                    values=["Aggressive", "Balanced", "IDS-Safe"],
                                    width=15, font=("Segoe UI", 9), state='readonly')
        profile_combo.grid(row=7, column=1, padx=10, pady=5, sticky='w')
        profile_combo.bind('<<ComboboxSelected>>', self.profile_changed)

        # IDS-safe rate limiting controls
        self.ids_safe_var = tk.BooleanVar(value=False)
        tk.Checkbutton(input_frame, text="🔒 Enable IDS-safe rate limiting", 
                      variable=self.ids_safe_var, bg='#ffffff', fg='#424242',
                      font=("Segoe UI", 9), selectcolor='#ffffff',
                      activebackground='#ffffff').grid(row=8, column=1, sticky='w', padx=10, pady=5)

        tk.Label(input_frame, text="⚡ Max connections/sec:", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=9, column=0, sticky='w', pady=5)
        
        self.max_rate_var = tk.DoubleVar(value=5.0)
        rate_spinbox = tk.Spinbox(input_frame, from_=0.1, to=100.0, increment=0.5,
                                 textvariable=self.max_rate_var,
                                 width=10, font=("Segoe UI", 9),
                                 relief=tk.SOLID, bd=1)
        rate_spinbox.grid(row=9, column=1, padx=10, pady=5, sticky='w')

        tk.Label(input_frame, text="⏱️ Rate jitter (seconds):", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=10, column=0, sticky='w', pady=5)
        
        self.jitter_var = tk.DoubleVar(value=0.1)
        jitter_spinbox = tk.Spinbox(input_frame, from_=0.0, to=5.0, increment=0.05,
                                    textvariable=self.jitter_var,
                                    width=10, font=("Segoe UI", 9),
                                    relief=tk.SOLID, bd=1)
        jitter_spinbox.grid(row=10, column=1, padx=10, pady=5, sticky='w')

        # Thread pool size
        tk.Label(input_frame, text="🔄 Parallel threads:", 
                font=("Segoe UI", 9), bg='#ffffff', fg='#424242', anchor='w').grid(row=11, column=0, sticky='w', pady=5)
        
        self.threads_var = tk.IntVar(value=20)
        threads_spinbox = tk.Spinbox(input_frame, from_=1, to=100, textvariable=self.threads_var,
                                     width=10, font=("Segoe UI", 9),
                                     relief=tk.SOLID, bd=1)
        threads_spinbox.grid(row=11, column=1, padx=10, pady=5, sticky='w')

        tk.Label(input_frame, text="⚠️ Note: Throttling reduces parallel scanning effectiveness", 
                font=("Segoe UI", 8), bg='#ffffff', fg='#f57c00', wraplength=400, justify='left').grid(row=12, column=1, sticky='w', padx=10)

        # Progress bar with modern styling
        progress_frame = tk.Frame(input_frame, bg='#ffffff')
        progress_frame.grid(row=13, column=0, columnspan=2, pady=10, padx=10, sticky='ew')
        input_frame.grid_rowconfigure(13, weight=0)
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Custom.Horizontal.TProgressbar",
                       background='#3f51b5',
                       troughcolor='#e0e0e0',
                       bordercolor='#e0e0e0',
                       lightcolor='#3f51b5',
                       darkcolor='#3f51b5')
        
        self.progress = ttk.Progressbar(progress_frame, mode='determinate',
                                       style="Custom.Horizontal.TProgressbar")
        self.progress.pack(fill='x', expand=True)

        # Buttons frame with modern design
        button_frame = tk.Frame(scrollable_frame, bg='#f5f5f5')
        button_frame.pack(pady=15, fill='both', padx=20)
        
        # Center the buttons
        button_container = tk.Frame(button_frame, bg='#f5f5f5')
        button_container.pack(expand=True)

        self.btn_scan = tk.Button(button_container, text='▶️  Start Scan', 
                                 command=self.run_scan_threaded,
                                 bg='#4caf50', fg='white', 
                                 font=("Segoe UI", 10, "bold"), 
                                 padx=20, pady=12, relief=tk.FLAT,
                                 cursor='hand2', borderwidth=0,
                                 activebackground='#45a049')
        self.btn_scan.grid(row=0, column=0, padx=5)

        self.btn_cancel = tk.Button(button_container, text='⏸️  Cancel', 
                                    command=self.cancel_scan, state='disabled',
                                    bg='#f44336', fg='white', 
                                    font=("Segoe UI", 10, "bold"), 
                                    padx=20, pady=12, relief=tk.FLAT,
                                    cursor='hand2', borderwidth=0,
                                    activebackground='#d32f2f')
        self.btn_cancel.grid(row=0, column=1, padx=5)

        tk.Button(button_container, text='🗑️  Clear', command=self.clear_results,
                 bg='#ff9800', fg='white', font=("Segoe UI", 10, "bold"), 
                 padx=20, pady=12, relief=tk.FLAT, cursor='hand2', borderwidth=0,
                 activebackground='#f57c00').grid(row=0, column=2, padx=5)

        tk.Button(button_container, text='💾  Save Report', command=self.save_report,
                 bg='#2196f3', fg='white', font=("Segoe UI", 10, "bold"), 
                 padx=20, pady=12, relief=tk.FLAT, cursor='hand2', borderwidth=0,
                 activebackground='#1976d2').grid(row=0, column=3, padx=5)

        tk.Button(button_container, text='❌  Exit', command=root.quit,
                 bg='#9e9e9e', fg='white', font=("Segoe UI", 10, "bold"), 
                 padx=20, pady=12, relief=tk.FLAT, cursor='hand2', borderwidth=0,
                 activebackground='#757575').grid(row=0, column=4, padx=5)

        # Results frame with modern card design
        results_frame = tk.LabelFrame(scrollable_frame, text="📊 Scan Results", 
                                     font=("Segoe UI", 10, "bold"),
                                     bg='#ffffff', fg='#1a237e', padx=15, pady=15,
                                     relief=tk.FLAT, bd=2, highlightbackground='#e0e0e0',
                                     highlightthickness=1)
        results_frame.pack(padx=25, pady=10, fill='both', expand=True)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap='word',
                                                     font=("Consolas", 9),
                                                     bg='#fafafa', fg='#212121', height=22,
                                                     relief=tk.FLAT, bd=0,
                                                     padx=10, pady=10, width=120)
        self.results_text.pack(fill='both', expand=True)

        # Status bar (fixed at bottom, not in scrollable area) - Modern design
        status_frame = tk.Frame(root, bg='#263238', height=30)
        status_frame.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(status_frame, text="✓ Ready to scan network", 
                                    font=("Segoe UI", 9), bg='#263238', 
                                    fg='#90caf9', anchor='w', padx=15, pady=5)
        self.status_label.pack(side='left', fill='both', expand=True)

        # Apply default profile settings on initialization
        # This ensures "Balanced" profile values are applied at startup
        # User can manually override any setting after this, and those edits
        # will be preserved unless they explicitly select a different profile
        self.profile_changed()

    def update_throttle_description(self, event=None):
        """Update the throttling mode description when selection changes."""
        mode = self.throttle_mode_var.get()
        if mode in THROTTLING_MODES:
            description = THROTTLING_MODES[mode]["description"]
            self.throttle_desc_label.config(text=description)
            
            # Warn if using aggressive throttling with many threads
            if mode in ["Slow", "Stealth", "Random", "Adaptive"] and self.threads_var.get() > 10:
                warning = f"{description} (Consider reducing threads to 5-10 for better stealth)"
                self.throttle_desc_label.config(text=warning, fg='#f57c00')
            else:
                self.throttle_desc_label.config(fg='#757575')

    def profile_changed(self, event=None):
        """Update scan parameters when scan profile is changed."""
        profile = self.scan_profile_var.get()
        
        if profile == "Aggressive":
            # Aggressive: Maximum speed, no rate limiting
            self.threads_var.set(200)
            self.ids_safe_var.set(False)
            self.max_rate_var.set(100.0)
            self.jitter_var.set(0.0)
        elif profile == "Balanced":
            # Balanced: Moderate speed with some stealth
            self.threads_var.set(50)
            self.ids_safe_var.set(False)
            self.max_rate_var.set(20.0)
            self.jitter_var.set(0.05)
        elif profile == "IDS-Safe":
            # IDS-Safe: Stealthy with rate limiting enabled
            self.threads_var.set(10)
            self.ids_safe_var.set(True)
            self.max_rate_var.set(3.0)
            self.jitter_var.set(0.2)

    def clear_results(self):
        """Clear the results text box."""
        self.results_text.delete('1.0', tk.END)
        self.status_label.config(text="✓ Results cleared. Ready to scan.", fg='#90caf9')
        self.progress['value'] = 0

    def cancel_scan(self):
        """Cancel the ongoing scan."""
        self.scan_cancelled = True
        self.status_label.config(text="⏸️ Cancelling scan...", fg='#ffb74d')

    def save_report(self):
        """Save the scan results to a file."""
        report_content = self.results_text.get('1.0', tk.END).strip()
        
        if not report_content:
            messagebox.showwarning("No Results", "No scan results to save. Please run a scan first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Network Scan Report",
            initialfile="network_quantum_scan_report.txt"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                messagebox.showinfo("Success", f"Report saved successfully to:\n{file_path}")
                self.status_label.config(text=f"💾 Report saved: {file_path}", fg='#66bb6a')
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save report:\n{e}")
                self.status_label.config(text="❌ Failed to save report.", fg='#ef5350')

    def run_scan_threaded(self):
        """Run scan in a separate thread to avoid blocking the GUI."""
        self.scan_cancelled = False
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()

    def run_scan(self):
        """Execute the network scan and display results."""
        try:
            # Parse inputs
            ip_input = self.ip_entry.get().strip()
            port_input = self.port_entry.get().strip()
            
            if not ip_input or not port_input:
                messagebox.showwarning("Missing Input", "Please enter both IP range and ports.")
                return

            # Parse IP addresses and ports
            try:
                ips = parse_ip_range(ip_input)
                ports = parse_port_range(port_input)
            except ValueError as e:
                messagebox.showerror("Input Error", str(e))
                return

            total_targets = len(ips) * len(ports)
            
            if total_targets > 1000:
                response = messagebox.askyesno("Large Scan", 
                    f"This will scan {total_targets} targets. This may take a while. Continue?")
                if not response:
                    return

            # Update UI
            self.btn_scan.config(state='disabled')
            self.btn_cancel.config(state='normal')
            self.status_label.config(text=f"⌛ Scanning {len(ips)} IPs on {len(ports)} port(s)...", fg='#ffb74d')
            self.progress['maximum'] = total_targets
            self.progress['value'] = 0
            self.root.update()

            # Clear previous results
            self.results_text.delete('1.0', tk.END)

            # Get throttling configuration
            throttle_mode = self.throttle_mode_var.get()
            throttle_config = THROTTLING_MODES.get(throttle_mode)
            
            # Create rate limiter if IDS-safe mode is enabled
            rate_limiter = None
            if self.ids_safe_var.get():
                max_rate = self.max_rate_var.get()
                jitter = self.jitter_var.get()
                rate_limiter = RateLimiter(max_rate, jitter)
                self.status_label.config(
                    text=f"🔒 IDS-safe mode: {max_rate} req/s with {jitter}s jitter",
                    fg='#ffb74d'
                )
                self.root.update()
            
            # Track scan statistics for adaptive throttling
            scan_stats = {'count': 0, 'errors': 0}
            
            # Run scan with thread pool
            results = []
            scanned = 0
            check_open = self.check_open_var.get()
            max_workers = self.threads_var.get()
            
            # Adjust thread count warning for throttled scans
            if throttle_mode != "Normal" and max_workers > 10:
                response = messagebox.askyesno("Throttling Warning",
                    f"You've selected {throttle_mode} mode with {max_workers} threads.\n\n"
                    f"For better IDS evasion, consider using 5-10 threads.\n\n"
                    f"Continue with current settings?")
                if not response:
                    return

            # Pre-filter with fast port checks if enabled
            targets_to_scan = []
            if check_open:
                self.status_label.config(text="🔍 Pre-scanning for open ports...", fg='#ffb74d')
                self.root.update()
                
                with ThreadPoolExecutor(max_workers=max_workers * 2) as executor:
                    port_futures = {executor.submit(is_port_open, ip, port, 0.3, rate_limiter): (ip, port) 
                                   for ip in ips for port in ports}
                    for future in as_completed(port_futures):
                        if future.result():
                            targets_to_scan.append(port_futures[future])
                
                self.status_label.config(text=f"✓ Found {len(targets_to_scan)} open ports. Analyzing certificates...", fg='#66bb6a')
                self.root.update()
            else:
                targets_to_scan = [(ip, port) for ip in ips for port in ports]
            
            if not targets_to_scan:
                messagebox.showinfo("No Open Ports", "No open ports found on the specified targets.")
                return
            
            # Update progress bar maximum to actual targets to scan
            self.progress['maximum'] = len(targets_to_scan)
            self.progress['value'] = 0
            
            # Execute parallel certificate scanning with throttling
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(analyze_certificate, ip, port, throttle_config, scan_stats, rate_limiter): (ip, port)
                    for ip, port in targets_to_scan
                }
                
                # Process completed tasks with batched GUI updates
                update_counter = 0
                for future in as_completed(futures):
                    if self.scan_cancelled:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    target = futures[future]
                    scanned += 1
                    update_counter += 1
                    
                    # Update progress bar every scan, but status text less frequently
                    self.progress['value'] = scanned
                    
                    # Update status text every 5 scans for smoother feedback
                    if update_counter >= 5 or scanned == len(targets_to_scan):
                        self.status_label.config(
                            text=f"Analyzing {target[0]}:{target[1]} ({scanned}/{len(targets_to_scan)})...", 
                            fg='#FF9800'
                        )
                        self.root.update()
                        update_counter = 0
                    
                    try:
                        result = future.result()
                        scan_stats['count'] += 1
                        if result and result.success:
                            results.append(result)
                        else:
                            scan_stats['errors'] += 1
                    except Exception as e:
                        scan_stats['errors'] += 1
                        # Silently skip failed scans
                        pass

            if self.scan_cancelled:
                self.results_text.insert('1.0', "=== SCAN CANCELLED ===\n\n")
                self.status_label.config(text=f"⏸️ Scan cancelled. {len(results)} certificates analyzed.", fg='#ffb74d')
            else:
                # Format and display results
                report = format_report(results)
                self.results_text.insert('1.0', report)

                # Update status
                vulnerable_count = sum(1 for r in results if r.quantum_vulnerable)
                if vulnerable_count > 0:
                    self.status_label.config(
                        text=f"⚠️ Scan complete: {len(results)} certificates, {vulnerable_count} quantum-vulnerable",
                        fg='#ef5350'
                    )
                else:
                    self.status_label.config(
                        text=f"✓ Scan complete: {len(results)} certificates found, 0 quantum-vulnerable",
                        fg='#66bb6a'
                    )

        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{e}")
            self.status_label.config(text="❌ Scan failed. See error message.", fg='#ef5350')
        
        finally:
            self.btn_scan.config(state='normal')
            self.btn_cancel.config(state='disabled')
            self.root.update()


def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
