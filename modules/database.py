# modules/database.py

import os
import sqlite3
import threading
import logging
from modules.config import VULNERABILITY_TYPES

db_lock = threading.Lock()

def setup_environment(database_folder, log_folder):
    """Create necessary folders if they don't exist."""
    os.makedirs(database_folder, exist_ok=True)
    os.makedirs(log_folder, exist_ok=True)

def connect_database(database_path):
    """Connect to the SQLite database."""
    conn = sqlite3.connect(database_path, check_same_thread=False)
    conn.execute('PRAGMA foreign_keys = ON;')
    return conn

def create_database(conn):
    """Create necessary tables in the database."""
    cursor = conn.cursor()

    # Create domains table with new columns
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_name TEXT UNIQUE NOT NULL,
            scan_date DATETIME,
            hsts_enabled BOOLEAN DEFAULT 0,
            hsts_preloaded BOOLEAN DEFAULT 0,
            dnssec_enabled BOOLEAN DEFAULT 0,
            session_resumption_caching BOOLEAN DEFAULT 0,
            session_resumption_tickets BOOLEAN DEFAULT 0,
            ocsp_stapling BOOLEAN DEFAULT 0,
            port_443_open BOOLEAN DEFAULT 0,
            port_80_open BOOLEAN DEFAULT 0,
            is_redirected BOOLEAN DEFAULT 0,
            redirect_target1 TEXT
        )
    """)

    # Create vulnerability_types table without description
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    # Insert predefined vulnerability types from config
    for vuln_type in VULNERABILITY_TYPES:
        if isinstance(vuln_type, tuple) and len(vuln_type) == 2:
            name, _ = vuln_type  # Ignore description
        elif isinstance(vuln_type, str):
            name = vuln_type
        else:
            continue  # Skip invalid format vulnerability types

        cursor.execute("""
            INSERT OR IGNORE INTO vulnerability_types (name) VALUES (?)
        """, (name,))

    # Create vulnerabilities table without protocol and description columns
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            vulnerability_type_id INTEGER,
            description TEXT,
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
            FOREIGN KEY(vulnerability_type_id) REFERENCES vulnerability_types(id) ON DELETE CASCADE
        )
    """)

    # Create certificates table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            subject TEXT,
            common_name TEXT,
            alternative_names TEXT,
            serial_number TEXT,
            valid_from DATETIME,
            valid_until DATETIME,
            key_type TEXT,
            key_size INTEGER,
            is_weak_key BOOLEAN DEFAULT 0,
            issuer TEXT,
            signature_algorithm TEXT,
            is_ev BOOLEAN DEFAULT 0,
            certificate_transparency BOOLEAN DEFAULT 0,
            ocsp_must_staple BOOLEAN DEFAULT 0,
            revocation_info TEXT,
            revocation_status TEXT DEFAULT 'Unknown',
            fingerprint_sha256 TEXT,
            trusted BOOLEAN DEFAULT 0,
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
        )
    """)

    # Create dns_caa_records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_caa_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            flags INTEGER,
            tag TEXT,
            value TEXT,
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
        )
    """)

    # Create http_headers table with protocol field
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS http_headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            protocol TEXT,
            hsts BOOLEAN DEFAULT 0,
            hsts_max_age INTEGER,
            hsts_preloaded BOOLEAN DEFAULT 0,
            csp TEXT,
            x_frame_options TEXT,
            x_content_type_options BOOLEAN DEFAULT 0,
            x_xss_protection BOOLEAN DEFAULT 0,
            referrer_policy TEXT,
            permissions_policy TEXT,
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
            UNIQUE(domain_id, protocol)
        )
    """)

    # Create http_methods table without is_unsecure column
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS http_methods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            protocol TEXT,
            method_name TEXT,
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
        )
    """)

    # Create tls_versions table before cipher_suites to satisfy foreign key constraint
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tls_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    # Insert predefined TLS versions if needed
    predefined_tls_versions = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
    for tls_version in predefined_tls_versions:
        cursor.execute("""
            INSERT OR IGNORE INTO tls_versions (name) VALUES (?)
        """, (tls_version,))

    # Create cipher_suites table without tls_version_id
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cipher_suites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            encryption TEXT,
            mac TEXT,
            forward_secrecy BOOLEAN DEFAULT 0,
            key_exchange TEXT,
            authentication TEXT,
            key_length INTEGER,
            secure_level TEXT
        )
    """)

    # Create cipher_suite_tls_versions association table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cipher_suite_tls_versions (
            cipher_suite_id INTEGER,
            tls_version_id INTEGER,
            PRIMARY KEY(cipher_suite_id, tls_version_id),
            FOREIGN KEY(cipher_suite_id) REFERENCES cipher_suites(id) ON DELETE CASCADE,
            FOREIGN KEY(tls_version_id) REFERENCES tls_versions(id) ON DELETE CASCADE
        )
    """)

    # Create dom_tls_cs table to map domains, TLS versions, and cipher suites
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dom_tls_cs (
            domain_id INTEGER,
            tls_version_id INTEGER,
            cipher_suite_id INTEGER,
            PRIMARY KEY(domain_id, tls_version_id, cipher_suite_id),
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
            FOREIGN KEY(tls_version_id) REFERENCES tls_versions(id) ON DELETE CASCADE,
            FOREIGN KEY(cipher_suite_id) REFERENCES cipher_suites(id) ON DELETE CASCADE
        )
    """)


    conn.commit()
    logging.info("All database tables have been created successfully.")

