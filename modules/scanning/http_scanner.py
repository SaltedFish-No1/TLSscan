# modules/scanning/http_scanner.py

import requests
import logging
import socket
from modules.scanning.base_scanner import BaseScanner
from modules.config import HTTPnHHTPs, ENABLE_METHOD_CHECK
from modules.database import db_lock
from modules.utils import log_exception
import dns.resolver


class HTTPScanner(BaseScanner):
    """Scanner for HTTP-related features of a domain."""

    COMMON_HTTP_METHODS = (HTTPnHHTPs.UNSECURE_METHODS +
                           HTTPnHHTPs.SECURE_METHODS +
                           HTTPnHHTPs.NOT_RECOMMENDED_METHODS)

    def __init__(self, domain_name: str, domain_id: int, conn):
        self.domain_name = domain_name
        self.domain_id = domain_id
        self.conn = conn
        self.cursor = conn.cursor()

    def get_or_create_vulnerability_type_id(self, vulnerability_name: str) -> int:
        """
        Get or create the vulnerability type ID based on the vulnerability name.
        
        Args:
            vulnerability_name (str): The name of the vulnerability type.
        
        Returns:
            int: The ID of the vulnerability type.
        
        Raises:
            ValueError: If vulnerability_name is empty.
            Exception: If database operation fails.
        """
        if not vulnerability_name or not vulnerability_name.strip():
            raise ValueError("vulnerability_name must be a non-empty string.")
        
        vulnerability_name = vulnerability_name.strip().title()  # Normalize the name
        
        with db_lock:
            try:
                # Try to get the existing vulnerability type ID
                self.cursor.execute("""
                    SELECT id FROM vulnerability_types WHERE LOWER(name) = LOWER(?)
                """, (vulnerability_name,))
                result = self.cursor.fetchone()
                if result:
                    return result[0]
                else:
                    # Insert a new vulnerability type
                    self.cursor.execute("""
                        INSERT INTO vulnerability_types (name)
                        VALUES (?)
                    """, (vulnerability_name,))
                    self.conn.commit()
                    return self.cursor.lastrowid
            except Exception as e:
                logging.error(f"Failed to get or create vulnerability type ID: {e}")
                raise

    def scan(self):
        """Perform HTTP and HTTPS scans, check for redirections, and extract HTTP headers and methods."""
        try:
            protocols = [
                ('https', f"https://{self.domain_name}", 443),
                ('http', f"http://{self.domain_name}", 80)
            ]

            for protocol, url, port in protocols:
                logging.info(f"Perform HTTP/HTTPS scanning on {protocol.upper()}://{self.domain_name}:{port}")

                # Initialize flags and variables
                hsts_enabled = False
                hsts_max_age = None
                hsts_preloaded = False
                csp = None
                x_frame_options = None
                x_content_type_options = False
                x_xss_protection = False
                referrer_policy = None
                permissions_policy = None

                # Only HSTS is relevant for HTTPS
                if protocol == 'http':
                    hsts_enabled = False
                    hsts_max_age = None
                    hsts_preloaded = False

                # Create a custom session
                session = requests.Session()
                adapter = requests.adapters.HTTPAdapter(max_retries=3)
                if protocol == 'https':
                    session.mount('https://', adapter)
                else:
                    session.mount('http://', adapter)

                try:
                    # For HTTP, perform redirection check
                    if protocol == 'http':
                        self.handle_redirection(session, url, port)  # Pass port here
                        # Perform GET request with redirects allowed to capture headers
                        response = session.get(url, allow_redirects=True, timeout=5)
                    else:
                        # For HTTPS, perform regular GET request
                        response = session.get(url, allow_redirects=True, timeout=5)

                    headers = response.headers

                    # Log the headers
                    logging.debug(f"Headers for {protocol.upper()}://{self.domain_name}:{port}: {headers}")

                    # Parse security-related headers
                    (hsts_enabled, hsts_max_age, hsts_preloaded, csp, x_frame_options,
                     x_content_type_options, x_xss_protection, referrer_policy,
                     permissions_policy) = self.parse_security_headers(headers, protocol)

                    # Update HTTP Headers in the database
                    self.update_http_headers(protocol, hsts_enabled, hsts_max_age,
                                             hsts_preloaded, csp, x_frame_options,
                                             x_content_type_options, x_xss_protection,
                                             referrer_policy, permissions_policy)

                    # Update HSTS status in domains table only for HTTPS
                    if protocol == 'https':
                        self.update_domains_hsts(hsts_enabled, hsts_preloaded)

                    # Handle HTTP methods
                    is_option_allowed = self.handle_options(session, url, protocol, port)  # Pass port here

                    if ENABLE_METHOD_CHECK and not is_option_allowed:
                        self.check_http_methods(session, url, protocol)

                    # Check for missing security headers only for HTTPS
                    if protocol == 'https':
                        missing_security_headers = [
                            header for header in HTTPnHHTPs.SECURITY_HEADERS
                            if header not in headers
                        ]
                        if missing_security_headers:
                            self.log_missing_security_headers(missing_security_headers, protocol)

                except requests.exceptions.SSLError as ssl_err:
                    error_message = str(ssl_err)
                    vulnerability_type = "Expired/Invalid Certificates"
                    self.insert_vulnerability(protocol, vulnerability_type, error_message)
                    logging.error(f"SSL error for {protocol.upper()}://{self.domain_name}:{port}: {error_message}")

                except socket.gaierror as dns_err:
                    error_message = f"DNS resolution failed: {dns_err}"
                    vulnerability_type = "DNS Resolution Failed"
                    self.insert_vulnerability(protocol, vulnerability_type, error_message)
                    logging.error(f"DNS error for {protocol.upper()}://{self.domain_name}:{port}: {error_message}")

                except requests.exceptions.ConnectionError as conn_err:
                    error_message = f"Connection error: {conn_err}"
                    vulnerability_type = "Connection Error"
                    self.insert_vulnerability(protocol, vulnerability_type, error_message)
                    logging.error(f"Connection error for {protocol.upper()}://{self.domain_name}:{port}: {error_message}")

                except Exception as e:
                    log_exception(e, f"{protocol.upper()}://{self.domain_name}:{port}")  # Include port here

            # Fetch DNS CAA records once (preferably outside the protocol loop)
            self.fetch_caa_records()

        except Exception as e:
            log_exception(e, self.domain_name)

    def parse_security_headers(self, headers, protocol):
        """
        Parse security-related headers from the response headers.
        """
        hsts_enabled = False
        hsts_max_age = None
        hsts_preloaded = False
        csp = None
        x_frame_options = None
        x_content_type_options = False
        x_xss_protection = False
        referrer_policy = None
        permissions_policy = None

        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()

            if header_name_lower == 'strict-transport-security' and protocol == 'https':
                hsts_enabled = True
                # Extract max-age value
                parts = header_value.split(';')
                for part in parts:
                    if 'max-age' in part.lower():
                        try:
                            hsts_max_age = int(part.split('=')[1])
                        except ValueError:
                            hsts_max_age = None
                    if 'preload' in part.lower():
                        hsts_preloaded = True

            elif header_name_lower == 'content-security-policy':
                csp = header_value

            elif header_name_lower == 'x-frame-options':
                x_frame_options = header_value

            elif header_name_lower == 'x-content-type-options':
                if 'nosniff' in header_value.lower():
                    x_content_type_options = True

            elif header_name_lower == 'x-xss-protection':
                if '1; mode=block' in header_value.lower():
                    x_xss_protection = True

            elif header_name_lower == 'referrer-policy':
                referrer_policy = header_value

            elif header_name_lower == 'permissions-policy':
                permissions_policy = header_value

        return (hsts_enabled, hsts_max_age, hsts_preloaded, csp, x_frame_options,
                x_content_type_options, x_xss_protection, referrer_policy, permissions_policy)

    def update_http_headers(self, protocol, hsts_enabled, hsts_max_age, hsts_preloaded,
                            csp, x_frame_options, x_content_type_options,
                            x_xss_protection, referrer_policy, permissions_policy):
        """
        Update or insert HTTP headers information into the database.
        """
        with db_lock:
            # Check if a record already exists for this domain and protocol
            self.cursor.execute("""
                SELECT id FROM http_headers WHERE domain_id = ? AND protocol = ?
            """, (self.domain_id, protocol.upper()))
            result = self.cursor.fetchone()

            if result:
                # Update existing record
                self.cursor.execute("""
                    UPDATE http_headers
                    SET hsts = ?, hsts_max_age = ?, hsts_preloaded = ?,
                        csp = ?, x_frame_options = ?, x_content_type_options = ?,
                        x_xss_protection = ?, referrer_policy = ?, permissions_policy = ?
                    WHERE domain_id = ? AND protocol = ?
                """, (
                    hsts_enabled,
                    hsts_max_age,
                    hsts_preloaded,
                    csp,
                    x_frame_options,
                    x_content_type_options,
                    x_xss_protection,
                    referrer_policy,
                    permissions_policy,
                    self.domain_id,
                    protocol.upper()
                ))
            else:
                # Insert new record
                self.cursor.execute("""
                    INSERT INTO http_headers (
                        domain_id, protocol, hsts, hsts_max_age, hsts_preloaded,
                        csp, x_frame_options, x_content_type_options,
                        x_xss_protection, referrer_policy, permissions_policy
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.domain_id,
                    protocol.upper(),
                    hsts_enabled,
                    hsts_max_age,
                    hsts_preloaded,
                    csp,
                    x_frame_options,
                    x_content_type_options,
                    x_xss_protection,
                    referrer_policy,
                    permissions_policy
                ))

    def update_domains_hsts(self, hsts_enabled, hsts_preloaded):
        """
        Update HSTS status in the domains table.
        """
        with db_lock:
            self.cursor.execute("""
                UPDATE domains
                SET hsts_enabled = ?, hsts_preloaded = ?
                WHERE id = ?
            """, (hsts_enabled, hsts_preloaded, self.domain_id))

    def handle_redirection(self, session, url, port):
        """
        Check if the domain redirects from HTTP to HTTPS and update the domains table.
        """
        try:
            response = session.get(url, allow_redirects=False, timeout=10)
            is_redirected = response.is_redirect or response.is_permanent_redirect
            redirect_target1 = response.headers.get('Location', None)

            # Update domains table with redirection info
            with db_lock:
                self.cursor.execute("""
                    UPDATE domains
                    SET is_redirected = ?, redirect_target1 = ?
                    WHERE id = ?
                """, (is_redirected, redirect_target1, self.domain_id))
                self.conn.commit()

            logging.info(f"HTTP redirection scan completed for {self.domain_name}. Redirected: {is_redirected}")

        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP redirection scan failed for {self.domain_name}: {e}")
            with db_lock:
                self.cursor.execute("""
                    UPDATE domains
                    SET is_redirected = ?, redirect_target1 = ?
                    WHERE id = ?
                """, (False, None, self.domain_id))
                self.conn.commit()

    def check_http_methods(self, session, url, protocol):
        """
        Try common HTTP methods to determine which are supported.
        """
        for method in self.COMMON_HTTP_METHODS:
            try:
                # Skip OPTIONS if already handled
                if method.upper() == "OPTIONS":
                    continue

                # Dynamically create request for each method
                response = session.request(method, url, timeout=5)

                # Determine if method is supported based on status code
                if response.status_code not in [405, 501]:
                    is_supported = True
                    logging.info(f"{method} supported on {protocol.upper()}://{self.domain_name}:{url}")
                else:
                    is_supported = False
                    logging.info(f"{method} not supported on {protocol.upper()}://{self.domain_name}:{url}")

                # Store the result in the database
                with db_lock:
                    self.cursor.execute("""
                        INSERT INTO http_methods (
                            domain_id, protocol, method_name
                        ) VALUES (?, ?, ?)
                    """, (self.domain_id, protocol.upper(), method))

            except requests.exceptions.RequestException as e:
                logging.warning(f"Failed to test {method} on {protocol.upper()}://{self.domain_name}:{url}: {e}")
                continue

    def handle_options(self, session, url, protocol, port):
        """
        Handle OPTIONS request to extract allowed HTTP methods.

        Args:
            session (requests.Session): The requests session.
            url (str): The URL to send the OPTIONS request to.
            protocol (str): The protocol being used ('http' or 'https').
            port (int): The port number.

        Returns:
            bool: True if OPTIONS is allowed (status code 200 or 204), False otherwise.
        """
        is_option_allowed = False
        try:
            options_response = session.options(url, timeout=5)
            if options_response.status_code in [200, 204]:
                allow_header = options_response.headers.get("Allow", "")
                if allow_header:
                    allowed_methods = [method.strip() for method in allow_header.split(',')]
                    for method in allowed_methods:
                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO http_methods (
                                    domain_id, protocol, method_name
                                ) VALUES (?, ?, ?)
                            """, (self.domain_id, protocol.upper(), method))
                    is_option_allowed = True
                else:
                    logging.info(f"No Allow header present for {protocol.upper()}://{self.domain_name}:{port}")
            else:
                logging.error(f"OPTIONS request failed for {protocol.upper()}://{self.domain_name}:{port} with status code {options_response.status_code}")
        except Exception as e:
            logging.error(f"OPTIONS request failed for {protocol.upper()}://{self.domain_name}:{port}: {e}")
        return is_option_allowed

    def log_missing_security_headers(self, missing_headers, protocol):
        """
        Log missing security headers by inserting a vulnerability record.
        """
        description = "".join(missing_headers)
        vulnerability_type = "Missing Security Headers"
        self.insert_vulnerability(protocol, vulnerability_type, description)

    def insert_vulnerability(self, protocol, vulnerability_type, description):
        """
        Insert a vulnerability record into the vulnerabilities table.
        """
        try:
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(vulnerability_type)
            combined_description = f"[{protocol.upper()}] {description}"

            with db_lock:
                self.cursor.execute("""
                    INSERT INTO vulnerabilities (
                        domain_id, vulnerability_type_id, description
                    )
                    VALUES (?, ?, ?)
                """, (self.domain_id, vulnerability_type_id, combined_description))
                self.conn.commit()
        except Exception as e:
            logging.error(f"Failed to insert vulnerability: {e}")
            raise

    def fetch_caa_records(self):
        """Fetch and store DNS CAA records for the domain."""
        try:
            answers = dns.resolver.resolve(self.domain_name, 'CAA')
            for rdata in answers:
                flags = rdata.flags
                tag = rdata.tag.decode('utf-8') if isinstance(rdata.tag, bytes) else rdata.tag
                value = rdata.value
                # Convert tag from bytes or hex to string if necessary
                if isinstance(tag, bytes):
                    tag = tag.decode('utf-8')
                elif isinstance(tag, int):
                    # Assuming tag is a list of ASCII codes, convert to string
                    tag = ''.join([chr(b) for b in tag.to_bytes((tag.bit_length() + 7) // 8, 'big')])

                with db_lock:
                    self.cursor.execute("""
                        INSERT INTO dns_caa_records (
                            domain_id, flags, tag, value
                        )
                        VALUES (?, ?, ?, ?)
                    """, (self.domain_id, flags, tag, value))
        except dns.resolver.NoAnswer:
            logging.info(f"No CAA records found for {self.domain_name}")
        except Exception as e:
            log_exception(e, self.domain_name)