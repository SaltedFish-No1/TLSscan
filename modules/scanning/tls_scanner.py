# modules/scanning/tls_scanner.py

import logging
from modules.scanning.base_scanner import BaseScanner
from modules.config import CipherSuites
from modules.database import db_lock
from modules.utils import log_exception

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    TlsResumptionSupportEnum,
)
from sslyze.errors import ConnectionToServerFailed, ServerHostnameCouldNotBeResolved
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from datetime import datetime
from cryptography.x509.oid import ExtensionOID

import dns.resolver  # Import for DNS CAA records

import requests
from cryptography.x509 import ocsp


class TLSScanner(BaseScanner):
    """Scanner for TLS/SSL-related information."""

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
        """Scan and collect related data."""
        try:
            # Set up SSLyze scan request with supported vulnerability scans
            scan_commands = [
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.TLS_1_3_EARLY_DATA,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.SESSION_RENEGOTIATION,
                ScanCommand.SESSION_RESUMPTION,
                ScanCommand.ELLIPTIC_CURVES,
            ]
            server_location = ServerNetworkLocation(
                hostname=self.domain_name, port=443
            )
            scan_request = ServerScanRequest(
                server_location=server_location,
                scan_commands=scan_commands
            )

            scanner = Scanner()
            scanner.queue_scans([scan_request])

            # Retrieve and process the scan results
            for server_scan_result in scanner.get_results():
                # Check if the scan was completed
                if server_scan_result.scan_status == "ERROR_NO_CONNECTIVITY":
                    logging.error(
                        f"Could not connect to {self.domain_name}: "
                        f"{server_scan_result.connectivity_error_trace}"
                    )
                    continue

                # Since the scan was successful, proceed to process results
                scan_result = server_scan_result.scan_result

                # Collect protocol details and vulnerabilities
                self.collect_protocol_details(scan_result)

                # Process CERTIFICATE_INFO
                self.process_certificate_info(scan_result.certificate_info)

                # Process TLS Cipher Suites
                self.process_tls_cipher_suites(scan_result)

                self.conn.commit()
                logging.info(
                    f"Successfully scanned and stored TLS results for {self.domain_name}"
                )

            # Fetch DNS CAA records
            self.fetch_caa_records()

        except ServerHostnameCouldNotBeResolved as dns_err:
            error_message = f"DNS resolution failed: {dns_err}"
            vulnerability_type = "DNS Resolution Failed"
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                vulnerability_type
            )

            # Skip for DNS resolution errors
            logging.error(f"DNS error for {self.domain_name}: {error_message}")

        except ConnectionToServerFailed as conn_err:
            error_message = str(conn_err)
            vulnerability_type = "NO_CONNECTIVITY"
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                vulnerability_type
            )
            # Skip for ConnectionToServerFailed
            logging.error(
                f"Connection error for {self.domain_name}: {error_message}"
            )

        except requests.exceptions.SSLError as ssl_err:
            error_message = f"SSL Certificate Verification Failed: {ssl_err}"
            vulnerability_type = "SSL Certificate Verification Failed"
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                vulnerability_type
            )

            with db_lock:
                self.cursor.execute("""
                    INSERT INTO vulnerabilities (
                        domain_id, vulnerability_type_id, description
                    )
                    VALUES (
                        ?, ?, ?
                    )
                """, (self.domain_id, vulnerability_type_id, "{error_message}"))
                self.conn.commit()
            logging.error(f"SSL error for {self.domain_name}: {error_message}")

        except Exception as e:
            # Catch all other exceptions, including SSL certificate verification errors
            if isinstance(e, requests.exceptions.SSLError):
                error_message = f"SSL Certificate Verification Failed: {e}"
                vulnerability_type = "SSL Certificate Verification Failed"
                vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                    vulnerability_type
                )

                with db_lock:
                    self.cursor.execute("""
                        INSERT INTO vulnerabilities (
                            domain_id, vulnerability_type_id, description
                        )
                        VALUES (
                            ?, ?, ?
                        )
                    """, (self.domain_id, vulnerability_type_id, f"{error_message}"))
                    self.conn.commit()
                logging.error(f"SSL error for {self.domain_name}: {error_message}")
            else:
                log_exception(e, self.domain_name)

    def collect_protocol_details(self, scan_result):
        """Collect protocol details and store them as vulnerabilities."""
        try:
            # Secure Renegotiation
            if scan_result.session_renegotiation:
                renegotiation_attempt = scan_result.session_renegotiation
                if renegotiation_attempt.status == "COMPLETED":
                    renegotiation_result = renegotiation_attempt.result
                    if not renegotiation_result.supports_secure_renegotiation:
                        # Insecure session renegotiation detected
                        vulnerability_type = "Insecure Session Renegotiation"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )
                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ''))

            # ROBOT Attack
            if scan_result.robot:
                robot_attempt = scan_result.robot
                if robot_attempt.status == "COMPLETED":
                    robot_result = robot_attempt.result
                    is_robot_vulnerable = robot_result.robot_result in [
                        "VULNERABLE_WEAK_ORACLE",
                        "VULNERABLE_STRONG_ORACLE"
                    ]
                    if is_robot_vulnerable:
                        vulnerability_type = "ROBOT Attack"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, robot_result.robot_result))

            # TLS Compression
            if scan_result.tls_compression:
                compression_attempt = scan_result.tls_compression
                if compression_attempt.status == "COMPLETED":
                    compression_result = compression_attempt.result
                    if compression_result.supports_compression:
                        vulnerability_type = "TLS Compression"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ""))

            # Heartbleed
            if scan_result.heartbleed:
                heartbleed_attempt = scan_result.heartbleed
                if heartbleed_attempt.status == "COMPLETED":
                    heartbleed_result = heartbleed_attempt.result
                    if heartbleed_result.is_vulnerable_to_heartbleed:
                        vulnerability_type = "Heartbleed"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ""))

            # OpenSSL CCS Injection
            if scan_result.openssl_ccs_injection:
                openssl_ccs_attempt = scan_result.openssl_ccs_injection
                if openssl_ccs_attempt.status == "COMPLETED":
                    openssl_ccs_result = openssl_ccs_attempt.result
                    if openssl_ccs_result.is_vulnerable_to_ccs_injection:
                        vulnerability_type = "OpenSSL CCS Injection"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ""))

            # TLS Fallback SCSV
            if scan_result.tls_fallback_scsv:
                tls_fallback_attempt = scan_result.tls_fallback_scsv
                if tls_fallback_attempt.status == "COMPLETED":
                    tls_fallback = tls_fallback_attempt.result
                    if not tls_fallback.supports_fallback_scsv:
                        vulnerability_type = "TLS Fallback SCSV"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ""))

            # Session Resumption
            session_resumption_tickets = False
            session_resumption_ids = False

            if scan_result.session_resumption:
                session_resumption_attempt = scan_result.session_resumption
                if session_resumption_attempt.status == "COMPLETED":
                    session_resumption_result = session_resumption_attempt.result

                    # Determine session resumption support
                    session_id_result = session_resumption_result.session_id_resumption_result
                    tls_ticket_result = session_resumption_result.tls_ticket_resumption_result

                    session_resumption_tickets = tls_ticket_result == "FULLY_SUPPORTED"
                    session_resumption_ids = session_id_result == "FULLY_SUPPORTED"

            # Update domains table
            with db_lock:
                self.cursor.execute("""
                    UPDATE domains
                    SET session_resumption_tickets = ?, session_resumption_caching = ?
                    WHERE id = ?
                """, (session_resumption_tickets, session_resumption_ids, self.domain_id))

            # Insert vulnerability if session resumption is incomplete or insecure
            if not (session_resumption_tickets and session_resumption_ids):
                vulnerability_type = "Insecure Session Resumption"
                descriptions = []
                if not session_resumption_tickets:
                    descriptions.append("TLS Ticket session resumption not fully supported.")
                if not session_resumption_ids:
                    descriptions.append("Session ID resumption not fully supported.")
                combined_description = " ".join(descriptions)
                vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                    vulnerability_type
                )

                with db_lock:
                    self.cursor.execute("""
                        INSERT INTO vulnerabilities (
                            domain_id, vulnerability_type_id, description
                        )
                        VALUES (
                            ?, ?, ?
                        )
                    """, (self.domain_id, vulnerability_type_id, combined_description))

            # OCSP Stapling
            if scan_result.certificate_info:
                cert_info_attempt = scan_result.certificate_info
                if cert_info_attempt.status == "COMPLETED":
                    cert_info = cert_info_attempt.result
                    ocsp_stapling_enabled = False
                    for deployment in cert_info.certificate_deployments:
                        if hasattr(deployment, 'ocsp_stapling_status') and deployment.ocsp_stapling_status.is_supported:
                            ocsp_stapling_enabled = True
                            break
                    # Update domains table
                    with db_lock:
                        self.cursor.execute("""
                            UPDATE domains
                            SET ocsp_stapling = ?
                            WHERE id = ?
                        """, (ocsp_stapling_enabled, self.domain_id))
                    if not ocsp_stapling_enabled:
                        vulnerability_type = "OCSP Stapling Not Enabled"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ""))

            # TLS 1.3 Early Data Support
            if scan_result.tls_1_3_early_data:
                early_data_attempt = scan_result.tls_1_3_early_data
                if early_data_attempt.status == "COMPLETED":
                    early_data_result = early_data_attempt.result
                    if early_data_result.supports_early_data:
                        vulnerability_type = "TLS 1.3 Early Data Support"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )

                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, ''))
                        logging.info(
                            f"TLS 1.3 Early Data supported for {self.domain_name}: Server supports TLS 1.3 Early Data (0-RTT)."
                        )

        except Exception as e:
            log_exception(e, self.domain_name)
            if scan_result:
                logging.error(f"Error processing TLS scan results for {self.domain_name}.")



    def process_certificate_info(self, cert_info_attempt):
            """Process certificate information and store it in the database."""
            from modules.database import db_lock
            from modules.utils import log_exception

            try:
                if cert_info_attempt.status != "COMPLETED":
                    logging.warning(
                        f"CERTIFICATE_INFO scan not completed for {self.domain_name}."
                    )
                    return

                cert_info = cert_info_attempt.result
                for deployment in cert_info.certificate_deployments:
                    for level, cert in enumerate(deployment.received_certificate_chain):
                        is_ev = deployment.leaf_certificate_is_ev if level == 0 else False

                        # Extract common names
                        common_names = cert.subject.get_attributes_for_oid(
                            x509.NameOID.COMMON_NAME
                        )
                        common_name = common_names[0].value if common_names else ''

                        # Extract alternative names
                        try:
                            ext = cert.extensions.get_extension_for_oid(
                                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            san = ext.value.get_values_for_type(x509.DNSName)
                        except x509.ExtensionNotFound:
                            san = []
                        alternative_names = ','.join(san)

                        # Get public key and key size
                        public_key = cert.public_key()
                        key_type = public_key.__class__.__name__
                        key_size = getattr(public_key, 'key_size', None)

                        # Check for certificate expiration
                        now = datetime.utcnow()
                        if cert.not_valid_before > now or cert.not_valid_after < now:
                            vulnerability_type = "Expired/Invalid Certificates"
                            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                                vulnerability_type
                            )

                            with db_lock:
                                self.cursor.execute("""
                                    INSERT INTO vulnerabilities (
                                        domain_id, vulnerability_type_id, description
                                    )
                                    VALUES (
                                        ?, ?, ?
                                    )
                                """, (self.domain_id, vulnerability_type_id, "Certificate is expired or invalid."))
                        else:
                            # Check if certificate is about to expire in 30 days
                            if (cert.not_valid_after - now).days < 30:
                                vulnerability_type = "Certificate About to Expire"
                                vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                                    vulnerability_type
                                )

                                with db_lock:
                                    self.cursor.execute("""
                                        INSERT INTO vulnerabilities (
                                            domain_id, vulnerability_type_id, description
                                        )
                                        VALUES (
                                            ?, ?, ?
                                        )
                                    """, (self.domain_id, vulnerability_type_id, "Certificate is about to expire in less than 30 days."))

                        # Check if certificate is trusted
                        trusted = False
                        try:
                            trusted = any(result.was_validation_successful for result in deployment.path_validation_results)
                        except AttributeError as e:
                            logging.error(f"Evaluate {self.domain_name} certificate trustable status encountered a problem {e}")

                        if not trusted:
                            vulnerability_type = "Untrusted Certificate"
                            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                                vulnerability_type
                            )

                            with db_lock:
                                self.cursor.execute("""
                                    INSERT INTO vulnerabilities (
                                        domain_id, vulnerability_type_id, description
                                    )
                                    VALUES (
                                        ?, ?, ?
                                    )
                                """, (self.domain_id, vulnerability_type_id, "Certificate is not trusted."))

                        # Check for OCSP Must-Staple
                        ocsp_must_staple = False
                        try:
                            tls_feature_ext = cert.extensions.get_extension_for_oid(
                                ExtensionOID.TLS_FEATURE
                            )
                            features = tls_feature_ext.value
                            for feature in features:
                                if feature == x509.TLSFeatureType.status_request:
                                    ocsp_must_staple = True
                                    break
                        except x509.ExtensionNotFound:
                            pass

                        # Check for Certificate Transparency
                        certificate_transparency = False
                        try:
                            sct_ext = cert.extensions.get_extension_for_oid(
                                ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
                            )
                            certificate_transparency = True
                        except x509.ExtensionNotFound:
                            pass

                        # Extract revocation information
                        revocation_info = self.get_revocation_info(cert)
                        revocation_status = self.check_revocation_status(cert)

                        # Calculate fingerprint
                        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
                        fingerprint_sha256 = self.get_certificate_fingerprint(cert_pem)

                        # Insert certificate record
                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO certificates (
                                    domain_id, subject, common_name, alternative_names,
                                    serial_number, valid_from, valid_until, key_type, key_size, issuer, signature_algorithm, is_ev,
                                    certificate_transparency, ocsp_must_staple, revocation_info,
                                    revocation_status, fingerprint_sha256, trusted
                                )
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                self.domain_id,
                                cert.subject.rfc4514_string(),
                                common_name,
                                alternative_names,
                                hex(cert.serial_number),
                                cert.not_valid_before,
                                cert.not_valid_after,
                                key_type,
                                key_size,
                                cert.issuer.rfc4514_string(),
                                cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else '',
                                is_ev,
                                certificate_transparency,
                                ocsp_must_staple,
                                revocation_info,
                                revocation_status,
                                fingerprint_sha256,
                                trusted
                            ))

            except requests.exceptions.SSLError as ssl_err:
                error_message = f"SSL Certificate Verification Failed: {ssl_err}"
                vulnerability_type = "SSL Certificate Verification Failed"
                vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                    vulnerability_type
                )

                with db_lock:
                    self.cursor.execute("""
                        INSERT INTO vulnerabilities (
                            domain_id, vulnerability_type_id, description
                        )
                        VALUES (
                            ?, ?, ?
                        )
                    """, (self.domain_id, vulnerability_type_id, error_message))
                    self.conn.commit()
                logging.error(f"SSL error during certificate processing for {self.domain_name}: {error_message}")

            except Exception as e:
                log_exception(e, self.domain_name)

    def get_revocation_info(self, cert):
        """Extract revocation information from the certificate."""
        ocsp_urls = []
        crl_urls = []
        try:
            aia_extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for access in aia_extension.value:
                if access.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    ocsp_urls.append(access.access_location.value)
        except x509.ExtensionNotFound:
            pass

        try:
            crl_extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            for dp in crl_extension.value:
                for fullname in dp.full_name:
                    crl_urls.append(fullname.value)
        except x509.ExtensionNotFound:
            pass

        revocation_info = {
            'ocsp_urls': ocsp_urls,
            'crl_urls': crl_urls
        }
        return str(revocation_info)

    def check_revocation_status(self, cert):
        """Check the revocation status of the certificate using OCSP and CRL."""
        # First, attempt OCSP check
        ocsp_status = self.check_ocsp_status(cert)
        if ocsp_status != 'Unknown':
            return ocsp_status

        # If OCSP check is inconclusive, attempt CRL check
        crl_status = self.check_crl_status(cert)
        return crl_status

    def check_ocsp_status(self, cert):
        """Check revocation status using OCSP."""
        try:
            # Get the issuer certificate
            issuer_cert = self.get_issuer_certificate(cert)
            if not issuer_cert:
                logging.warning(f"Issuer certificate not found for {self.domain_name}.")
                return 'Unknown'

            # Get OCSP URL
            try:
                aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                ocsp_urls = [
                    desc.access_location.value
                    for desc in aia.value
                    if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
                ]
                if not ocsp_urls:
                    logging.warning(f"No OCSP URL found in certificate for {self.domain_name}.")
                    return 'Unknown'
                ocsp_url = ocsp_urls[0]
            except x509.ExtensionNotFound:
                logging.warning(f"No AIA extension found in certificate for {self.domain_name}.")
                return 'Unknown'

            # Build OCSP request
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
            req = builder.build()

            # Send OCSP request
            headers = {'Content-Type': 'application/ocsp-request'}
            response = requests.post(
                ocsp_url,
                data=req.public_bytes(serialization.Encoding.DER),
                headers=headers,
                timeout=10
            )

            if response.status_code != 200:
                logging.warning(f"OCSP request failed with status code {response.status_code} for {self.domain_name}.")
                return 'Unknown'

            # Parse OCSP response
            ocsp_response = ocsp.load_der_ocsp_response(response.content)
            status = ocsp_response.certificate_status

            if status == ocsp.OCSPCertStatus.GOOD:
                return 'Good'
            elif status == ocsp.OCSPCertStatus.REVOKED:
                return 'Revoked'
            else:
                return 'Unknown'

        except requests.exceptions.SSLError as ssl_err:
            vulnerability_type = "OCSP SSL Certificate Verification Failed"
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                vulnerability_type
            )

            with db_lock:
                self.cursor.execute("""
                    INSERT INTO vulnerabilities (
                        domain_id, vulnerability_type_id, description
                    )
                    VALUES (
                        ?, ?, ?
                    )
                """, (self.domain_id, vulnerability_type_id,ssl_err))
                self.conn.commit()
            logging.error(f"OCSP SSL error for {self.domain_name}: {ssl_err}")
            return 'Unknown'

        except Exception as e:
            logging.error(f"OCSP check failed for {self.domain_name}: {e}")
            return 'Unknown'

    def check_crl_status(self, cert):
        """Check revocation status using CRL."""
        try:
            crl_urls = []
            try:
                crl_extension = cert.extensions.get_extension_for_oid(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS
                )
                for dp in crl_extension.value:
                    for fullname in dp.full_name:
                        crl_urls.append(fullname.value)
            except x509.ExtensionNotFound:
                logging.warning(f"No CRL Distribution Points found for {self.domain_name}.")
                return 'Unknown'

            for crl_url in crl_urls:
                try:
                    crl_response = requests.get(crl_url, timeout=10)
                    if crl_response.status_code == 200:
                        try:
                            # Try loading as DER
                            crl = x509.load_der_x509_crl(crl_response.content, default_backend())
                        except ValueError:
                            # If that fails, try loading as PEM
                            crl = x509.load_pem_x509_crl(crl_response.content, default_backend())

                        for revoked_cert in crl:
                            if revoked_cert.serial_number == cert.serial_number:
                                return 'Revoked'
                        return 'Good'
                    else:
                        logging.warning(f"Failed to download CRL from {crl_url} for {self.domain_name}.")
                except requests.exceptions.SSLError as ssl_err:
                    vulnerability_type = "CRL SSL Certificate Verification Failed"
                    vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                        vulnerability_type
                    )

                    with db_lock:
                        self.cursor.execute("""
                            INSERT INTO vulnerabilities (
                                domain_id, vulnerability_type_id, description
                            )
                            VALUES (
                                ?, ?, ?
                            )
                        """, (self.domain_id, vulnerability_type_id, "CRL SSL certificate verification failed due to hostname mismatch or other issues."))
                        self.conn.commit()
                    logging.error(f"CRL SSL error for {self.domain_name} at {crl_url}: {ssl_err}")
                except Exception as e:
                    logging.error(f"CRL check failed for {self.domain_name} at {crl_url}: {e}")
            return 'Unknown'

        except requests.exceptions.SSLError as ssl_err:
            vulnerability_type = "CRL SSL Certificate Verification Failed"
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                vulnerability_type
            )

            with db_lock:
                self.cursor.execute("""
                    INSERT INTO vulnerabilities (
                        domain_id, vulnerability_type_id, description
                    )
                    VALUES (
                        ?, ?, ?
                    )
                """, (self.domain_id, vulnerability_type_id, ssl_err))
                self.conn.commit()
            logging.error(f"CRL SSL error for {self.domain_name}: {ssl_err}")
            return 'Unknown'

        except Exception as e:
            logging.error(f"CRL check failed for {self.domain_name}: {e}")
            return 'Unknown'

    def get_issuer_certificate(self, cert):
        """
        Given an X.509 certificate, fetch the issuer's certificate using the Authority Information Access extension.
        """
        # Try to get the AIA extension
        try:
            aia_extension = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
        except x509.ExtensionNotFound:
            return None  # No AIA extension found

        # Find the CA Issuers access method
        issuer_url = None
        for access_description in aia_extension:
            if access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_url = access_description.access_location.value
                break

        if issuer_url is None:
            return None  # No issuer URL found

        # Download the issuer certificate
        try:
            response = requests.get(issuer_url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.SSLError as ssl_err:
            vulnerability_type = "Issuer Certificate SSL Verification Failed"
            vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                vulnerability_type
            )

            with db_lock:
                self.cursor.execute("""
                    INSERT INTO vulnerabilities (
                        domain_id, vulnerability_type_id, description
                    )
                    VALUES (
                        ?, ?, ?
                    )
                """, (self.domain_id, vulnerability_type_id, f"{ssl_err}"))
                self.conn.commit()
            logging.error(f"Issuer certificate SSL error for {self.domain_name}: {ssl_err}")
            return None
        except Exception as e:
            logging.error(f"Failed to download issuer certificate for {self.domain_name} from {issuer_url}: {e}")
            return None  # Failed to download issuer certificate

        # Try to load the issuer certificate
        try:
            # First try loading as DER
            issuer_cert = x509.load_der_x509_certificate(response.content, default_backend())
        except ValueError:
            try:
                # If that fails, try loading as PEM
                issuer_cert = x509.load_pem_x509_certificate(response.content, default_backend())
            except Exception:
                return None  # Failed to parse issuer certificate

        return issuer_cert

    def get_certificate_fingerprint(self, cert_pem: str) -> str:
        """Calculate SHA256 fingerprint of a certificate."""
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )
        fingerprint = cert.fingerprint(hashes.SHA256())
        fingerprint_hex = fingerprint.hex()
        return fingerprint_hex

    def process_tls_cipher_suites(self, scan_result):
        """Process TLS cipher suites and store them in the database."""
        from modules.database import db_lock
        from modules.utils import log_exception

        try:
            tls_versions = [
                (ScanCommand.SSL_2_0_CIPHER_SUITES, "SSL 2.0"),
                (ScanCommand.SSL_3_0_CIPHER_SUITES, "SSL 3.0"),
                (ScanCommand.TLS_1_0_CIPHER_SUITES, "TLS 1.0"),
                (ScanCommand.TLS_1_1_CIPHER_SUITES, "TLS 1.1"),
                (ScanCommand.TLS_1_2_CIPHER_SUITES, "TLS 1.2"),
                (ScanCommand.TLS_1_3_CIPHER_SUITES, "TLS 1.3")
            ]

            for tls_command, tls_version_name in tls_versions:
                tls_attempt = getattr(scan_result, tls_command.value)
                if tls_attempt.status != "COMPLETED":
                    logging.warning(
                        f"{tls_version_name} scan not completed for {self.domain_name}."
                    )
                    continue

                cipher_suites_result = tls_attempt.result
                if not cipher_suites_result.accepted_cipher_suites:
                    # If no accepted cipher suites for this TLS version
                    continue

                # Get or create TLS version ID
                self.cursor.execute("SELECT id FROM tls_versions WHERE name = ?", (tls_version_name,))
                result = self.cursor.fetchone()
                if result:
                    tls_version_id = result[0]
                else:
                    with db_lock:
                        self.cursor.execute("INSERT INTO tls_versions (name) VALUES (?)", (tls_version_name,))
                        tls_version_id = self.cursor.lastrowid

                for suite in cipher_suites_result.accepted_cipher_suites:
                    cipher_suite_name = suite.cipher_suite.name

                    # Determine if weak cipher
                    secure_level = CipherSuites.is_cipher_secure(cipher_suite_name)
                    if secure_level == "Weak":
                        # Insert vulnerability for weak cipher suite
                        vulnerability_type = "Weak Cipher Suite"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )
                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, f"Weak cipher suite detected: {cipher_suite_name}."))

                    elif secure_level == "Insecure":
                        # Insert vulnerability for insecure cipher suite
                        vulnerability_type = "Insecure Cipher Suite"
                        vulnerability_type_id = self.get_or_create_vulnerability_type_id(
                            vulnerability_type
                        )
                        with db_lock:
                            self.cursor.execute("""
                                INSERT INTO vulnerabilities (
                                    domain_id, vulnerability_type_id, description
                                )
                                VALUES (
                                    ?, ?, ?
                                )
                            """, (self.domain_id, vulnerability_type_id, f"Insecure cipher suite detected: {cipher_suite_name}."))


                    # Determine if cipher suite supports forward secrecy
                    forward_secrecy = self.is_cipher_suite_forward_secure(cipher_suite_name)

                    # Parse cipher suite components
                    key_exchange = authentication = encryption = mac = None
                    if 'WITH' in cipher_suite_name:
                        parts = cipher_suite_name.split('WITH')
                        if len(parts) < 2:
                            continue  # Invalid cipher suite format
                        kex_auth = parts[0].split('_')[1:]  # Skip 'TLS' or 'SSL'
                        encryption_mac = parts[1].split('_')
                        if len(kex_auth) >= 2:
                            key_exchange = kex_auth[0]
                            authentication = kex_auth[1]
                        elif len(kex_auth) == 1:
                            key_exchange = kex_auth[0]
                        if len(encryption_mac) >= 2:
                            encryption = encryption_mac[0]
                            mac = '_'.join(encryption_mac[1:])
                        elif len(encryption_mac) == 1:
                            encryption = encryption_mac[0]
                    else:
                        # TLS 1.3 cipher suites
                        parts = cipher_suite_name.split('_')
                        if len(parts) < 2:
                            encryption = cipher_suite_name  # Fallback to entire name
                        else:
                            encryption = '_'.join(parts[1:])

                    # Handle anonymous ciphers
                    if 'ANON' in cipher_suite_name.upper():
                        authentication = 'Anonymous'

                    # Handle RSA's dual role
                    if key_exchange == 'RSA' and authentication is None:
                        authentication = 'RSA'

                    # Manually set the cipher_suite_id
                    self.cursor.execute("SELECT MAX(id) FROM cipher_suites")
                    max_id = self.cursor.fetchone()[0] or 0
                    new_id = max_id + 1

                    # Insert or ignore cipher suite to maintain uniqueness
                    with db_lock:
                        self.cursor.execute("""
                            INSERT OR IGNORE INTO cipher_suites (
                                id, name, encryption, mac, forward_secrecy,
                                key_exchange, authentication, key_length, secure_level
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            new_id,
                            cipher_suite_name,
                            encryption,
                            mac,
                            forward_secrecy,
                            key_exchange,
                            authentication,
                            suite.cipher_suite.key_size or 0,
                            secure_level
                        ))

                        # Retrieve the cipher_suite_id
                        self.cursor.execute("""
                            SELECT id FROM cipher_suites
                            WHERE name = ?
                        """, (cipher_suite_name,))
                        cipher_suite_record = self.cursor.fetchone()
                        if cipher_suite_record:
                            cipher_suite_id = cipher_suite_record[0]

                            # Insert into cipher_suite_tls_versions to map cipher suite to TLS version
                            self.cursor.execute("""
                                INSERT OR IGNORE INTO cipher_suite_tls_versions (
                                    cipher_suite_id, tls_version_id
                                )
                                VALUES (?, ?)
                            """, (cipher_suite_id, tls_version_id))

                            # Insert into dom_tls_cs to establish the association
                            self.cursor.execute("""
                                INSERT OR IGNORE INTO dom_tls_cs (
                                    domain_id, tls_version_id, cipher_suite_id
                                )
                                VALUES (?, ?, ?)
                            """, (self.domain_id, tls_version_id, cipher_suite_id))
                        else:
                            logging.error(f"Failed to retrieve cipher_suite_id for {cipher_suite_name}.")
        except Exception as e:
            log_exception(e, self.domain_name)

    def is_cipher_suite_forward_secure(self, cipher_suite_name: str) -> bool:
        """Determine if a cipher suite supports forward secrecy."""
        return 'DHE' in cipher_suite_name or 'ECDHE' in cipher_suite_name

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