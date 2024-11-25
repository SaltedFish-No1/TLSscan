# modules/scanning/handshake_simulator.py
"""Deprecataed: SSLyze in TLS Scanner already provides enough information about supported protocols and ciphersuites."""
import ssl
import socket
import logging
from modules.scanning.base_scanner import BaseScanner
from modules.database import db_lock
from modules.utils import log_exception

class HandshakeSimulator(BaseScanner):
    """Simulator for SSL/TLS handshakes with different client configurations."""

    # Define handshake result enums
    HANDSHAKE_SUCCESS = 0
    HANDSHAKE_SSL_ERROR = 1
    HANDSHAKE_DNS_ERROR = 2
    HANDSHAKE_TIMEOUT = 3
    HANDSHAKE_OTHER_ERROR = 4

    def __init__(self, domain_name: str, domain_id: int, conn, client_configs: list):
        super().__init__(domain_name, domain_id, conn)
        self.client_configs = client_configs
        self.handshake_result_mapping = {
            "Success": self.HANDSHAKE_SUCCESS
            # Dynamically add failure states as needed
        }

    def scan(self):
        """Simulate handshakes with various client configurations."""
        try:
            for client in self.client_configs:
                for tls_version in client.tls_versions:
                    handshake_result = "Success"
                    negotiated_protocol = "N/A"
                    negotiated_cipher = "N/A"
                    try:
                        # Create SSL context
                        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

                        # Configure SSL context based on TLS version
                        tls_version_mapping = {
                            "TLSv1.0": ssl.TLSVersion.TLSv1,
                            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                            "TLSv1.3": ssl.TLSVersion.TLSv1_3
                        }

                        if tls_version not in tls_version_mapping:
                            logging.warning(
                                f"Unsupported TLS version: {tls_version} for client {client.name}"
                            )
                            continue

                        selected_version = tls_version_mapping[tls_version]
                        ssl_context.minimum_version = selected_version
                        ssl_context.maximum_version = selected_version

                        # Set cipher suites
                        cipher_suites_str = ':'.join(client.cipher_suites)
                        try:
                            ssl_context.set_ciphers(cipher_suites_str)
                        except ssl.SSLError as e:
                            logging.error(
                                f"Failed to set ciphers for {client.name} {client.version} on {client.platform}: {str(e)}"
                            )
                            handshake_result = "SSL_ERROR"
                            negotiated_protocol = "N/A"
                            negotiated_cipher = "N/A"
                            # Dynamically add to mapping if not exists
                            if handshake_result not in self.handshake_result_mapping:
                                self.handshake_result_mapping[handshake_result] = len(self.handshake_result_mapping)
                            # Proceed to store the result without continuing
                        else:
                            # Disable certificate verification if needed
                            ssl_context.check_hostname = False
                            ssl_context.verify_mode = ssl.CERT_NONE

                            # Create a socket and wrap it with SSL
                            with socket.create_connection((self.domain_name, 443), timeout=10) as sock:
                                with ssl_context.wrap_socket(sock, server_hostname=self.domain_name) as ssock:
                                    # Handshake succeeded
                                    negotiated_protocol = ssock.version()
                                    negotiated_cipher = ssock.cipher()[0]
                                    logging.info(
                                        f"Handshake succeeded for {client.name} {client.version} on {client.platform} with TLS {tls_version}"
                                    )

                        # Store handshake results in the database
                        with db_lock:
                            try:
                                self.cursor.execute("""
                                    INSERT INTO handshake_simulations (
                                        domain_id, client_name, client_version, platform,
                                        supported_protocol, supported_cipher_suites, handshake_result
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    self.domain_id,
                                    client.name,
                                    client.version,
                                    client.platform,
                                    negotiated_protocol,
                                    negotiated_cipher,
                                    self.get_handshake_result_enum(handshake_result)
                                ))
                                self.conn.commit()
                                logging.debug("Handshake result inserted successfully.")
                            except Exception as db_err:
                                logging.error(f"Database insert failed: {db_err}")
                                log_exception(db_err, self.domain_name)

                    except ssl.SSLError as ssl_err:
                        # Handle SSL handshake errors
                        handshake_result = "SSL_ERROR"
                        negotiated_protocol = "N/A"
                        negotiated_cipher = "N/A"

                        logging.error(
                            f"Handshake failed for {client.name} {client.version} on {client.platform} with TLS {tls_version}: {str(ssl_err)}"
                        )

                        # Dynamically add to mapping if not exists
                        if handshake_result not in self.handshake_result_mapping:
                            self.handshake_result_mapping[handshake_result] = len(self.handshake_result_mapping)

                        # Store the failed handshake result
                        with db_lock:
                            try:
                                self.cursor.execute("""
                                    INSERT INTO handshake_simulations (
                                        domain_id, client_name, client_version, platform,
                                        supported_protocol, supported_cipher_suites, handshake_result
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    self.domain_id,
                                    client.name,
                                    client.version,
                                    client.platform,
                                    negotiated_protocol,
                                    negotiated_cipher,
                                    self.get_handshake_result_enum(handshake_result)
                                ))
                                self.conn.commit()
                                logging.debug("Handshake error result inserted successfully.")
                            except Exception as db_err:
                                logging.error(f"Database insert failed: {db_err}")
                                log_exception(db_err, self.domain_name)

                    except socket.gaierror as dns_err:
                        # Handle DNS resolution errors
                        handshake_result = "DNS_ERROR"
                        negotiated_protocol = "N/A"
                        negotiated_cipher = "N/A"

                        logging.error(
                            f"DNS error during handshake for {client.name} {client.version} on {client.platform} with TLS {tls_version}: {dns_err}"
                        )

                        # Dynamically add to mapping if not exists
                        if handshake_result not in self.handshake_result_mapping:
                            self.handshake_result_mapping[handshake_result] = len(self.handshake_result_mapping)

                        # Store the DNS error handshake result
                        with db_lock:
                            try:
                                self.cursor.execute("""
                                    INSERT INTO handshake_simulations (
                                        domain_id, client_name, client_version, platform,
                                        supported_protocol, supported_cipher_suites, handshake_result
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    self.domain_id,
                                    client.name,
                                    client.version,
                                    client.platform,
                                    negotiated_protocol,
                                    negotiated_cipher,
                                    self.get_handshake_result_enum(handshake_result)
                                ))
                                self.conn.commit()
                                logging.debug("DNS error result inserted successfully.")
                            except Exception as db_err:
                                logging.error(f"Database insert failed: {db_err}")
                                log_exception(db_err, self.domain_name)

                    except socket.timeout:
                        handshake_result = "TIMEOUT"
                        negotiated_protocol = "N/A"
                        negotiated_cipher = "N/A"

                        logging.error(
                            f"Handshake timed out for {client.name} {client.version} on {client.platform} with TLS {tls_version}"
                        )

                        # Dynamically add to mapping if not exists
                        if handshake_result not in self.handshake_result_mapping:
                            self.handshake_result_mapping[handshake_result] = len(self.handshake_result_mapping)

                        # Store the timed out handshake result
                        with db_lock:
                            try:
                                self.cursor.execute("""
                                    INSERT INTO handshake_simulations (
                                        domain_id, client_name, client_version, platform,
                                        supported_protocol, supported_cipher_suites, handshake_result
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    self.domain_id,
                                    client.name,
                                    client.version,
                                    client.platform,
                                    negotiated_protocol,
                                    negotiated_cipher,
                                    self.get_handshake_result_enum(handshake_result)
                                ))
                                self.conn.commit()
                                logging.debug("Timeout result inserted successfully.")
                            except Exception as db_err:
                                logging.error(f"Database insert failed: {db_err}")
                                log_exception(db_err, self.domain_name)

                    except Exception as e:
                        handshake_result = "OTHER_ERROR"
                        negotiated_protocol = "N/A"
                        negotiated_cipher = "N/A"

                        log_exception(e, self.domain_name)

                        # Dynamically add to mapping if not exists
                        if handshake_result not in self.handshake_result_mapping:
                            self.handshake_result_mapping[handshake_result] = len(self.handshake_result_mapping)

                        # Store the exception handshake result
                        with db_lock:
                            try:
                                self.cursor.execute("""
                                    INSERT INTO handshake_simulations (
                                        domain_id, client_name, client_version, platform,
                                        supported_protocol, supported_cipher_suites, handshake_result
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    self.domain_id,
                                    client.name,
                                    client.version,
                                    client.platform,
                                    negotiated_protocol,
                                    negotiated_cipher,
                                    self.get_handshake_result_enum(handshake_result)
                                ))
                                self.conn.commit()
                                logging.debug("Other error result inserted successfully.")
                            except Exception as db_err:
                                logging.error(f"Database insert failed: {db_err}")
                                log_exception(db_err, self.domain_name)

        except Exception as e:
            log_exception(e, self.domain_name)

    def get_handshake_result_enum(self, result_str):
        """Map handshake result string to enum integer."""
        if result_str in self.handshake_result_mapping:
            return self.handshake_result_mapping[result_str]
        else:
            # Assign a new enum value dynamically
            new_enum = len(self.handshake_result_mapping)
            self.handshake_result_mapping[result_str] = new_enum
            return new_enum