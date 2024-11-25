# main.py

import argparse
import logging
import socket
import csv
from datetime import datetime, timezone
from urllib.parse import urlparse
from time import time
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys

from modules.config import DATABASE_FOLDER, LOG_FOLDER
import modules.config  # Import config to modify ENABLE_METHOD_CHECK
from modules.database import (
    setup_environment, connect_database, create_database, db_lock
)
from modules.utils import log_exception

# Suppress UTC zone warnings
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


def is_port_open(domain: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a specific port is open for a given domain."""
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            return True
    except:
        return False


def scan_domain(domain_name: str, conn):
    """Scan a single domain using HTTPScanner and TLSScanner."""
    from modules.scanning.http_scanner import HTTPScanner
    from modules.scanning.tls_scanner import TLSScanner

    try:
        scan_date = datetime.now(timezone.utc)

        # Check if ports 443 and 80 are open
        https_open = is_port_open(domain_name, 443)
        http_open = is_port_open(domain_name, 80)

        if not https_open and not http_open:
            # Record domains with closed ports
            with db_lock:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO domains (
                        domain_name, scan_date, port_443_open, port_80_open
                    )
                    VALUES (?, ?, ?, ?)
                """, (domain_name, scan_date, https_open, http_open))
                conn.commit()
            logging.info(f"Ports 443 and 80 are closed for {domain_name}, skipping scan.")
            return

        if http_open and not https_open:
            # Record domain and perform only HTTP scan
            with db_lock:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO domains (
                        domain_name, scan_date, port_443_open, port_80_open
                    )
                    VALUES (?, ?, ?, ?)
                """, (domain_name, scan_date, https_open, http_open))
                domain_id = cursor.lastrowid

            # Instantiate and run HTTP scanner
            http_scanner = HTTPScanner(domain_name, domain_id, conn)
            http_scanner.scan()

            logging.info(f"Only port 80 is open for {domain_name}, HTTP scan completed.")
            return

        # If port 443 is open (regardless of port 80)
        with db_lock:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO domains (
                    domain_name, scan_date, port_443_open, port_80_open
                )
                VALUES (?, ?, ?, ?)
            """, (domain_name, scan_date, https_open, http_open))
            domain_id = cursor.lastrowid

        # Instantiate and run HTTP scanner
        http_scanner = HTTPScanner(domain_name, domain_id, conn)
        http_scanner.scan()

        # Instantiate and run TLS scanner
        tls_scanner = TLSScanner(domain_name, domain_id, conn)
        tls_scanner.scan()

        logging.info(f"Scan successful for {domain_name}, results stored.")

    except Exception as e:
        log_exception(e, domain_name)


def is_valid_domain(domain: str) -> bool:
    """Simple regex validation for domain names."""
    import re
    regex = r'^(?:[a-zA-Z0-9]' \
            r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' \
            r'[a-zA-Z]{2,6}$'
    return re.match(regex, domain) is not None


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Domain security scanning tool")
    parser.add_argument('-i', '--input', required=True,
                        help='Path to the input CSV file containing domains to scan')
    parser.add_argument('-o', '--output', default='out.db',
                        help='Path to the output SQLite database file (default: out.db)')
    parser.add_argument('-t', '--threads', type=int, default=48,
                        help='Number of threads to use (default: 48)')
    parser.add_argument('--log', action='store_true',
                        help='Enable logging to file')
    parser.add_argument('--method-check', action='store_true',
                        help='Enable HTTP method checking (default: disabled)')
    parser.add_argument('--parts', type=int, default=1,
                        help='Number of parts to divide the input file into (default: 1)')
    parser.add_argument('--part', type=int, default=0,
                        help='Which part to scan (0-indexed, default: 0)')
    args = parser.parse_args()
    return args


def main():
    try:
        args = parse_arguments()
    except Exception as e:
        print(f"Error parsing arguments: {e}", file=sys.stderr)
        sys.exit(1)

    csv_filename = args.input
    database_path = args.output
    max_workers = args.threads
    enable_logging = args.log

    # Set ENABLE_METHOD_CHECK based on command-line argument
    modules.config.ENABLE_METHOD_CHECK = args.method_check

    # Initialize environment
    setup_environment(DATABASE_FOLDER, LOG_FOLDER)

    if enable_logging:
        # Set up logging
        from logging.handlers import RotatingFileHandler
        LOG_PATH = os.path.join(LOG_FOLDER, "scan_log.log")
        handler = RotatingFileHandler(LOG_PATH, maxBytes=10**7, backupCount=5)
        logging.basicConfig(
            handlers=[handler],
            level=logging.DEBUG,  # Set to DEBUG to log all levels
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
    else:
        # Disable logging
        logging.basicConfig(
            level=logging.CRITICAL  # Only log CRITICAL level
        )

    # Connect to database
    try:
        conn = connect_database(database_path)
    except Exception as e:
        print(f"Unable to connect to database: {e}", file=sys.stderr)
        logging.critical(f"Unable to connect to database: {e}")
        return

    # Create database tables (if not exist)
    try:
        create_database(conn)
    except Exception as e:
        print(f"Unable to create database tables: {e}", file=sys.stderr)
        logging.critical(f"Unable to create database tables: {e}")
        conn.close()
        return

    # Read CSV file
    # main.py

    try:
        with open(csv_filename, "r", newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            domain_names = []
            for row in reader:
                origin = row.get("origin", "").strip()
                if not origin:
                    continue
                if not origin.startswith(('http://', 'https://')):
                    origin = 'https://' + origin
                domain = urlparse(origin).netloc
                if is_valid_domain(domain):
                    domain_names.append(domain)
            total_domains = len(domain_names)
    except FileNotFoundError: 
        print(f"CSV file {csv_filename} not found.", file=sys.stderr)
        logging.critical(f"CSV file {csv_filename} not found.")
        conn.close()
        return
    except Exception as e:
        print(f"Error reading CSV file: {e}", file=sys.stderr)
        log_exception(e)
        conn.close()
        return

    # Divide the domain list into parts and select the specified part
    parts = args.parts
    part = args.part
    if parts > 1:
        chunk_size = (total_domains + parts - 1) // parts
        domain_names = domain_names[part * chunk_size:(part + 1) * chunk_size]
        total_domains = len(domain_names)

    start_time = time()
    completed_domains = 0

    # Define thread pool size based on the nature of the task (IO intensive)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_domain, domain_name, conn)
            for domain_name in domain_names
        ]

        with tqdm(total=total_domains, desc="Scanning: ") as pbar:
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error scanning domain: {str(e)}")

                # Update progress bar
                pbar.update(1)
                completed_domains += 1

                # Calculate time statistics
                elapsed_time = time() - start_time
                avg_time_per_domain = (elapsed_time / completed_domains
                                       if completed_domains else 0)
                remaining_domains = total_domains - completed_domains
                estimated_time_remaining = avg_time_per_domain * remaining_domains

                # Display additional information on the progress bar
                pbar.set_postfix({
                    "Elapsed": str(
                        datetime.fromtimestamp(elapsed_time, tz=timezone.utc).strftime("%H:%M:%S")
                    ),
                    "Avg s/it": f"{avg_time_per_domain:.2f}s",
                    "ETA": str(
                        datetime.fromtimestamp(estimated_time_remaining, tz=timezone.utc).strftime(
                            "%H:%M:%S"
                        )
                    )
                })

    conn.close()
    logging.info("All scans completed.")


if __name__ == "__main__":
    main()