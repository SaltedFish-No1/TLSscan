# modules/client_config.py

from dataclasses import dataclass
from typing import List

@dataclass
class ClientConfig:
    name: str
    version: str
    platform: str
    tls_versions: List[str]  # 支持的TLS版本列表
    cipher_suites: List[str]  # 支持的加密套件列表


# 定义多个客户端配置
CLIENT_CONFIGS = [
    # Desktop browsers
    ClientConfig(
        name="Firefox",
        version="68",
        platform="Windows 11",
        tls_versions=["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        cipher_suites=[
            'ECDHE-ECDSA-AES-128-GCM-SHA256',
            'ECDHE-RSA-AES-128-GCM-SHA256',
            'ECDHE-ECDSA-AES-256-GCM-SHA384',
            'ECDHE-RSA-AES-256-GCM-SHA384',
            'DHE-RSA-AES-128-GCM-SHA256',
            'DHE-RSA-AES-256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305-SHA256',
            'ECDHE-RSA-CHACHA20-POLY1305-SHA256',
        ]
    ),
    ClientConfig(
        name="Chrome",
        version="76",
        platform="Windows 10",
        tls_versions=["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        cipher_suites=[
            'ECDHE-ECDSA-AES-128-GCM-SHA256',
            'ECDHE-RSA-AES-128-GCM-SHA256',
            'ECDHE-ECDSA-AES-256-GCM-SHA384',
            'ECDHE-RSA-AES-256-GCM-SHA384',
            'DHE-RSA-AES-128-GCM-SHA256',
            'DHE-RSA-AES-256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305-SHA256',
            'ECDHE-RSA-CHACHA20-POLY1305-SHA256',
        ]
    ),
    ClientConfig(
        name="Internet Explorer",
        version="11",
        platform="Windows 7",
        tls_versions=["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        cipher_suites=[
            'RSA-AES-128-CBC-SHA',
            'RSA-AES-256-CBC-SHA',
            'ECDHE-RSA-AES-128-CBC-SHA',
            'ECDHE-RSA-AES-256-CBC-SHA',
        ]
    ),
    ClientConfig(
        name="Safari",
        version="12",
        platform="macOS 10.14",
        tls_versions=["TLSv1.2"],
        cipher_suites=[
            'ECDHE-ECDSA-AES-128-GCM-SHA256',
            'ECDHE-RSA-AES-128-GCM-SHA256',
            'ECDHE-ECDSA-AES-256-GCM-SHA384',
            'ECDHE-RSA-AES-256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305-SHA256',
            'ECDHE-RSA-CHACHA20-POLY1305-SHA256',
        ]
    ),
    ClientConfig(
        name="Edge",
        version="18",
        platform="Windows 10",
        tls_versions=["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
        cipher_suites=[
            'AES-128-GCM-SHA256',
            'AES-256-GCM-SHA384',
            'CHACHA20-POLY1305-SHA256',
            'ECDHE-ECDSA-AES-128-GCM-SHA256',
            'ECDHE-RSA-AES-128-GCM-SHA256',
            'ECDHE-ECDSA-AES-256-GCM-SHA384',
            'ECDHE-RSA-AES-256-GCM-SHA384',
        ]
    ),
    ClientConfig(
        name="Android Browser",
        version="9",
        platform="Android 9",
        tls_versions=["TLSv1.2", "TLSv1.3"],
        cipher_suites=[
            'AES-128-GCM-SHA256',
            'AES-256-GCM-SHA384',
            'CHACHA20-POLY1305-SHA256',
            'ECDHE-ECDSA-AES-128-GCM-SHA256',
            'ECDHE-RSA-AES-128-GCM-SHA256',
            'ECDHE-ECDSA-AES-256-GCM-SHA384',
            'ECDHE-RSA-AES-256-GCM-SHA384',
        ]
    ),
    ClientConfig(
        name="iOS Safari",
        version="12",
        platform="iOS 12",
        tls_versions=["TLSv1.2", "TLSv1.3"],
        cipher_suites=[
            'AES-128-GCM-SHA256',
            'AES-256-GCM-SHA384',
            'CHACHA20-POLY1305-SHA256',
            'ECDHE-ECDSA-AES-128-GCM-SHA256',
            'ECDHE-RSA-AES-128-GCM-SHA256',
            'ECDHE-ECDSA-AES-256-GCM-SHA384',
            'ECDHE-RSA-AES-256-GCM-SHA384',
        ]
    ),
]