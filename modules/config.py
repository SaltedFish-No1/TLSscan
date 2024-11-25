# modules/config.py

import os

# Define folder paths
DATABASE_FOLDER = "data"
LOG_FOLDER = "logs"
DATABASE_PATH = os.path.join(DATABASE_FOLDER, "scan_results.db")
LOG_PATH = os.path.join(LOG_FOLDER, "scan_log.log")
# Enable or disable method checking
ENABLE_METHOD_CHECK = False  # Set to False to disable method checking and rely solely on OPTIONS







class HTTPnHHTPs:
    # Comprehensive list of security-related HTTP headers
    SECURITY_HEADERS = [
        # Recommended headers for modern security practices
        'Content-Security-Policy',  # 防止 XSS 和其他代码注入攻击
        'Strict-Transport-Security',  # 强制 HTTPS 连接，防止中间人攻击
        'X-Content-Type-Options',  # 防止 MIME 类型嗅探
        'X-Frame-Options',  # 防止点击劫持攻击
        'Referrer-Policy',  # 控制引用信息泄露
        'Permissions-Policy',  # 控制特定 API 和功能的访问（替代 Feature-Policy）
        'Clear-Site-Data',  # 用于在用户注销时清除浏览器存储的数据
        'Cross-Origin-Embedder-Policy',  # 防止跨域嵌入（COEP）
        'Cross-Origin-Opener-Policy',  # 提升窗口之间的隔离级别（COOP）
        'Cross-Origin-Resource-Policy',  # 限制跨域资源的加载（CORP）
        'Access-Control-Allow-Origin',  # CORS 配置，控制跨域资源共享
        'Access-Control-Allow-Methods',  # CORS 配置，允许的 HTTP 方法
        'Access-Control-Allow-Headers',  # CORS 配置，允许的请求头
        'Timing-Allow-Origin',  # 控制性能计时信息的跨域共享
        'Server-Timing',  # 显示服务器性能数据，但可能泄露信息

        # Deprecated or no longer recommended headers
        'X-XSS-Protection',  # 已弃用的头，用于早期的 XSS 防护
        'Expect-CT',  # 已弃用的头，用于证书透明度验证
        'Feature-Policy',  # 已被 Permissions-Policy 替代，但可能仍需兼容性
        'Public-Key-Pins'  # 已弃用，用于防止证书劫持攻击（HPKP）
    ]

    # HTTP methods confirmed to have known vulnerabilities
    UNSECURE_METHODS = [
        "TRACE",        # Vulnerable to cross-site tracing (XST) attacks, leading to sensitive information disclosure.
        "TRACK",        # Similar to TRACE, used for cross-site tracing attacks.
        "PUT",          # Allows file uploads; if misconfigured, it can be exploited to upload malicious files.
        "DELETE",       # Allows file deletions; abuse can result in data loss or disruption.
        "CONNECT",      # Can establish proxy tunnels, bypassing firewalls, and could enable access to internal systems.
        "PROPFIND",     # WebDAV method; exposes file properties on the server, potentially revealing sensitive information.
        "LOCK",         # WebDAV method; allows locking of resources, which could lead to denial-of-service (DoS) attacks.
        "UNLOCK",       # WebDAV method; can interfere with resource operations and data integrity.
        "ACL",          # WebDAV method; allows modification of access control lists (ACLs), potentially granting unauthorized access.
    ]

    # HTTP methods not recommended to enable on servers (potential risks but not confirmed vulnerabilities)
    NOT_RECOMMENDED_METHODS = [
        "OPTIONS",      # Reveals supported HTTP methods on the server, aiding reconnaissance.
        "PATCH",        # Used for partial updates; if misconfigured, could allow unauthorized modifications.
        "SEARCH",       # WebDAV method; allows server-side queries, potentially exposing sensitive data.
        "MKCOL",        # WebDAV method; creates collections (directories) on the server, potentially leading to resource abuse.
        "MOVE",         # WebDAV method; moves resources on the server, which could disrupt operations.
        "COPY",         # WebDAV method; copies resources, possibly duplicating sensitive data or consuming storage.
        "REPORT",       # WebDAV method; may expose sensitive information about resources.
    ]


    # Secure and recommended HTTP methods
    SECURE_METHODS = [
        "GET",          # Used to retrieve resources without causing any side effects on the server.
        "POST",         # Used to submit data to the server, often for creating or processing resources. Safe when used with proper validation and authentication.
        "PUT",          # Can be secure for resource updates when access control and validation are correctly implemented.
        "DELETE",       # Can be secure for resource deletion when access control is properly enforced.
        "OPTIONS",      # Provides a list of allowed methods; secure if it does not reveal sensitive information.
        "HEAD",         # Similar to GET but without a response body; secure if server metadata does not expose sensitive data.
    ]
    @staticmethod
    def is_secure(method):
        if method in HTTPnHHTPs.HttpMethods.SECURE_METHODS:
            return "Secure"
        elif method in HTTPnHHTPs.HttpMethods.NOT_RECOMMENDED_METHODS:
            return "Not Recommended"
        elif method in HTTPnHHTPs.HttpMethods.UNSECURE_METHODS:
            return "Unsecure"
        else:
            return "Unknown"

# Vulnerability types for database storage
VULNERABILITY_TYPES = [
]


# Source: https://ciphersuite.info/cs/?singlepage=true&page=8
class CipherSuites:
    # Deprecated elliptic curves
    SECURE_KEYS = [
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
    "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]

    RECOMMENDED_KEYS = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
    "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
]

    INSECURE_KEYS = [
    "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
    "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
    "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
    "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
    "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
    "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_DH_anon_WITH_DES_CBC_SHA",
    "TLS_DH_anon_WITH_RC4_128_MD5",
    "TLS_DH_anon_WITH_SEED_CBC_SHA",
    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DHE_PSK_WITH_NULL_SHA",
    "TLS_DHE_PSK_WITH_NULL_SHA256",
    "TLS_DHE_PSK_WITH_NULL_SHA384",
    "TLS_DHE_PSK_WITH_RC4_128_SHA",
    "TLS_DHE_RSA_WITH_NULL_SHA",
    "TLS_DHE_RSA_WITH_RC4_128_SHA",
    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DH_RSA_WITH_DES_CBC_SHA",
    "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
    "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
    "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
    "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    "TLS_KRB5_WITH_DES_CBC_MD5",
    "TLS_KRB5_WITH_DES_CBC_SHA",
    "TLS_KRB5_WITH_IDEA_CBC_MD5",
    "TLS_KRB5_WITH_RC4_128_MD5",
    "TLS_KRB5_WITH_RC4_128_SHA",
    "TLS_NULL_WITH_NULL_NULL",
    "TLS_PSK_WITH_NULL_SHA",
    "TLS_PSK_WITH_NULL_SHA256",
    "TLS_PSK_WITH_NULL_SHA384",
    "TLS_PSK_WITH_RC4_128_SHA",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_PSK_WITH_NULL_SHA",
    "TLS_RSA_PSK_WITH_NULL_SHA256",
    "TLS_RSA_PSK_WITH_NULL_SHA384",
    "TLS_RSA_PSK_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA",
]

    WEAK_KEYS = [
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
    "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
    "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
    "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
    "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
    "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_DH_DSS_WITH_DES_CBC_SHA",
    "TLS_DH_DSS_WITH_SEED_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
    "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
    "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_PSK_WITH_AES_128_CCM",
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    "TLS_DHE_PSK_WITH_AES_256_CCM",
    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
    "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
    "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
    "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
    "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CCM",
    "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CCM",
    "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
    "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
    "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
    "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
    "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
    "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
    "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
    "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    ]

    @staticmethod
    def is_cipher_secure( cipher_suite):
        if cipher_suite in CipherSuites.SECURE_KEYS:
            return "Secure"
        elif cipher_suite in CipherSuites.RECOMMENDED_KEYS:
            return "Recommended"
        elif cipher_suite in CipherSuites.INSECURE_KEYS:
            return "Insecure"
        elif cipher_suite in CipherSuites.WEAK_KEYS:
            return "Weak"
        else:
            return "Unknown"