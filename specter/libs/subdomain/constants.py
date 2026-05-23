# this file contains all the constant values for subdomain


import ssl

CYAN = "cyan"
GREEN = "bright_green"
RED = "bright_red"
YELLOW = "yellow"
WHITE = "white"
DIM = "grey50"
DIMMER = "grey35"
DETAIL = "grey62"
BORDER = "grey23"
SVC_COL = "cyan"

CRTSH_URL = "https://crt.sh/?q=%25.{d}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={d}"
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{d}&size=200"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{d}?full=1"
SHODAN_DNS_URL = "https://api.shodan.io/dns/domain/{d}?key={k}"

WEB_PORTS = [80, 443, 8080, 8443, 8888, 3000, 5000, 4443]
HTTP_TO = 30.0
HTTP_W_MIN = 8
HTTP_W_MAX = 64
SCAN_TO = 1.0

DNS_PORT = 53
DNS_TO = 2.0
DNS_PKT_MAX = 2048
DNS_TRIES = 2
DNS_CNAME_MAX = 6
DNS_QTYPE_A = 1
DNS_QTYPE_CNAME = 5
DNS_QTYPE_AAAA = 28
DNS_IN = 1

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
    "webmail", "remote", "blog", "portal", "api", "dev", "staging",
    "test", "admin", "vpn", "m", "mobile", "app", "store", "forum",
    "support", "help", "cdn", "static", "media", "img", "images",
    "assets", "docs", "wiki", "git", "gitlab", "github", "jira",
    "confluence", "jenkins", "ci", "db", "mysql", "mongo", "redis",
    "elastic", "kibana", "grafana", "prometheus", "metrics", "status",
    "health", "monitor", "dashboard", "beta", "alpha", "old", "new",
    "v1", "v2", "v3", "prod", "uat", "qa", "sandbox", "demo",
    "preview", "internal", "intranet", "corp", "secure", "ssl", "web",
    "www2", "web2", "mx", "mx1", "mx2", "smtp2", "pop3", "imap",
    "exchange", "owa", "autodiscover", "proxy", "lb", "load", "gateway",
    "edge", "fw", "firewall", "server", "srv", "node", "cluster",
    "k8s", "kube", "docker", "aws", "gcp", "azure", "cloud", "s3",
    "bucket", "vault", "login", "auth", "sso", "oauth", "id", "account",
    "accounts", "billing", "pay", "payment", "shop", "checkout", "cart",
    "crm", "erp", "hr", "finance", "legal", "marketing", "search", "es",
    "solr", "data", "analytics", "upload", "download", "files", "backup",
    "archive", "news", "video", "live", "stream", "player", "ads", "promo",
]

