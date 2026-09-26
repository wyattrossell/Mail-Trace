"""Third-party reputation providers. All are optional and need an API key.

Every provider here only *reads* verdicts about indicators that already
exist in the message. Nothing is submitted for scanning and no file content
ever leaves the machine: attachments are looked up by hash only.
"""

from mailtrace_core.enrichment.reputation.abuseipdb import check_ip as abuseipdb_ip
from mailtrace_core.enrichment.reputation.safebrowsing import check_urls as safebrowsing_urls
from mailtrace_core.enrichment.reputation.urlhaus import (
    check_hash as urlhaus_hash,
)
from mailtrace_core.enrichment.reputation.urlhaus import (
    check_host as urlhaus_host,
)
from mailtrace_core.enrichment.reputation.urlhaus import (
    check_url as urlhaus_url,
)
from mailtrace_core.enrichment.reputation.virustotal import (
    check_domain as vt_domain,
)
from mailtrace_core.enrichment.reputation.virustotal import (
    check_hash as vt_hash,
)
from mailtrace_core.enrichment.reputation.virustotal import (
    check_ip as vt_ip,
)
from mailtrace_core.enrichment.reputation.virustotal import (
    check_url as vt_url,
)

__all__ = [
    "abuseipdb_ip",
    "safebrowsing_urls",
    "urlhaus_hash",
    "urlhaus_host",
    "urlhaus_url",
    "vt_domain",
    "vt_hash",
    "vt_ip",
    "vt_url",
]
