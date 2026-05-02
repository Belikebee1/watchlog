"""Check implementations.

Importing this package registers all checks via the @register_check decorator.
"""

# Import each check module to trigger registration.
from watchlog.checks import (  # noqa: F401
    apt_updates,
    disk_space,
    dns_records,
    docker_images,
    ip_blacklist,
    memory,
    services,
    ssh_brute,
    ssl_certs,
)
