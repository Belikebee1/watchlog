"""Reporter implementations.

Importing this package registers all reporters via the @register_reporter decorator.
"""

from watchlog.reporters import email as _email  # noqa: F401
from watchlog.reporters import json_file as _json  # noqa: F401
from watchlog.reporters import stdout as _stdout  # noqa: F401
