"""interlock's own OSDP protocol layer.

This package is interlock speaking OSDP by itself: a byte-exact frame codec, a
stream framer, and the verified wire constants. It depends on nothing from
libosdp (the lab's in-container oracle) so it runs on the host interpreter and
can later emit malformed frames a conformant library would refuse to build.
"""

from __future__ import annotations
