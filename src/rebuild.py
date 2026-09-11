"""Reproducible rebuild, and the normalisation that makes it usable.

Verification proves an attestation is authentic. It cannot prove the
attestation is TRUE, because a compromised builder signs whatever it likes with
a perfectly good key. Rebuilding independently and comparing is the only step
that closes that gap - which is why the gate does not stop at signature checks.

The hard part is not rebuilding. It is that almost every real build embeds
incidental nondeterminism - timestamps, absolute paths, archive ordering, the
build host name - so a naive byte comparison reports "not reproducible" every
single time and the check is abandoned within a week. Normalisation is what
makes the result mean something, and every rule here is a deliberate,
documented decision about what is *incidental* rather than *semantic*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .attest import digest_bytes

# Each pattern replaces an incidental value with a stable placeholder.
# Anything not listed is treated as semantic and WILL cause a mismatch. That
# default matters: a normaliser that strips too much reports success on a
# genuinely different binary, which is worse than no check at all.
NORMALISERS: list[tuple[str, re.Pattern[bytes], bytes]] = [
    ("build timestamp", re.compile(rb"BUILD_TIMESTAMP=\d+"), b"BUILD_TIMESTAMP=0"),
    ("build host", re.compile(rb"BUILD_HOST=[\w.-]+"), b"BUILD_HOST=normalised"),
    ("absolute source path", re.compile(rb"/home/[\w./-]+/src"), b"/src"),
    ("archive mtime", re.compile(rb"MTIME=\d{10}"), b"MTIME=0000000000"),
]


def normalise(data: bytes) -> bytes:
    for _, pattern, replacement in NORMALISERS:
        data = pattern.sub(replacement, data)
    return data


@dataclass(frozen=True)
class RebuildResult:
    reproducible: bool
    original_digest: str
    rebuilt_digest: str
    normalised_digest: str
    # Which normalisers actually fired. Reported so a reviewer can see what was
    # forgiven, rather than trusting that the comparison was strict.
    applied: tuple[str, ...]
    first_difference: int | None


def compare(original: bytes, rebuilt: bytes) -> RebuildResult:
    applied = tuple(
        name for name, pattern, _ in NORMALISERS
        if pattern.search(original) or pattern.search(rebuilt)
    )
    n_orig = normalise(original)
    n_rebuilt = normalise(rebuilt)

    first_diff: int | None = None
    if n_orig != n_rebuilt:
        limit = min(len(n_orig), len(n_rebuilt))
        first_diff = limit
        for i in range(limit):
            if n_orig[i] != n_rebuilt[i]:
                first_diff = i
                break

    return RebuildResult(
        reproducible=n_orig == n_rebuilt,
        original_digest=digest_bytes(original),
        rebuilt_digest=digest_bytes(rebuilt),
        normalised_digest=digest_bytes(n_orig),
        applied=applied,
        first_difference=first_diff,
    )


class Builder:
    """A deterministic toy builder, so the lab has something real to rebuild.

    Given source bytes it emits an 'artifact'. Two builds of identical source
    differ only in the incidental fields the normaliser knows about - which is
    exactly the situation a real reproducible-builds effort is trying to reach.
    """

    def __init__(self, host: str, timestamp: int, workdir: str) -> None:
        self.host = host
        self.timestamp = timestamp
        self.workdir = workdir

    def build(self, source: bytes, *, inject: bytes = b"") -> bytes:
        body = digest_bytes(source).encode()
        return (
            b"ARTIFACT_V1\n"
            + b"BUILD_TIMESTAMP=" + str(self.timestamp).encode() + b"\n"
            + b"BUILD_HOST=" + self.host.encode() + b"\n"
            + b"SOURCE_PATH=" + self.workdir.encode() + b"/src\n"
            + b"CODE=" + body + b"\n"
            + inject
        )
