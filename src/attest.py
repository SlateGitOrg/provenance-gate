"""Build provenance: attestation model, signing, and verification.

THE DIFFERENTIATOR LIVES HERE.

An SBOM tells you what is *in* a build. It does not tell you whether the build
itself is trustworthy, and an attacker who owns your CI runner will emit an
artifact with a perfectly accurate SBOM. The question that attack defeats is a
different one: did this binary actually come from that source, built by that
builder?

So this module verifies in-toto/SLSA-style provenance - and then refuses to
stop there. Verification proves the attestation is *authentic and policy
compliant*; it cannot prove the attestation is *true*, because the thing that
produced it may itself have been compromised. Only an independent rebuild can
do that. `rebuild.py` closes the loop.

Signing here is HMAC-SHA256 with a local trust root, using only the standard
library. Production uses Sigstore with x509 identities; the verification
*shape* - authenticate, then check policy, then rebuild - is identical, and
that shape is the part worth defending in an interview.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from typing import Any

PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


@dataclass(frozen=True)
class Subject:
    """The artifact being attested to."""

    name: str
    sha256: str


@dataclass(frozen=True)
class BuildDefinition:
    build_type: str
    source_repo: str
    source_ref: str
    source_digest: str
    entry_point: str
    parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RunDetails:
    builder_id: str
    # SLSA build levels: 0 unprovenanced .. 3 hardened, isolated builder.
    slsa_level: int
    invocation_id: str
    started_at: str
    finished_at: str


@dataclass(frozen=True)
class Provenance:
    subject: Subject
    build_definition: BuildDefinition
    run_details: RunDetails
    predicate_type: str = PREDICATE_TYPE

    def to_payload(self) -> bytes:
        """Canonical serialisation.

        Sorted keys and no incidental whitespace: if the bytes that get signed
        are not reproducible from the object, a re-serialised attestation fails
        verification for no reason and people start disabling the check.
        """
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SignedAttestation:
    provenance: Provenance
    signature: str
    key_id: str


class TrustRoot:
    """An offline trust root: key id -> secret.

    Offline is deliberate. A verifier that must reach a network service to
    decide whether to trust a build cannot run in an air-gapped release
    pipeline, which is exactly where this class of control is mandated.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def add_key(self, key_id: str, secret: bytes) -> None:
        self._keys[key_id] = secret

    def sign(self, provenance: Provenance, key_id: str) -> SignedAttestation:
        secret = self._keys[key_id]
        sig = hmac.new(secret, provenance.to_payload(), hashlib.sha256).digest()
        return SignedAttestation(
            provenance=provenance,
            signature=base64.b64encode(sig).decode(),
            key_id=key_id,
        )

    def verify_signature(self, att: SignedAttestation) -> bool:
        secret = self._keys.get(att.key_id)
        if secret is None:
            return False
        expected = hmac.new(
            secret, att.provenance.to_payload(), hashlib.sha256
        ).digest()
        try:
            actual = base64.b64decode(att.signature)
        except Exception:
            return False
        # Constant-time: a timing-variable comparison on a signature is a real
        # (if slow) forgery oracle, and it costs nothing to do correctly.
        return hmac.compare_digest(expected, actual)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Verification outcomes. Every rejection names a specific, actionable reason;
# "verification failed" is not a reason anyone can act on.
# ---------------------------------------------------------------------------

REASONS = {
    "UNKNOWN_KEY": "attestation signed by a key that is not in the trust root",
    "BAD_SIGNATURE": "signature does not match the attestation payload",
    "DIGEST_MISMATCH": "attestation does not describe this artifact",
    "WRONG_BUILDER": "builder identity is not permitted by policy",
    "WRONG_SOURCE": "source repository is not permitted by policy",
    "SLSA_TOO_LOW": "build level is below the policy minimum",
    "REPLAYED": "invocation id has already been seen",
    "NOT_REPRODUCIBLE": "independent rebuild produced a different artifact",
    "MISSING_ATTESTATION": "no provenance was supplied for this artifact",
}


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str | None = None
    detail: str = ""

    @property
    def explanation(self) -> str:
        if self.ok:
            return "verified"
        return f"{self.reason}: {REASONS.get(self.reason or '', '?')} {self.detail}".strip()


class Policy:
    """Policy as data. In production this is Rego; the decisions are the same."""

    def __init__(
        self,
        allowed_builders: set[str],
        allowed_sources: set[str],
        min_slsa_level: int,
    ) -> None:
        self.allowed_builders = allowed_builders
        self.allowed_sources = allowed_sources
        self.min_slsa_level = min_slsa_level


class Verifier:
    def __init__(self, trust_root: TrustRoot, policy: Policy) -> None:
        self.trust_root = trust_root
        self.policy = policy
        self._seen_invocations: set[str] = set()

    def verify(
        self, artifact: bytes, att: SignedAttestation | None
    ) -> Verdict:
        # An artifact with no attestation is not "probably fine". It is the
        # exact state an attacker wants you to accept.
        if att is None:
            return Verdict(False, "MISSING_ATTESTATION")

        if att.key_id not in self.trust_root._keys:
            return Verdict(False, "UNKNOWN_KEY", f"key_id={att.key_id}")
        if not self.trust_root.verify_signature(att):
            return Verdict(False, "BAD_SIGNATURE")

        p = att.provenance
        actual = digest_bytes(artifact)
        if actual != p.subject.sha256:
            return Verdict(
                False, "DIGEST_MISMATCH",
                f"artifact={actual[:12]} attested={p.subject.sha256[:12]}",
            )

        if p.run_details.builder_id not in self.policy.allowed_builders:
            return Verdict(False, "WRONG_BUILDER", f"builder={p.run_details.builder_id}")
        if p.build_definition.source_repo not in self.policy.allowed_sources:
            return Verdict(False, "WRONG_SOURCE", f"repo={p.build_definition.source_repo}")
        if p.run_details.slsa_level < self.policy.min_slsa_level:
            return Verdict(
                False, "SLSA_TOO_LOW",
                f"level={p.run_details.slsa_level} < {self.policy.min_slsa_level}",
            )

        # Replay: a genuine, correctly signed attestation for an OLD build,
        # re-presented to smuggle a superseded (and perhaps vulnerable)
        # artifact past the gate. The signature is valid, so signature checking
        # alone cannot catch it.
        if p.run_details.invocation_id in self._seen_invocations:
            return Verdict(
                False, "REPLAYED", f"invocation={p.run_details.invocation_id}"
            )
        self._seen_invocations.add(p.run_details.invocation_id)

        return Verdict(True)
