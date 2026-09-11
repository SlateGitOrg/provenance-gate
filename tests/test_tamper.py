"""Every tamper class must be rejected WITH THE CORRECT REASON.

Asserting only that verification failed is a weak test: a verifier that
rejects everything passes it, and so does one that rejects the right things
for the wrong reasons. Naming the expected reason is what makes this suite
evidence rather than reassurance.
"""

from __future__ import annotations

import copy
import dataclasses
import unittest

from src.attest import (
    BuildDefinition, Policy, Provenance, RunDetails, Subject, TrustRoot,
    Verifier, digest_bytes,
)
from src.rebuild import Builder, compare, normalise

GOOD_KEY = b"builder-key-0123456789abcdef"
EVIL_KEY = b"attacker-key-fedcba9876543210"

ARTIFACT = b"ARTIFACT_V1\nBUILD_TIMESTAMP=1700000000\nBUILD_HOST=ci-1\nCODE=abc\n"


def make_provenance(artifact: bytes = ARTIFACT, **overrides) -> Provenance:
    p = Provenance(
        subject=Subject(name="firmware.bin", sha256=digest_bytes(artifact)),
        build_definition=BuildDefinition(
            build_type="https://slsa.dev/container-based-build/v1",
            source_repo="git+https://github.com/acme/firmware",
            source_ref="refs/tags/v2.4.1",
            source_digest="a" * 40,
            entry_point="make release",
        ),
        run_details=RunDetails(
            builder_id="https://ci.acme.internal/builders/hardened-1",
            slsa_level=3,
            invocation_id="run-1001",
            started_at="2026-03-01T10:00:00Z",
            finished_at="2026-03-01T10:07:13Z",
        ),
    )
    for key, value in overrides.items():
        if key in {"subject", "build_definition", "run_details"}:
            p = dataclasses.replace(p, **{key: value})
    return p


def make_setup() -> tuple[TrustRoot, Verifier]:
    root = TrustRoot()
    root.add_key("builder-1", GOOD_KEY)
    policy = Policy(
        allowed_builders={"https://ci.acme.internal/builders/hardened-1"},
        allowed_sources={"git+https://github.com/acme/firmware"},
        min_slsa_level=3,
    )
    return root, Verifier(root, policy)


class TestHappyPath(unittest.TestCase):
    def test_a_genuine_attestation_verifies(self):
        root, verifier = make_setup()
        att = root.sign(make_provenance(), "builder-1")
        verdict = verifier.verify(ARTIFACT, att)
        self.assertTrue(verdict.ok, verdict.explanation)

    def test_a_gate_that_rejects_everything_would_fail_this(self):
        # Without this, all seven rejection tests below could pass on a
        # verifier whose implementation is `return False`.
        root, verifier = make_setup()
        for i in range(5):
            prov = dataclasses.replace(
                make_provenance(),
                run_details=dataclasses.replace(
                    make_provenance().run_details, invocation_id=f"run-{2000 + i}"
                ),
            )
            att = root.sign(prov, "builder-1")
            self.assertTrue(verifier.verify(ARTIFACT, att).ok)


class TestTamperClasses(unittest.TestCase):
    """The seven documented tamper classes."""

    def test_1_swapped_digest(self):
        """The attacker swaps the binary but keeps a valid attestation."""
        root, verifier = make_setup()
        att = root.sign(make_provenance(), "builder-1")
        evil = ARTIFACT.replace(b"CODE=abc", b"CODE=evil")
        verdict = verifier.verify(evil, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "DIGEST_MISMATCH")

    def test_2_forged_builder_identity(self):
        """Signed with a key we do not trust."""
        root, verifier = make_setup()
        rogue = TrustRoot()
        rogue.add_key("builder-1", EVIL_KEY)
        att = rogue.sign(make_provenance(), "builder-1")
        verdict = verifier.verify(ARTIFACT, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "BAD_SIGNATURE")

    def test_3_unknown_key(self):
        root, verifier = make_setup()
        other = TrustRoot()
        other.add_key("builder-99", EVIL_KEY)
        att = other.sign(make_provenance(), "builder-99")
        verdict = verifier.verify(ARTIFACT, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "UNKNOWN_KEY")

    def test_4_altered_source_ref(self):
        """Built from a fork, or from an unreviewed branch."""
        root, verifier = make_setup()
        prov = make_provenance()
        prov = dataclasses.replace(
            prov,
            build_definition=dataclasses.replace(
                prov.build_definition,
                source_repo="git+https://github.com/attacker/firmware",
            ),
        )
        att = root.sign(prov, "builder-1")
        verdict = verifier.verify(ARTIFACT, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "WRONG_SOURCE")

    def test_5_unapproved_builder(self):
        """A correctly signed attestation from a developer laptop."""
        root, verifier = make_setup()
        prov = make_provenance()
        prov = dataclasses.replace(
            prov,
            run_details=dataclasses.replace(
                prov.run_details, builder_id="https://laptop.local/make"
            ),
        )
        att = root.sign(prov, "builder-1")
        verdict = verifier.verify(ARTIFACT, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "WRONG_BUILDER")

    def test_6_downgraded_slsa_level(self):
        root, verifier = make_setup()
        prov = make_provenance()
        prov = dataclasses.replace(
            prov,
            run_details=dataclasses.replace(prov.run_details, slsa_level=1),
        )
        att = root.sign(prov, "builder-1")
        verdict = verifier.verify(ARTIFACT, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "SLSA_TOO_LOW")

    def test_7_replayed_attestation(self):
        """A genuine, valid attestation re-presented to smuggle an old build.

        The signature is perfectly good. Signature checking alone cannot
        catch this, which is why the verifier tracks invocation ids.
        """
        root, verifier = make_setup()
        att = root.sign(make_provenance(), "builder-1")
        self.assertTrue(verifier.verify(ARTIFACT, att).ok)
        verdict = verifier.verify(ARTIFACT, att)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "REPLAYED")

    def test_8_missing_attestation(self):
        _, verifier = make_setup()
        verdict = verifier.verify(ARTIFACT, None)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "MISSING_ATTESTATION")

    def test_every_rejection_explains_itself(self):
        _, verifier = make_setup()
        verdict = verifier.verify(ARTIFACT, None)
        self.assertIn("no provenance", verdict.explanation)


class TestSignatureHandling(unittest.TestCase):
    def test_payload_serialisation_is_canonical(self):
        a = make_provenance()
        b = copy.deepcopy(a)
        self.assertEqual(a.to_payload(), b.to_payload())

    def test_any_field_change_changes_the_payload(self):
        a = make_provenance()
        b = dataclasses.replace(
            a, run_details=dataclasses.replace(a.run_details, invocation_id="run-2")
        )
        self.assertNotEqual(a.to_payload(), b.to_payload())

    def test_malformed_signature_is_rejected_not_crashed(self):
        root, verifier = make_setup()
        att = root.sign(make_provenance(), "builder-1")
        broken = dataclasses.replace(att, signature="!!!not base64!!!")
        verdict = verifier.verify(ARTIFACT, broken)
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.reason, "BAD_SIGNATURE")


class TestReproducibility(unittest.TestCase):
    SOURCE = b"int main(void) { return 0; }"

    def test_two_builds_on_different_hosts_normalise_to_identical(self):
        a = Builder("ci-runner-1", 1_700_000_000, "/home/runner/work").build(self.SOURCE)
        b = Builder("ci-runner-9", 1_700_009_999, "/home/other/work").build(self.SOURCE)
        self.assertNotEqual(a, b, "the raw bytes should differ - that is the problem")
        result = compare(a, b)
        self.assertTrue(result.reproducible, "normalisation should reconcile these")
        self.assertIn("build timestamp", result.applied)
        self.assertIn("build host", result.applied)

    def test_a_GENUINELY_different_build_is_NOT_reported_reproducible(self):
        # The failure that makes over-eager normalisation dangerous.
        a = Builder("ci-1", 1_700_000_000, "/home/runner/work").build(self.SOURCE)
        b = Builder("ci-2", 1_700_000_001, "/home/runner/work").build(
            self.SOURCE, inject=b"BACKDOOR\n"
        )
        result = compare(a, b)
        self.assertFalse(result.reproducible)
        self.assertIsNotNone(result.first_difference)

    def test_different_source_produces_a_different_artifact(self):
        builder = Builder("ci-1", 1_700_000_000, "/home/runner/work")
        a = builder.build(self.SOURCE)
        b = builder.build(self.SOURCE + b" // comment")
        self.assertFalse(compare(a, b).reproducible)

    def test_normalisation_reports_what_it_forgave(self):
        a = Builder("ci-1", 1_700_000_000, "/home/runner/work").build(self.SOURCE)
        result = compare(a, a)
        self.assertTrue(result.reproducible)
        self.assertIn("build timestamp", result.applied)

    def test_normalise_is_idempotent(self):
        data = Builder("ci-1", 1_700_000_000, "/home/a/work").build(self.SOURCE)
        once = normalise(data)
        self.assertEqual(once, normalise(once))


if __name__ == "__main__":
    unittest.main()
