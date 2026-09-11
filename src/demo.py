"""The 60-second artefact: eight tamper attempts, and a compromised builder.

Run: python -m src.demo
"""

from __future__ import annotations

import dataclasses

from .attest import (
    BuildDefinition, Policy, Provenance, RunDetails, Subject, TrustRoot,
    Verifier, digest_bytes,
)
from .rebuild import Builder, compare

SOURCE = b"int main(void) { return 0; }"
KEY = b"builder-key-0123456789abcdef"


def setup():
    root = TrustRoot()
    root.add_key("builder-1", KEY)
    policy = Policy(
        allowed_builders={"https://ci.acme.internal/builders/hardened-1"},
        allowed_sources={"git+https://github.com/acme/firmware"},
        min_slsa_level=3,
    )
    return root, Verifier(root, policy)


def provenance_for(artifact: bytes, invocation: str) -> Provenance:
    return Provenance(
        subject=Subject("firmware.bin", digest_bytes(artifact)),
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
            invocation_id=invocation,
            started_at="2026-03-01T10:00:00Z",
            finished_at="2026-03-01T10:07:13Z",
        ),
    )


def main() -> None:
    honest = Builder("ci-runner-1", 1_700_000_000, "/home/runner/work")
    artifact = honest.build(SOURCE)

    print("\n  PROVENANCE-GATE - an SBOM cannot answer this question")
    print("  " + "-" * 68)
    print("  Artifact: firmware.bin  sha256:" + digest_bytes(artifact)[:16])
    print()

    root, verifier = setup()
    good = root.sign(provenance_for(artifact, "run-1001"), "builder-1")
    v = verifier.verify(artifact, good)
    print(f"  genuine build                       -> {'ACCEPT' if v.ok else 'REJECT'}")

    cases = []

    evil_bytes = artifact.replace(b"CODE=", b"CODE=X")
    cases.append(("binary swapped, attestation kept", evil_bytes,
                  root.sign(provenance_for(artifact, "run-1002"), "builder-1")))

    rogue = TrustRoot(); rogue.add_key("builder-1", b"attacker-key-xxxxxxxxxxxxxxxx")
    cases.append(("signed with a stolen-looking key", artifact,
                  rogue.sign(provenance_for(artifact, "run-1003"), "builder-1")))

    p = provenance_for(artifact, "run-1004")
    cases.append(("built from an attacker fork", artifact, root.sign(
        dataclasses.replace(p, build_definition=dataclasses.replace(
            p.build_definition, source_repo="git+https://github.com/evil/firmware")),
        "builder-1")))

    p = provenance_for(artifact, "run-1005")
    cases.append(("built on a developer laptop", artifact, root.sign(
        dataclasses.replace(p, run_details=dataclasses.replace(
            p.run_details, builder_id="https://laptop.local/make")), "builder-1")))

    p = provenance_for(artifact, "run-1006")
    cases.append(("SLSA level downgraded to 1", artifact, root.sign(
        dataclasses.replace(p, run_details=dataclasses.replace(
            p.run_details, slsa_level=1)), "builder-1")))

    cases.append(("no attestation at all", artifact, None))
    cases.append(("replay of run-1001", artifact, good))

    for label, art, att in cases:
        verdict = verifier.verify(art, att)
        status = "ACCEPT" if verdict.ok else "REJECT"
        print(f"  {label:<35} -> {status}  {verdict.reason or ''}")

    print("\n  Every attestation below is CORRECTLY SIGNED by a trusted key.")
    print("  " + "-" * 68)
    print("  A compromised runner emits a valid attestation for a backdoored")
    print("  build. Signature checks pass. Policy checks pass. So does the SBOM.")

    compromised = Builder("ci-runner-1", 1_700_000_000, "/home/runner/work")
    backdoored = compromised.build(SOURCE, inject=b"BACKDOOR\n")
    att = root.sign(provenance_for(backdoored, "run-2001"), "builder-1")
    verdict = verifier.verify(backdoored, att)
    print(f"\n    signature + policy verification   -> "
          f"{'ACCEPT' if verdict.ok else 'REJECT'}")

    independent = Builder("audit-host-7", 1_700_055_555, "/home/auditor/work")
    rebuilt = independent.build(SOURCE)
    result = compare(backdoored, rebuilt)
    print(f"    independent rebuild + diff        -> "
          f"{'ACCEPT' if result.reproducible else 'REJECT'}  "
          f"{'' if result.reproducible else 'NOT_REPRODUCIBLE'}")
    print(f"    first difference at byte {result.first_difference}")
    print(f"    normalisers applied: {', '.join(result.applied)}")
    print("\n  That is the whole argument for rebuilding. Verification proves the")
    print("  attestation is authentic; only a rebuild proves it is true.\n")


if __name__ == "__main__":
    main()
