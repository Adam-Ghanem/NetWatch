# Dependency update review policy

Dependabot proposes weekly updates for root Python requirements (pip), GitHub
Actions, and Dockerfiles. Each ecosystem is limited to three open Dependabot PRs
to avoid overwhelming the existing review queue. Dependabot does not merge,
deploy, execute scans, or enable remediation.

The production and enterprise Dockerfiles pin the Docker Official Image for
Python 3.12 to a patch-level Debian Trixie slim tag and its immutable
multi-platform manifest digest. The digest is authoritative; the tag is kept
for readability and review. The pinned reference was checked against the
Docker Hub Official Image metadata on 2026-11-23:
https://hub.docker.com/layers/library/python/3.12-slim/images/sha256-6d7c62c5c41e16e6d49e2b7c189b7aac36f80d0f8789d97dd1d316e0173f1585

Dependabot's Docker ecosystem proposes weekly tag/digest updates for both
Dockerfiles. Review each update as a pair and require the Python and Security
CI workflows, including the production image build, before accepting it. Do
not update only the tag or only the digest. The digest pins the base image
manifest; it does not pin Debian packages installed by apt-get or Python
dependencies installed from requirements files, which retain their separate
audit and update controls.

Review every PR before merging: confirm the upstream changelog, compatibility,
security impact, pinned constraints and transitive dependency changes. Require
Python CI and Security CI on the proposed commit. For action updates, check
publisher provenance and the requested token permissions. Keep existing
authorization-first network scope and opt-in provider-cost boundaries.

Security advisories may require manual urgent review rather than waiting for
the weekly cadence. The config is proposal-only; GitHub must enable Dependabot
and permit PR creation for updates to appear. No updates are applied to main
without human review.
