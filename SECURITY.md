# Security

The `v0.1.0` release is available. Report suspected vulnerabilities through a
private security advisory in the repository's Security tab when available. If
that option is unavailable, contact the maintainer through the GitHub profile.
Do not post exploit details, private firmware, or secrets in a public issue.

Include the affected revision, platform, impact, and a minimal synthetic
reproducer where possible. A response time is not guaranteed.

Crucksware processes untrusted filesystem metadata and contents. Its initial
comparison design requires stable local input trees and does not claim atomic
snapshots or containment against concurrent hostile changes. It does not execute
input files and does not modify the compared trees.
