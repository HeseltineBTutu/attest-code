"""External integrations with code generators and model providers.

Each subpackage is an isolated boundary: it may consume verifier output
(such as a JSON report) but must never influence verdicts, approvals,
evidence, or the invariant registry. A generator cannot be a verifier.
"""
