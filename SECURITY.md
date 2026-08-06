# Security Policy

## Supported version

Security and correctness fixes are applied to the latest released version,
currently `0.4.9`.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** flow in the repository Security
tab. Do not open a public issue for suspected credential exposure, path escape,
state-integrity bypass, Hook command injection, or completion-gate bypass.

Include the affected version, operating system, Codex version, reproduction
steps, and the smallest sanitized evidence needed to demonstrate the issue. Do
not attach raw prompts, transcripts, plugin-private state, credentials, or user
data.

## Security boundary

Context Guard is a local correctness sidecar, not a security sandbox. It cannot
make an untrusted Hook safe, prove semantic correctness, or replace operating
system access controls. Users must review and trust the exact Hook definition
before enabling it.
