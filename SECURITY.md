# Security Policy

This repository contains cryptographic code intended to protect *application-layer privacy* between a client and a gateway.

## Reporting a vulnerability

If you believe you have found a security vulnerability, please do **not** open a public GitHub issue.

Instead, email: **security@your-domain.example** (replace with your real address) with:
- a clear description of the issue
- impact assessment (what an attacker can do)
- steps to reproduce
- any suggested fixes

We will acknowledge receipt and work with you to coordinate a responsible disclosure.

## Scope notes

- This SDK does **not** prevent the upstream model provider from correlating requests based on prompt content, timing, or other side channels.
- Always treat secrets in prompts as sensitive. Prefer keeping long-term memory local and sending only minimized context.
