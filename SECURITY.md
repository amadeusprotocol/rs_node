# Security Policy

Security is non‑negotiable. If you believe you have found a vulnerability,
please follow this policy so we can fix it quickly and responsibly.

## Reporting a Vulnerability

- **Private, responsible disclosure only. Do not file public issues.**
- Email: **valy@ama.one**, or open a **GitHub Security Advisory** (private).

Include:

- A concise description and impact.
- Steps to reproduce (PoC), affected versions/commits.
- Any known mitigations or workarounds.

We aim to acknowledge and triage within a **few business days**.

## Supported Versions

- `main` branch has the latest patches.

## Severity & Target Timelines (max)

- **Critical** (RCE, key exfiltration, consensus break): fix/mitigate ASAP;
  coordinated disclosure **≤ 14 days**.
- **High** (priv-esc, DoS of default node, chain reorg vector): **≤ 30 days**.
- **Medium/Low** (info leak, minor DoS, hard‑to‑exploit): **≤ 90 days**.

If exploitation is observed in the wild, we may accelerate disclosure.

## Coordination & Disclosure

- We will coordinate a disclosure date with you once a fix or mitigation is
  ready.
- We may issue **security releases** and backports, and publish release notes
  and CVE(s) if appropriate.
- Credit is given by default (Hall of Fame) unless you request anonymity.

## Out of Scope (examples)

- Vulnerabilities in non‑supported dependencies without a demonstrated project
  impact.
- Issues requiring unrealistic permissions or non‑default configurations.
- Social engineering, physical attacks, or lost/stolen device scenarios.
- Best‑practice requests without a concrete vulnerability.

## Safe Harbor

We will not pursue or support legal action for good‑faith, non‑disruptive
research that respects this policy and applicable law.

Thank you for helping to keep **Amadeus Blockchain** and its users safe.
