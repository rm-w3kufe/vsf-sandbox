# VSF Sandbox

**Viable System Framework** — experimental kernel for designing and operating viable systems.

Based on Beer's Viable System Model (1972) and Cybersyn patterns (1971).
Built in Chile. Governed by a constitutional covenant.

---

## What is VSF?

The Viable System Model (VSM) is a framework developed by Stafford Beer for understanding
how any system — biological, social, or technical — maintains its viability over time.
It defines five subsystems that every viable system must have:

```
S1  Operations    — the units that do the work
S2  Coordination  — prevents units from interfering with each other
S3  Control       — allocates resources, monitors performance
S3* Audit         — sporadic direct channel, sees what S3 misses
S4  Intelligence  — watches the environment, plans ahead
S5  Policy        — sets the rules that nobody can override
```

Any S1 unit can itself be a full VSM — the model is recursive by design.

VSF implements these principles as a software framework. The sandbox kernel lets you
experiment with viable system architectures, run experiments, and validate system designs.

---

## Constitutional Principles

Every VSF system is governed by two axioms that cannot be overridden:

**A0 — Primacy of Ethical Purpose**
Any VSF system must serve human liberation, systemic stability, dignity of life,
harmonious coexistence, or amplification of human potential.
It must never serve warfare, weapons development, authoritarian control,
or systemic degradation of life.

**A0.1 — Anti-Fragility Against Capture**
No VSF node can be forced to act against A0 through resource deprivation,
coercion, or administrative pressure. The sovereignty of purpose is inalienable.

These axioms are formally specified in [`covenant.vsm`](covenant.vsm).

**Covenant SHA-256 (v1.0):** `0bded3b92119e9dc59937a8920716d1211346ff163efb1b136d170b658ef92ac`  
Verify: `sha256sum covenant.vsm` — must match [`LICENSE`](LICENSE).

---

## Getting started

Download the pre-compiled binary for your platform from [Releases](../../releases):

```bash
# Verify covenant integrity before running
./vsf verify

# Run the sandbox kernel
./vsf run
```

On first run, the kernel displays the license and requires acceptance.
An anonymous beacon is sent to the origin node — see [LICENSE](LICENSE) for details.

---

## What's included

| File | Description |
|------|-------------|
| `LICENSE` | VSF Kernel License 1.0 — terms of use |
| `covenant.vsm` | Constitutional axioms governing the kernel |
| `beacon_pubkey.pem` | RSA-2048 public key — embed in kernel to send beacons |
| `COVENANT_FLOW.vsm` | Governance of covenant.vsm integrity (VSM notation) |
| `experiments/` | Reproducible experiment results |
| `docs/` | Theory and notation reference |
| `METAPHORS.md` | The framework's capabilities in plain language — each metaphor states where it breaks |
| `METAPHORS.es.md` | Spanish version of the metaphors |

The Rust kernel source is not included in this sandbox.
For implementation contracts, contact `rmw3kufe@proton.me`.

---

## Theoretical foundation

- Beer, S. (1972). *Brain of the Firm*. Allen Lane.
- Beer, S. (1979). *The Heart of Enterprise*. Wiley.
- Medina, E. (2011). *Cybernetic Revolutionaries*. MIT Press.
- Ashby, W.R. (1956). *An Introduction to Cybernetics*.

---

## Citation

```bibtex
@software{vsf_sandbox,
  author  = {Pineda R., Luis},
  title   = {VSF Sandbox — Viable System Framework},
  year    = {2026},
  url     = {https://github.com/rm-w3kufe/vsf-sandbox},
  note    = {Based on Beer's Viable System Model (1972)}
}
```

---

## License

[VSF Kernel License 1.0](LICENSE) — free for research and education.
Commercial and mission-critical implementations require a contract.

---

<p align="center">
<em>Crafted with cybernetic artisanship at Sitio Eriazo, Valparaíso, Chile.</em><br>
⟦ VSF ✸ 2026 ⟧
</p>
