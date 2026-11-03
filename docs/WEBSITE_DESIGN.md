# Product website design

The public landing page lives in `website/` and is deployed at the repository root by the
`Docs` GitHub Pages workflow. It is deliberately separate from the authenticated React security
console in `frontend/` and from the MkDocs documentation site in `docs/`.

## Principles

- **Evidence before spectacle.** Product interfaces, documented workflows and source links carry the
  story; decorative cyberpunk effects do not.
- **Technical claims stay scoped.** Demonstration data is labelled as sample data, benchmark results
  retain their denominators and limitations, and the dynamic sandbox is described as design-only.
- **Security boundaries are explicit.** The page distinguishes static analysis from installation,
  behavioural risk from vulnerability risk, and unavailable intelligence from a clean result.
- **Progressive disclosure.** The page gives a concise product narrative first, then exposes findings,
  pipeline stages, architecture, screenshots, CLI workflows and documentation links for deeper review.
- **Accessible by default.** Interactive content uses semantic controls, keyboard focus, readable labels,
  responsive layouts and a reduced-motion fallback.

## Visual system

The landing page uses a restrained enterprise palette: `#F7F8FA` and white surfaces in light mode,
`#10151D` and `#171E29` in dark mode, blue as the product accent, and a consistent severity scale:

| Meaning | Colour |
|---|---|
| Critical | `#DC4444` |
| High | `#E58A35` |
| Medium | `#C29B27` |
| Low | `#499B76` |
| Informational | `#718096` |

`DM Sans` is used for interface and explanatory text. `IBM Plex Mono` is used for package names,
finding codes, hashes, command examples and other identifiers. Dark mode is controlled locally and
respects the reader's preference until a theme choice is saved.

## Components and interaction conventions

- The product demo uses tabs for overview, findings, attack-chain correlation and provenance.
- Findings can be filtered by severity and opened for a short evidence/remediation explanation.
- Pipeline and architecture controls reveal implementation detail without requiring a backend.
- The screenshot gallery uses real console captures from `docs/images/` and `website/assets/` with a
  keyboard-accessible lightbox.
- Workflow examples include a functional clipboard copy control and link back to the CLI/API docs.
- The mobile menu, theme control and lightbox are plain client-side JavaScript in `website/app.js`;
  no credentials, API calls or third-party runtime dependencies are required.

## Product-claim rules

When extending the page, check the README and the relevant document before adding a claim. Keep these
rules intact:

1. Do not describe the dynamic sandbox as implemented; `docs/SANDBOX.md` is a design document.
2. Do not present illustrative scan data as a live API result.
3. Keep `14 / 15` real-world and `13 / 14` synthetic benchmark results separate, with benign
   denominators and the methodology link visible.
4. Say that vulnerability intelligence is unknown or unavailable when it is not present; never turn
   that state into a zero-risk claim.
5. Do not imply marketplace distribution, customers, certifications, uptime or enterprise adoption
   unless the repository gains verifiable evidence for them.

## Deployment

`.github/workflows/docs.yml` builds MkDocs into `site/docs/`, copies `website/` into `site/`, and
deploys the combined artifact. Relative links in `website/index.html` therefore target `docs/` for
the documentation subtree and `assets/` for landing-page media. Any new asset must be checked under
the GitHub Pages subdirectory URL:

`https://rakshit-737.github.io/warden-supply-chain-security/`
