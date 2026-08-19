# Passport Cake Signer

## Repository boundaries

- This Foundation repository is the canonical Cake signer monorepo.
- The repository root contains the standalone Passport Prime / KeyOS app source.
- `mobile-wallet/` contains the companion Cake Wallet mobile fork.
- The Prime app builds only through the standalone Foundation SDK workflow.
- Do not copy or sync the app into a KeyOS source checkout.
- Never push the mobile fork to a Cake-owned repository unless the user
  explicitly authorizes that exact publication target.

## Passport Prime installation safety

- Use `foundation build`, `foundation pack`, or `foundation sideload`; never
  build or flash full firmware for this app.
- Run `foundation doctor` before diagnosing SDK failures.
- Do not create or rotate signing identities unless the user explicitly asks.
- Do not run a hardware-affecting sideload unless the user asks to use the
  connected Passport Prime.
