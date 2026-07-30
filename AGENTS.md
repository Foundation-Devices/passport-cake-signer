# Passport Cake Signer

## Repository boundaries

- This repository is the standalone Cake signer application source.
- Hardware firmware must be built and flashed only from the dedicated KeyOS
  integration worktree at `/Users/admin/Documents/AI/KeyOS-cake-signer`.
- Never build, flash, commit, or push this experiment from upstream
  `KeyOS-dev`, another application's KeyOS worktree, or a Foundation mainline
  branch.

## Passport Prime firmware safety

Before any hardware flash:

1. Synchronize the intended Cake source changes into the dedicated
   `KeyOS-cake-signer` integration worktree.
2. Read and follow that worktree's root `AGENTS.md`.
3. Build with `cargo xtask build-all` and no `--app` argument.
4. Never flash firmware built with
   `cargo xtask build-all --app gui-app-cake-signer`. The `--app` option
   replaces the default app list and produces firmware without Settings and
   other standard KeyOS applications.
5. Confirm the build output bundles both `gui-app-settings` and
   `gui-app-cake-signer`.
6. Flash and fully verify both boot and system partitions. Never bypass
   verification.
7. Confirm Passport Prime returns in normal USB mode and manually launch both
   Settings and Cake before reporting the flash complete.

If any preflight or verification step is missing, the firmware is not ready to
flash and the task is not complete.
