# Foundation SDK setup

This app targets Foundation SDK 1.0.0 and KeyOS 1.4 beta.

1. Install the Foundation SDK bundle for your operating system and put its
   `foundation` binary on `PATH`.
2. From this repository, run `foundation doctor`.
3. Enter the SDK environment with `foundation develop` if the doctor reports
   that the Nix shell or KeyOS target is missing.
4. Create a local signing identity with `foundation cert gen <name>`.
5. Build and package with `foundation pack --release`.

The CLI owns `.foundation-sdk/current`, `ui/ui`, `manifest.toml`, and `target/`.
They are generated and ignored. Do not commit them or replace their paths with
paths to a local KeyOS checkout.

To reset generated state:

```sh
foundation clean
foundation doctor
foundation pack --release
```

See [README.md](README.md) for publisher trust, installation, file-exchange
paths, and the KeyOS 1.4 third-party permission boundary.
