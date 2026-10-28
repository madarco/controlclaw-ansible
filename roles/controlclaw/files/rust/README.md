Dev rounds only (`cc_rust_source: files`): `scripts/dev-stage-bundles.sh` in controlclaw stages the
Rust box binaries here, with the `vars/rust_release.yml` that pins them. Production boxes download
the release assets instead. Either way the role checks each binary's sha256 against the pin.
