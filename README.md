# Play Integrity Fix — multiplex (BenOS)

Module id `playintegrityfix-benos`. A fork of the [`inject_s`](https://github.com/KOWX712/PlayIntegrityFix/tree/inject_s) Play Integrity Fix variant with a couple neat additions:

1. **Per-process fingerprint routing.** A single configuration file declares any number of named device profiles and a routing table mapping exact process names to profiles. Different processes receive different spoofed `Build` identities, or none at all.
2. **Manifest-sealed, encrypted-at-rest configuration.** The plaintext configuration never ships. It is sealed at build time into `pif.prop.enc` under an AES-256-GCM key derived from the byte content of the shipped module scripts and the pifcrypt binary, and, optionally, an out-of-module key file. Plaintext props never touch storage.

I use it with 2 fingerprints; one for com.android.vending, and the other to be so graciously granted permission to use RCS messaging by the oh so wise and powerful Google 🙄

 As is true with upstream, this is **not** a root-hiding module and does not defeat detection in third-party apps. Root and Zygisk are prerequisites: Magisk's built-in Zygisk, [ZygiskNext](https://github.com/Dr-TSNG/ZygiskNext), or [ReZygisk](https://github.com/PerformanC/ReZygisk).

## Profiles and the routing table

- Add packages intended as destinations to the appropriate section in `zygisk.cpp`. These valus must match the data dir for said app.
- A `[profile <name>]` header opens a profile block. Keys before the first header belong to the implicit `default` profile, which preserves single-profile (legacy) file behavior and is the fallback target.
- Routing keys are exact Zygisk `nice_name` values, for example `com.google.android.gms.unstable` or `com.google.android.apps.messaging:rcs`.
- **A process with no route is not injected.** Resolution order for a routed process is: the profile named by the route, else `default`, else an empty config.

Example `zygisk.cpp`:
```
constexpr std::array<std::string_view, 5> ALLOWED_PACKAGE_DIRS = {
        "/com.google.android.gms",
        "/com.google.mediatek.ims",
        "/com.google.android.ims",
        "/com.android.vending",
        "/com.google.android.apps.messaging",
};
```

Example `pif.prop`:

```properties
route.com.google.android.gms.unstable=rcs
route.com.android.vending=integrity
route.com.google.android.apps.messaging:rcs=rcs
route.com.google.android.apps.messaging=rcs

[profile rcs]
FINGERPRINT=...
MANUFACTURER=...
MODEL=...
SECURITY_PATCH=...
spoofBuild=true
spoofProps=true

[profile integrity]
FINGERPRINT=...
MANUFACTURER=...
MODEL=...
SECURITY_PATCH=...
DEVICE_INITIAL_SDK_INT=...
spoofBuild=true
spoofProps=true
spoofVendingBuild=true
spoofVendingSdk=true
```

## Sealed configuration and key derivation

Sealing is performed by `pifcrypt`, a small Rust binary (`pifcrypt/src/main.rs`), shipped as `module/bin/pifcrypt` (device, aarch64).

The key is derived at runtime from a length-prefixed transcript over an ordered manifest of module files plus the pifcrypt binary itself, and optionally an out-of-module key file. Properties of the construction:

- **The key is never stored.** Reproduction requires every manifest input to be byte-identical to its build-time state. Any modification changes the derived key; AES-256-GCM authentication then fails on unseal and yields no output.
- Manifest membership is fixed to files that are present and byte-stable at unseal time. `module.prop` (rewritten by the manager), `action.sh` (renamed under KernelSU/APatch), the payload itself, and `customize.sh` (install-time only) are excluded by design.

## Burger King: have it your way

The optional `--keyfile` argument folds a file's content (not path) into the key under a separate domain-separation label:

- **Manifest-only** (no key file): a portable module, installable as an ordinary KernelSU/Magisk module.
- **Manifest-plus-key-file**: the seal is bound to the byte content of a file that must be present on device at the compiled `KEYFILE_PATH` (`#define KEYFILE_PATH` in `zygisk.cpp`). Because only content is bound, the build-time staging path and the on-device path may differ. Intended to be used with a file on a read-only partition. A zero-length key file is rejected.

## Build

Requirements: Rust toolchain (host + aarch64 target), Android NDK, JDK, the Gradle wrapper in-tree, and a plaintext seed `pif.prop` kept outside the repository.

`build.sh` drives staging → Gradle build → seal → package. Builds pifcrypt binaries if they aren't already built. Fairly automated, as building other people's code is universally awful and I don't hate you that much. NOTE: it does not install cargo or build deps.

```
rustup target add aarch64-unknown-linux-musl
cargo install cargo-zigbuild
```

1. `module/bin/pifcrypt` in staging must already be the **device** (aarch64) binary that ships. It is a hashed manifest input; its bytes must equal the on-device binary exactly. Staging the host binary here causes every device to fail authentication.
2. The host `pifcrypt` runs the seal but is only an execution vehicle and is not hashed.
3. After sealing, an authenticated round-trip pifcrypt is run against the finalized staging tree. A seal inconsistent with the shipped bytes fails on the workstation rather than on device.

### build.sh:

- `./build.sh clean` = runs `gradle clean` and exits
- `./build.sh --keyfile <file> --rom-keyfile <path to matching file on device storage>` = lock module decryption to arbitrary file present in ROM. 
- `./build.sh --debug` = bundles somewhat broken `action.sh` debugger that prints whether decrypt was successful, some logging, and plaintext payload. Not included at this time, but will probably be posted in the near future once I make it properly portable (ie. doesn't require hard-coding the path to the on-device keyfile)

For a ROM-locked build, pass `--keyfile <PATH>` (and, if the on-device path differs, `--keyfile-device-path <PATH>`). All hashed inputs must be in their final shipped byte state before the seal runs; any post-seal edit to a manifest file invalidates the seal.

A `--debug` build stages an `action.sh` that prints the resolved configuration in plaintext and is gated behind an interactive confirmation. It must not be shipped.

## On-device flow

1. `post-fs-data.sh` scrubs any stray plaintext `pif.prop` and temp files.
2. On a routed process fork, the injected library requests the payload from the companion.
3. The companion resolves the route, forks `pifcrypt decrypt` with stdout piped back (no plaintext touches persistent storage), parses the sealed bundle, and streams the selected profile — and the classes DEX only when `spoofProvider` or `spoofSignature` require it — back over the companion socket.
4. Unrouted processes are rejected by the companion with no payload.

## Configuration reference

Per-profile build fields: `FINGERPRINT`, `MANUFACTURER`, `MODEL`, `SECURITY_PATCH`, `DEVICE_INITIAL_SDK_INT`, `BUILD_ID`.

| Option | Default | Effect |
| --- | --- | --- |
| `spoofBuild` | `true` | Spoof the `Build` fingerprint fields. |
| `spoofProps` | `true` | Spoof values read from system properties by GMS. Enable when not using TrickyStore. |
| `spoofProvider` | `false` | Install the custom keystore provider. Enable when not using TrickyStore. Pulls in the DEX. |
| `spoofSignature` | `false` | Spoof ROM signature; for test-key-signed ROMs. Pulls in the DEX. |
| `spoofVendingSdk` | `false` | Spoof SDK to 32 for the Play Store on Android 13+. Carries the upstream Play Store side effects. |
| `spoofVendingBuild` | `false` | Spoof the fingerprint field presented to the Play Store. |
| `DEBUG` | `false` | Verbose logging for the profile. |

Check ROM signature before enabling `spoofSignature`:

```sh
unzip -l /system/etc/security/otacerts.zip | grep -oE "testkey|releasekey"
```

## Repository layout

- `zygisk/src/main/cpp/` — injected library and companion. `zygisk.cpp` (routing, decrypt-via-pipe, companion), `pif_config.{hpp,cpp}` (bundle parser and resolver).
- `zygisk/src/main/java/es/chiteroman/playintegrityfix/` — keystore provider and package-info spoofing (loaded only when a routed profile needs the DEX).
- `pifcrypt/` — Rust sealing/unsealing binary and its build shim.
- `module/` — installable tree: install (`customize.sh`), runtime (`post-fs-data.sh`, `service.sh`, `security_patch.sh`), `bin/pifcrypt` (device binary), and the sealed `pif.prop.enc`.
- `build.sh` — build and terminal seal stages.
- `pif-clean.prop` — reference routing/profile template.

## Lineage and acknowledgments

Forked from [KOWX712/PlayIntegrityFix](https://github.com/KOWX712/PlayIntegrityFix) (`inject_s`), itself downstream of chiteroman's original Play Integrity Fix (removed from GitHub).

- [kdrag0n](https://github.com/kdrag0n/safetynet-fix) and [Displax](https://github.com/Displax/safetynet-fix) for the original approach.
- [osm0sis](https://github.com/osm0sis) for `autopif2.sh`; [backslashxx](https://github.com/backslashxx) and [KOWX712](https://github.com/KOWX712) for `action.sh`.

## License

See [`LICENSE`](LICENSE).
