# Drakora client configuration

Public network configuration and release metadata for the Drakora player mod on Minecraft 1.20.1. Player mod source remains private. Internal staff mods and private signing keys are not distributed here.

Clients supporting signed configuration fetch [network.signed.json](https://raw.githubusercontent.com/EnVisione/DrakoraUpdates/main/network.signed.json) at startup, before opening a new connection, and periodically while running. A connector waits at most 4.5 seconds for a refresh. Network requests run outside the render and packet threads. Unavailable or invalid responses preserve the last verified configuration, with a bundled configuration available for the first offline launch.

The released modpack builds that contain only a fixed endpoint list need one initial client update to gain this capability. Changing this repository cannot patch an older JAR that does not fetch configuration.

## Files and settings

`network.json` is the editable configuration. `network.signed.json` contains its exact bytes and an Ed25519 signature. `network-config.pub` is the public verification key. Clients pin that key and reject unsigned changes, reused revision numbers with different content, and older revisions than their current verified snapshot.

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Configuration format, currently `1`. |
| `revision` | Positive integer increased for every configuration change. Never reuse it. |
| `domains` | Network domain roots, including their subdomains. |
| `addresses` | Trusted numeric IP addresses and their exact permitted ports. Hostnames cannot substitute for this check. |
| `configurationSources` | Ordered HTTPS configuration sources. The bundled bootstrap URL remains a recovery source. |
| `downloadRoots` | HTTPS release download roots ending in `/`. Downloads must have exactly a release tag and filename below a root. |
| `downloadRedirectHosts` | HTTPS hosts allowed to serve redirected release assets. |
| `curseforgeProject` | Official CurseForge project URL used to validate release links. |
| `releases` | Published player releases. An empty array advertises no update. |

A release records `loader`, `minecraft`, `version`, `build`, `fileName`, `size`, `sha256`, `downloadUrl`, and `curseforgeUrl`. `build` permits a rebuilt patch to update an older build with the same mod version. Its value must match the JAR's embedded `assets/progressivevelocity/release.properties`. Downloads must use the matching loader, Minecraft version, archive identity, byte count, checksum and signed location.

`updates.json` mirrors the release catalog for older updater implementations. It does not change their endpoint trust rules. Do not add releases until both their download and CurseForge file page exist.

## Publish a configuration change

Requires Python 3.9 or newer and OpenSSL with Ed25519 support.

1. Edit `network.json` and increase `revision`.
2. Sign it with the private key kept outside this repository:

   ```sh
   python3 tools/network_config.py sign --key /private/network-config.key
   python3 tools/network_config.py verify
   ```

3. Review and publish `network.json`, `network.signed.json`, and `updates.json` together through the normal repository review process.

Editing the plain JSON alone does not activate a change. Never upload the private signing key or put it in a release, issue, build artifact or source archive. The public key, protocol identifiers and signature verification remain client trust anchors rather than remotely editable settings.

## Client updates

Update notices appear only on the verified Drakora network. The player chooses whether to install. Downloads have a fixed deadline and byte limit. A failed check retries; a missing player or screen does not consume the notice. Installation replaces the actual loader reported mod path and keeps a backup with a `.bak` suffix, so a second mod copy is not loaded.

The running JAR stays untouched on every operating system. A separate installer waits for Minecraft to exit, verifies that the original and downloaded files are unchanged, and performs the atomic replacement. This also handles the loaded archive lock on Windows. Close Minecraft before reopening it. A launcher changed file, invalid download, lost authorization before preparation, or unsupported atomic replacement preserves the original. A failed deferred attempt leaves its prepared files and `.drakora-update-result.properties` beside the mod for diagnosis and manual recovery.
