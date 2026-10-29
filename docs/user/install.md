# Install, packages and services

No signed release, notarised macOS package, Homebrew tap, winget submission or published MSI is claimed. Build from source for development. Rust 1.91+ and the platform linker are required; the Linux GNU build is dynamically linked and is not a universal static binary.

```sh
cargo install --locked --path crates/bunker
bunker --version
bunker --help
```

This source-install command also works in PowerShell with a configured Rust toolchain. Add Cargo's `bin` directory to `PATH`. macOS needs Command Line Tools; Windows needs the MSVC build tools.

## Package candidates

The manually dispatched `Unsigned package candidates` workflow builds Linux x86-64 GNU, macOS arm64/x86-64, and Windows x86-64 MSVC archives. Each archive includes the binary, licence, build record and a CycloneDX Cargo source-dependency inventory. That inventory includes build/dev dependencies and is not a precise linked-binary SBOM. GitHub artifact provenance is requested by the workflow; verify that the attestation step actually succeeded for the downloaded candidate. Provenance is not Authenticode, Apple signing or notarisation.

Build a candidate locally with `cargo build --locked --release --package bunker --target TARGET`, then `python3 packaging/scripts/package.py --target TARGET --output /tmp/bunker-packages`. The target must be installed in Rust. No signing or network publication occurs.

Download a candidate and its checksum through a trusted channel. Verify its GitHub provenance, when available, using `gh attestation verify ARCHIVE --repo jusso-dev/bunker`. A checksum downloaded with a malicious archive does not establish authenticity. After independent verification, install from the local archive:

```sh
python3 packaging/scripts/install.py --archive "$ARCHIVE" --sha256 "$EXPECTED_SHA256" --prefix "$HOME/.local"
```

PowerShell uses `python packaging/scripts/install.py --archive $Archive --sha256 $ExpectedSha256 --prefix "$env:LOCALAPPDATA\Bunker"`. Add the resulting `bin` directory to `PATH`. The installer verifies SHA-256 before reading the binary member, rejects symlinks/duplicate members, and never extracts arbitrary archive paths. It replaces an existing installed binary; stop running services first. It does not configure services or install a trusted publisher certificate.

`packaging/scripts/package-linux.sh deb|rpm VERSION BINARY OUTPUT_DIRECTORY` invokes separately installed `fpm` and native packaging tooling. The WiX v4 template `packaging/windows/bunker.wxs` can build an unsigned MSI using `wix build -arch x64 -d Version=0.1.0 -d BinaryPath=ABSOLUTE_BINARY_PATH packaging/windows/bunker.wxs`. Homebrew/winget files under `packaging/manifests/` are placeholder templates, not installable manifests. Native package builds and signed distribution remain unverified.

## Linux systemd

Review `packaging/systemd/bunker.service` before installing. Create an unprivileged `bunker` account. The unit selects `/usr/bin/bunker`, matching the DEB/RPM package; if installing the binary elsewhere, change `BUNKER_BINARY` in the unit. Install `run-daemon.sh` to `/usr/local/libexec/bunker/run-daemon.sh` with mode 0755. Give that account read access to `/srv/workspace`, write access to `/var/lib/bunker`, and initialize `/var/lib/bunker/repository` with the same identity. Provision `/etc/bunker/passphrase` through your secret manager, owned by root with mode 0600. Never put its contents in the unit file.

The unit requires systemd with `LoadCredential` support (247+). Install the reviewed unit, run `systemctl daemon-reload`, then `systemctl enable --now bunker.service`. Check `systemctl status bunker.service` and `bunker status --repo /var/lib/bunker/repository` under the appropriate local identity. The default unit grants only read access to the workspace; perform restores through a separately authorized operator. Customize mount paths and permissions for your host. Native systemd execution has not been tested on this macOS development host.

## macOS launchd

Copy `packaging/launchd/dev.bunker.agent.plist` to `~/Library/LaunchAgents/` after replacing every `/REPLACE/` path. Install the binary and daemon wrapper at the paths named in the template, both with mode 0755. Create and initialize the repository separately. Supply a passphrase file from your credential manager, mode 0600, outside the workspace and repository; the template contains only its path. This is a plaintext secret file protected by OS permissions, not Keychain integration.

Validate with `plutil -lint` and load with `launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.bunker.agent.plist"`. Inspect `launchctl print "gui/$(id -u)/dev.bunker.agent"`; stop with `launchctl bootout` using the same domain and plist path. User launch agents run after login, not as unattended pre-login system services. Repositories and data remain when uninstalling the service.

## Windows service wrapper

The CLI is a console program, not an SCM service. The `packaging/windows/bunker-service.xml` template requires an independently verified WinSW wrapper. Place the wrapper as `bunker-service.exe`, its matching XML, `run-daemon.ps1`, and `bunker.exe` in an administrator-controlled directory. Replace the workspace placeholder and configure a dedicated least-privilege service identity before installation; do not leave the wrapper running as LocalSystem.

Under that service identity, provision a DPAPI-protected credential using `Read-Host -AsSecureString | Export-Clixml -Path passphrase.dpapi.xml`, then restrict directory ACLs to administrators and the service identity. DPAPI is tied to that Windows account/machine and is not portable escrow. Initialize the repository with the same passphrase using a secure environment-injection process. The wrapper reads the protected value at runtime and removes it from its environment on exit.

After reviewing identity, ACLs, executable trust and paths, use WinSW's `install`, `start`, `stop`, and `uninstall` commands. The service defaults to manual start until configured and tested. Windows MSI signing, WinSW deployment and service lifecycle are not verified by this task.

## GitHub Actions

Use the repository action at `./.github/actions/snapshot` after checkout, or pin an audited commit for remote use. It requires an installed CLI, an initialized repository outside the workspace, and `BUNKER_PASSPHRASE` supplied as a job-level environment variable from Actions secrets. Inputs are `repository` (required absolute path), `workspace` (defaults to `GITHUB_WORKSPACE`), and `binary` (defaults to `bunker`). The snapshot runs in the action's post phase, including after earlier step failures.

Use a persistent, protected repository on a trusted self-hosted runner. A repository under a hosted runner's temporary directory disappears when the job ends. This action does not automatically upload an artifact or replicate the post-job snapshot. GitHub post actions run in reverse registration order; account for cleanup ordering. Cancellations, killed runners and infrastructure failures can prevent post execution. Never expose a passphrase or persistent repository to untrusted pull-request code. For hosted runners, explicitly snapshot and replicate before teardown using separately reviewed steps.
