# confide

Share secrets with a team, using **Google Drive as an encrypted backend**. The
server (Drive) only ever sees ciphertext; decryption keys never leave members'
machines.

## How it works

Two-level **envelope encryption** with per-member **key wrapping**:

1. Each **member** has an identity: an [age](https://age-encryption.org) X25519
   keypair (encryption) + an ed25519 keypair (signing).
2. Each **vault** has its own master age keypair. Secrets are encrypted *to the
   master public key*; reading requires the master private key.
3. The master private key is individually **wrapped** (encrypted) to every
   member's public key, so only members can recover it.
4. Every stored record (manifest, member entries, secrets) is **signed** by its
   author's ed25519 key and verified on read — so nobody with write access to
   the shared Drive folder can forge or inject data undetected.

```
SecretShare/<vault>/
  meta.json          # signed manifest: master PUBLIC key, admins, key epoch
  members/<name>.json # signed public-key record for each member
  keys/<name>.age     # master private key, wrapped to that member
  secrets/<name>.age  # AEAD ciphertext of the value + notes; named by the secret
```

Secret **names are stored in the clear** (they are the filenames), so listing is
a single directory read and fetching one secret touches exactly one file. The
secret **value and notes stay encrypted**. This means anyone with Drive access to
the folder can see the *names* of your secrets (e.g. `prod-db-password`) but not
their contents — pick names that aren't themselves sensitive.

## One-time setup: Google OAuth client (done once, by you)

The CLI uses a Google Cloud OAuth client (installed-app flow). You create it
**once** and **bake it into the binary** — teammates never touch this.

1. Create a project at <https://console.cloud.google.com/>.
2. **APIs & Services → Enable APIs** → enable **Google Drive API**.
3. **OAuth consent screen** → External → add your team's Google accounts as
   **Test users** (keeps you in testing mode; no Google verification needed).
4. **Credentials → Create credentials → OAuth client ID → Desktop app**.
5. Put the client ID/secret in a git-ignored `.env` and build:

   ```sh
   cat > .env <<'EOF'
   CLIENT_ID=xxxx.apps.googleusercontent.com
   CLIENT_SECRET=xxxx
   EOF
   make            # builds ./confide with the credentials embedded
   ```

The client ID/secret are compiled into the binary via `-ldflags`. **A Desktop-app
client secret is not confidential** — Google states installed apps can't keep it
secret, and PKCE (used on every login) is what actually secures the flow. So the
only thing you distribute to teammates is the **binary** — no `credentials.json`,
no env vars. They just run `confide login`.

> Testing-mode caveat: while the consent screen is in "Testing", only listed test
> users can log in and refresh tokens expire after 7 days (occasional re-login).
> Add each teammate as a test user. Publishing to production with the full `drive`
> scope requires Google verification, so testing mode is usually the pragmatic
> choice for a small team.

Overrides (rarely needed): `GOOGLE_OAUTH_CLIENT_ID`/`GOOGLE_OAUTH_CLIENT_SECRET`
env vars, or a `credentials.json` in the config dir, both take precedence over
the embedded default.

### One client for everyone vs. publishing publicly

The embedded client ID/secret is a single, **project-level** OAuth client (not
tied to a Workspace). One embedded client works for *all* users — each person
who logs in grants *your* app access to *their own* Drive, exactly like
`rclone`/`gcloud`/`gh`. The secret isn't confidential (Desktop-app secret).

What limits reach is the consent screen's **publishing status**, not the secret:

- **Testing mode** (default): only whitelisted test users (≤100) can log in, and
  refresh tokens expire after 7 days. Ideal for a private team.
- **Production**: anyone can log in — but because Confide uses the **restricted
  `drive` scope**, Google requires **app verification** (an annual third-party
  security assessment) before publishing to external users.

So if you want to release Confide publicly, the pragmatic path is
**bring-your-own client**: have each org create their own OAuth client and
supply it via the env vars / `credentials.json` above (or their own `make`
build). That avoids Google's verification process *and* the shared Drive API
quota that a single client ID would impose across all users.

## Installing (for teammates)

Teammates **do not** build from source and **do not** use `go install` —
`go install` compiles the public source on their machine, which has no OAuth
credentials embedded, so it would produce a binary that can't log in.

The binaries are built by CI (`.github/workflows/release.yml`) with the OAuth
client credentials injected from repository secrets at build time — the
credentials live only in GitHub Actions secrets, never in the source tree.

**One-liner (macOS / Linux):**

```sh
curl -fsSL https://raw.githubusercontent.com/NielsenMax/confide/main/install.sh | sh
confide login   # authorize your Google account (must be a test user)
```

The script detects your OS/arch, downloads the matching binary from the latest
release, and puts it on your PATH. Pin a version with `CONFIDE_VERSION=v0.1.0`,
or change the target dir with `CONFIDE_INSTALL_DIR=...`.

**Manual:** grab the asset for your OS/arch from the
[Releases](https://github.com/NielsenMax/confide/releases) page
(`confide_darwin_arm64`, `confide_linux_amd64`, `confide_windows_amd64.exe`, …),
then:

```sh
chmod +x confide_darwin_arm64
./confide_darwin_arm64 install --add-path   # copies to ~/.local/bin, updates shell rc
```

Only Google accounts added as **test users** on the OAuth consent screen can
complete `confide login`; the embedded client identity alone grants no access to
the team's vault (that's gated by Drive folder sharing + encryption).

### Staying up to date

Confide checks for a newer release at most once a day and prints a one-line
notice when one exists. To upgrade:

```sh
confide update            # downloads the latest release, verifies its checksum,
                          # and replaces the running binary in place
```

The notice is silenced for non-interactive shells and can be disabled with
`CONFIDE_NO_UPDATE_CHECK=1`. `confide update` upgrades the CLI only — it never
touches your vault or secrets.

### Cutting a release (maintainer)

One-time: add `CLIENT_ID` and `CLIENT_SECRET` under **Settings → Secrets and
variables → Actions**. Then tag:

```sh
git tag v0.1.0 && git push origin v0.1.0   # CI builds all platforms + publishes
```

## Usage

```sh
# Teammates receive the prebuilt ./confide binary and just run commands.
# (To build yourself: `make`, or `go build .` if credentials are embedded/overridden.)

# Put it on your PATH so you can run `confide` from anywhere:
./confide install --add-path         # copies to ~/.local/bin, updates your shell rc

# First run: create your identity, log in via browser, create the store folder.
./confide init --name alice          # add --drive-id <id> for a Shared Drive

# Create a vault (you become its admin + first member).
./confide vault create team

# Add secrets.
printf 'hunter2' | ./confide set db-password --notes prod
./confide set api-key --file ./key.pem
./confide ls
./confide get db-password

# Add or remove teammates — see "Adding a teammate" below.
```

### More commands

```sh
# Inject secrets into a process (like `doppler run` / `chamber exec`):
./confide run -- ./deploy.sh            # secrets become $DB_PASSWORD, $API_KEY, ...
eval "$(./confide env)"                 # export them into your current shell

# Copy a secret to the clipboard instead of printing it (avoids scrollback):
./confide get db-password --copy

# Admins: promote a member, list admins, rotate the key proactively:
./confide admin add bob
./confide admin ls
./confide rotate                         # re-key without changing membership

# Housekeeping:
./confide purge                          # remove soft-deleted tombstones you own
./confide version
```

Secret names are mapped to env var names for `run`/`env` (uppercased,
non-alphanumerics become `_`, e.g. `db-password` → `DB_PASSWORD`). Destructive
commands (`rm`, `member rm`, `rotate`) prompt for confirmation; pass `--yes`/`-y`
to skip it in scripts.

Members share one Drive folder. On a **Google Workspace** account use a Shared
Drive (`--drive-id`); on a **personal Gmail** account, create the vault in your
My Drive and share the `SecretShare` folder with your team (they need Editor
access). Full `drive` scope is used because members must read a folder they did
not themselves create.

## Adding a teammate

Admitting someone needs two kinds of access, and Confide splits them across two
commands:

- **Drive access** to the shared folder — granted by `invite` (an admin shares
  the Drive folder with their Google account).
- **Decryption access** — granted by `member add` (an admin wraps the vault
  master key to the newcomer's public key).

The newcomer can read nothing until **both** are done, and only an existing
admin can do either.

**0. One-time (personal Gmail, testing mode):** add the teammate's Google
account as a **test user** in your OAuth consent screen (Google Cloud Console →
APIs & Services → OAuth consent screen → Test users). Otherwise their login
fails with `access_denied`.

**1. Admin — share the folder and get the join command:**

```sh
confide invite bob@gmail.com
# Shares the SecretShare folder (Editor) with bob and prints the exact
# `confide init ... --root-folder-id <id>` command for him to run.
```

**2. Teammate — set up and produce a share token:**

```sh
# macOS only, if the binary was downloaded: xattr -d com.apple.quarantine ./confide
confide init --name bob --root-folder-id <id-from-invite>   # or --drive-id <id> for a Shared Drive
confide whoami          # prints a "share token" — send it to the admin (any channel; it's public-key material)
```

**3. Admin — admit them to the vault:**

```sh
confide member add bob <share-token>
```

**4. Teammate — use the vault:**

```sh
confide vault use team
confide ls
confide get db-password
```

**Removing a teammate** (any admin):

```sh
confide member rm bob   # rotates the master key and re-encrypts every secret
```

After this bob can't decrypt anything new. He still *knows* any values he
already read, so rotate those with `confide set` to fully invalidate them.

## Local key storage

Your private keys and OAuth token are stored in the **OS keychain** when
available (macOS Keychain / GNOME Keyring / Windows Credential Manager), falling
back to **passphrase-encrypted files** under the config dir otherwise.

## Security notes & limitations

- **Confidentiality & integrity**: age provides ChaCha20-Poly1305 AEAD per blob;
  ed25519 signatures add sender authenticity age alone doesn't give.
- **Revocation requires rotation**: `member rm` rotates the master key and
  re-encrypts everything, but a removed member still *knows* any secret value
  they already read. Rotate those values with `set` to fully invalidate them.
- **Mutable shared storage**: a party with Drive write access can *delete* or
  *roll back* files. Signatures make tampering detectable, but deletion/rollback
  by a malicious storage admin is not fully preventable — treat Drive access
  control as part of your trust boundary.
- **Membership is admin-gated**: only an existing admin (whose signing key is in
  the manifest) can admit members, and only a current member can decrypt the
  master key needed to wrap it for a newcomer.

## Troubleshooting

### Deleting a teammate's secret ("403 insufficientFilePermissions")

In a shared **My Drive** folder, each file is owned by whoever created it, and
Google only lets the **owner** permanently delete a file. So you can hard-delete
secrets you wrote, but not ones a teammate wrote. `rm` handles this transparently:
if it can't delete a teammate's file, it **soft-deletes** by truncating the file
to empty (which an Editor is allowed to do). Soft-deleted secrets are hidden from
`ls`, read as "not found", and their name can be reused. A **Shared Drive**
(Workspace) avoids the ownership split entirely and allows real deletes.

Soft-deletes leave a harmless empty file behind. Each owner can permanently clear
the ones they own with `confide purge`.

### macOS: "confide" Not Opened / "Apple could not verify..."

macOS Gatekeeper blocks binaries downloaded from the internet unless they're
code-signed and notarized by an Apple Developer account. This tool isn't, so a
teammate who *downloads* the binary will hit this. It's a quarantine flag, not a
problem with the file. Strip it and run:

```sh
xattr -d com.apple.quarantine ./confide   # if that errors: xattr -c ./confide
chmod +x ./confide
./confide --help
```

The Finder "right-click → Open" trick is unreliable for command-line binaries on
recent macOS, so `xattr` is the dependable route.

Alternatively, **building from source** produces a binary with no quarantine flag
and no Gatekeeper prompt (`make`, or `go build .`).

For wider distribution, code-sign with a Developer ID certificate and notarize
(`codesign` + `xcrun notarytool`) so recipients need no manual step — usually
overkill for a small internal team.

## Development

```sh
go test ./...
```
