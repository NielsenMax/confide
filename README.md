# secret-share

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
   make            # builds ./secret-share with the credentials embedded
   ```

The client ID/secret are compiled into the binary via `-ldflags`. **A Desktop-app
client secret is not confidential** — Google states installed apps can't keep it
secret, and PKCE (used on every login) is what actually secures the flow. So the
only thing you distribute to teammates is the **binary** — no `credentials.json`,
no env vars. They just run `secret-share login`.

> Testing-mode caveat: while the consent screen is in "Testing", only listed test
> users can log in and refresh tokens expire after 7 days (occasional re-login).
> Add each teammate as a test user. Publishing to production with the full `drive`
> scope requires Google verification, so testing mode is usually the pragmatic
> choice for a small team.

Overrides (rarely needed): `GOOGLE_OAUTH_CLIENT_ID`/`GOOGLE_OAUTH_CLIENT_SECRET`
env vars, or a `credentials.json` in the config dir, both take precedence over
the embedded default.

## Usage

```sh
# Teammates receive the prebuilt ./secret-share binary and just run commands.
# (To build yourself: `make`, or `go build .` if credentials are embedded/overridden.)

# First run: create your identity, log in via browser, create the store folder.
./secret-share init --name alice          # add --drive-id <id> for a Shared Drive

# Create a vault (you become its admin + first member).
./secret-share vault create team

# Add secrets.
printf 'hunter2' | ./secret-share set db-password --notes prod
./secret-share set api-key --file ./key.pem
./secret-share ls
./secret-share get db-password

# Admit a teammate: they run `whoami`, send you the share token, you add them.
#   (on Bob's machine)
./secret-share init --name bob
./secret-share whoami                      # prints a share token
#   (on your machine)
./secret-share member add bob <share-token>

# Revoke a member (rotates the master key + re-encrypts every secret).
./secret-share member rm bob
```

Members share one Drive folder. On a **Google Workspace** account use a Shared
Drive (`--drive-id`); on a **personal Gmail** account, create the vault in your
My Drive and share the `SecretShare` folder with your team (they need Editor
access). Full `drive` scope is used because members must read a folder they did
not themselves create.

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

### macOS: "secret-share" Not Opened / "Apple could not verify..."

macOS Gatekeeper blocks binaries downloaded from the internet unless they're
code-signed and notarized by an Apple Developer account. This tool isn't, so a
teammate who *downloads* the binary will hit this. It's a quarantine flag, not a
problem with the file. Strip it and run:

```sh
xattr -d com.apple.quarantine ./secret-share   # if that errors: xattr -c ./secret-share
chmod +x ./secret-share
./secret-share --help
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
