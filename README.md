# keysign

Sign the keys from a keysigning party and mail each signature to its owner,
encrypted to their key, one mail per user ID. It's a non-interactive
replacement for [caff](https://salsa.debian.org/debian/pgp-tools).

Requirements: Python 3.11+, GnuPG 2.2+, and an MTA (msmtp, or any `sendmail`
compatible program). Optionally a clone of the
[kernel.org pgpkeys](https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git)
repo in `pgpkeys/`. No Python packages beyond the standard library.

## Setup

```sh
cp keysign.toml.example keysign.toml
$EDITOR keysign.toml
```

```toml
name  = "Alice Example"
email = "alice@example.org"
keyid = "0123456789ABCDEF0123456789ABCDEF01234567"   # full fingerprint

# The message is piped to stdin and the recipient is appended as the last argument.
sendmail = ["msmtp", "-a", "default", "-f", "alice@example.org", "--"]

pgpkeys    = "pgpkeys/keys"
keyservers = ["hkps://keyserver.ubuntu.com", "hkps://keys.openpgp.org"]
maildir    = "mail"
```

Any other config file can be used with `-c FILE`.

keysign uses the keyring in `$GNUPGHOME` (default `~/.gnupg`), so point it at
the keyring that holds your secret key.

## Workflow

```sh
./keysign.py parse   party.txt -o party.keys
$EDITOR party.keys                  # review
./keysign.py fetch   party.keys
./keysign.py sign    party.keys     # -n for a dry run
./keysign.py prepare party.keys
./keysign.py send                       # -n for a dry run
./keysign.py clean   party.keys     # -n for a dry run
./keysign.py status  party.keys     # -v for every UID
```

For keys from paper slips, start with `add` instead of `parse`:

```sh
./keysign.py add slips.keys alice@example.org 'ABCD 1234 ... 9876' 0x1234567890ABCDEF
$EDITOR slips.keys                      # compare with the slips, mark '-' -> 'x'
./keysign.py fetch slips.keys           # then continue as above
```

`./keysign.py all LIST` runs fetch, sign and prepare in one go. All steps can
be re-run safely: they skip what is already done.

### parse

Reads a gpgparticipants style list (the printed party list with your `[x]`
marks) and writes a key list with one line per key:

```
x  89ABCDEF01234567  0123456789ABCDEF0123456789ABCDEF01234567  Alice Example <alice@example.org>
-  76543210FEDCBA98  FEDCBA9876543210FED__210FEDCBA9876543210  Bob Example <bob@example.org>
```

- `x`: both "Fingerprint OK" and "ID OK" are ticked. Only these keys get signed.
- `-`: not verified. These keys are fetched but never signed.
- `_` marks nibbles that were masked on the list. Those positions match any
  hex digit when keys are looked up.

To leave a key out, delete its line or comment it out with `#`.

### add

Looks up keys by email address, fingerprint (spaces and `_` for unknown
nibbles allowed) or key ID, and appends them to a key list. The list is
created if it doesn't exist, and keys already in it are skipped. Lookups use
the local keyring, kernel.org pgpkeys, WKD (email only) and the keyservers.

Each added key is printed with its fingerprint in groups of four for
comparison with the slip. New lines get `-`, so nothing is signed until you
change it to `x`. Anyone can upload a key with any email address, so an email
lookup can return keys of strangers; `add` warns when several keys match.

`-x` marks keys as verified right away, but only for queries that are a full
40 digit fingerprint (typed from the slip); other queries are still added as
`-`.

### fetch

Makes sure every listed key is in the keyring. Sources are tried in this order:

1. the local keyring
2. `pgpkeys/keys/<keyid>.asc` (kernel.org)
3. WKD for the email address on the list
4. the configured keyservers

A downloaded key is imported only if its fingerprint matches the list.
`--refresh` imports from the sources even when the key is already present.

### sign

Certifies all valid UIDs of each `x` key with `gpg --quick-sign-key`. There are
no prompts, except the passphrase/PIN through gpg-agent. Revoked and expired
keys are skipped, and so are UIDs you have already signed.

### prepare

For each UID you signed, it exports the key with only that UID, encrypts it to
the key, and writes a PGP/MIME mail to `mail/outbox/`. Keys without an
encryption subkey are skipped. A UID that already has a mail in `outbox/` or
`sent/` doesn't get a new one.

### send

Sends every mail in `mail/outbox/` with the configured `sendmail` command and
moves it to `mail/sent/`. Mails that fail stay in the outbox, so the next
`send` retries them.

### clean

Deletes the keys that `fetch` imported (recorded in `mail/imported`) once they
have nothing left to send. A verified key stays as long as it has mails in the
outbox or none sent yet. `--all` also deletes listed keys that were in the
keyring before `fetch`; check with `-n` first. Deleting a key also drops your
signature from your keyring; the recipient has it by mail.

### status

Shows one line per key: whether it is in the keyring, how many of its valid
UIDs you have signed, and how many mails are in the outbox or have been sent.
With `-v` it also lists every UID with its signed and mail state.

```
   keyid             keyring  signed  outbox  sent  name
x  89ABCDEF01234567  yes      2/2     -       2     Alice Example <alice@example.org>
x  0123456789ABCDEF  no       -       -       -     Carol Example <carol@example.org>
```

The signed count comes from your keyring, so a key deleted by `clean` shows
`no` / `-`; the `sent` column still shows its mails.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

They also run on GitHub Actions (`.github/workflows/tests.yml`) for every
push and pull request, with Python 3.11 to 3.13. The tests run offline in throwaway GnuPG homes with generated keys, a fake
pgpkeys directory, a stubbed network and a fake sendmail. Your keyring is
not touched.

## Files

| Path                         | Purpose                                       |
|------------------------------|-----------------------------------------------|
| `keysign.py`                 | the tool                                      |
| `keysign.toml.example`       | example settings, copy to `keysign.toml`      |
| `tests/test_keysign.py`      | test suite                                    |
| `*.keys`                     | key lists (yours, not tracked by git)         |
| `mail/outbox/`, `mail/sent/` | prepared and sent mails                       |
| `mail/imported`              | keys imported by `fetch`, used by `clean`     |

## License

MIT, see [LICENSE](LICENSE).
