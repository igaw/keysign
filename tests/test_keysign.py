"""Tests for keysign.

Run from the repository root with

    make test

or, with keysign installed (pip install -e .),

    python3 -m unittest discover -s tests -v

Everything runs offline: throwaway GnuPG homes, a fake kernel.org pgpkeys
directory, a stubbed HTTP layer and a fake sendmail.
"""

import contextlib
import email
import email.message
import email.utils
import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from keysign import cli as keysign

PARTICIPANTS = """\
     K E Y S I G N I N G   T E S T

SHA256 Checksum: ____ ____

001  [x] Fingerprint OK        [x] ID OK
pub   ed25519 2026-01-01 [SC]
      {alice_grouped}
uid                      Alice Example <alice@example.org>
uid                      Alice Example <alice@other.example>

_______________________________________________________________________________

002  [ ] Fingerprint OK        [ ] ID OK
pub   r sa4096 2020-01-01 [SC]
      {bob_masked}
uid                      Bob Exa mple <bob@example.org>

_______________________________________________________________________________

003  [x] Fingerprint OK        [ ] ID OK
pub   ed25519 2026-01-01 [SC]
      {carol_grouped}
uid                      Carol <carol@example.org>

_______________________________________________________________________________
"""


def gpg_in(home, *args, input=None):
    return subprocess.run(
        ["gpg", "--batch", "--homedir", str(home), *args],
        input=input,
        capture_output=True,
        check=True,
    ).stdout


def new_home(parent, name):
    home = Path(parent) / name
    home.mkdir(mode=0o700)
    return home


def gen_key(home, uid, *more_uids):
    gpg_in(
        home,
        "--passphrase",
        "",
        "--quick-gen-key",
        uid,
        "default",
        "default",
        "never",
    )
    listing = gpg_in(home, "--with-colons", "--list-keys", uid).decode()
    fpr = next(
        line.split(":")[9]
        for line in listing.splitlines()
        if line.startswith("fpr:")
    )
    for u in more_uids:
        gpg_in(home, "--passphrase", "", "--quick-add-uid", fpr, u)
    return fpr


def grouped(fpr):
    return " ".join(fpr[i : i + 4] for i in range(0, 40, 4))


def kill_agent(home):
    subprocess.run(
        ["gpgconf", "--homedir", str(home), "--kill", "all"],
        capture_output=True,
    )


class KeysignTestCase(unittest.TestCase):
    """Shared fixture: participant keys in SRC, a signer key, a fake net."""

    tmp: Path
    src: Path
    alice: str
    bob: str
    carol: str
    mallory: str
    signer: str
    signer_secret: bytes

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="keysign-test-"))
        cls.src = new_home(cls.tmp, "src")
        cls.alice = gen_key(
            cls.src,
            "Alice Example <alice@example.org>",
            "Alice Example <alice@other.example>",
        )
        cls.bob = gen_key(cls.src, "Bob Example <bob@example.org>")
        cls.carol = gen_key(cls.src, "Carol <carol@example.org>")
        cls.mallory = gen_key(cls.src, "Mallory <alice@example.org>")

        signer_home = new_home(cls.tmp, "signer")
        cls.signer = gen_key(signer_home, "Test Signer <signer@example.net>")
        cls.signer_secret = gpg_in(
            signer_home,
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--export-secret-keys",
            cls.signer,
        )
        kill_agent(signer_home)

    @classmethod
    def tearDownClass(cls):
        kill_agent(cls.src)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=self.tmp))
        self.home = new_home(self.dir, "gnupg")
        gpg_in(self.home, "--import", input=self.signer_secret)
        env = mock.patch.dict(os.environ, {"GNUPGHOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(kill_agent, self.home)

        self.pgpkeys = self.dir / "pgpkeys"
        self.pgpkeys.mkdir()
        self.maildir = self.dir / "mail"

        self.sendlog = self.dir / "sendlog"
        self.sendmail = self.dir / "fakesend"
        self.sendmail.write_text(
            textwrap.dedent(f"""\
            #!/bin/sh
            [ "$1" = fail@example.org ] && {{ echo refused >&2; exit 1; }}
            cat > /dev/null
            echo "$1" >> {self.sendlog}
            """)
        )
        self.sendmail.chmod(0o755)

        self.config = self.dir / "keysign.toml"
        self.config.write_text(
            textwrap.dedent(f"""\
            name = "Test Signer"
            email = "signer@example.net"
            keyid = "{self.signer}"
            sendmail = ["{self.sendmail}"]
            pgpkeys = "{self.pgpkeys}"
            keyservers = ["hkps://ks.test"]
            maildir = "{self.maildir}"
            """)
        )

        # Stub the network: map URL substrings to responses.
        self.net = {}
        net = mock.patch.object(keysign, "http_get", self.fake_http_get)
        net.start()
        self.addCleanup(net.stop)

    def fake_http_get(self, url, label):
        for needle, data in self.net.items():
            if needle in url:
                return data
        return None

    # helpers

    def run_cli(self, *argv):
        """Run keysign with argv; return (stdout, exit status)."""
        out = io.StringIO()
        status: int | str | None = 0
        with (
            mock.patch.object(
                sys, "argv", ["keysign", "-c", str(self.config), *argv]
            ),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            try:
                keysign.main()
            except SystemExit as e:
                status = e.code
        return out.getvalue(), status

    def export(self, fpr):
        return gpg_in(self.src, "--armor", "--export", fpr)

    def publish_kernel_org(self, fpr):
        (self.pgpkeys / f"{fpr[-16:]}.asc").write_bytes(self.export(fpr))

    def write_list(self, *lines):
        path = self.dir / "test.keys"
        path.write_text("".join(line + "\n" for line in lines))
        return path

    def entry(self, fpr, uid, status="x"):
        return f"{status}  {fpr[-16:]}  {fpr}  {uid}"

    def local_fprs(self):
        out = gpg_in(self.home, "--with-colons", "--list-keys").decode()
        return {
            line.split(":")[9]
            for line in out.splitlines()
            if line.startswith("fpr:")
        }

    def signed_uids(self, fpr):
        info = keysign.key_info(fpr, self.signer[-16:])
        return sorted(u["uid"] for u in info["uids"] if u["signed"])


class TestHelpers(unittest.TestCase):
    def test_zbase32_wkd_vector(self):
        # Example from draft-koch-openpgp-webkey-service.
        import hashlib

        h = keysign.zbase32(hashlib.sha1(b"joe.doe").digest())
        self.assertEqual(h, "iy9q119eutrkn8s1mk4r39qejnbu3n5q")

    def test_addr_of(self):
        self.assertEqual(
            keysign.addr_of("Uwe <uwe@kleine-könig.de>"),
            ("Uwe", "uwe@xn--kleine-knig-yfb.de"),
        )
        self.assertEqual(keysign.addr_of("[attribute]"), (None, None))

    def test_unescape(self):
        self.assertEqual(keysign.unescape(r"a\x3ab"), "a:b")
        self.assertEqual(keysign.unescape(r"K\xc3\xb6nig"), "König")

    def test_entry_matches_masked_fingerprint(self):
        fpr = "FDFB31C66E069650D4A0A096B7961F12E964645C"
        e = keysign.Entry("-", fpr[:19] + "__" + fpr[21:], "")
        self.assertFalse(e.complete)
        self.assertTrue(e.matches(fpr))
        self.assertFalse(e.matches("0" + fpr[1:]))
        self.assertEqual(e.keyid, "B7961F12E964645C")

    def test_read_list(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "l"
            fpr = "A46D32705865AA3DDEDC2904B7D2DD275D7EC087"
            p.write_text(
                f"# comment\n\nx  {fpr[-16:]}  {fpr}  Brian <b@x>"
                f"  # trailing\n# x {fpr[-16:]} {fpr} sent\n"
            )
            [e] = keysign.read_list(p)
            self.assertEqual(
                (e.status, e.fpr, e.uid), ("x", fpr, "Brian <b@x>")
            )

            p.write_text(f"x  0000000000000000  {fpr}  bad keyid\n")
            with self.assertRaises(SystemExit):
                keysign.read_list(p)
            p.write_text(f"y  {fpr[-16:]}  {fpr}  bad status\n")
            with self.assertRaises(SystemExit):
                keysign.read_list(p)


class TestConfigLookup(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="keysign-test-"))
        self.addCleanup(shutil.rmtree, self.dir)
        cwd = Path.cwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, cwd)

    def test_xdg_config_home(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg"}):
            self.assertEqual(
                keysign.default_config(),
                Path("/xdg/keysign/keysign.toml"),
            )

    def test_home_config(self):
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                keysign.default_config(),
                Path.home() / ".config/keysign/keysign.toml",
            )

    def test_local_config_wins(self):
        Path("keysign.toml").touch()
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg"}):
            self.assertEqual(keysign.default_config(), Path("keysign.toml"))

    def test_missing_config(self):
        with (
            mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.dir)}),
            mock.patch.object(sys, "argv", ["keysign", "send"]),
            self.assertRaises(SystemExit) as cm,
        ):
            keysign.main()
        self.assertIn("config not found", str(cm.exception.code))

    def test_version(self):
        out = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["keysign", "--version"]),
            contextlib.redirect_stdout(out),
            self.assertRaises(SystemExit),
        ):
            keysign.main()
        self.assertRegex(out.getvalue(), r"^keysign \d+\.\d+")


class TestPgpkeysSetting(KeysignTestCase):
    def config_with(self, pgpkeys):
        text = self.config.read_text()
        text = "\n".join(
            line
            for line in text.splitlines()
            if not line.startswith("pgpkeys")
        )
        if pgpkeys is not None:
            text += f'\npgpkeys = "{pgpkeys}"\n'
        self.config.write_text(text)

    def test_repo_root_with_tilde(self):
        repo = self.dir / "home" / "src" / "pgpkeys"
        (repo / "keys").mkdir(parents=True)
        (repo / "keys" / f"{self.alice[-16:]}.asc").write_bytes(
            self.export(self.alice)
        )
        self.config_with("~/src/pgpkeys")
        lst = self.write_list(self.entry(self.alice, "Alice"))
        with mock.patch.dict(os.environ, {"HOME": str(self.dir / "home")}):
            out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("(kernel.org)", out)

    def test_keys_directory_still_works(self):
        # The fixture points pgpkeys at the keys/ directory itself.
        self.publish_kernel_org(self.alice)
        lst = self.write_list(self.entry(self.alice, "Alice"))
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("(kernel.org)", out)

    def test_unset_skips_kernel_org(self):
        self.publish_kernel_org(self.alice)
        self.config_with(None)
        lst = self.write_list(self.entry(self.alice, "Alice"))
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("MISSING", out)

    def test_missing_repo_warns(self):
        self.config_with(self.dir / "nope")
        lst = self.write_list(self.entry(self.alice, "Alice"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cfg = keysign.Config(self.config)
            cfg.check_pgpkeys()
        self.assertIn("pgpkeys repo not found", err.getvalue())
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("MISSING", out)


class TestParse(KeysignTestCase):
    def test_parse(self):
        bob_masked = grouped(self.bob)
        bob_masked = bob_masked[:23] + "_  _" + bob_masked[26:]
        text = PARTICIPANTS.format(
            alice_grouped=grouped(self.alice),
            bob_masked=bob_masked,
            carol_grouped=grouped(self.carol),
        )
        src = self.dir / "list.txt"
        src.write_text(text)
        out = self.dir / "out.keys"
        stdout, status = self.run_cli("parse", str(src), "-o", str(out))
        self.assertEqual(status, 0)
        self.assertIn("wrote 3 keys", stdout)

        entries = keysign.read_list(out)
        self.assertEqual([e.status for e in entries], ["x", "-", "-"])
        self.assertEqual(entries[0].fpr, self.alice)
        self.assertEqual(entries[0].uid, "Alice Example <alice@example.org>")
        self.assertIn("_", entries[1].fpr)
        self.assertTrue(entries[1].matches(self.bob))
        # Only one box ticked is not verified.
        self.assertEqual(entries[2].fpr, self.carol)


class TestFetch(KeysignTestCase):
    def test_from_kernel_org(self):
        self.publish_kernel_org(self.alice)
        lst = self.write_list(self.entry(self.alice, "Alice"))
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("(kernel.org)", out)
        self.assertIn(self.alice, self.local_fprs())
        self.assertIn(
            self.alice, keysign.read_imported(keysign.Config(self.config))
        )

        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("have", out)

    def test_from_keyserver_with_masked_fingerprint(self):
        masked = self.bob[:19] + "__" + self.bob[21:]
        self.net["0x" + self.bob[-16:]] = self.export(self.bob)
        lst = self.write_list(self.entry(masked, "Bob", "-"))
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("(hkps://ks.test)", out)
        self.assertIn(self.bob, self.local_fprs())

    def test_from_wkd(self):
        self.net[".well-known/openpgpkey"] = self.export(self.carol)
        lst = self.write_list(
            self.entry(self.carol, "Carol <carol@example.org>")
        )
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("(wkd)", out)

    def test_wrong_key_is_not_imported(self):
        # The source returns a different key than the list asks for.
        (self.pgpkeys / f"{self.alice[-16:]}.asc").write_bytes(
            self.export(self.bob)
        )
        lst = self.write_list(self.entry(self.alice, "Alice"))
        out, _ = self.run_cli("fetch", str(lst))
        self.assertIn("MISMATCH", out)
        self.assertIn("MISSING", out)
        self.assertNotIn(self.bob, self.local_fprs())


class SignedFixture(KeysignTestCase):
    def setUp(self):
        super().setUp()
        self.publish_kernel_org(self.alice)
        self.publish_kernel_org(self.bob)
        self.list = self.write_list(
            self.entry(self.alice, "Alice Example <alice@example.org>"),
            self.entry(self.bob, "Bob Example <bob@example.org>", "-"),
        )
        self.run_cli("fetch", str(self.list))


class TestSign(SignedFixture):
    def test_dry_run_signs_nothing(self):
        out, _ = self.run_cli("sign", "-n", str(self.list))
        self.assertIn("would", out)
        self.assertEqual(self.signed_uids(self.alice), [])

    def test_sign_verified_only(self):
        out, _ = self.run_cli("sign", str(self.list))
        self.assertIn("sign ", out)
        self.assertEqual(
            self.signed_uids(self.alice),
            [
                "Alice Example <alice@example.org>",
                "Alice Example <alice@other.example>",
            ],
        )
        self.assertEqual(self.signed_uids(self.bob), [])

        out, _ = self.run_cli("sign", str(self.list))
        self.assertIn("signed", out)

    def test_missing_key(self):
        lst = self.write_list(self.entry(self.carol, "Carol"))
        out, _ = self.run_cli("sign", str(lst))
        self.assertIn("MISSING", out)


class TestPrepareSend(SignedFixture):
    def setUp(self):
        super().setUp()
        self.run_cli("sign", str(self.list))
        self.outbox = self.maildir / "outbox"
        self.sent = self.maildir / "sent"

    def test_one_encrypted_mail_per_uid(self):
        out, _ = self.run_cli("prepare", str(self.list))
        mails = sorted(self.outbox.glob("*.eml"))
        self.assertEqual(len(mails), 2)

        for m in mails:
            msg = email.message_from_bytes(m.read_bytes())
            self.assertEqual(msg.get_content_type(), "multipart/encrypted")
            self.assertIn(self.alice[-16:], msg["Subject"])
            rcpt = email.utils.parseaddr(msg["To"])[1]

            # Alice can decrypt it, and it holds exactly her signed UID.
            parts = msg.get_payload()
            assert isinstance(parts, list)
            body = parts[1]
            assert isinstance(body, email.message.Message)
            enc = body.get_payload(decode=True)
            inner = email.message_from_bytes(
                gpg_in(self.src, "--decrypt", input=enc)
            )
            key = next(
                p
                for p in inner.walk()
                if p.get_content_type() == "application/pgp-keys"
            )
            listing = gpg_in(
                self.src,
                "--with-colons",
                "--show-keys",
                input=key.get_payload(decode=True),
            ).decode()
            uids = [
                line.split(":")[9]
                for line in listing.splitlines()
                if line.startswith("uid:")
            ]
            self.assertEqual(len(uids), 1)
            self.assertIn(f"<{rcpt}>", uids[0])

        out, _ = self.run_cli("prepare", str(self.list))
        self.assertEqual(out.count("exists"), 2)
        self.assertEqual(len(list(self.outbox.glob("*.eml"))), 2)

    def test_send(self):
        self.run_cli("prepare", str(self.list))
        out, _ = self.run_cli("send", "-n")
        self.assertEqual(out.count("would send"), 2)
        self.assertFalse(self.sendlog.exists())

        out, status = self.run_cli("send")
        self.assertEqual(status, 0)
        self.assertEqual(
            sorted(self.sendlog.read_text().split()),
            ["alice@example.org", "alice@other.example"],
        )
        self.assertEqual(list(self.outbox.glob("*.eml")), [])
        self.assertEqual(len(list(self.sent.glob("*.eml"))), 2)

        # Sent mails are not prepared again.
        out, _ = self.run_cli("prepare", str(self.list))
        self.assertEqual(list(self.outbox.glob("*.eml")), [])

    def test_failed_send_stays_in_outbox(self):
        self.outbox.mkdir(parents=True)
        (self.outbox / "X_fail.eml").write_text(
            "To: fail@example.org\nSubject: x\n\nbody\n"
        )
        out, status = self.run_cli("send")
        self.assertNotEqual(status, 0)
        self.assertIn("FAILED", out)
        self.assertTrue((self.outbox / "X_fail.eml").exists())


class TestCleanStatus(SignedFixture):
    def test_clean(self):
        # Carol was in the keyring before keysign fetched anything.
        gpg_in(self.home, "--import", input=self.export(self.carol))
        lst = self.write_list(
            self.entry(self.alice, "Alice"),
            self.entry(self.bob, "Bob", "-"),
            self.entry(self.carol, "Carol", "-"),
        )
        self.run_cli("sign", str(lst))

        # Alice has nothing sent yet: kept. Bob is fetch-only: deleted.
        out, _ = self.run_cli("clean", str(lst))
        self.assertIn(self.alice, self.local_fprs())
        self.assertNotIn(self.bob, self.local_fprs())
        self.assertIn(self.carol, self.local_fprs())
        self.assertIn("was in the keyring before", out)

        self.run_cli("prepare", str(lst))
        out, _ = self.run_cli("clean", str(lst))
        self.assertIn("mails still in outbox", out)
        self.assertIn(self.alice, self.local_fprs())

        self.run_cli("send")
        out, _ = self.run_cli("clean", "-n", str(lst))
        self.assertIn(self.alice, self.local_fprs())
        self.run_cli("clean", str(lst))
        self.assertNotIn(self.alice, self.local_fprs())
        self.assertIn(self.carol, self.local_fprs())
        self.assertIn(self.signer, self.local_fprs())

        self.run_cli("clean", "--all", str(lst))
        self.assertNotIn(self.carol, self.local_fprs())
        self.assertIn(self.signer, self.local_fprs())

    def test_status(self):
        self.run_cli("sign", str(self.list))
        self.run_cli("prepare", str(self.list))
        out, _ = self.run_cli("status", str(self.list))
        alice = next(
            line for line in out.splitlines() if self.alice[-16:] in line
        )
        self.assertEqual(
            alice.split()[:5], ["x", self.alice[-16:], "yes", "2/2", "2"]
        )

        self.run_cli("send")
        out, _ = self.run_cli("status", "-v", str(self.list))
        self.assertEqual(out.count("signed   sent"), 2)


class TestAdd(KeysignTestCase):
    def setUp(self):
        super().setUp()
        self.list = self.dir / "slips.keys"

    def test_add_by_email_is_unverified(self):
        self.net["search=alice%40example.org"] = self.export(self.alice)
        out, _ = self.run_cli("add", "-x", str(self.list), "alice@example.org")
        self.assertIn("added as '-'", out)
        self.assertIn(grouped(self.alice), out)
        [e] = keysign.read_list(self.list)
        self.assertEqual((e.status, e.fpr), ("-", self.alice))
        self.assertEqual(e.uid, "Alice Example <alice@example.org>")

    def test_add_by_email_warns_on_several_keys(self):
        self.net["search=alice%40example.org"] = self.export(
            self.alice
        ) + self.export(self.mallory)
        out, _ = self.run_cli("add", str(self.list), "alice@example.org")
        self.assertIn("WARNING  2 keys", out)
        self.assertEqual(
            {e.fpr for e in keysign.read_list(self.list)},
            {self.alice, self.mallory},
        )

    def test_add_by_full_fingerprint_verified(self):
        self.publish_kernel_org(self.carol)
        self.run_cli("add", "-x", str(self.list), grouped(self.carol))
        [e] = keysign.read_list(self.list)
        self.assertEqual((e.status, e.fpr), ("x", self.carol))

    def test_add_masked_fingerprint_and_duplicates(self):
        self.publish_kernel_org(self.bob)
        masked = self.bob[:19] + "__" + self.bob[21:]
        self.run_cli("add", "-x", str(self.list), masked)
        out, _ = self.run_cli("add", str(self.list), "0x" + self.bob[-16:])
        self.assertIn("exists", out)
        [e] = keysign.read_list(self.list)
        self.assertEqual((e.status, e.fpr), ("-", self.bob))

    def test_add_wrong_fingerprint(self):
        self.publish_kernel_org(self.bob)
        wrong = (
            self.bob[:19]
            + ("0" if self.bob[19] != "0" else "1")
            + self.bob[20:]
        )
        out, _ = self.run_cli("add", str(self.list), wrong)
        self.assertIn("NOTFOUND", out)
        self.assertFalse(self.list.exists())

    def test_add_rejects_garbage(self):
        _, status = self.run_cli("add", str(self.list), "not-a-key")
        self.assertNotEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
