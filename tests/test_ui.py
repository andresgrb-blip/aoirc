import tempfile
import unittest
from pathlib import Path

from ui import (
    ANONOPS_CERT_FINGERPRINTS,
    Config,
    ConfigStore,
    is_sensitive_command,
    parse_names_list,
    parse_irc_line,
    secure_irc_line,
    validate_channel,
    validate_nick,
)


class ProtocolTests(unittest.TestCase):
    def test_parse_privmsg_with_prefix_and_trailing_body(self):
        msg = parse_irc_line(":alice!u@h PRIVMSG #ops :hello there")

        self.assertEqual(msg.prefix, "alice!u@h")
        self.assertEqual(msg.source_nick, "alice")
        self.assertEqual(msg.command, "PRIVMSG")
        self.assertEqual(msg.params, ["#ops", "hello there"])

    def test_ping_parse(self):
        msg = parse_irc_line("PING :irc.anonops.com")

        self.assertEqual(msg.command, "PING")
        self.assertEqual(msg.params, ["irc.anonops.com"])

    def test_parse_names_list_removes_user_prefixes(self):
        self.assertEqual(
            parse_names_list("@alice +bob %carol &dave ~erin frank"),
            {"alice", "bob", "carol", "dave", "erin", "frank"},
        )

    def test_secure_line_removes_crlf(self):
        self.assertEqual(secure_irc_line("JOIN #a\r\nOPER bad"), "JOIN #a  OPER bad")

    def test_secure_line_limits_irc_payload(self):
        self.assertLessEqual(len(secure_irc_line("x" * 900).encode("utf-8")), 510)


class ValidationTests(unittest.TestCase):
    def test_validates_nick(self):
        self.assertEqual(validate_nick("Anon_123"), "Anon_123")
        with self.assertRaises(ValueError):
            validate_nick("1startsWrong")

    def test_validates_channel(self):
        self.assertEqual(validate_channel("#opnewblood"), "#opnewblood")
        with self.assertRaises(ValueError):
            validate_channel("opnewblood")


class ConfigTests(unittest.TestCase):
    def test_defaults_pin_anonops_fingerprints(self):
        cfg = Config()

        self.assertTrue(cfg.use_tls)
        self.assertTrue(cfg.verify_cert_fingerprint)
        self.assertEqual(cfg.port, 6697)
        self.assertEqual(cfg.tls_fingerprints_sha256, list(ANONOPS_CERT_FINGERPRINTS))

    def test_config_store_creates_private_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            store = ConfigStore(path)
            cfg = store.load()

            self.assertTrue(path.exists())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIsInstance(cfg, Config)

    def test_config_rejects_string_booleans(self):
        with self.assertRaises(ValueError):
            Config.from_dict({"use_tls": "false"})

    def test_config_rejects_unknown_tls_version(self):
        with self.assertRaises(ValueError):
            Config.from_dict({"tls_min_version": "SSLv3"})

    def test_config_accepts_nickserv_password(self):
        cfg = Config.from_dict({"nickserv_password": "s3cret", "nickserv_join_delay_seconds": 1})

        self.assertEqual(cfg.nickserv_password, "s3cret")
        self.assertTrue(cfg.nickserv_auto_identify)

    def test_sensitive_commands_are_detected(self):
        self.assertTrue(is_sensitive_command("/identify s3cret"))
        self.assertTrue(is_sensitive_command("/ns identify s3cret"))
        self.assertFalse(is_sensitive_command("/join #opnewblood"))


if __name__ == "__main__":
    unittest.main()
