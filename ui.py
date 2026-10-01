#!/usr/bin/env python3
"""AOIRC: a small Tkinter IRC client focused on AnonOps-safe defaults."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import queue
import secrets
import socket
import ssl
import stat
import string
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
from typing import Any


APP_NAME = "aoirc"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / APP_NAME / "config.json"
DEFAULT_SERVER = "irc.anonops.com"
DEFAULT_PORT = 6697
DEFAULT_COMMANDS = (
    "/connect",
    "/disconnect",
    "/join",
    "/part",
    "/msg",
    "/nick",
    "/identify",
    "/ns",
    "/nickserv",
    "/me",
    "/names",
    "/topic",
    "/raw",
    "/save",
    "/help",
    "/quit",
)

TLS_VERSION_MAP = {
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# Published by AnonOps as SHA-256 fingerprints for their self-signed TLS certs.
ANONOPS_CERT_FINGERPRINTS = (
    "FB35FE610F269695729811931632AA93489099BC90BD9F221DAE2B5737136FD1",
    "439832313E1573971C551571399B6D4EF7D65D876480F3A373CB90F33524CABE",
)


def normalize_fingerprint(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch in string.hexdigits.upper())


def secure_irc_line(text: str) -> str:
    """Return one protocol-safe IRC line without CR/LF injection."""
    line = text.replace("\r", " ").replace("\n", " ").strip()
    encoded = line.encode("utf-8")
    if len(encoded) <= 510:
        return line
    return encoded[:510].decode("utf-8", errors="ignore")


def parse_bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"{label} must be a boolean")


def is_sensitive_command(text: str) -> bool:
    lowered = text.strip().lower()
    if lowered.startswith("/identify"):
        return True
    if lowered.startswith("/ns identify") or lowered.startswith("/nickserv identify"):
        return True
    if " nickserv :identify " in lowered or " nickserv identify " in lowered:
        return True
    return False


def parse_names_list(raw_names: str) -> set[str]:
    prefixes = "@+%&~"
    return {
        name.lstrip(prefixes)
        for name in raw_names.split()
        if name and name.lstrip(prefixes)
    }


@dataclasses.dataclass(slots=True)
class Config:
    server: str = DEFAULT_SERVER
    port: int = DEFAULT_PORT
    nick: str = dataclasses.field(
        default_factory=lambda: f"aoirc_{secrets.token_hex(3)}"
    )
    username: str = "aoirc"
    realname: str = "AOIRC"
    channels: list[str] = dataclasses.field(default_factory=list)
    nickserv_password: str = ""
    nickserv_service: str = "NickServ"
    nickserv_auto_identify: bool = True
    nickserv_join_delay_seconds: float = 2.0
    use_tls: bool = True
    tls_min_version: str = "TLSv1.2"
    verify_cert_fingerprint: bool = True
    tls_fingerprints_sha256: list[str] = dataclasses.field(
        default_factory=lambda: list(ANONOPS_CERT_FINGERPRINTS)
    )
    connect_timeout_seconds: float = 15.0
    encoding: str = "utf-8"
    nickname_colors: bool = True
    redact_sensitive_input: bool = True

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        cfg = cls()
        for field in dataclasses.fields(cls):
            if field.name in raw:
                setattr(cfg, field.name, raw[field.name])
        cfg.port = int(cfg.port)
        cfg.server = validate_host(str(cfg.server))
        cfg.nick = validate_nick(str(cfg.nick))
        cfg.username = validate_token(str(cfg.username), "username")
        cfg.realname = str(cfg.realname).replace("\r", " ").replace("\n", " ")[:80]
        cfg.nickserv_password = str(cfg.nickserv_password).replace("\r", "").replace("\n", "")
        cfg.nickserv_service = validate_nick(str(cfg.nickserv_service))
        cfg.nickserv_auto_identify = parse_bool(
            cfg.nickserv_auto_identify, "nickserv_auto_identify"
        )
        cfg.nickserv_join_delay_seconds = float(cfg.nickserv_join_delay_seconds)
        if cfg.nickserv_join_delay_seconds < 0 or cfg.nickserv_join_delay_seconds > 15:
            raise ValueError("nickserv_join_delay_seconds must be between 0 and 15")
        if not isinstance(cfg.channels, list):
            raise ValueError("channels must be a list")
        cfg.channels = [validate_channel(str(channel)) for channel in cfg.channels]
        cfg.use_tls = parse_bool(cfg.use_tls, "use_tls")
        cfg.verify_cert_fingerprint = parse_bool(
            cfg.verify_cert_fingerprint, "verify_cert_fingerprint"
        )
        cfg.nickname_colors = parse_bool(cfg.nickname_colors, "nickname_colors")
        cfg.redact_sensitive_input = parse_bool(
            cfg.redact_sensitive_input, "redact_sensitive_input"
        )
        if cfg.tls_min_version not in TLS_VERSION_MAP:
            raise ValueError("tls_min_version must be TLSv1.2 or TLSv1.3")
        if not isinstance(cfg.tls_fingerprints_sha256, list):
            raise ValueError("tls_fingerprints_sha256 must be a list")
        cfg.tls_fingerprints_sha256 = [
            normalize_fingerprint(str(value)) for value in cfg.tls_fingerprints_sha256
        ]
        if cfg.port < 1 or cfg.port > 65535:
            raise ValueError("port must be between 1 and 65535")
        return cfg

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def validate_host(value: str) -> str:
    host = value.strip()
    if not host or len(host) > 253:
        raise ValueError("server host is invalid")
    allowed = set(string.ascii_letters + string.digits + "-._:")
    if any(ch not in allowed for ch in host):
        raise ValueError("server host contains unsafe characters")
    return host


def validate_token(value: str, label: str) -> str:
    token = value.strip()
    if not token or any(ch.isspace() or ch in "\r\n\0" for ch in token):
        raise ValueError(f"{label} is invalid")
    return token[:32]


def validate_nick(value: str) -> str:
    nick = validate_token(value, "nick")
    allowed_first = set(string.ascii_letters + "[]\\`_^{|}")
    allowed_rest = allowed_first | set(string.digits + "-")
    if nick[0] not in allowed_first or any(ch not in allowed_rest for ch in nick[1:]):
        raise ValueError("nick is invalid for IRC")
    return nick[:30]


def validate_channel(value: str) -> str:
    channel = value.strip()
    if not channel.startswith("#") or any(ch in "\r\n\0 ,:" for ch in channel):
        raise ValueError(f"channel is invalid: {value!r}")
    return channel[:80]


class ConfigStore:
    def __init__(self, path: Path):
        self.path = path.expanduser()

    def load(self) -> Config:
        if not self.path.exists():
            cfg = Config()
            self.save(cfg)
            return cfg
        self._reject_insecure_path()
        with self.path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, dict):
            raise ValueError("configuration root must be an object")
        return Config.from_dict(raw)

    def save(self, cfg: Config) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(cfg.to_dict(), indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=str(self.path.parent), text=True
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def _reject_insecure_path(self) -> None:
        if self.path.is_symlink():
            raise PermissionError(f"refusing symlinked config: {self.path}")
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            os.chmod(self.path, 0o600)


@dataclasses.dataclass(slots=True)
class IRCMessage:
    raw: str
    prefix: str | None
    command: str
    params: list[str]
    trailing: str | None

    @property
    def source_nick(self) -> str | None:
        if not self.prefix:
            return None
        return self.prefix.split("!", 1)[0]


def parse_irc_line(line: str) -> IRCMessage:
    raw = line.rstrip("\r\n")
    rest = raw
    prefix = None
    trailing = None
    if rest.startswith(":"):
        prefix, _, rest = rest[1:].partition(" ")
    if " :" in rest:
        rest, trailing = rest.split(" :", 1)
    parts = rest.split() if rest else []
    command = parts[0].upper() if parts else ""
    params = parts[1:]
    if trailing is not None:
        params.append(trailing)
    return IRCMessage(raw=raw, prefix=prefix, command=command, params=params, trailing=trailing)


@dataclasses.dataclass(slots=True)
class UIEvent:
    kind: str
    text: str
    target: str = "status"
    nick: str | None = None
    data: str | None = None


class IRCConnection:
    def __init__(self, cfg: Config, events: "queue.Queue[UIEvent]"):
        self.cfg = cfg
        self.events = events
        self.sock: socket.socket | ssl.SSLSocket | None = None
        self.file: Any = None
        self.reader: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.connected = False

    def connect(self) -> None:
        self.disconnect("reconnecting")
        self.stop_event.clear()
        raw_sock = socket.create_connection(
            (self.cfg.server, self.cfg.port), timeout=self.cfg.connect_timeout_seconds
        )
        raw_sock.settimeout(None)
        if self.cfg.use_tls:
            sock = self._wrap_tls(raw_sock)
        else:
            sock = raw_sock
        self.sock = sock
        self.file = sock.makefile("r", encoding=self.cfg.encoding, errors="replace", newline="\r\n")
        self.connected = True
        self.send_raw(f"NICK {self.cfg.nick}")
        self.send_raw(f"USER {self.cfg.username} 0 * :{self.cfg.realname}")
        self.reader = threading.Thread(target=self._read_loop, name="aoirc-reader", daemon=True)
        self.reader.start()
        self.events.put(
            UIEvent("system", f"Connected to {self.cfg.server}:{self.cfg.port}", "status")
        )

    def disconnect(self, reason: str = "bye") -> None:
        self.stop_event.set()
        if self.connected:
            try:
                self.send_raw(f"QUIT :{secure_irc_line(reason)}")
            except OSError:
                pass
        with self.lock:
            sock = self.sock
            self.sock = None
            self.file = None
            self.connected = False
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def send_raw(self, line: str) -> None:
        safe = secure_irc_line(line)
        data = f"{safe}\r\n".encode(self.cfg.encoding, errors="replace")
        if len(data) > 512:
            data = data[:510] + b"\r\n"
        with self.lock:
            if self.sock is None:
                raise OSError("not connected")
            self.sock.sendall(data)

    def privmsg(self, target: str, body: str) -> None:
        self.send_raw(f"PRIVMSG {target} :{body}")

    def identify_nickserv(self, password: str | None = None) -> None:
        secret = password if password is not None else self.cfg.nickserv_password
        if not secret:
            raise ValueError("NickServ password is empty")
        service = validate_nick(self.cfg.nickserv_service)
        self.send_raw(f"PRIVMSG {service} :IDENTIFY {secret}")

    def _join_configured_channels(self) -> None:
        if self.stop_event.is_set():
            return
        for channel in self.cfg.channels:
            try:
                self.send_raw(f"JOIN {channel}")
            except OSError as exc:
                self.events.put(UIEvent("error", f"Auto-join failed for {channel}: {exc}", "status"))

    def _wrap_tls(self, raw_sock: socket.socket) -> ssl.SSLSocket:
        context = ssl.create_default_context()
        context.minimum_version = TLS_VERSION_MAP[self.cfg.tls_min_version]
        context.options |= ssl.OP_NO_COMPRESSION
        if self.cfg.verify_cert_fingerprint:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        wrapped = context.wrap_socket(raw_sock, server_hostname=self.cfg.server)
        if self.cfg.verify_cert_fingerprint:
            cert = wrapped.getpeercert(binary_form=True)
            actual = hashlib.sha256(cert).hexdigest().upper()
            expected = {normalize_fingerprint(item) for item in self.cfg.tls_fingerprints_sha256}
            if actual not in expected:
                wrapped.close()
                pretty = ":".join(actual[index : index + 2] for index in range(0, len(actual), 2))
                raise ssl.SSLError(f"TLS fingerprint mismatch: {pretty}")
        return wrapped

    def _read_loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                line = self.file.readline() if self.file else ""
                if not line:
                    break
                msg = parse_irc_line(line)
                if msg.command == "PING" and msg.params:
                    self.send_raw(f"PONG :{msg.params[-1]}")
                    continue
                self._handle_message(msg)
        except OSError as exc:
            if not self.stop_event.is_set():
                self.events.put(UIEvent("error", f"Network error: {exc}", "status"))
        finally:
            self.connected = False
            if not self.stop_event.is_set():
                self.events.put(UIEvent("system", "Disconnected", "status"))

    def _handle_message(self, msg: IRCMessage) -> None:
        if msg.command == "001":
            if self.cfg.nickserv_auto_identify and self.cfg.nickserv_password:
                self.identify_nickserv()
                self.events.put(
                    UIEvent(
                        "system",
                        f"Sent IDENTIFY to {self.cfg.nickserv_service}; waiting before auto-join.",
                        "status",
                    )
                )
                if self.cfg.channels:
                    timer = threading.Timer(
                        self.cfg.nickserv_join_delay_seconds,
                        self._join_configured_channels,
                    )
                    timer.daemon = True
                    timer.start()
            else:
                self._join_configured_channels()
            self.events.put(UIEvent("system", msg.params[-1] if msg.params else msg.raw, "status"))
            return
        if msg.command == "404":
            channel = msg.params[1] if len(msg.params) > 1 else "status"
            reason = msg.params[-1] if msg.params else msg.raw
            self.events.put(
                UIEvent(
                    "error",
                    f"Server refused message to {channel}: {reason}. Join confirmation is required before speaking.",
                    channel,
                )
            )
            return
        if msg.command == "JOIN":
            channel = msg.params[0] if msg.params else "status"
            nick = msg.source_nick
            self.events.put(UIEvent("join", f"{nick or '*'} joined {channel}", channel, nick))
            return
        if msg.command == "PART":
            channel = msg.params[0] if msg.params else "status"
            nick = msg.source_nick
            self.events.put(UIEvent("part", f"{nick or '*'} left {channel}", channel, nick))
            return
        if msg.command == "QUIT":
            nick = msg.source_nick
            self.events.put(UIEvent("quit", f"{nick or '*'} quit", "status", nick))
            return
        if msg.command == "NICK":
            old_nick = msg.source_nick
            new_nick = msg.params[-1].lstrip(":") if msg.params else None
            if old_nick and new_nick:
                self.events.put(
                    UIEvent("nick", f"{old_nick} is now known as {new_nick}", "status", old_nick, new_nick)
                )
            return
        if msg.command == "353":
            channel = msg.params[2] if len(msg.params) > 2 else "status"
            users = msg.params[-1] if msg.params else ""
            self.events.put(UIEvent("names", f"Users in {channel}: {users}", channel))
            return
        if msg.command == "332":
            channel = msg.params[1] if len(msg.params) > 1 else "status"
            topic = msg.params[-1] if msg.params else ""
            self.events.put(UIEvent("topic", f"Topic for {channel}: {topic}", channel))
            return
        if msg.command == "PRIVMSG" and len(msg.params) >= 2:
            target, body = msg.params[0], msg.params[1]
            display_target = msg.source_nick if target == self.cfg.nick else target
            nick = msg.source_nick or "?"
            if body.startswith("\x01ACTION ") and body.endswith("\x01"):
                text = f"* {nick} {body[8:-1]}"
            else:
                text = f"<{nick}> {body}"
            self.events.put(UIEvent("message", text, display_target, nick))
            return
        if msg.command == "NOTICE" and len(msg.params) >= 2:
            self.events.put(UIEvent("notice", f"-{msg.source_nick or 'notice'}- {msg.params[1]}", "status"))
            return
        self.events.put(UIEvent("raw", msg.raw, "status", msg.source_nick))


class TkClient:
    def __init__(self, cfg: Config, store: ConfigStore):
        self.cfg = cfg
        self.store = store
        self.events: "queue.Queue[UIEvent]" = queue.Queue()
        self.conn = IRCConnection(cfg, self.events)
        self.buffers: dict[str, list[tuple[str, str | None]]] = {"status": []}
        self.users: dict[str, set[str]] = {}
        self.joined_channels: set[str] = set()
        self.current = "status"
        self.history: list[str] = []
        self.history_index: int | None = None
        self.status = "Ready. /connect to start, /help for commands."
        self.root = tk.Tk()
        self.target_list: tk.Listbox
        self.user_list: tk.Listbox
        self.output: ScrolledText
        self.input_var = tk.StringVar()
        self.status_var = tk.StringVar(value=self.status)
        self.server_var = tk.StringVar(value=self.cfg.server)
        self.port_var = tk.StringVar(value=str(self.cfg.port))
        self.nick_var = tk.StringVar(value=self.cfg.nick)
        self.nickserv_password_var = tk.StringVar(value=self.cfg.nickserv_password)

    def run(self) -> None:
        self._build_ui()
        self._append("status", self.status, None)
        self.root.after(100, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.mainloop()

    def _build_ui(self) -> None:
        self.root.title("AOIRC - AnonOps IRC")
        self.root.minsize(900, 560)
        self.root.configure(bg="#050505")

        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Ao.TFrame", background="#050505")
        style.configure("Ao.TLabel", background="#050505", foreground="#ff4444")
        style.configure("Ao.TButton", background="#1a1a1a", foreground="#ff5555")
        style.configure("Ao.TEntry", fieldbackground="#0b0b0b", foreground="#ff5555")

        top = ttk.Frame(self.root, style="Ao.TFrame", padding=(10, 8))
        top.pack(fill=tk.X)

        ttk.Label(top, text="Server", style="Ao.TLabel").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.server_var, width=28, style="Ao.TEntry").pack(
            side=tk.LEFT, padx=(6, 12)
        )
        ttk.Label(top, text="Port", style="Ao.TLabel").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.port_var, width=7, style="Ao.TEntry").pack(
            side=tk.LEFT, padx=(6, 12)
        )
        ttk.Label(top, text="Nick", style="Ao.TLabel").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.nick_var, width=18, style="Ao.TEntry").pack(
            side=tk.LEFT, padx=(6, 12)
        )
        ttk.Label(top, text="NickServ", style="Ao.TLabel").pack(side=tk.LEFT)
        ttk.Entry(
            top,
            textvariable=self.nickserv_password_var,
            width=18,
            show="*",
            style="Ao.TEntry",
        ).pack(side=tk.LEFT, padx=(6, 12))
        ttk.Button(top, text="Connect", command=self._connect_from_toolbar, style="Ao.TButton").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(top, text="Disconnect", command=lambda: self._run_command("/disconnect"), style="Ao.TButton").pack(
            side=tk.LEFT
        )

        body = ttk.Frame(self.root, style="Ao.TFrame")
        body.pack(fill=tk.BOTH, expand=True)

        self.target_list = tk.Listbox(
            body,
            bg="#080808",
            fg="#ff4444",
            selectbackground="#330000",
            selectforeground="#ffffff",
            highlightthickness=0,
            relief=tk.FLAT,
            activestyle="none",
            width=22,
        )
        self.target_list.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0), pady=(0, 8))
        self.target_list.bind("<<ListboxSelect>>", self._select_target)

        self.output = ScrolledText(
            body,
            bg="#000000",
            fg="#ff3333",
            insertbackground="#ff5555",
            selectbackground="#550000",
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=12,
            pady=10,
            state=tk.DISABLED,
        )
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.output.tag_config("system", foreground="#ffcc66")
        self.output.tag_config("self", foreground="#ffffff")
        self.output.tag_config("nick0", foreground="#ff5555")
        self.output.tag_config("nick1", foreground="#66d9ef")
        self.output.tag_config("nick2", foreground="#a6e22e")
        self.output.tag_config("nick3", foreground="#f92672")

        users_frame = ttk.Frame(body, style="Ao.TFrame")
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=(0, 8))
        ttk.Label(users_frame, text="Users", style="Ao.TLabel").pack(anchor=tk.W, pady=(0, 6))
        self.user_list = tk.Listbox(
            users_frame,
            bg="#080808",
            fg="#ff4444",
            selectbackground="#330000",
            selectforeground="#ffffff",
            highlightthickness=0,
            relief=tk.FLAT,
            activestyle="none",
            width=22,
        )
        self.user_list.pack(fill=tk.BOTH, expand=True)
        self.user_list.bind("<Double-Button-1>", self._open_query_from_user)

        bottom = ttk.Frame(self.root, style="Ao.TFrame", padding=(10, 0, 10, 8))
        bottom.pack(fill=tk.X)
        prompt = ttk.Label(bottom, textvariable=self.status_var, style="Ao.TLabel")
        prompt.pack(fill=tk.X, pady=(0, 6))
        entry = ttk.Entry(bottom, textvariable=self.input_var, style="Ao.TEntry")
        entry.pack(fill=tk.X)
        entry.bind("<Return>", self._submit_input)
        entry.bind("<Up>", lambda _event: self._history(-1))
        entry.bind("<Down>", lambda _event: self._history(1))
        entry.bind("<Tab>", self._autocomplete)
        entry.focus_set()

        self._refresh_targets()
        self._refresh_users()

    def _submit_input(self, _event: Any = None) -> str | None:
        text = self.input_var.get().strip()
        self.input_var.set("")
        self.history_index = None
        if not text:
            return None
        if not (self.cfg.redact_sensitive_input and is_sensitive_command(text)):
            self.history.append(text)
        self._run_command(text)
        return None

    def _run_command(self, text: str) -> None:
        try:
            if text.startswith("/"):
                self._command(text)
            else:
                self._send_message(self.current, text)
        except (OSError, ValueError, ssl.SSLError) as exc:
            self._append("status", f"Error: {exc}", None)
            self._set_status(f"Error: {exc}")

    def _history(self, direction: int) -> str:
        if not self.history:
            return "break"
        if self.history_index is None:
            self.history_index = len(self.history)
        self.history_index = min(len(self.history), max(0, self.history_index + direction))
        text = "" if self.history_index == len(self.history) else self.history[self.history_index]
        self.input_var.set(text)
        return "break"

    def _autocomplete(self, _event: Any = None) -> str:
        text = self.input_var.get()
        try:
            cursor = self.root.focus_get().index(tk.INSERT)
        except (AttributeError, tk.TclError):
            cursor = len(text)
        before = text[:cursor]
        token = before.split()[-1] if before.split() else before
        options = (
            list(DEFAULT_COMMANDS)
            if token.startswith("/")
            else sorted(self.users.get(self.current, set()))
        )
        matches = [option for option in options if option.startswith(token)]
        if len(matches) == 1:
            replacement = matches[0]
            start = len(before) - len(token)
            new_text = text[:start] + replacement + text[cursor:]
            self.input_var.set(new_text)
            self.root.focus_get().icursor(start + len(replacement))
        elif matches:
            self._append("status", "Matches: " + ", ".join(matches[:12]), None)
        return "break"

    def _command(self, text: str) -> None:
        cmd, _, rest = text.partition(" ")
        cmd = cmd.lower()
        rest = rest.strip()
        if cmd == "/connect":
            self._connect_from_toolbar()
        elif cmd == "/disconnect":
            self.conn.disconnect("disconnect")
            self.joined_channels.clear()
            self.users.clear()
            self._refresh_users()
            self._set_status("Disconnected")
        elif cmd == "/join":
            channel = validate_channel(rest)
            self.conn.send_raw(f"JOIN {channel}")
            self.current = channel
            self.buffers.setdefault(channel, [])
            if channel not in self.cfg.channels:
                self.cfg.channels.append(channel)
            self._append(channel, f"Joining {channel}; wait for server confirmation before speaking.", None)
            self._refresh_targets()
            self._render_current()
        elif cmd == "/part":
            channel = validate_channel(rest or self.current)
            self.conn.send_raw(f"PART {channel}")
            if channel in self.cfg.channels:
                self.cfg.channels.remove(channel)
        elif cmd == "/msg":
            target, _, body = rest.partition(" ")
            if not target or not body:
                raise ValueError("usage: /msg <nick|#channel> <message>")
            self._send_message(target, body)
        elif cmd == "/me":
            if self.current == "status":
                raise ValueError("choose a channel or nick first")
            self._send_message(self.current, f"\x01ACTION {rest}\x01", action=True)
        elif cmd == "/nick":
            nick = validate_nick(rest)
            self.conn.send_raw(f"NICK {nick}")
            self.cfg.nick = nick
            self.nick_var.set(nick)
        elif cmd == "/identify":
            secret = rest or self.nickserv_password_var.get()
            self.cfg.nickserv_password = secret
            self.conn.identify_nickserv(secret)
            self._append("status", f"Sent IDENTIFY to {self.cfg.nickserv_service}.", None)
        elif cmd in {"/ns", "/nickserv"}:
            if not rest:
                raise ValueError(f"usage: {cmd} <NickServ command>")
            self.conn.privmsg(self.cfg.nickserv_service, rest)
            self._append("status", f"Sent command to {self.cfg.nickserv_service}.", None)
        elif cmd == "/names":
            target = validate_channel(rest or self.current)
            self.conn.send_raw(f"NAMES {target}")
        elif cmd == "/topic":
            target = validate_channel(rest or self.current)
            self.conn.send_raw(f"TOPIC {target}")
        elif cmd == "/raw":
            if not rest:
                raise ValueError("usage: /raw <IRC command>")
            self.conn.send_raw(rest)
        elif cmd == "/save":
            self.store.save(self.cfg)
            self._append("status", f"Saved config to {self.store.path}", None)
        elif cmd == "/help":
            self._show_help()
        elif cmd == "/quit":
            self._close()
        else:
            raise ValueError(f"unknown command: {cmd}")

    def _send_message(self, target: str, body: str, action: bool = False) -> None:
        if target == "status":
            raise ValueError("choose a channel or use /msg <target> <message>")
        safe_target = validate_channel(target) if target.startswith("#") else validate_nick(target)
        if safe_target.startswith("#") and safe_target not in self.joined_channels:
            raise ValueError(
                f"not joined to {safe_target} yet; wait for JOIN confirmation to avoid noexternalmsg"
            )
        self.conn.privmsg(safe_target, body)
        if action:
            display = f"* {self.cfg.nick} {body[8:-1]}"
        else:
            display = f"<{self.cfg.nick}> {body}"
        self._append(safe_target, display, self.cfg.nick)

    def _show_help(self) -> None:
        self._append(
            "status",
            "Commands: /connect /join #chan /part [#chan] /msg target text /nick nick /names /topic /raw /save /quit",
            None,
        )
        self._append(
            "status",
            "Security: TLS is on by default; AnonOps SHA-256 certificate fingerprints are pinned in config.",
            None,
        )

    def _drain_events(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                return
            self._append(event.target, event.text, event.nick)
            if event.kind == "join" and event.nick:
                self.users.setdefault(event.target, set()).add(event.nick)
                if event.nick == self.cfg.nick:
                    self.joined_channels.add(event.target)
                    self._set_status(f"Joined {event.target}")
            elif event.kind == "names":
                _, _, names = event.text.partition(": ")
                self.users.setdefault(event.target, set()).update(parse_names_list(names))
            elif event.kind in {"part", "quit"} and event.nick:
                if event.kind == "part" and event.nick == self.cfg.nick:
                    self.joined_channels.discard(event.target)
                    self.users.pop(event.target, None)
                elif event.kind == "quit" and event.nick == self.cfg.nick:
                    self.joined_channels.clear()
                    self.users.clear()
                else:
                    for names in self.users.values():
                        names.discard(event.nick)
            elif event.kind == "nick" and event.nick and event.data:
                for names in self.users.values():
                    if event.nick in names:
                        names.discard(event.nick)
                        names.add(event.data)
                if event.nick == self.cfg.nick:
                    self.cfg.nick = event.data
                    self.nick_var.set(event.data)
            self._set_status(event.text[:160])
            self._refresh_users()

    def _append(self, target: str, text: str, nick: str | None) -> None:
        clean = text.replace("\r", " ").replace("\n", " ")
        self.buffers.setdefault(target, []).append((f"{time.strftime('%H:%M')} {clean}", nick))
        self.buffers[target] = self.buffers[target][-1000:]
        self._refresh_targets()
        if target == self.current:
            self._render_current()

    def _connect_from_toolbar(self) -> None:
        try:
            self.cfg.server = validate_host(self.server_var.get())
            self.cfg.port = int(self.port_var.get())
            if self.cfg.port < 1 or self.cfg.port > 65535:
                raise ValueError("port must be between 1 and 65535")
            self.cfg.nick = validate_nick(self.nick_var.get())
            self.cfg.nickserv_password = self.nickserv_password_var.get().replace("\r", "").replace("\n", "")
        except ValueError as exc:
            self._append("status", f"Error: {exc}", None)
            self._set_status(f"Error: {exc}")
            return
        self.joined_channels.clear()
        self.users.clear()
        self._refresh_users()
        self._set_status(f"Connecting to {self.cfg.server}:{self.cfg.port} ...")
        threading.Thread(target=self._connect_worker, name="aoirc-connect", daemon=True).start()

    def _connect_worker(self) -> None:
        try:
            self.conn.connect()
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.events.put(UIEvent("error", f"Connect failed: {exc}", "status"))

    def _poll_events(self) -> None:
        self._drain_events()
        self.root.after(100, self._poll_events)

    def _refresh_targets(self) -> None:
        targets = list(self.buffers)
        current_selection = self.current
        self.target_list.delete(0, tk.END)
        for target in targets:
            self.target_list.insert(tk.END, target)
        if current_selection in targets:
            index = targets.index(current_selection)
            self.target_list.selection_set(index)
            self.target_list.activate(index)

    def _refresh_users(self) -> None:
        self.user_list.delete(0, tk.END)
        if not self.current.startswith("#"):
            return
        for nick in sorted(self.users.get(self.current, set()), key=str.casefold):
            self.user_list.insert(tk.END, nick)

    def _render_current(self) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        for text, nick in self.buffers.setdefault(self.current, []):
            tag = self._tag_for_nick(nick)
            self.output.insert(tk.END, text + "\n", tag)
        self.output.configure(state=tk.DISABLED)
        self.output.see(tk.END)

    def _select_target(self, _event: Any) -> None:
        selection = self.target_list.curselection()
        if not selection:
            return
        self.current = self.target_list.get(selection[0])
        self._set_status(f"Current target: {self.current}")
        self._render_current()
        self._refresh_users()

    def _open_query_from_user(self, _event: Any) -> None:
        selection = self.user_list.curselection()
        if not selection:
            return
        nick = self.user_list.get(selection[0])
        if not nick or nick == self.cfg.nick:
            return
        self.buffers.setdefault(nick, [])
        self.current = nick
        self._refresh_targets()
        self._render_current()
        self._refresh_users()
        self._set_status(f"Current target: {nick}")

    def _tag_for_nick(self, nick: str | None) -> str:
        if not nick:
            return "system"
        if nick == self.cfg.nick:
            return "self"
        if not self.cfg.nickname_colors:
            return "nick0"
        return f"nick{sum(nick.encode('utf-8')) % 4}"

    def _set_status(self, text: str) -> None:
        self.status = text
        self.status_var.set(text)

    def _close(self) -> None:
        self.conn.disconnect("client closed")
        self.root.destroy()


def load_config(path: Path) -> tuple[ConfigStore, Config]:
    store = ConfigStore(path)
    return store, store.load()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AOIRC minimal secure IRC client")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"config JSON path (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument("--server", help="override configured IRC server")
    parser.add_argument("--port", type=int, help="override configured IRC port")
    parser.add_argument("--nick", help="override configured IRC nickname")
    parser.add_argument("--no-tls-pin", action="store_true", help="use normal CA validation instead of fingerprint pinning")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    store, cfg = load_config(args.config)
    if args.server:
        cfg.server = validate_host(args.server)
    if args.port:
        cfg.port = args.port
    if args.nick:
        cfg.nick = validate_nick(args.nick)
    if args.no_tls_pin:
        cfg.verify_cert_fingerprint = False
    TkClient(cfg, store).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
