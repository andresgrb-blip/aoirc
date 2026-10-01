# AOIRC

AOIRC is a small Tkinter IRC client with AnonOps-oriented secure defaults.

## Start

```bash
python3 ui.py
```

## Linux Debian package

The package supports Debian, Ubuntu, and derivatives with Python 3.10 or newer.
It uses system Python and Tkinter and is architecture-independent (`all`),
including x86-64 and ARM64 systems.

Install from the directory containing the package:

```bash
sudo apt install ./aoirc_0.1.0_all.deb
```

Open **AOIRC** from the applications menu. It opens the English Tkinter GUI
without a terminal. The `aoirc` command is also available and accepts the same
options as `ui.py`. A graphical desktop session is required.

Rebuild on Linux or macOS without external build dependencies:

```bash
python3 packaging/build_deb.py
```

The output is `dist/aoirc_0.1.0_all.deb` with a `.deb.sha256` checksum file.
The package contains only the application, launcher, desktop entry, and README;
personal configuration and passwords are never included. Installation does not
connect to IRC or create a user configuration. Configuration is created on first
launch in the user's home directory. Removing the package preserves this file.

The builder follows the [Debian binary package format](https://manpages.debian.org/bookworm/dpkg-dev/deb.5.en.html)
and the launcher follows the [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry/latest/recognized-keys.html).

## Configuration

The first run creates a private config file at:

```text
~/.config/aoirc/config.json
```

Use the top bar to connect, or type commands in the bottom input:

```text
/connect
/join #opnewblood
/msg nick hello
/identify
/nick newnick
/save
/quit
```

If your nickname is registered, put the NickServ password in the top bar before connecting.
AOIRC sends `IDENTIFY` after the IRC welcome and waits briefly before auto-joining saved channels.
The left panel shows channels and private conversations. The right panel shows users for the selected channel; double-click a nick to open a private conversation.

## Security defaults

- Connects to `irc.anonops.com` on port `6697`.
- Uses TLS by default with TLS 1.2 or newer.
- Pins the AnonOps SHA-256 TLS certificate fingerprints because AnonOps uses self-signed certificates.
- Writes config files with mode `0600`.
- Sanitizes outbound IRC lines to prevent CR/LF command injection.
- Avoids storing `/identify` commands in input history.
- Refuses to send to a channel until the server confirms you joined it, which avoids `noexternalmsg` errors caused by speaking before JOIN completes.
- Keeps a live user list from IRC `NAMES`, `JOIN`, `PART`, `QUIT`, and `NICK` messages.
- Does not write chat logs.

IRC is not end-to-end encrypted. TLS protects the connection to the server, but the IRC network can still process messages in the normal IRC way.
# aoirc
