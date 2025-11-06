# KCP Protocol Dissector for Wireshark

[日本語版はこちら (Japanese)](README_ja.md)

## Overview

This is a Wireshark dissector (decoder) for the KCP protocol. KCP is a fast and reliable ARQ (Automatic Repeat-reQuest) protocol that runs on top of UDP.

KCP Protocol Reference: https://github.com/skywind3000/kcp

## Features

- Decodes KCP protocol headers including:
  - Conversation ID (conv)
  - Command type (cmd): PUSH, ACK, WASK, WINS
  - Fragment number (frg)
  - Window size (wnd)
  - Timestamp (ts)
  - Sequence number (sn)
  - Unacknowledged sequence number (una)
  - Data length (len)
  - Payload data
- Supports multiple KCP segments in a single UDP datagram
- Heuristic dissector for automatic protocol detection
- Configurable UDP port associations

## Installation

### Method 1: User Plugin Directory (Recommended)

1. Locate your Wireshark personal plugins directory:
   - **Windows**: `%APPDATA%\Wireshark\plugins`
   - **Linux/Unix**: `~/.local/lib/wireshark/plugins`
   - **macOS**: `~/.local/lib/wireshark/plugins`

2. Copy `kcp_dissector.lua` to this directory

3. Restart Wireshark or reload Lua plugins (Ctrl+Shift+L)

### Method 2: Global Plugin Directory

1. Locate Wireshark's global plugins directory:
   - Run Wireshark and go to: Help → About Wireshark → Folders → Personal Plugins

2. Copy `kcp_dissector.lua` to the global plugins directory

3. Restart Wireshark

## Usage

### Automatic Detection

The dissector includes a heuristic analyzer that automatically detects KCP traffic based on:
- Valid command field (81-84)
- Reasonable packet length
- Proper packet structure

### Manual Port Configuration

By default, the dissector is registered for these UDP ports:
- 4000-4005
- 9999
- 10000

To decode KCP on a different port:
1. Right-click on a UDP packet
2. Select "Decode As..."
3. Select "UDP port" and your port number
4. Select "KCP" as the protocol
5. Click "OK"

### Modifying Default Ports

Edit the `kcp_ports` table in `kcp_dissector.lua`:

```lua
local kcp_ports = {4000, 4001, 4002, 4003, 4004, 4005, 9999, 10000}
```

Add or remove ports as needed, then reload the Lua plugins.

## Protocol Structure

KCP header format (24 bytes):

```
+---------------+---------------+---------------+---------------+
|                       conv (4 bytes)                          |
+---------------+---------------+---------------+---------------+
|      cmd      |      frg      |          wnd (2 bytes)        |
+---------------+---------------+---------------+---------------+
|                        ts (4 bytes)                           |
+---------------+---------------+---------------+---------------+
|                        sn (4 bytes)                           |
+---------------+---------------+---------------+---------------+
|                       una (4 bytes)                           |
+---------------+---------------+---------------+---------------+
|                       len (4 bytes)                           |
+---------------+---------------+---------------+---------------+
|                    data (variable length)                     |
+---------------+---------------+---------------+---------------+
```

Command types:
- 81 (0x51): PUSH - Data segment
- 82 (0x52): ACK - Acknowledgment
- 83 (0x53): WASK - Window Ask
- 84 (0x54): WINS - Window Size

## Troubleshooting

**Dissector not loading:**
- Check Wireshark's Lua plugin path: Help → About Wireshark → Folders
- Look for errors: Analyze → Reload Lua Plugins (Ctrl+Shift+L)
- Check the Wireshark console for error messages

**KCP packets not decoded:**
- Verify the UDP port matches your application
- Use "Decode As..." to manually assign the protocol
- Check that packet structure matches KCP format

## License

This dissector is provided as-is for educational and analysis purposes.
