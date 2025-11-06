# KCP Protocol Dissector for Wireshark

[日本語](#日本語説明) | [English](#english)

## English

### Overview

This is a Wireshark dissector (decoder) for the KCP protocol. KCP is a fast and reliable ARQ (Automatic Repeat-reQuest) protocol that runs on top of UDP.

KCP Protocol Reference: https://github.com/skywind3000/kcp

### Features

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

### Installation

#### Method 1: User Plugin Directory (Recommended)

1. Locate your Wireshark personal plugins directory:
   - **Windows**: `%APPDATA%\Wireshark\plugins`
   - **Linux/Unix**: `~/.local/lib/wireshark/plugins`
   - **macOS**: `~/.local/lib/wireshark/plugins`

2. Copy `kcp_dissector.lua` to this directory

3. Restart Wireshark or reload Lua plugins (Ctrl+Shift+L)

#### Method 2: Global Plugin Directory

1. Locate Wireshark's global plugins directory:
   - Run Wireshark and go to: Help → About Wireshark → Folders → Personal Plugins

2. Copy `kcp_dissector.lua` to the global plugins directory

3. Restart Wireshark

### Usage

#### Automatic Detection

The dissector includes a heuristic analyzer that automatically detects KCP traffic based on:
- Valid command field (81-84)
- Reasonable packet length
- Proper packet structure

#### Manual Port Configuration

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

#### Modifying Default Ports

Edit the `kcp_ports` table in `kcp_dissector.lua`:

```lua
local kcp_ports = {4000, 4001, 4002, 4003, 4004, 4005, 9999, 10000}
```

Add or remove ports as needed, then reload the Lua plugins.

### Protocol Structure

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

### Troubleshooting

**Dissector not loading:**
- Check Wireshark's Lua plugin path: Help → About Wireshark → Folders
- Look for errors: Analyze → Reload Lua Plugins (Ctrl+Shift+L)
- Check the Wireshark console for error messages

**KCP packets not decoded:**
- Verify the UDP port matches your application
- Use "Decode As..." to manually assign the protocol
- Check that packet structure matches KCP format

### License

This dissector is provided as-is for educational and analysis purposes.

---

## 日本語説明

### 概要

これはWireshark用のKCPプロトコルディセクタ（デコーダ）です。KCPはUDP上で動作する高速で信頼性の高いARQ（自動再送要求）プロトコルです。

KCPプロトコルリファレンス: https://github.com/skywind3000/kcp

### 機能

- 以下を含むKCPプロトコルヘッダーのデコード:
  - 会話ID (conv)
  - コマンドタイプ (cmd): PUSH、ACK、WASK、WINS
  - フラグメント番号 (frg)
  - ウィンドウサイズ (wnd)
  - タイムスタンプ (ts)
  - シーケンス番号 (sn)
  - 未確認シーケンス番号 (una)
  - データ長 (len)
  - ペイロードデータ
- 単一のUDPデータグラム内の複数のKCPセグメントをサポート
- 自動プロトコル検出のためのヒューリスティックディセクタ
- 設定可能なUDPポート関連付け

### インストール方法

#### 方法1: ユーザープラグインディレクトリ（推奨）

1. Wiresharkの個人用プラグインディレクトリを確認:
   - **Windows**: `%APPDATA%\Wireshark\plugins`
   - **Linux/Unix**: `~/.local/lib/wireshark/plugins`
   - **macOS**: `~/.local/lib/wireshark/plugins`

2. `kcp_dissector.lua`をこのディレクトリにコピー

3. Wiresharkを再起動、またはLuaプラグインをリロード（Ctrl+Shift+L）

#### 方法2: グローバルプラグインディレクトリ

1. Wiresharkのグローバルプラグインディレクトリを確認:
   - Wiresharkを起動し、ヘルプ → Wiresharkについて → フォルダ → Personal Plugins

2. `kcp_dissector.lua`をグローバルプラグインディレクトリにコピー

3. Wiresharkを再起動

### 使用方法

#### 自動検出

ディセクタには以下に基づいてKCPトラフィックを自動検出するヒューリスティック解析が含まれています:
- 有効なコマンドフィールド（81-84）
- 妥当なパケット長
- 適切なパケット構造

#### 手動ポート設定

デフォルトでは、以下のUDPポートに対してディセクタが登録されています:
- 4000-4005
- 9999
- 10000

異なるポートでKCPをデコードする場合:
1. UDPパケットを右クリック
2. 「デコード方法...」を選択
3. 「UDPポート」とポート番号を選択
4. プロトコルとして「KCP」を選択
5. 「OK」をクリック

#### デフォルトポートの変更

`kcp_dissector.lua`の`kcp_ports`テーブルを編集:

```lua
local kcp_ports = {4000, 4001, 4002, 4003, 4004, 4005, 9999, 10000}
```

必要に応じてポートを追加または削除し、Luaプラグインをリロードします。

### プロトコル構造

KCPヘッダーフォーマット（24バイト）:

```
+---------------+---------------+---------------+---------------+
|                       conv (4バイト)                          |
+---------------+---------------+---------------+---------------+
|      cmd      |      frg      |          wnd (2バイト)        |
+---------------+---------------+---------------+---------------+
|                        ts (4バイト)                           |
+---------------+---------------+---------------+---------------+
|                        sn (4バイト)                           |
+---------------+---------------+---------------+---------------+
|                       una (4バイト)                           |
+---------------+---------------+---------------+---------------+
|                       len (4バイト)                           |
+---------------+---------------+---------------+---------------+
|                    data (可変長)                              |
+---------------+---------------+---------------+---------------+
```

コマンドタイプ:
- 81 (0x51): PUSH - データセグメント
- 82 (0x52): ACK - 確認応答
- 83 (0x53): WASK - ウィンドウ問い合わせ
- 84 (0x54): WINS - ウィンドウサイズ

### トラブルシューティング

**ディセクタが読み込まれない:**
- WiresharkのLuaプラグインパスを確認: ヘルプ → Wiresharkについて → フォルダ
- エラーを確認: 分析 → Luaプラグインをリロード（Ctrl+Shift+L）
- Wiresharkコンソールでエラーメッセージを確認

**KCPパケットがデコードされない:**
- UDPポートがアプリケーションと一致しているか確認
- 「デコード方法...」を使用して手動でプロトコルを割り当て
- パケット構造がKCPフォーマットと一致しているか確認

### ライセンス

このディセクタは教育および解析目的でそのまま提供されています。
