# Wireshark Luaディセクタ開発ガイド

[English version is here](DEVELOPMENT.md)

## 目次
1. [はじめに](#はじめに)
2. [前提条件](#前提条件)
3. [基本構造](#基本構造)
4. [プロトコルの宣言](#プロトコルの宣言)
5. [フィールドの定義](#フィールドの定義)
6. [ディセクタ関数](#ディセクタ関数)
7. [ポート登録](#ポート登録)
8. [ヒューリスティックディセクタ](#ヒューリスティックディセクタ)
9. [デバッグ方法](#デバッグ方法)
10. [ベストプラクティス](#ベストプラクティス)
11. [API リファレンス](#apiリファレンス)

## はじめに

WiresharkはLuaで記述されたプロトコルディセクタをサポートしており、Cコードをコンパイルすることなく独自プロトコルをデコードできます。このガイドでは、KCPディセクタを実例として、Luaディセクタの作成方法を解説します。

### Luaディセクタを使う理由

- **コンパイル不要**: すぐに記述してテスト可能
- **クロスプラットフォーム**: Windows、Linux、macOSで動作
- **迅速なプロトタイピング**: 開発中の素早い反復が可能
- **共有が簡単**: 単一の`.lua`ファイルで配布可能

## 前提条件

### 必要な知識

- Luaプログラミングの基礎知識
- ネットワークプロトコルの基本的な理解
- デコードしたいプロトコルの仕様理解

### ツール

- Wireshark（バージョン3.0以降を推奨）
- Luaコード用のテキストエディタ
- テスト用のサンプルパケットキャプチャ（PCAPファイル）

## 基本構造

典型的なWireshark Luaディセクタは以下の構造を持ちます：

```lua
-- 1. プロトコルの宣言
local my_proto = Proto("MYPROTO", "My Protocol")

-- 2. フィールドの定義
local f = my_proto.fields
f.field1 = ProtoField.uint32("myproto.field1", "Field 1", base.HEX)

-- 3. ディセクタ関数
function my_proto.dissector(buffer, pinfo, tree)
    -- パケット解析ロジック
end

-- 4. ポート登録
local udp_table = DissectorTable.get("udp.port")
udp_table:add(12345, my_proto)

-- 5. （オプション）ヒューリスティックディセクタ
function my_proto.heuristic(buffer, pinfo, tree)
    -- 自動検出ロジック
end
my_proto:register_heuristic("udp", my_proto.heuristic)
```

## プロトコルの宣言

### プロトコルの作成

`Proto`コンストラクタを使用してプロトコルを宣言します：

```lua
local proto_name = Proto(short_name, description)
```

**パラメータ:**
- `short_name`: フィルタで使用する短縮名（例: "kcp"、"http"）
- `description`: UIに表示される人間が読める説明

**例:**
```lua
local kcp_proto = Proto("KCP", "KCP Protocol")
```

これにより、ユーザーは次のようにパケットをフィルタできます: `kcp` または `kcp.conv == 0x12345678`

## フィールドの定義

### フィールドタイプ

Wiresharkは`ProtoField`を通じて様々なフィールドタイプを提供します：

```lua
local f = my_proto.fields

-- 整数型
f.uint8_field  = ProtoField.uint8("proto.field",  "説明", base.DEC)
f.uint16_field = ProtoField.uint16("proto.field", "説明", base.DEC)
f.uint32_field = ProtoField.uint32("proto.field", "説明", base.DEC)
f.uint64_field = ProtoField.uint64("proto.field", "説明", base.DEC)

-- 符号付き整数
f.int8_field   = ProtoField.int8("proto.field",   "説明", base.DEC)
f.int16_field  = ProtoField.int16("proto.field",  "説明", base.DEC)
f.int32_field  = ProtoField.int32("proto.field",  "説明", base.DEC)

-- その他のタイプ
f.string_field = ProtoField.string("proto.field", "説明")
f.bytes_field  = ProtoField.bytes("proto.field",  "説明")
f.bool_field   = ProtoField.bool("proto.field",   "説明")
f.ipv4_field   = ProtoField.ipv4("proto.field",   "説明")
```

### 表示形式（Base）

- `base.DEC`: 10進数（123）
- `base.HEX`: 16進数（0x7b）
- `base.OCT`: 8進数（0173）
- `base.BIN`: 2進数（0b01111011）

### 値文字列（列挙型）

数値を読みやすい文字列にマッピングします：

```lua
f.command = ProtoField.uint8("proto.cmd", "コマンド", base.DEC, {
    [0] = "接続",
    [1] = "切断",
    [2] = "データ",
    [3] = "確認応答"
})
```

**KCPの例:**
```lua
f.cmd = ProtoField.uint8("kcp.cmd", "Command", base.DEC, {
    [81] = "PUSH",
    [82] = "ACK",
    [83] = "WASK (Window Ask)",
    [84] = "WINS (Window Size)"
})
```

## ディセクタ関数

ディセクタ関数は各パケットに対して呼び出され、実際の解析を行います。

### 関数シグネチャ

```lua
function proto.dissector(buffer, pinfo, tree)
    -- 解析ロジック
    return bytes_consumed
end
```

**パラメータ:**
- `buffer`: パケットデータを含むTVB（Testy Virtual Buffer）
- `pinfo`: パケット情報（アドレス、タイムスタンプなど）
- `tree`: 解析データを表示するプロトコルツリー

**戻り値:**
- 処理したバイト数（0の場合はパケットが一致しない）

### バッファ操作

```lua
-- バッファ長を取得
local len = buffer:len()

-- バッファからデータを読み取る
local value = buffer(offset, length):uint()     -- ビッグエンディアン符号なし
local value = buffer(offset, length):le_uint()  -- リトルエンディアン符号なし
local value = buffer(offset, length):int()      -- ビッグエンディアン符号付き
local value = buffer(offset, length):string()   -- 文字列

-- 一般的なパターン
local uint8  = buffer(offset, 1):uint()
local uint16 = buffer(offset, 2):le_uint()
local uint32 = buffer(offset, 4):le_uint()
```

### パケット情報の設定

```lua
-- プロトコル列を設定
pinfo.cols.protocol = "MYPROTO"

-- 情報列を設定
pinfo.cols.info = "マイプロトコルパケット"

-- 情報列に追加
pinfo.cols.info:append(" | 追加情報")
```

### プロトコルツリーへの追加

```lua
-- サブツリーを作成
local subtree = tree:add(proto, buffer(offset, length), "マイプロトコル")

-- フィールドを追加（ビッグエンディアン）
subtree:add(f.field_name, buffer(offset, length))

-- フィールドを追加（リトルエンディアン）
subtree:add_le(f.field_name, buffer(offset, length))

-- カスタム値でフィールドを追加
subtree:add(f.field_name, buffer(offset, length), custom_value)
```

### 完全な例

```lua
function kcp_proto.dissector(buffer, pinfo, tree)
    -- 最小サイズをチェック
    if buffer:len() < 24 then
        return 0
    end

    -- プロトコル名を設定
    pinfo.cols.protocol = "KCP"

    local offset = 0

    -- ヘッダーフィールドを読み取る
    local conv = buffer(offset, 4):le_uint()
    local cmd  = buffer(offset + 4, 1):uint()
    local len  = buffer(offset + 20, 4):le_uint()

    -- サブツリーを作成
    local subtree = tree:add(kcp_proto, buffer(offset, 24 + len))

    -- フィールドを追加
    subtree:add_le(f.conv, buffer(offset, 4))
    subtree:add(f.cmd, buffer(offset + 4, 1))

    -- 情報列を設定
    pinfo.cols.info = string.format("Conv=0x%08x Cmd=%d", conv, cmd)

    return 24 + len
end
```

## ポート登録

### UDPポート登録

```lua
local udp_table = DissectorTable.get("udp.port")
udp_table:add(12345, my_proto)

-- 複数のポートを登録
local ports = {4000, 4001, 4002}
for _, port in ipairs(ports) do
    udp_table:add(port, my_proto)
end

-- 「デコード方法...」機能を有効化
udp_table:add(0, my_proto)
```

### TCPポート登録

```lua
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(12345, my_proto)
```

### その他のプロトコル登録

```lua
-- IPプロトコル番号で登録
local ip_table = DissectorTable.get("ip.proto")
ip_table:add(17, my_proto)  -- 17 = UDP

-- Ethernetタイプで登録
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x0800, my_proto)  -- 0x0800 = IPv4
```

## ヒューリスティックディセクタ

ヒューリスティックディセクタは、ポート番号に依存せずにプロトコルを自動検出します。

### 基本パターン

```lua
function proto.heuristic(buffer, pinfo, tree)
    -- 検証チェック
    if buffer:len() < minimum_size then
        return false
    end

    -- プロトコルの特徴をチェック
    if not looks_like_my_protocol(buffer) then
        return false
    end

    -- 一致した場合、ディセクタを呼び出す
    proto.dissector(buffer, pinfo, tree)
    return true
end

-- ヒューリスティックディセクタを登録
proto:register_heuristic("udp", proto.heuristic)
```

### KCPの例

```lua
function kcp_proto.heuristic(buffer, pinfo, tree)
    -- 最低限ヘッダーサイズが必要
    if buffer:len() < 24 then
        return false
    end

    -- コマンドフィールドをチェック（81-84である必要がある）
    local cmd = buffer(4, 1):uint()
    if cmd < 81 or cmd > 84 then
        return false
    end

    -- 長さフィールドが妥当かチェック
    local len = buffer(20, 4):le_uint()
    if len > 65535 then
        return false
    end

    -- パケットサイズが一致するかチェック
    if buffer:len() < 24 + len then
        return false
    end

    -- 一致したので、KCPとして処理
    kcp_proto.dissector(buffer, pinfo, tree)
    return true
end
```

### ヒューリスティックのベストプラクティス

1. **具体的に**: 誤検出を避けるため複数のフィールドをチェック
2. **早期リターン**: 一致しないパケットに対して素早くfalseを返す
3. **マジックナンバーをチェック**: 利用可能な場合はプロトコル署名を使用
4. **範囲を検証**: フィールド値が期待される範囲内であることを確認
5. **パフォーマンス**: チェックを軽量に保つ（ヒューリスティックは頻繁に実行される）

## デバッグ方法

### コンソール出力

デバッグには`print()`を使用します：

```lua
print("デバッグ: フィールド値 = " .. value)
print(string.format("デバッグ: conv=0x%08x", conv))
```

出力の確認方法：
- **Linux/macOS**: Wiresharkを起動したターミナル
- **Windows**: ヘルプ → Wiresharkについて → Wireshark（コンソールウィンドウ）

### エラーの確認

ディセクタをロードした後、以下を確認：
1. 分析 → Luaプラグインをリロード（Ctrl+Shift+L）
2. コンソールでエラーメッセージを確認
3. ヘルプ → Wiresharkについて → プラグインタブを確認

### テスト戦略

1. **シンプルに始める**: まず最小限の機能でテスト
2. **テストキャプチャを使用**: 既知の正しいパケットを含むPCAPファイルを使用
3. **検証を追加**: 読み取る前にバッファサイズをチェック
4. **段階的な開発**: 機能を一つずつ追加
5. **フィルタを使用**: 定義したフィールドでフィルタリングをテスト

### よくあるエラー

**"Proto has not been registered"**
- フィールドを使用する前に`Proto()`を呼び出していることを確認

**"bad argument #2 to 'add'"**
- バッファのオフセットと長さが有効か確認
- バッファの終端を超えて読み取っていないか確認

**"attempt to index field '?' (a nil value)"**
- フィールドが適切に定義されていない
- フィールド定義の構文を確認

## ベストプラクティス

### コードの整理

```lua
-- 1. プロトコルを説明するヘッダーコメント
-- 2. プロトコルの宣言
-- 3. 定数
-- 4. フィールドの定義
-- 5. ヘルパー関数
-- 6. メインディセクタ関数
-- 7. ヒューリスティック関数（必要な場合）
-- 8. 登録コード
-- 9. ロード確認メッセージ
```

### パフォーマンス

- **バッファサイズを早期にチェック**: 無効なパケットに対して早期に失敗
- **文字列操作を避ける**: 可能な限り数値比較を使用
- **テーブル検索をキャッシュ**: `buffer:len()`をローカル変数に格納
- **ヒューリスティックの複雑さを制限**: 自動検出を高速に保つ

### エラーハンドリング

```lua
-- 常にバッファサイズをチェック
if buffer:len() < expected_size then
    return 0
end

-- フィールド値を検証
local version = buffer(0, 1):uint()
if version ~= 1 then
    -- エキスパート情報を追加
    tree:add_proto_expert_info(expert_info)
    return 0
end
```

### ドキュメント

- プロトコル構造を説明するコメントを追加
- フィールドのオフセットとサイズを文書化
- パケットフォーマットの例を含める
- プロトコル仕様を参照
- 使用例を提供

## APIリファレンス

### Protoオブジェクト

```lua
local proto = Proto(name, description)
proto.dissector(buffer, pinfo, tree)
proto.heuristic(buffer, pinfo, tree)
proto:register_heuristic(table_name, heuristic_func)
```

### ProtoField

```lua
ProtoField.uint8(abbr, name, base, valuestring, mask, desc)
ProtoField.uint16(...)
ProtoField.uint32(...)
ProtoField.uint64(...)
ProtoField.int8(...)
ProtoField.string(...)
ProtoField.bytes(...)
ProtoField.bool(...)
ProtoField.ipv4(...)
ProtoField.ipv6(...)
```

### Buffer（TVB）

```lua
buffer:len()                    -- バッファ長を取得
buffer(offset, length)          -- 範囲を取得
buffer(offset, length):uint()   -- 符号なし読み取り（ビッグエンディアン）
buffer(offset, length):le_uint() -- 符号なし読み取り（リトルエンディアン）
buffer(offset, length):int()    -- 符号付き読み取り（ビッグエンディアン）
buffer(offset, length):le_int() -- 符号付き読み取り（リトルエンディアン）
buffer(offset, length):string() -- 文字列として読み取り
buffer(offset, length):bytes()  -- ByteArrayとして読み取り
```

### Pinfo（パケット情報）

```lua
pinfo.cols.protocol      -- プロトコル列
pinfo.cols.info          -- 情報列
pinfo.cols.src           -- 送信元アドレス
pinfo.cols.dst           -- 宛先アドレス
pinfo.src                -- 送信元アドレス（読み取り専用）
pinfo.dst                -- 宛先アドレス（読み取り専用）
pinfo.src_port           -- 送信元ポート
pinfo.dst_port           -- 宛先ポート
pinfo.abs_ts             -- 絶対タイムスタンプ
```

### Tree

```lua
tree:add(proto, buffer_range, label)      -- プロトコルサブツリーを追加
tree:add(field, buffer_range)             -- フィールドを追加（ビッグエンディアン）
tree:add_le(field, buffer_range)          -- フィールドを追加（リトルエンディアン）
tree:add(field, buffer_range, value)      -- カスタム値で追加
subtree:append_text(text)                 -- サブツリーのテキストに追加
```

### DissectorTable

```lua
DissectorTable.get(table_name)     -- ディセクタテーブルを取得
table:add(pattern, dissector)      -- ディセクタをテーブルに追加
table:remove(pattern, dissector)   -- ディセクタを削除
```

## 追加リソース

### 公式ドキュメント

- [Wireshark Lua APIドキュメント](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)
- [Wireshark Wiki - Lua](https://wiki.wireshark.org/Lua)
- [Wireshark Wiki - Lua Examples](https://wiki.wireshark.org/Lua/Examples)

### サンプルコード

Wiresharkには多くのLuaディセクタの例が含まれています：
- Wiresharkのインストールディレクトリを確認
- `plugins/`サブディレクトリを探す
- パターンを学ぶために既存のディセクタを研究

### コミュニティ

- [Wireshark Q&A](https://ask.wireshark.org/)
- [Wireshark メーリングリスト](https://www.wireshark.org/lists/)

## まとめ

このガイドは、Wireshark Luaディセクタ作成の基礎をカバーしています。このリポジトリ内のKCPディセクタは、これらの概念を実際の実装で示しています。シンプルなディセクタから始めて、APIに慣れるにつれて徐々に機能を追加していきましょう。

質問や貢献については、メインのREADME.mdファイルを参照してください。
