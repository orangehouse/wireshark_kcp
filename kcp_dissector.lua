-- ============================================================================
-- Wireshark用 KCPプロトコルディセクタ
-- KCP Protocol Dissector for Wireshark
-- ============================================================================
-- KCPは高速で信頼性の高いARQ（自動再送要求）プロトコルです
-- KCP is a fast and reliable ARQ (Automatic Repeat-reQuest) protocol
--
-- プロトコル仕様: https://github.com/skywind3000/kcp
-- Protocol Specification: https://github.com/skywind3000/kcp
-- ============================================================================

-- ----------------------------------------------------------------------------
-- プロトコルの宣言
-- Declare the protocol
-- ----------------------------------------------------------------------------
-- Proto関数でプロトコルを定義します
-- 第1引数: プロトコルの短縮名（フィルタで使用）
-- 第2引数: プロトコルの表示名（パケット一覧に表示される名前）
local kcp_proto = Proto("KCP", "KCP Protocol")

-- ----------------------------------------------------------------------------
-- プロトコルフィールドの定義
-- Define protocol fields
-- ----------------------------------------------------------------------------
-- これらのフィールドはWiresharkのパケット詳細ペインに表示されます
-- フィルタリングにも使用できます（例: kcp.conv == 0x12345678）
local f = kcp_proto.fields

-- 会話ID（4バイト、リトルエンディアン、16進数表示）
-- KCP接続を識別するための一意なID
f.conv = ProtoField.uint32("kcp.conv", "Conversation ID", base.HEX)

-- コマンドタイプ（1バイト、10進数表示）
-- 81=PUSH（データ送信）、82=ACK（確認応答）、83=WASK（ウィンドウ問い合わせ）、84=WINS（ウィンドウサイズ通知）
f.cmd = ProtoField.uint8("kcp.cmd", "Command", base.DEC, {
    [81] = "PUSH",  -- データセグメント送信
    [82] = "ACK",   -- 確認応答
    [83] = "WASK (Window Ask)",  -- 受信ウィンドウサイズ問い合わせ
    [84] = "WINS (Window Size)"  -- 受信ウィンドウサイズ通知
})

-- フラグメント番号（1バイト、10進数表示）
-- データが分割されている場合の残りフラグメント数（0の場合は最後のフラグメント）
f.frg = ProtoField.uint8("kcp.frg", "Fragment", base.DEC)

-- ウィンドウサイズ（2バイト、リトルエンディアン、10進数表示）
-- 送信側が受信可能なセグメント数
f.wnd = ProtoField.uint16("kcp.wnd", "Window Size", base.DEC)

-- タイムスタンプ（4バイト、リトルエンディアン、10進数表示）
-- セグメント送信時刻（ミリ秒単位）、RTT計算に使用
f.ts = ProtoField.uint32("kcp.ts", "Timestamp", base.DEC)

-- シーケンス番号（4バイト、リトルエンディアン、10進数表示）
-- このセグメントの番号
f.sn = ProtoField.uint32("kcp.sn", "Sequence Number", base.DEC)

-- 未確認シーケンス番号（4バイト、リトルエンディアン、10進数表示）
-- 受信側が次に受信を期待するシーケンス番号
f.una = ProtoField.uint32("kcp.una", "Unacknowledged", base.DEC)

-- データ長（4バイト、リトルエンディアン、10進数表示）
-- ヘッダー後に続くペイロードデータのバイト数
f.len = ProtoField.uint32("kcp.len", "Length", base.DEC)

-- データペイロード（可変長、バイト列表示）
-- 実際に転送されるアプリケーションデータ
f.data = ProtoField.bytes("kcp.data", "Data")

-- ----------------------------------------------------------------------------
-- 定数定義
-- Constants
-- ----------------------------------------------------------------------------
-- KCPヘッダーのサイズ（24バイト固定）
-- KCP header size (24 bytes fixed)
local KCP_OVERHEAD = 24

-- ----------------------------------------------------------------------------
-- ディセクタ関数（メイン処理）
-- Dissector function (Main processing)
-- ----------------------------------------------------------------------------
-- この関数はWiresharkがKCPパケットを検出したときに呼び出されます
-- This function is called when Wireshark detects a KCP packet
--
-- 引数:
--   buffer: パケットデータを含むバッファ
--   pinfo:  パケット情報（タイムスタンプ、アドレスなど）
--   tree:   プロトコルツリー（Wiresharkの詳細ペイン）
-- 戻り値:
--   処理したバイト数（0の場合は処理失敗）
function kcp_proto.dissector(buffer, pinfo, tree)
    -- バッファサイズがKCPヘッダーの最小サイズより小さい場合は処理を中断
    -- Check if buffer is large enough for KCP header
    if buffer:len() < KCP_OVERHEAD then
        return 0
    end

    -- パケット一覧の「プロトコル」列に「KCP」と表示
    -- Set protocol name in packet list
    pinfo.cols.protocol = "KCP"

    -- バッファ内の現在位置を追跡
    local offset = 0
    -- 処理した総バイト数
    local total_consumed = 0

    -- 複数のKCPセグメントが単一のUDPデータグラムに含まれている場合があるため、ループ処理
    -- KCP packets can be batched in a single UDP datagram, so loop through them
    while offset < buffer:len() do
        -- 残りのバッファサイズがKCPヘッダーサイズ未満の場合はループを終了
        if buffer:len() - offset < KCP_OVERHEAD then
            break
        end

        -- ========================================================================
        -- ヘッダーフィールドの読み取り（リトルエンディアン形式）
        -- Read header fields (little-endian format)
        -- ========================================================================
        -- 会話ID（オフセット0、4バイト）
        local conv = buffer(offset, 4):le_uint()
        -- コマンド（オフセット4、1バイト）
        local cmd = buffer(offset + 4, 1):uint()
        -- フラグメント番号（オフセット5、1バイト）
        local frg = buffer(offset + 5, 1):uint()
        -- ウィンドウサイズ（オフセット6、2バイト）
        local wnd = buffer(offset + 6, 2):le_uint()
        -- タイムスタンプ（オフセット8、4バイト）
        local ts = buffer(offset + 8, 4):le_uint()
        -- シーケンス番号（オフセット12、4バイト）
        local sn = buffer(offset + 12, 4):le_uint()
        -- 未確認シーケンス番号（オフセット16、4バイト）
        local una = buffer(offset + 16, 4):le_uint()
        -- データ長（オフセット20、4バイト）
        local len = buffer(offset + 20, 4):le_uint()

        -- セグメント全体のサイズを計算（ヘッダー24バイト + データ長）
        -- Calculate total segment size (24-byte header + data length)
        local segment_size = KCP_OVERHEAD + len

        -- このセグメント全体を処理するのに十分なデータがバッファにあるか確認
        -- Check if we have enough data for this complete segment
        if offset + segment_size > buffer:len() then
            break
        end

        -- ========================================================================
        -- Wiresharkツリーへの情報追加
        -- Add information to Wireshark tree
        -- ========================================================================
        -- このKCPセグメントのサブツリーを作成
        -- Create subtree for this KCP segment
        local subtree = tree:add(kcp_proto, buffer(offset, segment_size), "KCP Protocol")

        -- 各ヘッダーフィールドをツリーに追加
        -- リトルエンディアンフィールドには add_le を使用
        -- Add each header field to the tree
        -- Use add_le for little-endian fields
        subtree:add_le(f.conv, buffer(offset, 4))       -- 会話ID
        subtree:add(f.cmd, buffer(offset + 4, 1))       -- コマンド
        subtree:add(f.frg, buffer(offset + 5, 1))       -- フラグメント
        subtree:add_le(f.wnd, buffer(offset + 6, 2))    -- ウィンドウサイズ
        subtree:add_le(f.ts, buffer(offset + 8, 4))     -- タイムスタンプ
        subtree:add_le(f.sn, buffer(offset + 12, 4))    -- シーケンス番号
        subtree:add_le(f.una, buffer(offset + 16, 4))   -- 未確認シーケンス番号
        subtree:add_le(f.len, buffer(offset + 20, 4))   -- データ長

        -- データペイロードが存在する場合（len > 0）、ツリーに追加
        -- Add data payload if present (len > 0)
        if len > 0 then
            subtree:add(f.data, buffer(offset + 24, len))
        end

        -- ========================================================================
        -- パケット情報列の文字列を作成
        -- Create info string for packet list
        -- ========================================================================
        -- コマンド番号を読みやすい名前に変換
        -- Convert command number to readable name
        local cmd_name = "UNKNOWN"
        if cmd == 81 then cmd_name = "PUSH"
        elseif cmd == 82 then cmd_name = "ACK"
        elseif cmd == 83 then cmd_name = "WASK"
        elseif cmd == 84 then cmd_name = "WINS"
        end

        -- パケット一覧の「情報」列に表示する文字列をフォーマット
        -- Format string for "Info" column in packet list
        local info = string.format("Conv=0x%08x Cmd=%s Sn=%d Una=%d Len=%d",
                                   conv, cmd_name, sn, una, len)

        -- 最初のセグメントの場合は情報を設定、2つ目以降は追加
        -- Set info for first segment, append for subsequent segments
        if offset == 0 then
            pinfo.cols.info = info
        else
            -- 複数セグメントがある場合は「|」で区切って表示
            pinfo.cols.info:append(" | " .. info)
        end

        -- ========================================================================
        -- 次のセグメントへ移動
        -- Move to next segment
        -- ========================================================================
        offset = offset + segment_size
        total_consumed = offset
    end

    -- 処理した総バイト数を返す
    -- Return total number of bytes consumed
    return total_consumed
end

-- ----------------------------------------------------------------------------
-- UDPポートへのディセクタ登録
-- Register dissector for UDP ports
-- ----------------------------------------------------------------------------
-- UDPポートテーブルを取得
-- Get UDP port dissector table
local udp_port_table = DissectorTable.get("udp.port")

-- KCPで一般的に使用されるポート番号のリスト
-- アプリケーションに応じて変更してください
-- List of commonly used KCP ports
-- Modify these based on your application
local kcp_ports = {4000, 4001, 4002, 4003, 4004, 4005, 9999, 10000}

-- 指定したポートすべてにKCPディセクタを登録
-- Register KCP dissector for all specified ports
for _, port in ipairs(kcp_ports) do
    udp_port_table:add(port, kcp_proto)
end

-- ポート0に登録することで「デコード方法...」メニューから手動選択を可能にする
-- Register on port 0 to allow manual "Decode As..." selection
udp_port_table:add(0, kcp_proto)

-- ----------------------------------------------------------------------------
-- ヒューリスティックディセクタ（自動検出機能）
-- Heuristic dissector (Auto-detection)
-- ----------------------------------------------------------------------------
-- ポート番号に関係なくKCPパケットを自動的に検出します
-- パケットの内容を検査してKCPフォーマットであるかを判断します
-- Automatically detect KCP packets regardless of port number
-- Inspects packet contents to determine if it matches KCP format
--
-- 引数:
--   buffer: パケットデータを含むバッファ
--   pinfo:  パケット情報
--   tree:   プロトコルツリー
-- 戻り値:
--   true:  KCPパケットとして処理した
--   false: KCPパケットではない
function kcp_proto.heuristic(buffer, pinfo, tree)
    -- 最低限KCPヘッダーサイズ（24バイト）が必要
    -- Need at least 24 bytes for KCP header
    if buffer:len() < KCP_OVERHEAD then
        return false
    end

    -- コマンドフィールドが有効な範囲（81-84）であることを確認
    -- Check if cmd field is valid (81-84)
    local cmd = buffer(4, 1):uint()
    if cmd < 81 or cmd > 84 then
        return false
    end

    -- データ長フィールドが妥当な値であることを確認
    -- MTU（Maximum Transmission Unit）の上限として65535バイトを使用
    -- Check if length field is reasonable
    -- Use 65535 bytes as MTU (Maximum Transmission Unit) limit
    local len = buffer(20, 4):le_uint()
    if len > 65535 then  -- 妥当なMTU上限
        return false
    end

    -- パケット全体のサイズが宣言されたサイズと一致するか確認
    -- Check if total packet size matches declared size
    if buffer:len() < KCP_OVERHEAD + len then
        return false
    end

    -- すべてのチェックをパスしたので、KCPパケットとして処理
    -- All checks passed, process as KCP packet
    kcp_proto.dissector(buffer, pinfo, tree)
    return true
end

-- ヒューリスティックディセクタをUDPプロトコルに登録
-- Register heuristic dissector for UDP protocol
kcp_proto:register_heuristic("udp", kcp_proto.heuristic)

-- ディセクタが正常にロードされたことをコンソールに出力
-- Print success message to console
print("KCP Protocol Dissector loaded successfully")
print("KCPプロトコルディセクタが正常に読み込まれました")
