-- KCP Protocol Dissector for Wireshark
-- KCP is a fast and reliable ARQ protocol
-- https://github.com/skywind3000/kcp

-- Declare the protocol
local kcp_proto = Proto("KCP", "KCP Protocol")

-- Define protocol fields
local f = kcp_proto.fields
f.conv = ProtoField.uint32("kcp.conv", "Conversation ID", base.HEX)
f.cmd = ProtoField.uint8("kcp.cmd", "Command", base.DEC, {
    [81] = "PUSH",
    [82] = "ACK",
    [83] = "WASK (Window Ask)",
    [84] = "WINS (Window Size)"
})
f.frg = ProtoField.uint8("kcp.frg", "Fragment", base.DEC)
f.wnd = ProtoField.uint16("kcp.wnd", "Window Size", base.DEC)
f.ts = ProtoField.uint32("kcp.ts", "Timestamp", base.DEC)
f.sn = ProtoField.uint32("kcp.sn", "Sequence Number", base.DEC)
f.una = ProtoField.uint32("kcp.una", "Unacknowledged", base.DEC)
f.len = ProtoField.uint32("kcp.len", "Length", base.DEC)
f.data = ProtoField.bytes("kcp.data", "Data")

-- KCP header size (24 bytes)
local KCP_OVERHEAD = 24

-- Dissector function
function kcp_proto.dissector(buffer, pinfo, tree)
    -- Check if buffer is large enough for KCP header
    if buffer:len() < KCP_OVERHEAD then
        return 0
    end

    -- Set protocol name in packet list
    pinfo.cols.protocol = "KCP"

    local offset = 0
    local total_consumed = 0

    -- KCP packets can be batched in a single UDP datagram
    while offset < buffer:len() do
        if buffer:len() - offset < KCP_OVERHEAD then
            break
        end

        -- Read header fields
        local conv = buffer(offset, 4):le_uint()
        local cmd = buffer(offset + 4, 1):uint()
        local frg = buffer(offset + 5, 1):uint()
        local wnd = buffer(offset + 6, 2):le_uint()
        local ts = buffer(offset + 8, 4):le_uint()
        local sn = buffer(offset + 12, 4):le_uint()
        local una = buffer(offset + 16, 4):le_uint()
        local len = buffer(offset + 20, 4):le_uint()

        -- Calculate total segment size
        local segment_size = KCP_OVERHEAD + len

        -- Check if we have enough data for this segment
        if offset + segment_size > buffer:len() then
            break
        end

        -- Create subtree for this KCP segment
        local subtree = tree:add(kcp_proto, buffer(offset, segment_size), "KCP Protocol")

        -- Add header fields to tree
        subtree:add_le(f.conv, buffer(offset, 4))
        subtree:add(f.cmd, buffer(offset + 4, 1))
        subtree:add(f.frg, buffer(offset + 5, 1))
        subtree:add_le(f.wnd, buffer(offset + 6, 2))
        subtree:add_le(f.ts, buffer(offset + 8, 4))
        subtree:add_le(f.sn, buffer(offset + 12, 4))
        subtree:add_le(f.una, buffer(offset + 16, 4))
        subtree:add_le(f.len, buffer(offset + 20, 4))

        -- Add data if present
        if len > 0 then
            subtree:add(f.data, buffer(offset + 24, len))
        end

        -- Create info string
        local cmd_name = "UNKNOWN"
        if cmd == 81 then cmd_name = "PUSH"
        elseif cmd == 82 then cmd_name = "ACK"
        elseif cmd == 83 then cmd_name = "WASK"
        elseif cmd == 84 then cmd_name = "WINS"
        end

        local info = string.format("Conv=0x%08x Cmd=%s Sn=%d Una=%d Len=%d",
                                   conv, cmd_name, sn, una, len)

        if offset == 0 then
            pinfo.cols.info = info
        else
            pinfo.cols.info:append(" | " .. info)
        end

        -- Move to next segment
        offset = offset + segment_size
        total_consumed = offset
    end

    return total_consumed
end

-- Register the dissector for UDP ports
-- You can modify these ports based on your application
local udp_port_table = DissectorTable.get("udp.port")

-- Common KCP ports (you may need to adjust these)
local kcp_ports = {4000, 4001, 4002, 4003, 4004, 4005, 9999, 10000}

for _, port in ipairs(kcp_ports) do
    udp_port_table:add(port, kcp_proto)
end

-- Also allow manual "Decode As..." selection
udp_port_table:add(0, kcp_proto)

-- Heuristic dissector for auto-detection
function kcp_proto.heuristic(buffer, pinfo, tree)
    -- Need at least 24 bytes for KCP header
    if buffer:len() < KCP_OVERHEAD then
        return false
    end

    -- Check if cmd field is valid (81-84)
    local cmd = buffer(4, 1):uint()
    if cmd < 81 or cmd > 84 then
        return false
    end

    -- Check if length field is reasonable
    local len = buffer(20, 4):le_uint()
    if len > 65535 then  -- Reasonable MTU limit
        return false
    end

    -- Check if total size matches
    if buffer:len() < KCP_OVERHEAD + len then
        return false
    end

    -- Looks like KCP, use our dissector
    kcp_proto.dissector(buffer, pinfo, tree)
    return true
end

-- Register heuristic dissector
kcp_proto:register_heuristic("udp", kcp_proto.heuristic)

print("KCP Protocol Dissector loaded successfully")
