# Wireshark Lua Dissector Development Guide

[日本語版はこちら (Japanese)](DEVELOPMENT_ja.md)

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Basic Structure](#basic-structure)
4. [Protocol Declaration](#protocol-declaration)
5. [Field Definitions](#field-definitions)
6. [Dissector Function](#dissector-function)
7. [Port Registration](#port-registration)
8. [Heuristic Dissector](#heuristic-dissector)
9. [Debugging](#debugging)
10. [Best Practices](#best-practices)
11. [API Reference](#api-reference)

## Introduction

Wireshark supports protocol dissectors written in Lua, allowing you to decode custom protocols without compiling C code. This guide explains how to create Lua dissectors using the KCP dissector as a practical example.

### Why Use Lua Dissectors?

- **No compilation required**: Write and test immediately
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Rapid prototyping**: Quick iteration during development
- **Easy to share**: Single `.lua` file distribution

## Prerequisites

### Required Knowledge

- Basic understanding of Lua programming
- Familiarity with network protocols
- Understanding of the protocol you want to dissect

### Tools

- Wireshark (version 3.0 or later recommended)
- Text editor for Lua code
- Sample packet captures (PCAP files) for testing

## Basic Structure

A typical Wireshark Lua dissector has the following structure:

```lua
-- 1. Protocol Declaration
local my_proto = Proto("MYPROTO", "My Protocol")

-- 2. Field Definitions
local f = my_proto.fields
f.field1 = ProtoField.uint32("myproto.field1", "Field 1", base.HEX)

-- 3. Dissector Function
function my_proto.dissector(buffer, pinfo, tree)
    -- Packet parsing logic
end

-- 4. Port Registration
local udp_table = DissectorTable.get("udp.port")
udp_table:add(12345, my_proto)

-- 5. (Optional) Heuristic Dissector
function my_proto.heuristic(buffer, pinfo, tree)
    -- Auto-detection logic
end
my_proto:register_heuristic("udp", my_proto.heuristic)
```

## Protocol Declaration

### Creating a Protocol

Use the `Proto` constructor to declare your protocol:

```lua
local proto_name = Proto(short_name, description)
```

**Parameters:**
- `short_name`: Short name used in filters (e.g., "kcp", "http")
- `description`: Human-readable description shown in UI

**Example:**
```lua
local kcp_proto = Proto("KCP", "KCP Protocol")
```

This allows users to filter packets with: `kcp` or `kcp.conv == 0x12345678`

## Field Definitions

### Field Types

Wireshark provides various field types through `ProtoField`:

```lua
local f = my_proto.fields

-- Integer types
f.uint8_field  = ProtoField.uint8("proto.field",  "Description", base.DEC)
f.uint16_field = ProtoField.uint16("proto.field", "Description", base.DEC)
f.uint32_field = ProtoField.uint32("proto.field", "Description", base.DEC)
f.uint64_field = ProtoField.uint64("proto.field", "Description", base.DEC)

-- Signed integers
f.int8_field   = ProtoField.int8("proto.field",   "Description", base.DEC)
f.int16_field  = ProtoField.int16("proto.field",  "Description", base.DEC)
f.int32_field  = ProtoField.int32("proto.field",  "Description", base.DEC)

-- Other types
f.string_field = ProtoField.string("proto.field", "Description")
f.bytes_field  = ProtoField.bytes("proto.field",  "Description")
f.bool_field   = ProtoField.bool("proto.field",   "Description")
f.ipv4_field   = ProtoField.ipv4("proto.field",   "Description")
```

### Base Display Formats

- `base.DEC`: Decimal (123)
- `base.HEX`: Hexadecimal (0x7b)
- `base.OCT`: Octal (0173)
- `base.BIN`: Binary (0b01111011)

### Value Strings (Enumerations)

Map numeric values to readable strings:

```lua
f.command = ProtoField.uint8("proto.cmd", "Command", base.DEC, {
    [0] = "CONNECT",
    [1] = "DISCONNECT",
    [2] = "DATA",
    [3] = "ACK"
})
```

**KCP Example:**
```lua
f.cmd = ProtoField.uint8("kcp.cmd", "Command", base.DEC, {
    [81] = "PUSH",
    [82] = "ACK",
    [83] = "WASK (Window Ask)",
    [84] = "WINS (Window Size)"
})
```

## Dissector Function

The dissector function is called for each packet and performs the actual parsing.

### Function Signature

```lua
function proto.dissector(buffer, pinfo, tree)
    -- Your parsing logic
    return bytes_consumed
end
```

**Parameters:**
- `buffer`: TVB (Testy Virtual Buffer) containing packet data
- `pinfo`: Packet information (addresses, timestamps, etc.)
- `tree`: Protocol tree for displaying parsed data

**Return Value:**
- Number of bytes consumed (0 if packet doesn't match)

### Buffer Operations

```lua
-- Get buffer length
local len = buffer:len()

-- Read data from buffer
local value = buffer(offset, length):uint()     -- Big-endian unsigned
local value = buffer(offset, length):le_uint()  -- Little-endian unsigned
local value = buffer(offset, length):int()      -- Big-endian signed
local value = buffer(offset, length):string()   -- String

-- Common patterns
local uint8  = buffer(offset, 1):uint()
local uint16 = buffer(offset, 2):le_uint()
local uint32 = buffer(offset, 4):le_uint()
```

### Setting Packet Information

```lua
-- Set protocol column
pinfo.cols.protocol = "MYPROTO"

-- Set info column
pinfo.cols.info = "My protocol packet"

-- Append to info column
pinfo.cols.info:append(" | Additional info")
```

### Adding to Protocol Tree

```lua
-- Create subtree
local subtree = tree:add(proto, buffer(offset, length), "My Protocol")

-- Add fields (big-endian)
subtree:add(f.field_name, buffer(offset, length))

-- Add fields (little-endian)
subtree:add_le(f.field_name, buffer(offset, length))

-- Add field with custom value
subtree:add(f.field_name, buffer(offset, length), custom_value)
```

### Complete Example

```lua
function kcp_proto.dissector(buffer, pinfo, tree)
    -- Check minimum size
    if buffer:len() < 24 then
        return 0
    end

    -- Set protocol name
    pinfo.cols.protocol = "KCP"

    local offset = 0

    -- Read header fields
    local conv = buffer(offset, 4):le_uint()
    local cmd  = buffer(offset + 4, 1):uint()
    local len  = buffer(offset + 20, 4):le_uint()

    -- Create subtree
    local subtree = tree:add(kcp_proto, buffer(offset, 24 + len))

    -- Add fields
    subtree:add_le(f.conv, buffer(offset, 4))
    subtree:add(f.cmd, buffer(offset + 4, 1))

    -- Set info column
    pinfo.cols.info = string.format("Conv=0x%08x Cmd=%d", conv, cmd)

    return 24 + len
end
```

## Port Registration

### UDP Port Registration

```lua
local udp_table = DissectorTable.get("udp.port")
udp_table:add(12345, my_proto)

-- Register multiple ports
local ports = {4000, 4001, 4002}
for _, port in ipairs(ports) do
    udp_table:add(port, my_proto)
end

-- Enable "Decode As..." feature
udp_table:add(0, my_proto)
```

### TCP Port Registration

```lua
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(12345, my_proto)
```

### Other Protocol Registration

```lua
-- Register for IP protocol number
local ip_table = DissectorTable.get("ip.proto")
ip_table:add(17, my_proto)  -- 17 = UDP

-- Register for Ethernet type
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x0800, my_proto)  -- 0x0800 = IPv4
```

## Heuristic Dissector

Heuristic dissectors automatically detect protocols without relying on port numbers.

### Basic Pattern

```lua
function proto.heuristic(buffer, pinfo, tree)
    -- Validation checks
    if buffer:len() < minimum_size then
        return false
    end

    -- Check for protocol signatures
    if not looks_like_my_protocol(buffer) then
        return false
    end

    -- If matched, call dissector
    proto.dissector(buffer, pinfo, tree)
    return true
end

-- Register heuristic dissector
proto:register_heuristic("udp", proto.heuristic)
```

### KCP Example

```lua
function kcp_proto.heuristic(buffer, pinfo, tree)
    -- Need at least header size
    if buffer:len() < 24 then
        return false
    end

    -- Check command field (must be 81-84)
    local cmd = buffer(4, 1):uint()
    if cmd < 81 or cmd > 84 then
        return false
    end

    -- Check length field is reasonable
    local len = buffer(20, 4):le_uint()
    if len > 65535 then
        return false
    end

    -- Check packet size matches
    if buffer:len() < 24 + len then
        return false
    end

    -- Matched, process as KCP
    kcp_proto.dissector(buffer, pinfo, tree)
    return true
end
```

### Heuristic Best Practices

1. **Be specific**: Check multiple fields to avoid false positives
2. **Fail fast**: Return false quickly for non-matching packets
3. **Check magic numbers**: Use protocol signatures when available
4. **Validate ranges**: Ensure field values are within expected ranges
5. **Performance**: Keep checks lightweight (heuristics run often)

## Debugging

### Console Output

Use `print()` for debugging:

```lua
print("Debug: field value = " .. value)
print(string.format("Debug: conv=0x%08x", conv))
```

View output in:
- **Linux/macOS**: Terminal where Wireshark was launched
- **Windows**: Help → About Wireshark → Wireshark (Console window)

### Checking for Errors

After loading your dissector, check:
1. Analyze → Reload Lua Plugins (Ctrl+Shift+L)
2. Look for error messages in console
3. Check Help → About Wireshark → Plugins tab

### Testing Strategy

1. **Start simple**: Test with minimal functionality first
2. **Use test captures**: Create/use PCAP files with known good packets
3. **Add validation**: Check buffer sizes before reading
4. **Incremental development**: Add features one at a time
5. **Use filters**: Test filtering with your defined fields

### Common Errors

**"Proto has not been registered"**
- Make sure you call `Proto()` before using fields

**"bad argument #2 to 'add'"**
- Check buffer offset and length are valid
- Ensure you don't read past buffer end

**"attempt to index field '?' (a nil value)"**
- Field not properly defined
- Check field definition syntax

## Best Practices

### Code Organization

```lua
-- 1. Header comments explaining the protocol
-- 2. Protocol declaration
-- 3. Constants
-- 4. Field definitions
-- 5. Helper functions
-- 6. Main dissector function
-- 7. Heuristic function (if needed)
-- 8. Registration code
-- 9. Load confirmation message
```

### Performance

- **Check buffer size early**: Fail fast for invalid packets
- **Avoid string operations**: Use numeric comparisons when possible
- **Cache table lookups**: Store `buffer:len()` in a local variable
- **Limit heuristic complexity**: Keep auto-detection fast

### Error Handling

```lua
-- Always check buffer size
if buffer:len() < expected_size then
    return 0
end

-- Validate field values
local version = buffer(0, 1):uint()
if version ~= 1 then
    -- Add expert info
    tree:add_proto_expert_info(expert_info)
    return 0
end
```

### Documentation

- Add comments explaining protocol structure
- Document field offsets and sizes
- Include example packet format
- Reference protocol specifications
- Provide usage examples

## API Reference

### Proto Object

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

### Buffer (TVB)

```lua
buffer:len()                    -- Get buffer length
buffer(offset, length)          -- Get range
buffer(offset, length):uint()   -- Read unsigned (big-endian)
buffer(offset, length):le_uint() -- Read unsigned (little-endian)
buffer(offset, length):int()    -- Read signed (big-endian)
buffer(offset, length):le_int() -- Read signed (little-endian)
buffer(offset, length):string() -- Read string
buffer(offset, length):bytes()  -- Read as ByteArray
```

### Pinfo (Packet Info)

```lua
pinfo.cols.protocol      -- Protocol column
pinfo.cols.info          -- Info column
pinfo.cols.src           -- Source address
pinfo.cols.dst           -- Destination address
pinfo.src                -- Source address (read-only)
pinfo.dst                -- Destination address (read-only)
pinfo.src_port           -- Source port
pinfo.dst_port           -- Destination port
pinfo.abs_ts             -- Absolute timestamp
```

### Tree

```lua
tree:add(proto, buffer_range, label)      -- Add protocol subtree
tree:add(field, buffer_range)             -- Add field (big-endian)
tree:add_le(field, buffer_range)          -- Add field (little-endian)
tree:add(field, buffer_range, value)      -- Add with custom value
subtree:append_text(text)                 -- Append to subtree text
```

### DissectorTable

```lua
DissectorTable.get(table_name)     -- Get dissector table
table:add(pattern, dissector)      -- Add dissector to table
table:remove(pattern, dissector)   -- Remove dissector
```

## Additional Resources

### Official Documentation

- [Wireshark Lua API Documentation](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)
- [Wireshark Wiki - Lua](https://wiki.wireshark.org/Lua)
- [Wireshark Wiki - Lua Examples](https://wiki.wireshark.org/Lua/Examples)

### Sample Code

Wireshark includes many Lua dissector examples:
- Check your Wireshark installation directory
- Look in `plugins/` subdirectory
- Study existing dissectors for patterns

### Community

- [Wireshark Q&A](https://ask.wireshark.org/)
- [Wireshark Mailing Lists](https://www.wireshark.org/lists/)

## Conclusion

This guide covers the essentials of creating Wireshark Lua dissectors. The KCP dissector in this repository demonstrates these concepts in a real-world implementation. Start with a simple dissector and gradually add features as you become more comfortable with the API.

For questions or contributions, please refer to the main README.md file.
