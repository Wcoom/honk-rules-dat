#!/usr/bin/env python3
"""极简 protobuf 读写，够用于 v2ray 的 geosite.dat / geoip.dat。

只实现本项目需要的部分：
  wire type 0 (varint)、2 (length-delimited)、5/1 跳过。

不依赖任何第三方库 —— 本机没有 protobuf 运行时，而这两个文件的结构
（GeoSiteList / GeoIPList）固定且简单，手写比装依赖更可控。
"""


def read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def write_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def iter_fields(buf):
    """遍历一层 message 的字段，产出 (field_number, wire_type, value_bytes_or_int)。"""
    pos = 0
    end = len(buf)
    while pos < end:
        key, pos = read_varint(buf, pos)
        field = key >> 3
        wire = key & 7
        if wire == 0:
            val, pos = read_varint(buf, pos)
            yield field, wire, val
        elif wire == 2:
            ln, pos = read_varint(buf, pos)
            yield field, wire, buf[pos:pos + ln]
            pos += ln
        elif wire == 1:  # fixed64
            yield field, wire, buf[pos:pos + 8]
            pos += 8
        elif wire == 5:  # fixed32
            yield field, wire, buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")


def field_varint(num, value):
    return write_varint((num << 3) | 0) + write_varint(value)


def field_bytes(num, data):
    if isinstance(data, str):
        data = data.encode()
    return write_varint((num << 3) | 2) + write_varint(len(data)) + data


def decode_utf8(b):
    return b.decode("utf-8", errors="replace")
