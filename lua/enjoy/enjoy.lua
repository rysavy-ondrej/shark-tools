--
-- Copyright (c) 2025 Brno University of Technology
--
-- This file is part of shark-tools package.
--
-- shark-tools package is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- shark-tools package is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
--[[

This TShark Lua module extracts detailed connection (bidirectional flow) information from network packets. 
A connection is defined as a bidirectional flow where the client (the initiating side) is designated as the source. 
In addition to basic flow attributes, the module enriches each connection with protocol-specific metadata for:

IP – Basic network layer details.
TCP – Transmission Control Protocol specifics.
UDP – User Datagram Protocol specifics.
DNS – Domain Name System query and response data.
TLS – Transport Layer Security handshake and encryption parameters.
HTTP/HTTP2 – Web protocol transactions and header information.

Required Modules:

json – For encoding the extracted data into JSON.
ordered_table – To maintain the insertion order of keys in table structures.
enjoy_dns – For parsing and processing DNS-related fields.
enjoy_tls – For parsing and processing TLS-related fields.
enjoy_http – For parsing and processing HTTP-related fields.
enjoy_http2 – For parsing and processing HTTP/2-related fields.

The module outputs each connection record as a line of Newline-Delimited JSON (NDJSON) to stdout, 
facilitating easy integration with downstream processing pipelines.

The module accepts parameters:
flush - interval in seconds to export connections. If not specified it exports connection at the end of processing (offline mode).
debug - set to true to see the packet processing details.

Usage:
  tshark -q -X lua_script:enjoy.lua -r your_capture_file.pcap
  
  tshark -q -X lua_script:enjoy.lua -X lua_script1:flush=30 -i network_interface
  
  tshark -q -X lua_script:enjoy.lua -X lua_script1:flush=30 -X lua_script1:debug=true -i network_interface

Example:
  tshark -q -X lua_script:enjoy.lua -X lua_script1:flush=30 -X lua_script1:debug=true -i "Ethernet 2" 

  
--]]


function info_write(str)
    io.stderr:write("Info: " )
    io.stderr:write(str)
    io.stderr:write("\n")
end

local handle = io.popen("tshark -v")
local result = handle:read("*a")
handle:close()

-- Extract the version from the result
local version_major, version_minor, version_patch = result:match("TShark %(Wireshark%) (%d+)%.(%d+)%.(%d+)")
if (tonumber(version_major) == 3 and tonumber(version_minor) >= 6) or tonumber(version_major) == 4
then
    info_write(string.format("TShark version: %d.%d.%d", version_major,version_minor,version_patch))
else
    error("Invalid tshark version. At least 3.6.x is required.")
end

-------------------------------------------------------------------------------
-- ARGUMENTS:
-------------------------------------------------------------------------------
local args_array = {...}
local args_map = {}
for _, pairStr in ipairs(args_array) do
    local key, value = pairStr:match("([^=]+)=(.+)")
    if key and value then
        args_map[key] = value
    end
end

local __debug = false
if args_map["debug"] then
    __debug = true
end



function debug_write(str)
    if __debug then
        io.stderr:write(str)
    end
end


local packets_processed = 0
local connections_flushed = 0

local flush_interval = nil
if args_map["flush"] then 
    flush_interval = tonumber(args_map["flush"])  
    if not flush_interval or not (flush_interval > 0) then error("Invalid flush interval specified. It must be number > 0.") end

    info_write(string.format("Running Enjoy in online mode with capture interval %d seconds.", flush_interval))

else
    info_write("Running Enjoy in batch mode.\n")    
end



-------------------------------------------------------------------------------
-- GLOBAL:
-------------------------------------------------------------------------------
-- Use JSON lib to generate the output
local json = require("json")
local obj = require("ordered_table")
-- Table to store connections; key is based on TCP/UDP stream id 
local connections = {}
-- The timestamp of the first packet 
local connections_start = nil

-- The timestamp of the last processed packet
local last_packet_time = nil

-------------------------------------------------------------------------------
-- TAPS: Define TAPs used to process the input packets. 
-------------------------------------------------------------------------------
local tap = Listener.new("ip") 
local tcp_tap = Listener.new("tcp")  
local udp_tap = Listener.new("udp") 

local tls = require("enjoy_tls")
tls.create_tap(connections, __debug)

local http = require("enjoy_http")
http.create_tap(connections)

local http2 = require("enjoy_http2")
http2.create_tap(connections)

local dns = require("enjoy_dns")
dns.create_tap(connections, __debug)

-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
-- Extract stream index used to collect packet into connections
local f_tcp_stream        = Field.new("tcp.stream")
local f_udp_stream        = Field.new("udp.stream")

-- Field extractors for IP protocol:
local f_ip_src      = Field.new("ip.src")
local f_ip_dst      = Field.new("ip.dst")
local f_ip_proto    = Field.new("ip.proto")
local f_ip_len      = Field.new("ip.len")

-- Field extractors for TCP protocol:
local f_tcp_srcport = Field.new("tcp.srcport")
local f_tcp_dstport = Field.new("tcp.dstport")
local f_tcp_len     = Field.new("tcp.len")
local f_tcp_flags   = Field.new("tcp.flags")

-- Field extractors for UDP protocol:
local f_udp_srcport = Field.new("udp.srcport")
local f_udp_dstport = Field.new("udp.dstport")
local f_udp_len     = Field.new("udp.length")

-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
IP_PROTOCOLS = {
    [1]   = "ICMP",
    [2]   = "IGMP",
    [3]   = "GGP",
    [4]   = "IP",   -- Encapsulation of IP within IP
    [6]   = "TCP",
    [8]   = "EGP",
    [9]   = "IGP",        -- Obsolete: Interior Gateway Protocol
    [17]  = "UDP",
    [41]  = "IPv6",       -- Used for IPv6 encapsulation in IPv4
    [47]  = "GRE",
    [50]  = "ESP",
    [51]  = "AH",
    [89]  = "OSPF",
    [132] = "SCTP"
}

function update_connection(conn, pinfo, client)
    -- Update connection duration.
    conn.td = pinfo.abs_ts - conn.ts
    -- Determine direction: compare with the stored fields
    if client then
        -- Packet from client to server.
        conn.ip.psent = conn.ip.psent + 1
        conn.ip.bsent = conn.ip.bsent + f_ip_len().value
    else
        -- Packet from server to client.
        conn.ip.precv = conn.ip.precv + 1
        conn.ip.brecv = conn.ip.brecv + f_ip_len().value
    end
end

function init_ip_counters(ip)
    ip.bsent = 0
    ip.brecv = 0
    ip.psent = 0
    ip.precv = 0
    return ip
end

function get_tcp_flags_string(flags)
    local flagStr = ""
    flagStr = flagStr .. (bit.band(flags, 0x20) ~= 0 and "U" or "u")  -- URG (0x20)
    flagStr = flagStr .. (bit.band(flags, 0x10) ~= 0 and "A" or "a")  -- ACK (0x10)
    flagStr = flagStr .. (bit.band(flags, 0x08) ~= 0 and "P" or "p")  -- PSH (0x08)
    flagStr = flagStr .. (bit.band(flags, 0x04) ~= 0 and "R" or "r")  -- RST (0x04)
    flagStr = flagStr .. (bit.band(flags, 0x02) ~= 0 and "S" or "s")  -- SYN (0x02)
    flagStr = flagStr .. (bit.band(flags, 0x01) ~= 0 and "F" or "f")  -- FIN (0x01)
    return flagStr
end

--
-- For each packet (UDP or TCP) we collect some information:
-- timestamp
-- direction
-- length
-- flags (for TCP only)
function get_packet_metrics(pinfo, client)
    prec = obj { }
    prec.ts = pinfo.abs_ts
    if client then prec.dir = ">" else prec.dir = "<" end
    
    if f_tcp_len() then prec.len = f_tcp_len().value
    elseif f_udp_len() then prec.len = f_udp_len().value
    else prec.len = 0
    end

    if f_tcp_flags() then
        prec.flags = get_tcp_flags_string(f_tcp_flags().value)
    end
    return prec
end


-------------------------------------------------------------------------------
-- TAP PACKET FUNCTION:
-------------------------------------------------------------------------------
function tcp_tap.packet(pinfo, tvb)
    debug_write("t_")
    debug_write(pinfo.number)
    local stream_id = f_tcp_stream()
    if not stream_id or not f_ip_src() then 
        debug_write("!") 
        return 
    else
        debug_write(" ")
    end
    

    local key = "tcp." .. tostring(stream_id.value)

    local ip_src   = tostring(f_ip_src())
    local ip_dst   = tostring(f_ip_dst())
    local ip_proto = IP_PROTOCOLS[f_ip_proto().value]
    local tcp_src  = f_tcp_srcport().value
    local tcp_dst  = f_tcp_dstport().value


    local conn = connections[key]
    if not conn then
        conn = obj { }
        conn.id = key
        conn.ts = pinfo.abs_ts    -- first seen timestamp
        conn.td = 0              -- duration, initially 0  
        conn.ip = obj { }
        conn.tcp = obj { }
        conn.ip.proto = ip_proto

        if tcp_src > tcp_dst then 
            conn.ip.src = ip_src      
            conn.ip.dst = ip_dst
            conn.tcp.srcport = tcp_src
            conn.tcp.dstport = tcp_dst
        else
            conn.ip.src = ip_dst     
            conn.ip.dst = ip_src
            conn.tcp.srcport = tcp_dst
            conn.tcp.dstport = tcp_src      
        end
        init_ip_counters(conn.ip)
        conn.tcp.segs = { }
        connections[key] = conn
        debug_write("+")
        debug_write(key)
        debug_write(" ")
    end
    

    local client = ip_src == conn.ip.src and tcp_src == conn.tcp.srcport
    update_connection(conn, pinfo, client)
    table.insert(conn.tcp.segs, get_packet_metrics(pinfo, client))
end

function udp_tap.packet(pinfo, tvb)
    debug_write("u_")
    debug_write(pinfo.number)
    local stream_id = f_udp_stream()

    if not stream_id or not f_ip_src() then 
        debug_write("!") 
        return 
    else
        debug_write(" ")
    end

    local key = "udp." .. tostring(stream_id.value)
    local ip_src   = tostring(f_ip_src())
    local ip_dst   = tostring(f_ip_dst())
    local ip_proto = IP_PROTOCOLS[f_ip_proto().value]
    local src_port  = f_udp_srcport().value
    local dst_port  = f_udp_dstport().value


    local conn = connections[key]
    if not conn then
        conn = obj { }
        conn.id = key
        conn.ts = pinfo.abs_ts    -- first seen timestamp
        conn.td = 0              -- duration, initially 0  
        conn.ip = obj { }
        conn.udp = obj { }
        conn.ip.proto = ip_proto

        if src_port > dst_port then 
            conn.ip.src = ip_src      
            conn.ip.dst = ip_dst
            conn.udp.srcport = src_port
            conn.udp.dstport = dst_port
        else
            conn.ip.src = ip_dst      
            conn.ip.dst = ip_src
            conn.udp.srcport = dst_port
            conn.udp.dstport = src_port      
        end
        init_ip_counters(conn.ip)
        conn.udp.dgms = { }
        connections[key] = conn

        debug_write("+")
        debug_write(key)
        debug_write(" ")
    end

    local client = ip_src == conn.ip.src and src_port == conn.udp.srcport
    update_connection(conn, pinfo, client)
    table.insert(conn.udp.dgms, get_packet_metrics(pinfo, client))    
end

function clear_connections()
    for k in pairs(connections) do connections[k] = nil end
end

function flush_connections(ts)
    evt = obj { }
    evt.event = 'flow-export'
    evt.ts = connections_start
    evt.te = ts
    print(json.encode(evt))

    local connection_array = {}
    for key, value in pairs(connections) do
        table.insert(connection_array, value)
    end
    clear_connections()

    table.sort(connection_array, function(a, b) return a.ts < b.ts end)
    for _, conn in pairs(connection_array) do
        debug_write(conn.id)
        debug_write(" ")
        local json_line = json.encode(conn)
        print(json_line)
        connections_flushed = connections_flushed + 1
    end
    io.flush()
end

function tap.packet(pinfo, tvb)
    debug_write("p_")
    debug_write(pinfo.number)
    debug_write(" ")
    packets_processed = packets_processed + 1

    last_packet_time = pinfo.abs_ts
    if not connections_start then connections_start = pinfo.abs_ts end
    if flush_interval and (pinfo.abs_ts > (connections_start + flush_interval)) then
           
        debug_write("\nf(")
        debug_write(pinfo.abs_ts)
        debug_write(")[ ")

        flush_connections(pinfo.abs_ts)
        
        debug_write("]\n")

        connections_start = pinfo.abs_ts
    end
end

-------------------------------------------------------------------------------
-- TAP DRAW FUNCTION:
-------------------------------------------------------------------------------
function tap.draw()
    flush_connections(last_packet_time)
    print('{"event" : "eof" }')
    io.flush()
    info_write(string.format("Capture completed. Processed %d packets in %d connections.", packets_processed, connections_flushed))
end