--[[
triage.lua

This TShark Lua script extracts connection (bidirectional flow) information from each packet.
A connection is defined as a bidirectional flow where the client is the source side of the connection.
It also enrich the connection with the following protocol related information:

Tested with:

TShark (Wireshark) 4.2.5 (v4.2.5-0-g4aa814ac25a1).

TShark (Wireshark) 4.4.5.


Usage:
  tshark -q -X lua_script:triage.lua -r your_capture_file.pcap
--]]

-------------------------------------------------------------------------------
-- GLOBAL:
-------------------------------------------------------------------------------
-- Use JSON lib to generate the output
local json = require("json")
local obj = require("ordered_table")
-- Table to store connections; key is based on TCP/UDP stream id 
local connections = {}

-------------------------------------------------------------------------------
-- TAPS:
-------------------------------------------------------------------------------
-- Define TAPs used to process the input packets. 
local tap = Listener.new("ip") 
local tcp_tap = Listener.new("tcp")  
local udp_tap = Listener.new("udp") 

-- Instantiate external taps to process application protocols:
local tls = require("triage_tls")
tls.create_tap(connections)

local dns = require("triage_dns")
dns.create_tap(connections)

local http = require("triage_http")
http.create_tap(connections)

local http2 = require("triage_http2")
http2.create_tap(connections)

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
    prec = obj {}
    prec.ts = pinfo.abs_ts
    --if client then prec.dir = ">" else prec.dir = "<" end
    if client then prec.dir = -1 else prec.dir = 1 end

    if f_tcp_len() then prec.len = f_tcp_len().value
    elseif f_udp_len() then prec.len = f_udp_len().value
    else prec.len = 0
    end

    if f_tcp_flags() then
        prec.flags = obj {}
        prec.flags.str = get_tcp_flags_string(f_tcp_flags().value)
        prec.flags.val = f_tcp_flags().value 
    end
    return prec
end

-------------------------------------------------------------------------------
-- TAP PACKET FUNCTION:
-------------------------------------------------------------------------------
function tcp_tap.packet(pinfo, tvb)
    local stream_id = f_tcp_stream()
    if not stream_id then return end
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
    end

    local client = ip_src == conn.ip.src and tcp_src == conn.tcp.srcport
    update_connection(conn, pinfo, client)
    table.insert(conn.tcp.segs, get_packet_metrics(pinfo, client))
end

function udp_tap.packet(pinfo, tvb)
    local stream_id = f_udp_stream()
    if not stream_id then return end
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
    end


    local client = ip_src == conn.ip.src and src_port == conn.udp.srcport
    update_connection(conn, pinfo, client)
    table.insert(conn.udp.dgms, get_packet_metrics(pinfo, client))    
end

-------------------------------------------------------------------------------
-- TAP DRAW FUNCTION:
-------------------------------------------------------------------------------
function tap.draw()
    local connection_array = {}
    for key, value in pairs(connections) do
        table.insert(connection_array, value)
    end
    table.sort(connection_array, function(a, b)
        return a.ts < b.ts
    end)
    for _, conn in pairs(connection_array) do
        local json_line = json.encode(conn)
        print(json_line)
    end
end