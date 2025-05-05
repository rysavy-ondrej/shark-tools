local tls = { _version = "0.1" }

-------------------------------------------------------------------------------
-- TAP&TABLE:
-------------------------------------------------------------------------------

local tap = Listener.new("frame","tls")         -- this is not working for 4.4.5!! Search for the listener for TLS in this version! Using ("tcp","tls") leads to the incorrect order!
local connection_table = nil

local __debug = false
function debug_write(str)
    if __debug then
        io.stderr:write(str)
    end
end


function tls.create_tap(connections, debug)
    connection_table = connections
    __debug = debug
    return tap   
end

local obj = require("ordered_table")
local sfield = require("safe_field")

-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
local f_tcp_stream      = Field.new("tcp.stream")
local f_tcp_srcport     = Field.new("tcp.srcport")
local f_ip_src          = Field.new("ip.src")

-- TLS specific fields:
local f_tls_rec_length  = Field.new("tls.record.length")
local f_tls_rec_ctype    = Field.new("tls.record.content_type")
local f_tls_rec_otype    = Field.new("tls.record.opaque_type")
local f_tls_rec_ver     = Field.new("tls.record.version")

-- TLS-specific field extractors (handshake)
local f_tls_hs_type         = Field.new("tls.handshake.type")
local f_tls_hs_version      = Field.new("tls.handshake.version")
local f_tls_hs_ciphersuite  = Field.new("tls.handshake.ciphersuite")
local f_tls_hs_extension    = Field.new("tls.handshake.extension.type")
local f_tls_hs_groups       = Field.new("tls.handshake.extensions_supported_group")
local f_tls_hs_ec_points    = Field.new("tls.handshake.extensions_ec_point_format")
local f_tls_hs_sni          = Field.new("tls.handshake.extensions_server_name")
local f_tls_hs_alpn         = Field.new("tls.handshake.extensions_alpn_str")
local f_tls_hs_sig_hash     = Field.new("tls.handshake.sig_hash_alg")
local f_tls_hs_sup_version  = Field.new("tls.handshake.extensions.supported_version")

-- TLS-JA hashes field extractors (handshake)
local f_tls_hs_ja3  = Field.new("tls.handshake.ja3")
local f_tls_hs_ja4  = sfield.new("tls.handshake.ja4", "JA4+ Plugin for Wireshark not installed. See https://github.com/FoxIO-LLC/ja4/tree/main/wireshark")
local f_tls_hs_ja3s  = Field.new("tls.handshake.ja3s")
local f_tls_ja4_ja4s  = sfield.new("ja4.ja4s", "JA4+ Plugin for Wireshark not installed. See https://github.com/FoxIO-LLC/ja4/tree/main/wireshark")
local f_tls_ja4_ja4x  = sfield.new("ja4.ja4x", "JA4+ Plugin for Wireshark not installed. See https://github.com/FoxIO-LLC/ja4/tree/main/wireshark") 

-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
GREASE_VALUES = {
    [0x0A0A] = true,
    [0x1A1A] = true,
    [0x2A2A] = true,
    [0x3A3A] = true,
    [0x4A4A] = true,
    [0x5A5A] = true,
    [0x6A6A] = true,
    [0x7A7A] = true,
    [0x8A8A] = true,
    [0x9A9A] = true,
    [0xAAAA] = true,
    [0xBABA] = true,
    [0xCACA] = true,
    [0xDADA] = true,
    [0xEAEA] = true,
    [0xFAFA] = true
}

function remove_grease(list)
    local clean_list = {}
    for i, entry in ipairs(list) do
        if GREASE_VALUES[entry.value] == nil then
            table.insert(clean_list, entry.value)
        end
    end
    return clean_list
end

function to_hexarray(list)
    local clean_list = {}
    for i, entry in ipairs(list) do
        table.insert(clean_list, string.format('%04X', tonumber(entry.value)))
    end
    return clean_list
end
function to_strarray(list)
    local clean_list = {}
    for i, entry in ipairs(list) do
        table.insert(clean_list, tostring(entry.value))
    end
    return clean_list
end

function to_hexstring(x)
    return string.format('%04X', x.value)
end

function get_recinfo(len, ct, ver, dir)
    local r = obj {}
    r.ver = ver
    r.ct = ct
    r.len = len
    r.dir = dir
    return r
end

-------------------------------------------------------------------------------
-- TAP PACKET FUNCTION:
-------------------------------------------------------------------------------
function tap.packet(pinfo, tvb)
    
    debug_write("s_")
    debug_write(pinfo.number)
    debug_write(" ")

    if not connection_table then error("connection_table is nil!") end
    local stream_id = f_tcp_stream()
    if not stream_id then return end
    local key = "tcp." .. tostring(stream_id.value)

    local conn = connection_table[key]
    if not conn then 
        debug_write("!")
        debug_write(key)
        debug_write(" ")
        return 
    end

    -- for client/server side identification
    local ip_src   = tostring(f_ip_src())
    local tcp_src  = f_tcp_srcport().value    
    -- initialize TLS for the first time
    if not conn.tls then conn.tls = obj {} end
    if not conn.tls.recs then conn.tls.recs = {} end


    local tls_types = nil
    if f_tls_rec_ctype() then 
        tls_types = { f_tls_rec_ctype() }
    elseif f_tls_rec_otype() then
        tls_types = { f_tls_rec_otype() }  
    end 
    local tls_vers = { f_tls_rec_ver() }

    -- Process TLS record lengths.
    local tls_lengths = { f_tls_rec_length() }
    if tls_lengths and #tls_lengths > 0 then
        for i, rec in ipairs(tls_lengths) do
            local rec_val = tonumber(tostring(rec))
            local rec_typ,rec_ver = nil
            if tls_types and #tls_types >= i then rec_typ = tonumber(tls_types[i].value) end
            if tls_vers and #tls_vers >= i then rec_ver = to_hexstring(tls_vers[i]) end
            if rec_val then
                if ip_src == conn.ip.src and tcp_src == conn.tcp.srcport then
                    table.insert(conn.tls.recs, get_recinfo(rec_val, rec_typ, rec_ver, -1 ))
                else
                    table.insert(conn.tls.recs, get_recinfo(rec_val, rec_typ, rec_ver, 1 ))
                end
            end
        end
    end

    -------------------------------------------------
    -- TLS HANDSHAKE
    if f_tls_hs_type() then
        local hs_type = tonumber(f_tls_hs_type().value)
        -------------------------------------------------
        -- CLIENT HELLO:
        if hs_type == 1 then
            
            if f_tls_hs_version() then
                conn.tls.cver = to_hexstring(f_tls_hs_version())
            end

            local ciphers = { f_tls_hs_ciphersuite() }
            if ciphers then
                conn.tls.cciphers = to_hexarray(ciphers)
            end

            local extensions = { f_tls_hs_extension() }
            if extensions then
                conn.tls.cexts = to_hexarray(extensions) 
            end

            local server_name = f_tls_hs_sni()
            if server_name then
                conn.tls.sni = tostring(server_name)
            end

            local alpn_arr = { f_tls_hs_alpn() }
            if alpn_arr then
                conn.tls.alpn = to_strarray(alpn_arr)
            end

            local sig_algo = { f_tls_hs_sig_hash() }
            if sig_algo then
                conn.tls.csigs = to_hexarray(sig_algo)
            end

            local sup_vers = { f_tls_hs_sup_version() }
            if sup_vers then
                conn.tls.csvers = to_hexarray(sup_vers)
            end

            local ja3 = f_tls_hs_ja3()
            if ja3 then
                conn.tls.ja3 = tostring(ja3)
            end
            
            local ja4 = f_tls_hs_ja4()
            if ja4 then
                conn.tls.ja4 = tostring(ja4)
            end

        -------------------------------------------------   
        -- SERVER HELLO:
        elseif hs_type == 2 then       

            local ver = f_tls_hs_version()
            if ver then
                conn.tls.sver = to_hexstring(ver)
            end

            local cipher = f_tls_hs_ciphersuite()
            if cipher then
                conn.tls.scipher = to_hexstring(cipher)
            end

            local extensions = { f_tls_hs_extension() }
            if extensions then
                conn.tls.sexts = to_hexarray(extensions) 
            end

            local sup_vers = { f_tls_hs_sup_version() }
            if sup_vers then
                conn.tls.ssvers = to_hexarray(sup_vers)
            end

            local ja3s = f_tls_hs_ja3s()
            if ja3s then
                conn.tls.ja3s = tostring(ja3s)
            end

            if f_tls_ja4_ja4s() then
                conn.tls.ja4s = tostring(f_tls_ja4_ja4s().value)
            end

        end
    end
end


-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return tls