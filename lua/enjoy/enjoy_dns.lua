local dns = { _version = "0.1" }

-------------------------------------------------------------------------------
-- TAP&TABLE:
-------------------------------------------------------------------------------

local tap = Listener.new("dns")     -- must be dns not udp with dns filter!
local connection_table = nil

local __debug = false
function debug_write(str)
    if __debug then
        io.stderr:write(str)
    end
end


function dns.create_tap(connections, debug)
    connection_table = connections
    __debug = debug
    return tap   
end

local obj = require("ordered_table")

-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
-- Extract stream index used to collect packet into connections
local f_udp_stream        = Field.new("udp.stream")
-- Field extractors for connection and DNS fields.
local f_dns_id          = Field.new("dns.id")
local f_dns_qry_name    = Field.new("dns.qry.name")
local f_dns_qry_type    = Field.new("dns.qry.type")
local f_dns_flags_resp  = Field.new("dns.flags.response")
local f_dns_count_queries = Field.new("dns.count.queries")
local f_dns_count_answers = Field.new("dns.count.answers")
local f_dns_count_auth_rr = Field.new("dns.count.auth_rr")
local f_dns_count_add_rr = Field.new("dns.count.add_rr")
local f_dns_flags_rcode = Field.new("dns.flags.rcode")
local f_dns_a           = Field.new("dns.a")
local f_dns_aaaa       = Field.new("dns.aaaa")
local f_dns_cname       = Field.new("dns.cname")
local f_dns_ns       = Field.new("dns.ns")
local f_dns_resp_name   = Field.new("dns.resp.name")
local f_dns_resp_type   = Field.new("dns.resp.type")
local f_dns_resp_ttl   = Field.new("dns.resp.ttl")


-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
DNS_RESPONSE_TYPES = {
    [1]   = "A",
    [2]   = "NS",
    [3]   = "MD",
    [4]   = "MF",
    [5]   = "CNAME",
    [6]   = "SOA",
    [7]   = "MB",
    [8]   = "MG",
    [9]   = "MR",
    [10]  = "NULL",
    [11]  = "WKS",
    [12]  = "PTR",
    [13]  = "HINFO",
    [14]  = "MINFO",
    [15]  = "MX",
    [16]  = "TXT",
    [17]  = "RP",
    [18]  = "AFSDB",
    [19]  = "X25",
    [20]  = "ISDN",
    [21]  = "RT",
    [22]  = "NSAP",
    [23]  = "NSAP-PTR",
    [24]  = "SIG",
    [25]  = "KEY",
    [26]  = "PX",
    [27]  = "GPOS",
    [28]  = "AAAA",
    [29]  = "LOC",
    [30]  = "NXT",
    [31]  = "EID",
    [32]  = "NIMLOC",
    [33]  = "SRV",
    [34]  = "ATMA",
    [35]  = "NAPTR",
    [36]  = "KX",
    [37]  = "CERT",
    [38]  = "A6",
    [39]  = "DNAME",
    [40]  = "SINK",
    [41]  = "OPT",
    [42]  = "APL",
    [43]  = "DS",
    [44]  = "SSHFP",
    [45]  = "IPSECKEY",
    [46]  = "RRSIG",
    [47]  = "NSEC",
    [48]  = "DNSKEY",
    [49]  = "DHCID",
    [50]  = "NSEC3",
    [51]  = "NSEC3PARAM",
    [52]  = "TLSA",
    [53]  = "SMIMEA",
    [55]  = "HIP",
    [56]  = "NINFO",
    [57]  = "RKEY",
    [58]  = "TALINK",
    [59]  = "CDS",
    [60]  = "CDNSKEY",
    [61]  = "OPENPGPKEY",
    [62]  = "CSYNC",
    [63]  = "ZONEMD",
    [64]  = "SVCB",
    [65]  = "HTTPS",
    [99]  = "SPF",
    [100] = "UINFO",
    [101] = "UID",
    [102] = "GID",
    [103] = "UNSPEC",
    [104] = "NID",
    [105] = "L32",
    [106] = "L64",
    [107] = "LP",
    [108] = "EUI48",
    [109] = "EUI64",
    [249] = "TKEY",
    [250] = "TSIG",
    [251] = "IXFR",
    [252] = "AXFR",
    [253] = "MAILB",
    [254] = "MAILA",
    [255] = "ANY",
    [256] = "URI",
    [257] = "CAA",
    [258] = "AVC",
    [259] = "DOA",
    [260] = "AMTRELAY"
}

local function array_new(len, value)
    local arr = {}
    for i = 1, len do
        arr[i] = value
    end
    return arr
end

local function array_concat(...)
    local result = {}
    local arrays = {...}
    for _, arr in ipairs(arrays) do
        for i = 1, #arr do
            result[#result + 1] = arr[i]
        end
    end
    return result
end
local function get_query(qn,qt)
    local q = obj {}
    q.qn = qn
    q.qt = qt
    return q
end

local function get_response(rr, qn, rt, ttl, rv)
    local r = obj {}
    r.rr = rr
    r.qn = qn
    r.rt = rt
    r.ttl = ttl
    r.rv = rv
    return r
end
-------------------------------------------------------------------------------
-- TAP PACKET FUNCTION:
-------------------------------------------------------------------------------
function tap.packet(pinfo, tvb)
    debug_write("d_")
    debug_write(pinfo.number)
    debug_write(" ")
    -- get the key for the communicaton based on UDP Stream ID
    local udp_stream_id = f_udp_stream()
    if not udp_stream_id then return end
    local key = "udp." .. tostring(udp_stream_id.value) 

    local entry = connection_table[key]
    if not entry then return end

    if not entry.dns then entry.dns = {} end

    local respFlagField = f_dns_flags_resp()
    if not respFlagField then return end    -- not flag!?!
    local isResponse = respFlagField.value
    
    -- DNS Request packet
    if not isResponse then
        local query_names =  { f_dns_qry_name() }
        local query_types =  { f_dns_qry_type() }
        local dns_queries = {} 
        for i, n in ipairs(query_names) do
            table.insert(dns_queries, get_query(tostring(n), DNS_RESPONSE_TYPES[tonumber(tostring(query_types[i]))] ))
        end
        entry.dns.queries = dns_queries
        
    else
        entry.dns.rcode = f_dns_flags_rcode() and tonumber(f_dns_flags_rcode().value) or 0
        -- Reconstructing the answers is a bit tricky
        -- Fields such as 'dns.a' and 'dns.cname' are arrays 
        -- but they do not have information to which response they belong to.
        -- Thus we need first to enumerate all responses and then 
        -- identify the corresponsind items depending on the response type

        local ans_count = tonumber(f_dns_count_answers().value)
        local aut_count = tonumber(f_dns_count_auth_rr().value)
        local add_count = tonumber(f_dns_count_add_rr().value)
        local rr_map = array_concat(array_new(ans_count, "answer"), array_new(aut_count, "authority"), array_new(add_count, "additional"))

        local dns_a = { f_dns_a() }
        local dns_cname = { f_dns_cname() }
        local dns_ns = { f_dns_ns() }
        local dns_aaaa = { f_dns_aaaa() }

        local resp_names =  { f_dns_resp_name() }
        local resp_types =  { f_dns_resp_type() }
        local resp_ttl =  { f_dns_resp_ttl() }
        local dns_responses = {}
        for i, rn in ipairs(resp_names) do
            local rn_str = tostring(rn)
            local rn_type = DNS_RESPONSE_TYPES[tonumber(tostring(resp_types[i]))]
            local resp_val = ""
            if rn_type == "A" then
                resp_val = tostring(dns_a[1])
                table.remove(dns_a,1)
            elseif rn_type == "CNAME" then
                resp_val = tostring(dns_cname[1])
                table.remove(dns_cname,1) 
            elseif rn_type == "NS" then
                resp_val = tostring(dns_ns[1])
                table.remove(dns_ns,1)
            elseif rn_type == "AAAA" then
                resp_val = tostring(dns_aaaa[1])
                table.remove(dns_aaaa,1)                                       
            end
            table.insert(dns_responses, get_response(rr_map[i], rn_str, rn_type, tonumber(tostring(resp_ttl[i])), resp_val) )
        end
        entry.dns.responses = dns_responses
    end
end

-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return dns