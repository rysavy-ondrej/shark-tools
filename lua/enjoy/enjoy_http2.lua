local http2 = { _version = "0.1" }

-------------------------------------------------------------------------------
-- TAP&TABLE:
-------------------------------------------------------------------------------

local tap = Listener.new("http2")     -- must be dns not udp with dns filter!
local connection_table = nil
function http2.create_tap(connections)
    connection_table = connections
    return tap   
end

local obj = require("ordered_table")
local sfield = require("safe_field")
-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
-- Extract stream index used to collect packet into connections
local f_tcp_stream        = Field.new("tcp.stream")
local f_frame_number        = Field.new("frame.number")

local f_http2_req_full_uri = sfield.new("http2.request.full_uri", "Field http2.request.full_uri is available from version 4.0.0.")     -- not available in 3.6.7
local f_http2_req_method = Field.new("http2.headers.method")
local f_http2_req_ua = Field.new("http2.headers.user_agent")
local f_http2_req_in = sfield.new("http2.request_in", "Field http2.request_in is available from version 4.0.0.")                 -- not available in 3.6.7

local f_http2_resp_code = Field.new("http2.headers.status")
local f_http2_resp_server = Field.new("http2.headers.server")

local f_http2_content_type = Field.new("http2.headers.content_type")
local f_http2_content_length = Field.new("http2.headers.content_length")


-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
local function get_request(method, uri, agent, content_type, req_num)
    local req = obj {}
    if method then req.method = tostring(method) end
    if uri then req.uri = tostring(uri) end
    if agent then req.agent = tostring(agent) end
    if content_type then req.content_type = tostring(content_type) end
    if req_num then req.rnum = tonumber(req_num.value) end
    return req
end
local function get_respond(code, content_type, server, req_num)
    local res = obj {}
    if code then res.code = tostring(code) end
    if server then res.server = tostring(server) end
    if content_type then res.content_type = tostring(content_type) end
    if req_num then res.rnum = tonumber(req_num.value) end
    return res
end
-------------------------------------------------------------------------------
-- TAP PACKET FUNCTION:
-------------------------------------------------------------------------------
function tap.packet(pinfo, tvb)
  
    local stream_id = f_tcp_stream()
    if not stream_id then return end
    local key = "tcp." .. tostring(stream_id.value) 

    local conn = connection_table[key]
    if not conn then return end

    -- HTTP2 Request:
    if f_http2_req_method() then
        if not conn.http2 then conn.http2 = obj {} end
        if not conn.http2.req then conn.http2.req = {} end
        
        table.insert(conn.http2.req, get_request(f_http2_req_method(), f_http2_req_full_uri(), f_http2_req_ua(), f_http2_content_type(), f_frame_number() ))
    end

    -- HTTP2 Response:
    if f_http2_resp_code() then
        if not conn.http2 then conn.http2 = obj {} end
        if not conn.http2.res then conn.http2.res = {} end

        table.insert(conn.http2.res, get_respond(f_http2_resp_code(), f_http2_content_type(), f_http2_resp_server(), f_http2_req_in() ))
    end

end

-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return http2