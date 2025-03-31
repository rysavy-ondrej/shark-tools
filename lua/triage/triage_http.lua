local http = { _version = "0.1" }

-------------------------------------------------------------------------------
-- TAP&TABLE:
-------------------------------------------------------------------------------

local tap = Listener.new("http")     -- must be dns not udp with dns filter!
local connection_table = nil
function http.create_tap(connections)
    connection_table = connections
    return tap   
end

local obj = require("ordered_table")
-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
-- Extract stream index used to collect packet into connections
local f_tcp_stream        = Field.new("tcp.stream")
local f_frame_number        = Field.new("frame.number")

local f_http_req_full_uri  = Field.new("http.request.full_uri")
local f_http_req_method  = Field.new("http.request.method")
local f_http_req_ua  = Field.new("http.user_agent")
local f_http_req_content_type = Field.new("http.content_type")
local f_http_req_in = Field.new("http.request_in")
local f_http_req_content_length = Field.new("http.content_length")

local f_http_resp_code = Field.new("http.response.code")
local f_http_resp_server = Field.new("http.server")
local f_http_resp_content_type = Field.new("http.content_type")
local f_http_resp_in = Field.new("http.response_in")
local f_http_resp_time = Field.new("http.time")
local f_http_resp_content_length = Field.new("http.content_length")

-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
local function get_request(method, uri, agent, content_type, content_len, req_num)
    local req = obj {}
    if method then req.method = tostring(method) end
    if uri then req.uri = tostring(uri) end
    if agent then req.agent = tostring(agent) end
    if content_type then req.content_type = tostring(content_type) end
    if content_len then req.content_len = tostring(content_len.value) end
    if req_num then req.rnum = tonumber(req_num.value) end
    return req
end
local function get_respond(code, server, content_type, content_len, res_num, res_time)
    local res = obj {}
    if code then res.code = tostring(code) end
    if server then res.server = tostring(server) end
    if content_type then res.content_type = tostring(content_type) end
    if content_len then res.content_len = tostring(content_len.value) end
    if res_num then res.rnum = tonumber(res_num.value) end
    if res_time then res.time = tonumber(res_time.value) end
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

    -- HTTP1 Request:
    if f_http_req_method() then
        if not conn.http then conn.http = obj {} end
        if not conn.http.req then conn.http.req = {} end

        table.insert(conn.http.req, get_request(f_http_req_method(), f_http_req_full_uri(), f_http_req_ua(), f_http_req_content_type(), f_http_req_content_length(), f_frame_number() ))
    end

    -- HTTP1 Response:
    if f_http_resp_code() then
        if not conn.http then conn.http = obj {} end
        if not conn.http.res then conn.http.res = {} end

        table.insert(conn.http.res, get_respond(f_http_resp_code(),  f_http_resp_server(), f_http_resp_content_type(), f_http_resp_content_length(), f_http_req_in(), f_http_resp_time() ))
    end
end

-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return http