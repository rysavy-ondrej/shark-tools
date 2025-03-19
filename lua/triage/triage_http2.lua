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

-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
-- Extract stream index used to collect packet into connections
local f_tcp_stream        = Field.new("tcp.stream")

local f_http2_req_full_uri = Field.new("http2.request.full_uri")
local f_http2_req_method = Field.new("http2.headers.method")
local f_http2_req_ua = Field.new("http2.headers.user_agent")

local f_http2_resp_code = Field.new("http2.headers.status")
local f_http2_resp_server = Field.new("http2.headers.server")

local f_http2_content_type = Field.new("http2.headers.content_type")
local f_http2_content_length = Field.new("http2.headers.content_length")


-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
local function get_request(method, uri, agent, content_type)
    local req = obj {}
    if method then req.method = tostring(method) end
    if uri then req.uri = tostring(uri) end
    if agent then req.agent = tostring(agent) end
    if content_type then req.content_type = tostring(content_type) end
    return req
end
local function get_respond(code, content_type, server)
    local res = obj {}
    if code then res.code = tostring(code) end
    if server then res.server = tostring(server) end
    if content_type then res.content_type = tostring(content_type) end
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
        
        table.insert(conn.http2.req, get_request(f_http2_req_method(), f_http2_req_full_uri(), f_http2_req_ua(), f_http2_content_type() ))
    end

    -- HTTP2 Response:
    if f_http2_resp_code() then
        if not conn.http2 then conn.http2 = obj {} end
        if not conn.http2.res then conn.http2.res = {} end

        table.insert(conn.http2.res, get_respond(f_http2_resp_code(), f_http2_content_type(), f_http2_resp_server() ))
    end

end

-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return http2