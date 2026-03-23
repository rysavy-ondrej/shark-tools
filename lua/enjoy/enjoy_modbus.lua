local modbus = { _version = "0.1" }

-------------------------------------------------------------------------------
-- TAP&TABLE:
-------------------------------------------------------------------------------

local tap = Listener.new("frame", "mbtcp")
local connection_table = nil

function modbus.create_tap(connections)
    connection_table = connections
    return tap
end

local obj = require("ordered_table")

-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
local f_tcp_stream = Field.new("tcp.stream")
local f_ip_src = Field.new("ip.src")
local f_tcp_srcport = Field.new("tcp.srcport")

local f_mbtcp_unit_id = Field.new("mbtcp.unit_id")
local f_modbus_func_code = Field.new("modbus.func_code")
local f_modbus_exception_code = Field.new("modbus.exception_code")

-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
local READ_FUNCTIONS = {
    [1] = true,   -- Read Coils
    [2] = true,   -- Read Discrete Inputs
    [3] = true,   -- Read Holding Registers
    [4] = true,   -- Read Input Registers
}

local WRITE_FUNCTIONS = {
    [5] = true,   -- Write Single Coil
    [6] = true,   -- Write Single Register
    [15] = true,  -- Write Multiple Coils
    [16] = true,  -- Write Multiple Registers
    [22] = true,  -- Mask Write Register
    [23] = true,  -- Read/Write Multiple Registers
}

local DIAGNOSTIC_FUNCTIONS = {
    [8] = true,   -- Diagnostics
}

local OTHER_FUNCTIONS = {
    [7] = true,   -- Read Exception Status
    [11] = true,  -- Get Comm Event Counter
    [12] = true,  -- Get Comm Event Log
    [17] = true,  -- Report Server ID
    [20] = true,  -- Read File Record
    [21] = true,  -- Write File Record
    [24] = true,  -- Read FIFO Queue
    [43] = true,  -- Encapsulated Interface Transport
}

local function ensure_modbus(conn)
    if not conn.modbus then
        conn.modbus = obj {}
        conn.modbus.read_requests = 0
        conn.modbus.write_requests = 0
        conn.modbus.diagnostic_requests = 0
        conn.modbus.other_requests = 0
        conn.modbus.undefined_requests = 0
        conn.modbus.success_responses = 0
        conn.modbus.error_responses = 0
    end
    return conn.modbus
end

local function is_client_packet(conn)
    local ip_src = f_ip_src()
    local tcp_src = f_tcp_srcport()
    return ip_src and tostring(ip_src) == conn.ip.src and tcp_src and tcp_src.value == conn.tcp.srcport
end

local function classify_request(info, func_code)
    if READ_FUNCTIONS[func_code] then
        info.read_requests = info.read_requests + 1
    elseif WRITE_FUNCTIONS[func_code] then
        info.write_requests = info.write_requests + 1
    elseif DIAGNOSTIC_FUNCTIONS[func_code] then
        info.diagnostic_requests = info.diagnostic_requests + 1
    elseif OTHER_FUNCTIONS[func_code] then
        info.other_requests = info.other_requests + 1
    else
        info.undefined_requests = info.undefined_requests + 1
    end
end

-------------------------------------------------------------------------------
-- TAP PACKET FUNCTION:
-------------------------------------------------------------------------------
function tap.packet(pinfo, tvb)
    local stream_id = f_tcp_stream()
    if not stream_id then return end

    local key = "tcp." .. tostring(stream_id.value)
    local conn = connection_table[key]
    if not conn or not conn.tcp or not conn.ip then return end

    local func_code_field = f_modbus_func_code()
    if not func_code_field then return end

    local info = ensure_modbus(conn)

    local unit_id = f_mbtcp_unit_id()
    if unit_id and info.unit_id == nil then
        info.unit_id = tonumber(unit_id.value)
    end

    local func_code = tonumber(func_code_field.value)
    if not func_code then return end

    if is_client_packet(conn) then
        classify_request(info, func_code)
    else
        if f_modbus_exception_code() then
            info.error_responses = info.error_responses + 1
        else
            info.success_responses = info.success_responses + 1
        end
    end
end

-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return modbus
