local mqtt = { _version = "0.1" }

-------------------------------------------------------------------------------
-- TAP&TABLE:
-------------------------------------------------------------------------------

local tap = Listener.new("frame", "mqtt")
local connection_table = nil

function mqtt.create_tap(connections)
    connection_table = connections
    return tap
end

local obj = require("ordered_table")

-------------------------------------------------------------------------------
-- FIELDS:
-------------------------------------------------------------------------------
local f_tcp_stream = Field.new("tcp.stream")

local f_mqtt_msgtype = Field.new("mqtt.msgtype")
local f_mqtt_clientid = Field.new("mqtt.clientid")
local f_mqtt_ver = Field.new("mqtt.ver")
local f_mqtt_protoname = Field.new("mqtt.protoname")
local f_mqtt_topic = Field.new("mqtt.topic")
local f_mqtt_conack_val = Field.new("mqtt.conack.val")
local f_mqtt_msg = Field.new("mqtt.msg")

-------------------------------------------------------------------------------
-- FUNCTIONS:
-------------------------------------------------------------------------------
local MQTT_MSGTYPE_CONNECT = 1
local MQTT_MSGTYPE_CONNACK = 2
local MQTT_MSGTYPE_PUBLISH = 3
local MQTT_MSGTYPE_SUBSCRIBE = 8

local function ensure_mqtt(conn)
    if not conn.mqtt then conn.mqtt = obj {} end
    return conn.mqtt
end

local function ensure_connection_info(conn)
    local mqtt_info = ensure_mqtt(conn)
    if not mqtt_info.connection then mqtt_info.connection = obj {} end
    return mqtt_info.connection
end

local function get_subscribe_event(topics)
    local event = obj {}
    event.topics = topics
    return event
end

local function get_publish_event(topic, msg)
    local event = obj {}
    if topic then event.topic = topic end
    if msg then event.msg = msg end
    return event
end

local function get_topics()
    local topics = {}
    for _, topic in ipairs({ f_mqtt_topic() }) do
        table.insert(topics, tostring(topic))
    end
    return topics
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

    local msgtype = f_mqtt_msgtype()

    if msgtype and tonumber(msgtype.value) == MQTT_MSGTYPE_CONNECT then
        local connection = ensure_connection_info(conn)

        local clientid = f_mqtt_clientid()
        if clientid then connection.clientid = tostring(clientid) end

        local version = f_mqtt_ver()
        if version then connection.ver = tostring(version) end

        local protoname = f_mqtt_protoname()
        if protoname then connection.protoname = tostring(protoname) end
    end

    if msgtype and tonumber(msgtype.value) == MQTT_MSGTYPE_CONNACK then
        local connection = ensure_connection_info(conn)
        local conack = f_mqtt_conack_val()
        if conack then connection.conack = tonumber(conack.value) end
    end

    if msgtype and tonumber(msgtype.value) == MQTT_MSGTYPE_SUBSCRIBE then
        local topics = get_topics()
        if #topics > 0 then
            local mqtt_info = ensure_mqtt(conn)
            if not mqtt_info.subscribe then mqtt_info.subscribe = {} end
            table.insert(mqtt_info.subscribe, get_subscribe_event(topics))
        end
    end

    if msgtype and tonumber(msgtype.value) == MQTT_MSGTYPE_PUBLISH then
        local topic = f_mqtt_topic()
        local message = f_mqtt_msg()

        if topic or message then
            local mqtt_info = ensure_mqtt(conn)
            if not mqtt_info.publish then mqtt_info.publish = {} end
            table.insert(
                mqtt_info.publish,
                get_publish_event(
                    topic and tostring(topic) or nil,
                    message and tostring(message) or nil
                )
            )
        end
    end
end

-------------------------------------------------------------------------------
-- END:
-------------------------------------------------------------------------------
return mqtt
