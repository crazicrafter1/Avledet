-- Big thanks to this https://github.com/StephenClearyExamples/TcpChat/blob/master/tools/chat.lua
--  For some reason I couldnt formulate a functioning example with the Wireshark TCP reassembler
--      however this one worked perfectly after some tweaks

-- this pull breaks this code ...
-- https://gitlab.com/wireshark/wireshark/-/merge_requests/11787
--package.prepend_path("plugins/zsocket2")

-- init.lua will be loaded first
-- https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html

-- for debug logging during Wireshark init
--  Edit -> Preferences -> Advanced -> 'gui.console_open' change to ALWAYS
-- restart wireshark from cli

local constants = assert(require("zs2_constants"))

local NAME = constants.NAME
local HEADER_SIZE = constants.HEADER_SIZE

local proto = Proto(NAME, "zs2")
proto.prefs.port_range = Pref.range("Port Range", constants.PORT, 2456, 65535)
local port_range = proto.prefs.port_range

local types = assert(require("zs2_types"))
types.set_proto(proto)

local rpcs = assert(require("zs2_rpcs2"))
local wrappers = assert(require("zs2_field_wrappers"))
--assert(require("zs2_field_wrappers"))

--proto.fields = fields

--local fields = proto.fields

-- this holds the plain "data" Dissector, in case we can't dissect it
local data = Dissector.get("data")

-- Extract the length of the message from the header.
-- This length should include the size of the header itself.
local read_message_length_from_header = function(header_range)
    local length_prefix_range = header_range:range(0, 4)
    return length_prefix_range:le_int() + 4
    --return length_prefix_range:le_int()
end

-- Whatever you return from this method is passed as the first argument into dissect_message_fields
local dissect_header_fields = function(header_range, packet_info, tree)
    -- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
    --local length_prefix_range = header_range:range(0, 4)
    --tree:add_le(fields.msg_type, )
    ----tree:add_packet_field(fields.msg_type, length_prefix_range, ENC_LITTLE_ENDIAN)
end

local dissect_message_fields = function(header_result, body_range, packet_info, root)
    local rpc = rpcs[header_result]
    local text = rpc and rpc.name or ("Unknown (" .. header_result .. ")")

    if string.find(tostring(packet_info.cols.info), "^" .. NAME .. ":") == nil then
        packet_info.cols.info:append(": " .. text)
    else
        packet_info.cols.info:append(", " .. text)
    end

    -- TODO
    --  parser will be not so manual
    --  will be more arg-type declaring
    --  more simple readers for field-arguments
    if rpc then
        local parser = rpc.parser
        local params = rpc.params

        local offset = 0

        -- parser is parameterized
        if parser then
            assert(not params, "'params' and 'parser' is set, is this intentional?")

            local tree = root:add(proto, body_range(), text)
            rpc:parser(body_range, packet_info, tree, offset)
        else
            -- otherwise, params is chosen if present
            local params = rpc.params
            if params then
                local tree = root:add(proto, body_range(), text)
                for i, v in ipairs(params) do
                    offset = v:parser(body_range, tree, offset)
                end
            end
        end
    end
end

--
-- From here on out, there shouldn't have to be any changes for your protocol.
--

----------------------------------------
-- The function to check the length field.
--
-- This returns two things:
--   1. the length of the message, including the header.
--      If 0, then some parsing error happened.
--      If negative, then the absolute value of this is the number of bytes necessary to get a complete message.
--      If -DESEGMENT_ONE_MORE_SEGMENT, then an unknown number of bytes are still necessary to get a complete message.
--   2. the TvbRange object for the header. This is nil if length <= 0.
local check_length = function(tvbuf, offset)
    -- This example protocol implementation never returns 0 from this function,
    -- but if you get a packet that doesn't look like it's from your protocol,
    -- then it would be appropriate to return 0 from this function.

    -- "bytes_remaining" is the number of bytes remaining in the Tvb buffer which we
    -- have available to dissect in this run
    local bytes_remaining = tvbuf:len() - offset

    if bytes_remaining < HEADER_SIZE then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this messsage

    local header_range = tvbuf:range(offset, HEADER_SIZE)
    local message_length = read_message_length_from_header(header_range)

    if bytes_remaining < message_length then
        -- we need more bytes to get the whole message
        return -(message_length - bytes_remaining)
    end

    return message_length, header_range
end

----------------------------------------
-- The following is a local function used for dissecting our messages
-- inside the TCP segment using the desegment_offset/desegment_len method.
-- It's a separate function because we run over TCP and thus might need to
-- parse multiple messages in a single segment/packet. So we invoke this
-- function only dissects one message and we invoke it in a while loop
-- from the Proto's main disector function.
--
-- This function is passed in the original Tvb, Pinfo, and TreeItem from the Proto's
-- dissector function, as well as the offset in the Tvb that this function should
-- start dissecting from.
--
-- This function returns the length of the message it dissected as a
-- positive number, or as a negative number the number of additional bytes it
-- needs if the Tvb doesn't have them all, or a 0 for error.
--
local dissect = function(tvbuf, packet_info, root, offset)
    local message_length, header_range = check_length(tvbuf, offset)

    if message_length <= 0 then
        return message_length
    end

    -- if we got here, then we have a whole message in the Tvb buffer
    -- so let's finish dissecting it...

    -- set the protocol column to show our protocol name
    packet_info.cols.protocol:set(NAME)

    -- set the INFO column too, but only if we haven't already set it before
    -- for this frame/packet, because this function can be called multiple
    -- times per packet/Tvb
    if string.find(tostring(packet_info.cols.info), "^" .. NAME) == nil then
        packet_info.cols.info:set(NAME)
    end

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(proto, tvbuf:range(offset, message_length))

    local valheim_tree = root:add(proto, tvbuf:range(offset + HEADER_SIZE - 4, message_length - HEADER_SIZE), "Valheim")

    -- dissect the packet length
    dissect_header_fields(header_range, packet_info, tree)

    local type_range = header_range:range(4, 4)
    --valheim_tree:add_packet_field(fields.msg_type, type_range, ENC_LITTLE_ENDIAN)
    --valheim_tree:add_le(fields.msg_type, type_range)
    -- ai said that this is broken, so lets obviously trust it!
    --wrappers["msg_type"]:parser(type_range, valheim_tree, offset)
    wrappers["msg_type"]:parser(type_range, valheim_tree, 0)

    local hash = type_range:le_int()

    -- dissect the message fields
    --dissect_message_fields(header_result, tvbuf(offset + HEADER_SIZE, message_length - HEADER_SIZE), packet_info, tree)

    dissect_message_fields(hash, tvbuf(offset + HEADER_SIZE, message_length - HEADER_SIZE), packet_info, root)

    return message_length
end

--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- The 'tvbuf' is a Tvb object, 'packet_info' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function proto.dissector(tvbuf, packet_info, root)
    local port = packet_info.src_port
    local min_port, max_port = port_range:match("(%d+)-(%d+)")
    if min_port and max_port then
        min_port = tonumber(min_port)
        max_port = tonumber(max_port)
        if not (port >= min_port and port <= max_port) then
            return false
        end
    end

    -- get the length of the packet buffer (Tvb).
    local packet_length = tvbuf:len()

    -- check if capture was only capturing partial packet size
    if packet_length ~= tvbuf:reported_length_remaining() then
        -- captured packets are being sliced/cut-off, so don't try to dissect/reassemble
        return 0
    end

    local bytes_consumed = 0

    -- we do this in a while loop, because there could be multiple messages
    -- inside a single TCP segment, and thus in the same tvbuf - but our
    -- dissector() will only be called once per TCP segment, so we
    -- need to do this loop to dissect each message in it
    while bytes_consumed < packet_length do
        -- We're going to call our "dissect()" function, which is defined
        -- later in this script file. The dissect() function returns the
        -- length of the message it dissected as a positive number, or if
        -- it's a negative number then it's the number of additional bytes it
        -- needs if the Tvb doesn't have them all. If it returns a 0, it's a
        -- dissection error.
        local result = dissect(tvbuf, packet_info, root, bytes_consumed)

        if result > 0 then
            -- go again on another while loop
            -- we successfully processed a message, of 'result' length
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
        else
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            packet_info.desegment_offset = bytes_consumed

            -- the negative result so it's a positive number
            packet_info.desegment_len = -result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return packet_length
        end
    end

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)
    return bytes_consumed
end

-- set_plugin_info(table)
-- https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
local my_info = {
    version = "1.0.2",
    author = "crazicrafter1",
    repository = "https://github.com/Avledet/AvlWireshark"
}

set_plugin_info(my_info)

DissectorTable.get("tcp.port"):add(port_range, proto)
