local proto

local readEncodedInt = function(buffer, offset)
    local out = 0
    local num2 = 0
    while num2 ~= 35 do
        local b = buffer:range(offset, 1):le_uint()
        offset = offset + 1

        assert(b >= 0 and b <= 255, "byte too big")

        -- not supported in lua 5.2 (which Wireshark uses)
        --out |= (b & 127) << num2
        --out = out | ((b & 127) << num2)
        out = bit.bor(out, bit.lshift(bit.band(b, 127), num2))
        num2 = num2 + 7
        --if (b & 128) == 0 then
        if bit.band(b, 128) == 0 then
            return out, offset
        end
    end
    error("bad encoded int")
end

return {
    readStringRange = function(buffer, offset)
        local length, offset = readEncodedInt(buffer, offset)

        return buffer:range(offset, length), offset + length
    end,
    --local readUBytesRange(buffer, offset)
    --local length = buffer
    --end

    --local readString(buffer, offset)
    --    local length, offset = readEncodedInt(buffer, offset)
    --
    --    return buffer(offset, length):string(), offset + length
    --end

    -- fields_array: an array of map-pairs: [{'name/desc' = 'fld_name', 'field' = readers.addZDOID}, ...]
    addContainer = function(body_range, root, name, fields_array, offset)
        -- TODO
        --  iterate array, adding fields
        --  gather field size, instead of hard-coded like the below...

        -- assume size-prefix is 4 bytes
        local count_range = body_range:range(offset, 4) -- TODO make size-count variable
        local count = count_range:le_int()
        offset = offset + 4 -- TODO change this '4' too

        local list_tree = root:add(proto, name .. "(" .. tostring(count) .. " items)")

        for i = 1, count do
            for k, v in ipairs(fields_array) do
                -- parse fields in order as they appear
                --v['field']()
            end
        end
    end,
    addZDOID = function(body_range, root, name, field_userid, field_id, offset)
        local range_userid = body_range(offset, 8)
        local range_id = body_range(offset + 8, 4)

        local tree =
            root:add(
            proto,
            body_range(offset, 12),
            name .. " (" .. tostring(range_userid:le_int64()) .. ":" .. tostring(range_id:le_uint()) .. ")"
        )

        tree:add_le(field_userid, range_userid)
        tree:add_le(field_id, range_id)

        return offset + 12
    end,
    addString = function(body_range, root, name, field_string, offset)
        local length, offset1 = readEncodedInt(body_range, offset)
        local string_range = body_range:range(offset1, length) --, offset + length

        --local tree = root:add(proto, body_range(offset, (offset1 - offset) + length), get_field_name(field_string) .. " (" .. string_range:string() .. ")")

        local tree =
            root:add(
            proto,
            body_range(offset, (offset1 - offset) + length),
            name .. " (" .. string_range:string() .. ")"
        )

        -- Encoded 7-bit display
        local tree_enclength =
            tree:add(proto, body_range(offset, offset1 - offset), "Length (" .. tostring(length) .. ")")

        -- String contents
        tree:add(field_string, string_range) --, ENC_UTF_8 + ENC_STRING)

        return offset1 + length
    end,
    addVector3 = function(body_range, root, name, field_x, field_y, field_z, offset)
        -- Ranges
        local x_range = body_range:range(offset, 4)
        local y_range = body_range:range(offset + 4, 4)
        local z_range = body_range:range(offset + 8, 4)

        -- Subtree
        local tree =
            root:add(
            proto,
            body_range(offset, 12),
            name .. " (" .. x_range:le_float() .. ", " .. y_range:le_float() .. ", " .. z_range:le_float() .. ")"
        )

        -- Ranged fields
        tree:add_le(field_x, x_range)
        tree:add_le(field_y, y_range)
        tree:add_le(field_z, z_range)

        return offset + 12
    end,
    addBytes = function(body_range, root, name, field_length, field_bytes, offset)
        -- Ranges
        local length_range = body_range:range(offset, 4)
        local length = length_range:le_int()
        local bytes_range = body_range(offset + 4, length)

        -- Subtree
        local tree = root:add(proto, body_range(offset, 4 + length), name .. " (" .. tostring(length) .. " bytes)")

        -- Ranged fields
        tree:add_le(field_length, length_range)
        tree:add(field_bytes, bytes_range)

        return offset + 4 + length
    end,
    set_proto = function(_proto)
        proto = _proto
    end,
    get_proto = function()
        return proto
    end
}
