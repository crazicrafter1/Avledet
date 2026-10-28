local constants = assert(require("zs2_constants"))
local util = assert(require("zs2_util")) --str extensions

local NAME = constants.NAME
local proto  -- forward declare

local read_encoded_int = function(buffer, offset)
    local out = 0
    local num2 = 0
    while num2 ~= 35 do
        local b_len = buffer:len()
        -- inside the loop, before buffer:range(offset, 1):
        if offset >= b_len then
            error(string.format("read_encoded_int: offset %d >= buffer len %d", offset, b_len))
        end

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
            return offset, out
        end
    end
    error("bad encoded int")
end

--local string_range_offset = function(buffer, offset)
--    local length, offset = read_encoded_int(buffer, offset)
--
--    return buffer:range(offset, length), offset + length
--end

local id_validate = function(id)
    assert(not id:startswith(".") and not id:endswith("."))
    return NAME .. "." .. id
end

local field_class_factorysub = function(wrapper, body_range, offset, tvb_label_func, opt_on_render, opt_label)
    --for k, v in pairs(wrapper) do
    --    print(tostring(k) .. " ||| " .. tostring(v))
    --end

    local value_range = body_range:range(offset, wrapper.size)

    local value -- fwd decl
    if type(tvb_label_func) == 'string' then
        -- ie, value_range:le_int()...
        value = value_range[tvb_label_func](value_range)
    else -- function
        value = tvb_label_func(value_range)
        --value = assert(value ~= nil, 'parsed primitive: "' .. wrapper.name .. '" tried returning nil')
        assert(value ~= nil, 'parsed primitive: "' .. wrapper.name .. '" tried returning nil')
    end

    local render_func = function(root)
        local tree, _value = root:add_packet_field(wrapper.field, value_range, ENC_LITTLE_ENDIAN, opt_label) -- might be opt...

        if opt_on_render then
            opt_on_render(tree, _value)
        end

        return tree
    end

    -- TODO this might be bad return for factory
    return offset + wrapper.size, value, render_func -- ?!? is this correct ORDER?????
end

--local field_class_ctor = function(self_mapper, base)
--    local field_class = self_mapper.field_class
--    return field_class
--end

local fcm = function(field_class, tvb_label_func, size)
    local _type = type(tvb_label_func)
    assert(_type == 'string' or _type == 'function', 'tvb_label_func must be the tvb function name or a defined lambda')
    assert(type(size) == 'number')

    return {
        field_class = field_class,
        size = size,
        --factory = field_class_factory
        factory = function(wrapper, body_range, offset, opt_on_render, opt_label)
            return field_class_factorysub(wrapper, body_range, offset, tvb_label_func, opt_on_render, opt_label)
        end
    }
end

--[[
    what is a generator?
        the user-side builder

    what is a mapper?
        the internal memory-efficient shallow-copier
--]]

local fields_mapped  -- fwd decl

fields_mapped = {
    --  and will be used by every rpc/route/view... -- map will contain basic type definitions
    uint8 = fcm(ProtoField.uint8, 'uint', 1), -- size
    uint16 = fcm(ProtoField.uint16, 'le_uint', 2),
    uint32 = fcm(ProtoField.uint32, 'le_uint',  4),
    uint64 = fcm(ProtoField.uint64, 'le_uint64', 8),
    int8 = fcm(ProtoField.int8, 'int', 1), -- size
    int16 = fcm(ProtoField.int16, 'le_int', 2),
    int32 = fcm(ProtoField.int32, 'le_int', 4),
    int64 = fcm(ProtoField.int64, 'le_int64', 8),
    float = fcm(ProtoField.float, 'le_float', 4),
    double = fcm(ProtoField.double, 'le_float', 8),
    bool = fcm(ProtoField.bool, function(tvb) return tvb:uint() ~= 0 end, 1),
    bytes = {
        field_class = ProtoField.bytes,
        factory = function(wrapper, body_range, offset)
            -- parser
            local length_range = body_range:range(offset, 4)
            local length = length_range:le_int()
            local payload_range = body_range(offset + 4, length)
            local entire_range = body_range(offset, 4 + length)

            local render_func = function(root)
                -- Subtree
                local tree = root:add(proto, entire_range, wrapper.name .. " (" .. tostring(length) .. " bytes)")

                -- Ranged fields
                --tree:add_le(field_length, length_range)
                tree:add(wrapper.field, payload_range)
            end

            return offset + 4 + length, payload_range, render_func -- TODO range here to conform, but... might not be correct return value
        end
    },
    string = {
        field_class = ProtoField.string,
        -- self is 'this' (wrapper) table
        --  mapped.string:parser(tree)
        factory = function(wrapper, body_range, offset)
            local offset1, length = read_encoded_int(body_range, offset)

--[[             local value = ""
            if length > 0 then
                local string_range = body_range(offset1, length) --, offset + length
                value = string_range:string()
            end ]]

            local value = ""
            local string_range  -- declare outside the if
            if length > 0 then
                string_range = body_range(offset1, length)
                value = string_range:string()
            end

            --local tree = root:add(proto, body_range(offset, (offset1 - offset) + length), get_field_name(field_string) .. " (" .. string_range:string() .. ")")

            -- TODO
            --  THIS bind(...) FUNCTION IS NEEDED
            -- because, lua captures by var id slot
            -- not by value... so, we MUST MAKE COPIES
            local render_func = function(root)
                local tree = root:add(
                    proto,
                    body_range(offset, (offset1 - offset) + length),
                    wrapper.name .. " (" .. value .. ")"
                )

                -- Encoded 7-bit (display)
                tree:add(proto, body_range(offset, offset1 - offset), "Length (" .. tostring(length) .. ")")

                -- String contents (field)
                --  string_range is nil if length above is 0
                --  so we add dummy "" contents
                tree:add(wrapper.field, string_range or "") --, ENC_UTF_8 + ENC_STRING)
            end

            return offset1 + length, value, render_func --bind_renderer(wrapper, ) -- render_func
        end
    },
    zdoid = {
        field_classes = {userid = ProtoField.int64, id = ProtoField.uint32},
        -- TODO; unused
        type_classes = {
            userid = "int64",
            id = "uint32"
        },
        --mapped_classes = {userid = }
        -- self is 'this' (wrapper) table
        --  wrapper:parser(tree)


        -- TODO for more complicated variable-length trees, with variable length subfields
        --  the entire subtree must be parsed to calculate the correct body_range for the root
        
        --  SOOOOO... we range ahead of time (see above body_range)
        --      to make things about 1000x easier, we can just return a functions with visibility to the enclosed tree vars
        --      which will then add fields to the root once parsing is completed
        factory = function(wrapper, body_range, offset)
            local range_userid = body_range(offset, 8)
            local range_id = body_range(offset + 8, 4)

            local user_id_value = range_userid:le_int64()
            local id_value = range_id:le_uint()

            local render_func = function(root)
                local tree =
                    root:add(
                    proto,
                    body_range(offset, 12),
                    wrapper.name .. " (" .. tostring(user_id_value) .. ":" .. tostring(id_value) .. ")"
                )

                tree:add_packet_field(wrapper.fields.userid, range_userid, ENC_LITTLE_ENDIAN)
                tree:add_packet_field(wrapper.fields.id, range_id, ENC_LITTLE_ENDIAN)
            end

            local obj = {
                user_id = user_id_value,
                id = id_value
            }

            return offset + 12, obj, render_func
        end
    },
    vec3 = {
        field_classes = {x = ProtoField.float, y = ProtoField.float, z = ProtoField.float},
        factory = function(wrapper, body_range, offset)
            -- Ranges
            local x_range = body_range:range(offset + 0, 4)
            local y_range = body_range:range(offset + 4, 4)
            local z_range = body_range:range(offset + 8, 4)

            local x_value = x_range:le_float()
            local y_value = y_range:le_float()
            local z_value = z_range:le_float()

            local render_func = function(root)
                -- Subtree
                local tree =
                    root:add(
                    proto,
                    body_range(offset, 12),
                    wrapper.name ..
                        " (" .. x_value .. ", " .. y_value .. ", " .. z_value .. ")"
                )

                tree:add_packet_field(wrapper.fields.x, x_range, ENC_LITTLE_ENDIAN)
                tree:add_packet_field(wrapper.fields.y, y_range, ENC_LITTLE_ENDIAN)
                tree:add_packet_field(wrapper.fields.z, z_range, ENC_LITTLE_ENDIAN)
            end

            local obj = {
                x = x_value,
                y = y_value,
                z = z_value
            }

            return offset + 12, obj, render_func
        end
    },
    quat = {
        field_classes = {x = ProtoField.float, y = ProtoField.float, z = ProtoField.float, w = ProtoField.float},
        factory = function(wrapper, body_range, offset)
            -- Ranges
            local x_range = body_range:range(offset + 0, 4)
            local y_range = body_range:range(offset + 4, 4)
            local z_range = body_range:range(offset + 8, 4)
            local w_range = body_range:range(offset + 12, 4)

            local x_value = x_range:le_float()
            local y_value = y_range:le_float()
            local z_value = z_range:le_float()
            local w_value = w_range:le_float()

            local render_func = function(root)
                -- Subtree
                local tree =
                    root:add(
                    proto,
                    body_range(offset, 16),
                    wrapper.name .. " (" .. x_value .. ", " .. y_value .. ", " .. z_value .. ", " .. w_value .. ")"
                )

                tree:add_packet_field(wrapper.fields.x, x_range, ENC_LITTLE_ENDIAN)
                tree:add_packet_field(wrapper.fields.y, y_range, ENC_LITTLE_ENDIAN)
                tree:add_packet_field(wrapper.fields.z, z_range, ENC_LITTLE_ENDIAN)
                tree:add_packet_field(wrapper.fields.w, w_range, ENC_LITTLE_ENDIAN)
            end

            local obj = {
                x = x_value,
                y = y_value,
                z = z_value,
                w = w_value
            }

            return offset + 16, obj, render_func
        end
    }
    --,
    --userinfo = {
    --    field_classes = {name = ProtoField.string, id = ProtoField.string},
    --    factory = function(wrapper, body_range, offset)
    --        --wrapper.fields.name
    --        error("userinfo is nyi")
    --    end
    --}
    --,
    --container = {
    --    field_classes = {length = ProtoField.int32},
    --    type_classes = function(class_key)
    --    end,
    --    factory = function(wrapper, body_range, offset)
    --        error("nyi; container")
    --    end
    --}
}

local generator = function(class_key, sub_filter_id, name, base_optional)
    local mapped = fields_mapped[class_key]

    assert(type(name) == "string", "name must be a string")
    assert(type(sub_filter_id) == "string", "sub_filter_id must be a string")

    local wrapper = {
        factory = assert(mapped.factory, 'mapped class "' .. class_key .. '" is missing a factory'),
        name = name,
        sub_filter_id = sub_filter_id
    }

    wrapper.parser = function(wrapper, body_range, root, offset) -- TODO label
        local offset1, obj, render_func = wrapper:factory(body_range, offset)
        
        local err_base = "factory for generator: '" .. wrapper.name .. "' is missing a required "

        assert(offset1, err_base .. "offset")
        assert(obj ~= nil, err_base .. "parsed object table")
        assert(render_func, err_base .. "render_func")

        return offset1, obj, render_func(root)
    end

    local field_classes = mapped.field_classes
    if field_classes then
        -- usage
        --  wrapper:parser(range, tree, offset)
        local fields = {}

        for k, field_class in pairs(field_classes) do
            local absolute_id = id_validate(sub_filter_id .. "." .. k)
            local field = assert(field_class(absolute_id, k, base_optional))
            fields[k] = field -- trivial parser access!

            --proto.fields[ws_id .. "_" .. k] = field --field is now registered
            proto.fields[#proto.fields + 1] = field
        end

        wrapper.fields = fields
    else
        --wrapper.field = proto.fields[ws_id]
        local field_class = assert(mapped.field_class, 'must assign a "field_class" or "field_classes"')

        local absolute_id = id_validate(sub_filter_id)
        local field = assert(field_class(absolute_id, name, base_optional)) -- field is ctor'd

        --proto.fields[ws_id] = assert(field_class(absolute_id, name, base_opt)) --field is now registered

        -- We do not
        -- fk
        proto.fields[#proto.fields + 1] = field

        wrapper.field = field
        wrapper.size = mapped.size -- nil-nil | or value!
    end

    return wrapper
end

--[[
local _compiler = function(wrappers)
    -- registers all protos at once
    local fields = {}

    --https://stackoverflow.com/questions/75379622/how-to-add-an-array-of-fields-as-a-protofield-in-lua-dissector
    for k, field in pairs(wrappers) do
    end

    proto.fields = fields
end--]]
--[[
usage:
    local generator = assert(require('zs2_types'))
    
    local field_wrappers = {
        clienthandshake_haspw = generator(),
        --cli... keep adding fields

        -- add all top-level readings

        -- no need for manual sub fields for encap/containerized types
    }

    wrapper = generator()
--]]
return {
    generator = generator,
    set_proto = function(_proto)
        proto = _proto
    end,
    get_proto = function()
        return proto
    end
}
