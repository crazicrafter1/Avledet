local readers = assert(require("zsocket2_readers"))
local fields = assert(require("zsocket2_fields"))
local prefabs = assert(require("zsocket2_prefabs"))
local constants = assert(require("zsocket2_constants"))

local proto = readers.get_proto()

local PORT = constants.PORT

return {
    [1233642074] = {
        name = "ServerHandshake"
    },
    [1021693670] = {
        name = "ClientHandshake",
        parser = function(body_range, packet_info, tree, offset)
            --[[
                Wireshark lua Fields:
                    are the visual representation

                    highlighting: also visual, but ties in with payload

                    add_packet_field: used for highlighting (but apparently try to avoid for simplicity)
                        https://osqa-ask.wireshark.org/questions/11750/is-there-a-lua-bug-that-prevents-byte-highlighting-upon-field-selection/

                intended usage (parsing)
                    field_wrapper: dict:
                        'field': raw ProtoField
                        'parser': reader: function()
                        --'size': primarily for primitive types
                            actually, incorporate with parser()

                    offset = field_wrapper:read(body_range, tree, offset)

                intended usage (declaring)
                    -- above...
                    local HIGHLIGHT = true
                    -- ...
                    
                    local wrapper = generator:uint8('peerinfo.userid', 'User ID', HIGHLIGHT)

                    local wrapper1 = generator:string('peerinfo.version', 'Version', HIGHLIGHT)
                        -- because wrapper is comprised of a e7-int, bytes
                        -- contain 2 fields, ids: 'peerinfo.version.length', 'peerinfo.version.payload'
            --]]
            --field_wrapper

            tree:add_packet_field(fields.clienthandshake_haspassword, body_range:range(offset, 1), ENC_LITTLE_ENDIAN)
            offset = offset + 1

            offset = readers.addString(body_range, tree, "Password Salt", fields.clienthandshake_passwordsalt, offset)
        end
    },
    [-725574882] = {
        name = "PeerInfo",
        parser = function(body_range, packet_info, tree, offset)
            -- skip parameter package length
            offset = offset + 4

            tree:add_packet_field(fields.peerinfo_userid, body_range:range(offset, 8), ENC_LITTLE_ENDIAN)
            offset = offset + 8

            offset = readers.addString(body_range, tree, "Version", fields.peerinfo_version, offset)

            --local version_range, offset = readStringRange(body_range, offset)
            --tree:add_packet_field(fields.peerinfo_version, version_range, ENC_UTF_8 + ENC_STRING)

            tree:add_packet_field(fields.peerinfo_networkversion, body_range:range(offset, 4), ENC_LITTLE_ENDIAN)
            offset = offset + 4

            offset =
                readers.addVector3(
                body_range,
                tree,
                "Position",
                fields.peerinfo_posx,
                fields.peerinfo_posy,
                fields.peerinfo_posz,
                offset
            )

            --tree:add_packet_field(fields.peerinfo_posx, body_range:range(offset, 4), ENC_LITTLE_ENDIAN)
            --tree:add_packet_field(fields.peerinfo_posy, body_range:range(offset + 4, 4), ENC_LITTLE_ENDIAN)
            --tree:add_packet_field(fields.peerinfo_posz, body_range:range(offset + 8, 4), ENC_LITTLE_ENDIAN)
            --offset = offset + 12

            offset = readers.addString(body_range, tree, "Name", fields.peerinfo_name, offset)

            --local name_range, offset = readStringRange(body_range, offset)
            --tree:add_packet_field(fields.peerinfo_name, name_range, ENC_UTF_8 + ENC_STRING)

            -- if server
            if packet_info.dst_port == PORT then
                ---local ticketLen = body_range:range(offset, 4):le_uint()
                --offset = offset + 4
                -- TODO this doesnt work for some reason
                --assert(fields.peerinfo_sessionticket, 'sessionticket field is nil')
                --tree:add_packet_field(fields.peerinfo_sessionticket, body_range:range(offset, ticketLen), ENC_NONE)
                ---tree:add(fields.peerinfo_sessionticket, body_range:range(offset, ticketLen))
                --tree:add_packet_field(fields.peerinfo_sessionticket, body_range:range(offset, ticketLen), ENC_STRING)
                --tree:add(fields.peerinfo_sessionticket, body_range:range(offset, ticketLen))
                offset = readers.addString(body_range, tree, "Password", fields.peerinfo_password, offset)

                --local password_range, offset = readStringRange(body_range, offset)
                --tree:add_packet_field(fields.peerinfo_password, password_range, ENC_UTF_8 + ENC_STRING)

                offset =
                    readers.addBytes(
                    body_range,
                    tree,
                    "Session Ticket",
                    fields.peerinfo_sessionticketlength,
                    fields.peerinfo_sessionticket,
                    offset
                )
            else
                offset = readers.addString(body_range, tree, "World Name", fields.peerinfo_worldname, offset)

                --local worldname_range, offset = readStringRange(body_range, offset)
                --tree:add_packet_field(fields.peerinfo_worldname, worldname_range, ENC_UTF_8 + ENC_STRING)

                tree:add_packet_field(fields.peerinfo_worldseed, body_range:range(offset, 4), ENC_LITTLE_ENDIAN)
                offset = offset + 4

                offset = readers.addString(body_range, tree, "World Seed Name", fields.peerinfo_worldseedname, offset)

                --local worldseedname_range, offset = readStringRange(body_range, offset)
                --tree:add_packet_field(fields.peerinfo_worldseedname, worldseedname_range, ENC_UTF_8 + ENC_STRING)

                tree:add_packet_field(fields.peerinfo_worlduid, body_range:range(offset, 8), ENC_LITTLE_ENDIAN)
                offset = offset + 8

                tree:add_packet_field(fields.peerinfo_worldgenversion, body_range:range(offset, 4), ENC_LITTLE_ENDIAN)
                offset = offset + 4

                tree:add_packet_field(fields.peerinfo_worldtime, body_range:range(offset, 8), ENC_LITTLE_ENDIAN)
                offset = offset + 8
            end
        end
    },
    [-667652280] = {
        name = "RoutedRpc",
        parser = function(body_range, packet_info, tree, offset)
            -- skip parameter package length
            offset = offset + 4

            tree:add_le(fields.routedrpc_msgid, body_range:range(offset, 8))
            offset = offset + 8

            tree:add_le(fields.routedrpc_senderid, body_range:range(offset, 8))
            offset = offset + 8

            tree:add_le(fields.routedrpc_targetid, body_range:range(offset, 8))
            offset = offset + 8

            offset =
                readers.addZDOID(
                body_range,
                tree,
                "Target ZDOID",
                fields.routedrpc_targetzdoid_userid,
                fields.routedrpc_targetzdoid_id,
                offset
            )

            --tree:add_le(fields.routedrpc_targetzdoid_userid, body_range:range(offset, 8))
            --offset = offset + 8
            --
            --tree:add_le(fields.routedrpc_targetzdoid_id, body_range:range(offset, 4))
            --offset = offset + 4

            tree:add_le(fields.routedrpc_type, body_range:range(offset, 4))
            offset = offset + 4

            offset =
                readers.addBytes(
                body_range,
                tree,
                "Parameters",
                fields.routedrpc_parameterslength,
                fields.routedrpc_parameters,
                offset
            )

            --tree:add(fields.routedrpc_parameters, body_range:range(offset, ticketLen))

            -- TODO populate the tree with fully verbose elements (sub items to precisely denote the position and the ranges)
            --  create sub elements for:
            --      maybe an easy deserialize method:
            --          local readZDOID = function(tree, field, offset) ... end
            --          local readString = function(tree, field, offset) ... end
            --      ZDOID
            --      string
            --      bytes
            --

            -- read length first
            --tree:add_le(fields.routedrpc_parameters, body_range:range(offset, 4))
        end
    },
    [-2045981424] = {
        name = "NetTime",
        parser = function(body_range, packet_info, tree, offset)
            tree:add_le(fields.nettime_time, body_range:range(offset, 8))
        end
    },
    [1191884308] = {
        name = "CharacterID",
        parser = function(body_range, packet_info, tree, offset)
            -- parsers should be ignored
            offset =
                readers.addZDOID(
                body_range,
                tree,
                "CharacterID",
                fields.characterid_zdoid_userid,
                fields.characterid_zdoid_id,
                offset
            )
        end
    },
    [-508691474] = {
        name = "Unban",
        parser = function(body_range, packet_info, tree, offset)
            offset = readers.addString(body_range, tree, "Name", fields.unban_name, offset)
        end
    },
    [-23454927] = {
        name = "RemotePrint",
        parser = function(body_range, packet_info, tree, offset)
            offset = readers.addString(body_range, tree, "Text", fields.remoteprint_text, offset)
        end
    },
    [-265949079] = {
        name = "PlayerList",
        parser = function(body_range, packet_info, tree, offset)
            -- skip parameter pkg length
            offset = offset + 4

            local count_range = body_range:range(offset, 4)
            local count = count_range:le_int()

            tree:add_le(fields.playerlist_length, count_range)
            offset = offset + 4

            local list_tree = tree:add(proto, "Players (" .. tostring(count) .. ")")

            for i = 1, count do
                offset = readers.addString(body_range, list_tree, "Name", fields.playerlist_name, offset)
                offset = readers.addString(body_range, list_tree, "Host", fields.playerlist_host, offset)
                offset =
                    readers.addZDOID(
                    body_range,
                    list_tree,
                    "CharacterID",
                    fields.playerlist_zdoid_userid,
                    fields.playerlist_zdoid_id,
                    offset
                )

                local public_range = body_range:range(offset, 1)
                local public = public_range:le_int() == true
                offset = offset + 1
                if public then
                    offset =
                        readers.addVector3(
                        body_range,
                        list_tree,
                        "Position",
                        fields.playerlist_pos_x,
                        fields.playerlist_pos_y,
                        fields.playerlist_pos_z,
                        offset
                    )
                end
            end
        end
    },
    [1664081997] = {
        name = "RefPos",
        parser = function(body_range, packet_info, tree, offset)
            offset =
                readers.addVector3(
                body_range,
                tree,
                "Position",
                fields.refpos_x,
                fields.refpos_y,
                fields.refpos_z,
                offset
            )
        end
    },
    [542500494] = {
        name = "ServerSyncedPlayerData",
        parser = function(body_range, packet_info, tree, offset)
            --            offset = readers.addVector3(body_range, tree, "Position", fields.refpos_x, fields.refpos_y, fields.refpos_z, offset)
            --
            error("TODO")
        end
    },
    [-1975616347] = {
        name = "ZDOData",
        parser = function(body_range, packet_info, tree, offset)
            -- skip parameter pkg length
            offset = offset + 4

            local count_range = body_range:range(offset, 4)
            local count = count_range:le_int()
            offset = offset + 4

            local invalid_tree = tree:add(proto, "Invalidated ZDOs (" .. tostring(count) .. ")")

            invalid_tree:add_le(fields.zdodata_invalid_count, count_range)

            for i = 1, count do
                offset =
                    readers.addZDOID(
                    body_range,
                    invalid_tree,
                    "ZDOID #" .. tostring(i),
                    fields.zdodata_invalid_zdoid_userid,
                    fields.zdodata_invalid_zdoid_id,
                    offset
                )
            end

            -- read zdoids
            -- what sucks is that this sequence of ZDOData:subzdos is null terminated, instead of length terminated

            local zdo_count = 0

            local old_offset = offset

            while body_range:range(offset, 8):le_int64() ~= Int64.new(0) or
                body_range:range(offset + 8, 4):le_uint() ~= 0 do
                zdo_count = zdo_count + 1

                offset = offset + 12 + 2 + 4 + 8 + 12

                -- skip zdo-pkg
                offset = offset + 4 + body_range:range(offset, 4):le_int()
            end

            offset = old_offset

            local zdos_tree = tree:add(proto, "ZDOs (" .. tostring(zdo_count) .. ")")
            for i = 1, zdo_count do
                local zdo_tree = zdos_tree:add(proto, "ZDO (#" .. tostring(i) .. ")")

                offset =
                    readers.addZDOID(
                    body_range,
                    zdo_tree,
                    "ZDOID",
                    fields.zdodata_zdoid_userid,
                    fields.zdodata_zdoid_id,
                    offset
                )

                zdo_tree:add_le(fields.zdodata_ownerrev, body_range:range(offset, 2))
                offset = offset + 2

                zdo_tree:add_le(fields.zdodata_datarev, body_range:range(offset, 4))
                offset = offset + 4

                zdo_tree:add_le(fields.zdodata_owner, body_range:range(offset, 8))
                offset = offset + 8

                offset =
                    readers.addVector3(
                    body_range,
                    zdo_tree,
                    "Position",
                    fields.zdodata_x,
                    fields.zdodata_y,
                    fields.zdodata_z,
                    offset
                )

                --offset = offset + 4 + body_range:range(offset, 4):le_int()
                -- This is the offset after the ZDO sub package has been completely read
                local postOffset = offset + 4 + body_range:range(offset, 4):le_int()

                -- Skip zdo-deserialize for now
                local sub_tree = zdo_tree:add(proto, "ZDO Package")

                -- skip pkg len
                offset = offset + 4

                local zdo_flags_range = body_range(offset, 2)
                local zdo_flags = zdo_flags_range:le_uint()

                sub_tree:add_le(fields.zdodata_zdopkg_flags, zdo_flags_range)
                offset = offset + 2

                local prefab_range = body_range(offset, 4)

                sub_tree:add_le(fields.zdodata_zdopkg_prefab, prefab_range):append_text(
                    " (" .. tostring(prefabs[prefab_range:le_int()]) .. ")"
                )
                offset = offset + 4

                if bit.band(zdo_flags, 4096) > 0 then
                    offset =
                        readers.addVector3(
                        body_range,
                        sub_tree,
                        "Rotation",
                        fields.zdodata_zdopkg_rot_x,
                        fields.zdodata_zdopkg_rot_y,
                        fields.zdodata_zdopkg_rot_z,
                        offset
                    )
                end

                -- Panic (skips any unfinished ZDO sub package reads)
                offset = postOffset

                --zdo_tree
            end
        end
    },
    [838896224] = {
        name = "Disconnect",
        parser = function(body_range, packet_info, tree, offset)
            -- no data
            --  goodbye ¯\_(ツ)_/¯
        end
    },
    [0] = {
        name = "Keep Alive (PingPong)",
        parser = function(body_range, packet_info, tree, offset)
            tree:add_packet_field(fields.pingpong_type, body_range:range(offset, 1), ENC_LITTLE_ENDIAN)
        end
    }
    --[] = {
    --    name = "",
    --    parser = function(body_range, packet_info, tree)
    --
    --    end
    --},
}
