local Types = assert(require("zs2_types"))
local Fields = assert(require("zs2_field_wrappers"))
local prefabs = assert(require("zs2_prefabs"))
local constants = assert(require("zs2_constants"))

local proto = Types.get_proto()

local PORT = constants.PORT

local gen = Types.generator
local compile = function(wrapper_array)
    local res = {}

    for i, wrapper in ipairs(wrapper_array) do
        res[wrapper.sub_filter_id] = wrapper
    end

    return res
end

-- zs2 and not zs2.keepalive.server and not zs2.nettime and not zs2.routedrpc.setevent.time and not zs2.zdodata.id.userid and not zs2.msg_type==-265949079 and not zs2.rpcsynced.public and not zs2.routedrpc.method==199378019 and not zs2.routedrpc.method==-461013576

-- https://github.com/Valheim-Modding/Wiki/wiki/RPC-Method-registrations
return {
    [-1090292557] = {
        name = "GlobalKeys",
        --params = {
        --    -- TODO containerized...
        --    0
        --},
        parser = function(self, body_range, packet_info, tree, offset)
        end
    },
    [-1100589719] = {
        name = "LocationIcons",
        --params = {
        --    -- TODO containerized...
        --    0
        --},
        parser = function(self, body_range, packet_info, tree, offset)
        end
    },
    [-1550530018] = {
        name = "SetEvent",
        params = {
            gen("string", "routedrpc.setevent.name", "Event Name"),
            gen("float", "routedrpc.setevent.time", "Event Time"),
            gen("string", "routedrpc.setevent.pos", "Event Position")
        }
    },
    [-1182660091] = {
        name = "ChatMessage",
        params = {
            gen("vec3", "routedrpc.chatmessage.pos", "Position"),
            gen("int32", "routedrpc.chatmessage.type", "Message Type"),
            gen("string", "routedrpc.chatmessage.name", "User Name"),
            gen("string", "routedrpc.chatmessage.id", "User ID"),
            gen("string", "routedrpc.chatmessage.text", "Text")
        },
        -- TODO add extensions / whether join-msg or ...

        dummy = 0
    },
    [-461013576] = {
        name = "Step (FootStep.cs)",
        params = {
            gen("int32", "routedrpc.step.index", "Particle Index"),
            gen("vec3", "routedrpc.step.position", "Position")
        }
    },
    [531685242] = {
        name = "SetTrigger (ZAnim)",
        params = {
            gen("string", "routedrpc.set_trigger", "Animation")
        }
    },
    [199378019] = {
        name = "DestroyZDO",
        --params = {
        --    -- TODO containerized...
        --    0
        --},
        parser = function(self, body_range, packet_info, tree, offset)
            --tree:add_packet_field(fields.clienthandshake_haspassword, body_range:range(offset, 1), ENC_LITTLE_ENDIAN)
            --offset = offset + 1
            --
            --offset = readers.addString(body_range, tree, "Password Salt", fields.clienthandshake_passwordsalt, offset)
        end
    },
    [213315071] = {
        name = "RPC_ResetCloth"
    },
    [2039200370] = {
        name = "RPC_FreezeFrame",
        params = {
            gen("float", "routedrpc.freezeframe", "?Time Maybe?")
        }
    },
    --[[ [15349388] = {
        name = "RPC_DamageText",
        -- TODO pkg-params
        fields = compile {
            gen("int32", "routedrpc.damage_text.text_type", "Text Type"),
            gen("vec3", "routedrpc.damage_text.pos", "Position"),
            gen("string", "routedrpc.damage_text.text", "Text"),
            gen("bool", "routedrpc.damage_text.bool", "?Bool?")
        },
        parser = function(self, body_range, packet_info, tree, offset)
            -- skip <pkg-len>
            offset = offset + 4

            local text
            offset = self.fields["routedrpc.damage_text.text_type"]:parser(body_range, tree, offset)
            offset = self.fields["routedrpc.damage_text.pos"]:parser(body_range, tree, offset)
            offset, text = self.fields["routedrpc.damage_text.text"]:parser(body_range, tree, offset)
            offset = self.fields["routedrpc.damage_text.bool"]:parser(body_range, tree, offset)

            packet_info.cols.info:append(", " .. text)
        end
    }, ]]
    [1130726949] = {
        name = "Damage"
        -- TODO hitdata param
    },
    [1299689241] = {
        name = "RPC_RequestOwn"
    }
}
