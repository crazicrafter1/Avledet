local constants = assert(require("zs2_constants"))
local types = assert(require("zs2_types"))

local NAME = constants.NAME

-- wrappers
local wrappers = {}

-- will register to wrappers map
local gen = function(key, id, name, base_opt)
    wrappers[id] = types.generator(key, id, name, base_opt)
end

gen("int32", "msg_type", "Message Type")
gen("bool", "ping_or_pong", "Is Ping Test Message")
--gen("bool", "s2c_handshake.locked", "Has Password")
--gen("string", "s2c_handshake.salt", "Password Salt")

--[[
return {
    gen(''),

    -- All fields should go here, not just header fields.
    -- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#:~:text=11.6.7.%C2%A0ProtoField
    length_prefix = ProtoField.int32(NAME .. ".length_prefix", "Length Prefix", base.DEC),
    type = ProtoField.int32(NAME .. ".type", "Message Type", base.DEC),
    pingpong_type = ProtoField.bool(NAME .. ".pingpong.type", "Is Ping"),
    clienthandshake_haspassword = ProtoField.bool(NAME .. ".clienthandshake.haspassword", "Has Password"),
    clienthandshake_passwordsalt = ProtoField.bytes(NAME .. ".clienthandshake.passwordsalt", "Password Salt"),
    peerinfo_userid = ProtoField.int64(NAME .. ".peerinfo.userid", "UserID", base.DEC),
    peerinfo_version = ProtoField.string(NAME .. ".peerinfo.version", "Version"),
    peerinfo_networkversion = ProtoField.uint32(NAME .. ".peerinfo.networkversion", "Network Version", base.DEC),
    peerinfo_posx = ProtoField.float(NAME .. ".peerinfo.posx", "X", base.DEC),
    peerinfo_posy = ProtoField.float(NAME .. ".peerinfo.posy", "Y", base.DEC),
    peerinfo_posz = ProtoField.float(NAME .. ".peerinfo.posz", "Z", base.DEC),
    peerinfo_name = ProtoField.string(NAME .. ".peerinfo.name", "name"), -- TODO base.UNICODE
    peerinfo_password = ProtoField.bytes(NAME .. ".peerinfo.password", "Password"),
    peerinfo_sessionticketlength = ProtoField.int32(NAME .. ".peerinfo.sessionticketlength", "Length"),
    peerinfo_sessionticket = ProtoField.bytes(NAME .. ".peerinfo.sessionticket", "Bytes"),
    peerinfo_worldname = ProtoField.string(NAME .. ".peerinfo.worldname", "World Name"),
    peerinfo_worldseed = ProtoField.int32(NAME .. ".peerinfo.worldseed", "World Seed", base.DEC),
    peerinfo_worldseedname = ProtoField.string(NAME .. ".peerinfo.worldseedname", "World Seed Name"),
    peerinfo_worlduid = ProtoField.int64(NAME .. ".peerinfo.worlduid", "World UID", base.DEC),
    peerinfo_worldgenversion = ProtoField.int32(NAME .. ".peerinfo.worldgenversion", "World Gen Version", base.DEC),
    peerinfo_worldtime = ProtoField.double(NAME .. ".peerinfo.worldtime", "World Time", base.DEC),
    routedrpc_msgid = ProtoField.int64(NAME .. ".routedrpc.msgid", "Message ID", base.DEC),
    routedrpc_senderid = ProtoField.int64(NAME .. ".routedrpc.senderid", "Sender Peer ID", base.DEC),
    routedrpc_targetid = ProtoField.int64(NAME .. ".routedrpc.targetid", "Target Peer ID", base.DEC),
    routedrpc_targetzdoid_userid = ProtoField.int64(NAME .. ".routedrpc.targetzdoid.userid", "UserID", base.DEC),
    routedrpc_targetzdoid_id = ProtoField.uint32(NAME .. ".routedrpc.targetzdoid.id", "ID", base.DEC),
    routedrpc_type = ProtoField.int32(NAME .. ".routedrpc.type", "Type", base.DEC),
    routedrpc_parameterslength = ProtoField.int32(NAME .. ".routedrpc.parameterslength", "Length"),
    routedrpc_parameters = ProtoField.bytes(NAME .. ".routedrpc.parameters", "Parameter Data"),
    nettime_time = ProtoField.double(NAME .. ".nettime.time", "Nettime", base.DEC),
    playerlist_length = ProtoField.int32(NAME .. ".playerlist.length", "Length"),
    --playerlist_name_length = ProtoField.string(NAME .. ".playerlist.name.length", "Length"),
    playerlist_name = ProtoField.string(NAME .. ".playerlist.name", "Name"),
    --playerlist_host_length = ProtoField.string(NAME .. ".playerlist.host.length", "Length"),
    playerlist_host = ProtoField.string(NAME .. ".playerlist.host", "Host"),
    playerlist_zdoid_userid = ProtoField.int64(NAME .. ".playerlist.zdoid.userid", "UserID", base.DEC),
    playerlist_zdoid_id = ProtoField.uint32(NAME .. ".playerlist.zdoid.id", "ID", base.DEC),
    playerlist_publicposition = ProtoField.bool(NAME .. ".playerlist.publicposition", "Public Position"),
    playerlist_pos_x = ProtoField.float(NAME .. ".playerlist.pos.x", "x", base.DEC),
    playerlist_pos_y = ProtoField.float(NAME .. ".playerlist.pos.y", "y", base.DEC),
    playerlist_pos_z = ProtoField.float(NAME .. ".playerlist.pos.z", "z", base.DEC),
    characterid_zdoid_userid = ProtoField.int64(NAME .. ".characterid.zdoid.userid", "UserID", base.DEC),
    characterid_zdoid_id = ProtoField.uint32(NAME .. ".characterid.zdoid.id", "ID", base.DEC),
    unban_name = ProtoField.string(NAME .. ".unban.name", "Name"),
    remoteprint_text = ProtoField.string(NAME .. ".remoteprint.text", "Text"),
    refpos_x = ProtoField.float(NAME .. ".refpos.x", "x", base.DEC),
    refpos_y = ProtoField.float(NAME .. ".refpos.y", "y", base.DEC),
    refpos_z = ProtoField.float(NAME .. ".refpos.z", "z", base.DEC),
    refpos_public = ProtoField.bool(NAME .. ".refpos.public", "Public Position"),
    zdodata_invalid_count = ProtoField.int32(NAME .. ".zdodata.invalid.count", "Count", base.DEC),
    zdodata_invalid_zdoid_userid = ProtoField.int64(NAME .. ".zdodata.invalid.zdoid.userid", "UserID", base.DEC),
    zdodata_invalid_zdoid_id = ProtoField.int32(NAME .. ".zdodata.invalid.zdoid.id", "ID", base.DEC),
    zdodata_zdoid_userid = ProtoField.int64(NAME .. ".zdodata.zdoid.userid", "UserID", base.DEC),
    zdodata_zdoid_id = ProtoField.uint32(NAME .. ".zdodata.zdoid.id", "ID", base.DEC),
    zdodata_ownerrev = ProtoField.uint16(NAME .. ".zdodata.ownerrev", "Owner Revision", base.DEC),
    zdodata_datarev = ProtoField.uint32(NAME .. ".zdodata.datarev", "Data Revision", base.DEC),
    zdodata_owner = ProtoField.int64(NAME .. ".zdodata.owner", "Owner", base.DEC),
    zdodata_x = ProtoField.float(NAME .. ".zdodata.x", "x", base.DEC),
    zdodata_y = ProtoField.float(NAME .. ".zdodata.y", "y", base.DEC),
    zdodata_z = ProtoField.float(NAME .. ".zdodata.z", "z", base.DEC),
    --zdodata_zdopkg = ProtoField.bytes(NAME .. ".zdodata.zdopkg", "ZDO Package"),

    zdodata_zdopkg_flags = ProtoField.uint16(NAME .. ".zdodata.zdopkg.flags", "Flags", base.DEC),
    zdodata_zdopkg_prefab = ProtoField.int32(NAME .. ".zdodata.zdopkg.prefab", "Prefab Hash", base.DEC),
    zdodata_zdopkg_rot_x = ProtoField.float(NAME .. ".zdodata.zdopkg.rot.x", "x", base.DEC),
    zdodata_zdopkg_rot_y = ProtoField.float(NAME .. ".zdodata.zdopkg.rot.y", "y", base.DEC),
    zdodata_zdopkg_rot_z = ProtoField.float(NAME .. ".zdodata.zdopkg.rot.z", "z", base.DEC),
    zdodata_zdopkg_connection_type = ProtoField.int8(
        NAME .. ".zdodata.zdopkg.connection.type",
        "Connection Type",
        base.DEC
    ),
    zdodata_zdopkg_connection_zdoid_userid = ProtoField.int64(
        NAME .. ".zdodata.zdopkg.connection.zdoid.userid",
        "UserID",
        base.DEC
    ),
    zdodata_zdopkg_connection_zdoid_id = ProtoField.uint32(
        NAME .. ".zdodata.zdopkg.connection.zdoid.id",
        "ID",
        base.DEC
    )
    --,
    --destroyzdo_

    --zdodata_zdopkg_float_hash = ProtoField.int32(NAME .. ".zdodata.zdopkg.float.hash", "Hash", base.DEC),
    --zdodata_zdopkg_float_value = ProtoField.float(NAME .. ".zdodata.zdopkg.float.value", "Value", base.DEC),
    --
    --zdodata_zdopkg_vector3_hash = ProtoField.int32(NAME .. ".zdodata.zdopkg.float.hash", "Hash", base.DEC),
    --zdodata_zdopkg_vector3_x = ProtoField.float(NAME .. ".zdodata.zdopkg.float.value", "Value", base.DEC),

    --text_length = ProtoField.uint16(NAME .. ".text_length", "Text Length", base.DEC),
    --text = ProtoField.string(NAME .. ".text", "Text"),
    --from_length = ProtoField.uint8(NAME .. ".from_length", "From Length"),
    --from = ProtoField.string(NAME .. ".from", "From"),
    --request_id = ProtoField.guid(NAME .. ".request_id", "Request Id"),
    --nickname_length = ProtoField.uint8(NAME .. ".nickname_length", "Nickname Length"),
    --nickname = ProtoField.string(NAME .. ".nickname", "Nickname"),
    --error_message_length = ProtoField.uint16(NAME .. ".error_message_length", "Error Message Length"),
    --error_message = ProtoField.string(NAME .. ".error_message", "Error Message"),
}
--]]
return wrappers
