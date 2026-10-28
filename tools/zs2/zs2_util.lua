function string:contains(sub)
    return self:find(sub, 1, true) ~= nil
end

function string:startswith(start)
    return self:sub(1, #start) == start
end

function string:endswith(ending)
    return ending == "" or self:sub(-(#ending)) == ending
end

function string:replace(old, new)
    local s = self
    local search_start_idx = 1

    while true do
        local start_idx, end_idx = s:find(old, search_start_idx, true)
        if (not start_idx) then
            break
        end

        local postfix = s:sub(end_idx + 1)
        s = s:sub(1, (start_idx - 1)) .. new .. postfix

        search_start_idx = -1 * postfix:len()
    end

    return s
end

function string:insert(pos, text)
    return self:sub(1, pos - 1) .. text .. self:sub(pos)
end

-- https://github.com/stein197/lua-string/blob/e16e5a908fe9b17751378168d99d440687c0ffcf/init.lua#L51
--- Splits the string by supplied separator. If the `pattern` parameter is set to true then the separator is considered
--- as a pattern.
--- @param sep string Separator by which separate the string.
--- @param pattern? boolean `true` for separator to be considered as a pattern. `false` by default.
--- @return string[] t Table of substrings separated by `sep` string.
function string:split(sep, pattern)
    if sep == "" then
        return self:totable()
    end
    local rs = {}
    local previdx = 1
    while true do
        local startidx, endidx = self:find(sep, previdx, not pattern)
        if not startidx then
            table.insert(rs, self:sub(previdx))
            break
        end
        table.insert(rs, self:sub(previdx, startidx - 1))
        previdx = endidx + 1
    end
    return rs
end
