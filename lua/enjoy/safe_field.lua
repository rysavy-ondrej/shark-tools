
local field = { _version = "0.1" }

local function warn(msg)
    -- prepend “Warning: ” and append a newline
    local str = ("Warning: %s\n"):format(msg)
    io.stderr:write(str)
end

function field.new(name, error_msg)
    local ok, extractor = pcall(Field.new, name)
    if not ok then
        warn(error_msg)
        return function() return nil end
    end
    return extractor
end

return field
