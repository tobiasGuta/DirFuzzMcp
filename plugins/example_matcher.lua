-- Example Lua Match Plugin
-- This plugin matches responses containing valid JSON with a "success" field

function match(response)
    -- Access response fields:
    -- response.status_code (number)
    -- response.size (number)
    -- response.words (number)
    -- response.lines (number)
    -- response.body (string)
    -- response.content_type (string)
    
    local body = response.body
    
    -- Simple check: body contains "success": true
    if string.find(body, '"success"%s*:%s*true') then
        return true
    end
    
    return false
end
