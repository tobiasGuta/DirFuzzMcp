-- Example Lua Mutate Plugin
-- This plugin generates variants of the input path

function mutate(original)
    local variants = {}
    
    -- Always include original
    table.insert(variants, original)
    
    -- Add uppercase version
    table.insert(variants, string.upper(original))
    
    -- Add lowercase version  
    table.insert(variants, string.lower(original))
    
    -- Add with common suffixes
    table.insert(variants, original .. ".bak")
    table.insert(variants, original .. ".old")
    table.insert(variants, original .. "~")
    
    return variants
end
