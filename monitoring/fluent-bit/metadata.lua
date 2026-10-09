-- Keep the existing Krate/EPC selection and Loki labels without API access.
local source = debug.getinfo(1, 'S').source:sub(2)
local directory = source:match('^(.*)/') or '.'
local json = dofile(directory .. '/vendor/dkjson.lua')
local root = os.getenv('KRATE_DOCKER_ROOT') or '/var/lib/docker/containers'
local log_root = os.getenv('KRATE_LOG_ROOT') or '/sources'
local collector = os.getenv('KRATE_COLLECTOR_CONTAINER')
local discovery = os.getenv('KRATE_DISCOVERY_CONTAINER')
local cache = {}
local cache_size = 0

local function metadata_name(id, now)
    local previous = cache[id]
    if previous and now - previous.checked < 5 then
        previous.used = now
        return previous.name
    end
    local name = previous and previous.name
    local file = io.open(root .. '/' .. id .. '/config.v2.json', 'r')
    if file then
        local text = file:read('*a')
        file:close()
        local ok, data = pcall(json.decode, text)
        if ok and type(data) == 'table' and type(data.Name) == 'string' then
            name = data.Name:gsub('^/', '')
        else
            name = nil
            print('Krate collector: invalid Docker metadata for ' .. id)
        end
    elseif not name then
        print('Krate collector: Docker metadata unavailable for ' .. id)
    end
    if not previous then
        if cache_size == 256 then
            local oldest_id, oldest
            for key, value in pairs(cache) do
                if not oldest or value.used < oldest then
                    oldest_id, oldest = key, value.used
                end
            end
            cache[oldest_id] = nil
            cache_size = cache_size - 1
        end
        cache_size = cache_size + 1
    end
    cache[id] = {name=name, checked=now, used=now}
    return name
end

function enrich(tag, timestamp, record)
    local now = os.time()
    if now - timestamp.sec > 604800 then
        return -1, timestamp, record
    end
    local path = record.filepath
    if type(path) ~= 'string' or path:sub(1, #log_root + 1) ~= log_root .. '/' then
        return -1, timestamp, record
    end
    local id, filename = path:sub(#log_root + 2):match('^(%x+)/([^/]+)$')
    if not id or #id ~= 64 or filename ~= id .. '-json.log' then
        return -1, timestamp, record
    end
    local name = metadata_name(id, now)
    if not name or name == collector or name == discovery or not (name:match('^krate%-') or name:match('^epc%-')) then
        return -1, timestamp, record
    end
    record.container = name
    record.container_id = id
    return 2, timestamp, record
end
