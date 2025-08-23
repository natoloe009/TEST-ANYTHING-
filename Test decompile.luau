-- by lovrewe (improved)

assert(getscriptbytecode, "Exploit not supported.")

local API = getgenv().KonstantAPI or "http://api.plusgiant5.com"
local last_call = 0

local request = (syn and syn.request) 
             or (http and http.request) 
             or http_request 
             or (fluxus and fluxus.request) 
             or request

assert(request, "No supported HTTP request function found.")

local function call(endpoint, scriptPath)
    local success, bytecode = pcall(getscriptbytecode, scriptPath)
    if not success then
        return {
            success = false,
            error = string.format("Failed to get script bytecode:\n\n--[[\n%s\n--]]", bytecode)
        }
    end

    -- rate limiting
    local elapsed = os.clock() - last_call
    if elapsed < 0.5 then
        task.wait(0.5 - elapsed)
    end

    local httpResult = request({
        Url = API .. endpoint,
        Body = bytecode,
        Method = "POST",
        Headers = { ["Content-Type"] = "text/plain" }
    })

    last_call = os.clock()

    if not httpResult or httpResult.StatusCode ~= 200 then
        return {
            success = false,
            error = string.format("Konstant API request failed:\n\n--[[\n%s\n--]]", httpResult and httpResult.Body or "No response")
        }
    end

    return { success = true, data = httpResult.Body }
end

local function decompile(scriptPath)
    return call("/konstant/decompile", scriptPath)
end

local function disassemble(scriptPath)
    return call("/konstant/disassemble", scriptPath)
end

getgenv().decompile = decompile
getgenv().disassemble = disassemble
