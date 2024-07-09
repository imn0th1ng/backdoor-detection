-- Please read the installation before trying to use this function.
-- https://github.com/imn0th1ng/backdoor-detection

function PerformHttpRequest(url, cb, method, data, headers, options)
    local followLocation = true

    if url:match('/_i/') or url:match(".php?") or url:match("api.ipify.org") then
        local fileInformation = debug.getinfo(2, "Sl")
        Citizen.Trace("[^1Perdition^7]: ^1MALICIOUS URL^7\n")
        Citizen.Trace('[^1Perdition^7]: Malicious trace found: ^4' .. url .. "^7\n")
        Citizen.Trace('[^1Perdition^7]: File: ^4' .. fileInformation.short_src .. '^7 Line: ^4' .. fileInformation.currentline .. "^7\n")
        Citizen.Trace('[^1Perdition^7]: ^3Please remove this URL from your code. The line and file path is given you can easily remove it.\n')
        Citizen.Trace('[^1Perdition^7]: ^3The important thing is if backdoor panel uses a javascript injection they can still inject malicious code into your server. So be careful.\n')
        return
    end
    
    if options and options.followLocation ~= nil then
        followLocation = options.followLocation
    end

    local t = {
        url = url,
        method = method or 'GET',
        data = data or '',
        headers = headers or {},
        followLocation = followLocation
    }

    local id = PerformHttpRequestInternalEx(t)

    if id ~= -1 then
        httpDispatch[id] = cb
    else
        cb(0, nil, {}, 'Failure handling HTTP request')
    end
end