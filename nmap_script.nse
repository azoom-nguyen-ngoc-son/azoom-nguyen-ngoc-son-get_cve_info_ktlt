local shortport = require "shortport"
local http = require "http"
local json = require "json"

-- The Rule Section --

portrule = function(host,port)
	return port.protocol == 'tcp' and port.number == 80 
end 

-- The Action Section --
function get_api(ver_id)
	local api_version="1.7"
	local option={
    		header={
      			['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version)
    		},
	        any_af = true,	
  	}

	
	uri = ("https://www.cvedetails.com/json-feed.php?version_id=%s"):format(nmap.registry.args.ver_id)
	local result = http.get_url(uri,option)
	return result.body
end


action = function(host, port)

    local uri = "/index.html"
    local response = http.get(host, port, uri)
    
    
    if tostring(response.status) == "200" then 
    
    	return get_api(nmap.registry.args.ver_id)
    else 
   	return tostring(response.status) -- "Maybe 5xx errors !!!"
    end
    	
end
