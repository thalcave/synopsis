description = [[
Attempts to find the IP address of a computer with a certain MAC address
]]

---
--@usage
-- nmap host --script mac-to-ip --script-args searched_mac=mac
-- nmap --script /mnt/download/Work/MyWork/Nmap/mac-to-ip.nse --script-args 'searched_mac=00:21:70:F4:95:5F' 172.28.124.- -oN mac_result.txt

author = "Florin Micu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

-- various handy functions that are too small to justify modules of their own.
require("stdnse")

hostrule = function(host)
	-- verify that indeed is a MAC address
	return (host.mac_addr ~= nil and string.len(host.mac_addr) == 6)
end


-- the actual functionality
action = function(host)
	local searched_mac = string.lower(nmap.registry.args.searched_mac)
	if searched_mac == nil then
		stdnse.print_debug(0, "Missing argument: searched_mac")
		return
	end

	local mac_addr = host.mac_addr
	local mac_string = string.lower(string.format("%02x:%02x:%02x:%02x:%02x:%02x", mac_addr:byte(1), mac_addr:byte(2), mac_addr:byte(3), mac_addr:byte(4), mac_addr:byte(5), mac_addr:byte(6)))

	stdnse.print_debug(0, "MAC Address %s", mac_string)

	if string.match(mac_string, searched_mac) then
		return "ip found: "..host.ip
	else
		return "no match"
	end

end