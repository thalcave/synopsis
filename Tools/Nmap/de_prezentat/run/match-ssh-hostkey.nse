description = [[
Attempts to find the IP address of a computer with a certain ssh host key
]]

---
--@usage
-- nmap host --script match-ssh-hostkey --script-args ssh_searchkey=key
-- nmap -n -Pn -p 22 --open --script /mnt/download/Work/MyWork/Nmap/match-ssh-hostkey.nse --script-args 'ssh_searchkey="2048 7f:73:3c:ba:4e:76:dd:46:8c:d7:e7:e7:49:35:35:a5"' 172.28.124.- -oN scan_result.txt

author = "Florin Micu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

-- Library containing functions for building short portrules.
require "shortport"

-- Functions for the SSH-1 protocol. This module also contains functions for formatting key fingerprints.
require("ssh1")
-- Functions for the SSH-2 protocol
require("ssh2")

-- Creates a portrule that returns true when given an open port matching either a port number or service name.
portrule = shortport.port_or_service(22, "ssh")

-- the actual functionality
action = function(host, port)
	-- read ssh key fingerprint
	local searched_key = nmap.registry.args.ssh_searchkey
	if searched_key == nil then
		return
	end

	-- get ssh key from host
	local key = ssh2.fetch_host_key( host, port, "ssh-rsa" )

	-- Format a key fingerprint in hexadecimal.
	local fprint = ssh1.fingerprint_hex( key.fingerprint, key.algorithm, key.bits )

	if string.match(fprint, searched_key) then
		return "ip found: "..host.ip
	else
		return "no match"
	end
end