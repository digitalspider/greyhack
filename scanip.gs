if params.len > 0 and (params[0] == "-h" or params[0] == "--help") then
	exit("Usage: ipscan [ipAddress]")
end if

scan_ip = function(ipAddress)
	isLanIp = is_lan_ip( ipAddress )
	if isLanIp then
		router = get_router
	else 
		router = get_router( ipAddress )
	end if

	if router == null then exit("ERROR: ip address not found")
	
	isRouterIp = router.local_ip == ipAddress
	ports = null
	
	if not isLanIp or isRouterIp then
		ports = router.used_ports
	else
		ports = router.device_ports(ipAddress)
		if (typeof(ports) == "string" and ports.matches("is unreachable")) then
			print(ports)
			return
		end if
	end if

	if ports == null then exit("EROR: no ports not found")
	
	print("IP: "+ipAddress)
	info = ""
	
	for port in ports
		service_info = router.port_info(port)
		lan_ips = port.get_lan_ip
		port_status = "open"
		
		if(port.is_closed and not isLanIp) then
			port_status = "closed"
		end if
		if info.len>0 then
			info = info + "\n |- " + port.port_number + " " + port_status + " " + service_info + " " + lan_ips
		else
			info = " |- " + port.port_number + " " + port_status + " " + service_info + " " + lan_ips
		end if
	end for
	if info.len>0 then print(info)
end function

if params.len > 0 then ipAddress = params[0] else ipAddress = ""
router = get_router( ipAddress )
print("router version: "+router.kernel_version)
computers = router.devices_lan_ip
print("computers: "+computers)
for local_ip in router.devices_lan_ip
	if not local_ip.matches("\.1$") then continue
	subRouter = get_router(local_ip)
	if not subRouter then
		print("ERROR: Could not get router for "+local_ip)
		continue
	end if
	subnet = subRouter.local_ip.replace("\.1$",".")
	print("\nsubnet: "+subnet+"\n")
	for subnet_local_ip in subRouter.devices_lan_ip
		if (subnet_local_ip.matches(subnet)) then
			scan_ip(subnet_local_ip)
		end if
	end for
end for
