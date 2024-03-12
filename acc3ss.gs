if params.len < 1 or params[0] == "-h" or params[0] == "--help" then 
    exit("<b>Usage: " + program_path.split("/")[-1] + " [ip_address] [?port] [?conn]</b>")
end if

metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then
    metaxploit = include_lib(current_path + "/metaxploit.so")
end if
if not metaxploit then exit("Error: Can't find metaxploit library in the /lib path or the current folder")

crypto = include_lib("/lib/crypto.so")
if not crypto then
    crypto = include_lib(current_path + "/crypto.so")
end if

decrypt = function(data)
	if not data then return data
	dataParts = data.split(":")
	if not crypto or not dataParts.len>1 then return data
	pass = crypto.decipher(dataParts[1])
	if pass then return dataParts[0]+":"+pass
	return data
end function

ip_address = params[0]
if params.len > 1 then port = params[1] else port = "0"
if params.len > 2 then action = params[2] else action = ""
if params.len > 3 then memory = params[3] else memory = ""
if params.len > 4 then vuln = params[4] else vuln = ""

if port.is_match("\.so$") then 
	libName = port
	print("loading local lib: /lib/"+libName)
	localMetaLib = metaxploit.load("/lib/"+libName)
	metaLib = localMetaLib

	if action == "-v" then
		print("/lib/"+libName+": "+metaLib.version)
		exit()
	end if
else
	net_session = metaxploit.net_use(ip_address, to_int(port))
	if not net_session then exit("Could not get net session.")
	print("active_users?: "+net_session.is_any_active_user+" active_root?: "+net_session.is_root_active_user+" users: "+net_session.get_num_users+" ports_fw: "+net_session.get_num_portforward);
//	if (net_session.is_root_active_user) then exit("Have an active root user")
	metaLib = net_session.dump_lib
end if

if not metaLib then exit("ERROR: Could not get metaLib")

if memory and vuln then
	print("Running overflow memory: "+memory+" vuln: "+vuln+" ip: "+ip_address)
	result = metaLib.overflow(memory, vuln, ip_address)
	if not result then exit("No result from vulnerability")
	resultType = typeof(result)
	print("typeof res="+resultType)
	if resultType == "shell" then
		res = result.launch("/bin/cat", "/etc/passwd")
		print("res: "+res);
	else if resultType == "computer" then
		file = result.File("/etc/passwd")
		print(file.path)
		print(file.get_content)
		print(decrypt(file.get_content))
	else if resultType == "file" then
		print("res: "+result.name+" path: "+result.path);
		if not result.parent then exit("no parent of file")
		print(result.parent.name)
		if result.parent.name != "/" then result = result.parent
		for folder in result.parent.get_folders
			if folder.name != "etc" then continue
			for file in folder.get_files 
				if file.name != "passwd" then continue
				print(file.path)
				print(file.get_content)
				print(decrypt(file.get_content))
				break
			end for
		end for
		for folder in result.parent.get_folders
			if folder.name != "home" then continue
			print("Printing home holders")
			for file in folder.get_folders
				print(file.path)
			end for
		end for	
	end if
	exit("Finished running custom exploit")
end if

libName = metaLib.lib_name
libVersion = metaLib.version
cacheKey = libName+":"+libVersion
cacheFilename = "/lib/acc3ss.txt"
localComputer=get_shell.host_computer
cacheFile=localComputer.File(cacheFilename)
if not cacheFile then
	localComputer.touch("/lib","acc3ss.txt")
	cacheFile=localComputer.File(cacheFilename)
end if
cached=[]
useCache = false
if cacheFile and cacheFile.has_permission("w") then useCache=true
if useCache then
	cached = cacheFile.get_content.split("\n")
end if
print("cached length="+cached.len)
mems=[]
for cache in cached
	found = cache.matches("^"+cacheKey+".*")
	if found.len == 0 then continue
	print("found in cache: "+cache)
	cacheParts = cache.split(":")
	libName = cacheParts[0]
	libVersion = cacheParts[1]
	mems = cacheParts[2].split(",")
end for

if not mems.len then
	print("Running scan")
	mems = metaxploit.scan(metaLib)
	memLine = cacheKey+":"+mems.join(",")
	print(memLine)
	if useCache then
		cacheContent = ""
		sep = ""
		for cacheLine in cached
			if not cacheLine then continue
			cacheContent = cacheContent + sep + cacheLine
			sep = char(10)
		end for
		cacheContent = cacheContent + sep + memLine
		cacheFile.set_content(cacheContent)
	end if
end if

memExploits = []
for memory in mems
	scanAddress = metaxploit.scan_address(metaLib, memory)
	//print("memory: "+memory+" scanAddress: "+scanAddress)
	segments = scanAddress.split("Unsafe check: ")[1:]
	exploits = []
	for segment in segments
		labelStart = segment.indexOf("<b>")
		labelEnd = segment.indexOf("</b>")
		exploits.push(segment[labelStart + 3: labelEnd])
	end for
	print("memory: "+memory+" exploits: " + exploits.join(", "))
	memExploits.push([memory, exploits])
end for

shellExps = []
computerExps = []
fileExps = []
for memExploit in memExploits
	memory = memExploit[0]
	exploits = memExploit[1]
	for vuln in exploits
		print("Running overflow memory: "+memory+" vuln: "+vuln+" ip: "+ip_address)
		result = metaLib.overflow(memory, vuln, ip_address)
		if not result then
			print("Attach failed")
			continue
		end if
		resultType = typeof(result)
		print("typeof res="+resultType)
		if resultType == "shell" then shellExps.push([memory, vuln])
		if resultType == "computer" then computerExps.push([memory, vuln])
		if resultType == "file" then fileExps.push([memory, vuln])
	end for
end for

print("shell exploits")
for memExploit in shellExps
	memory = memExploit[0]
	exploit = memExploit[1]
	print("* "+memory+" "+exploit)
end for
print("computer exploits")
for memExploit in computerExps
	memory = memExploit[0]
	exploit = memExploit[1]
	print("* "+memory+" "+exploit)
end for
print("file exploits")
for memExploit in fileExps
	memory = memExploit[0]
	exploit = memExploit[1]
	print("* "+memory+" "+exploit)
end for

// explioit
if shellExps.len > 0 then 
	print("Found exploits available")
	for memExploit in shellExps
		memory = memExploit[0]
		exploit = memExploit[1]
		print("Running exploit: "+exploit+" memory: "+memory+" ip_address: "+ip_address)
		result = metaLib.overflow(memory, exploit, ip_address)
		if action == "conn" then
			result.start_terminal
		else if action == "scp" then
			localShell = get_shell
			res = localShell.scp("/bin/nmap", "/bin/", result)
			print("scp res: "+res);
			useGuestHomeDir = false
			if typeof(res) == "string" and res.matches("permission denied") then useGuestHomeDir = true
			guestHomeDir = "/home/guest/"
			if useGuestHomeDir then destDir = guestHomeDir else destDir = "/bin/"
			print("Uploading files /bin/")
			res = localShell.scp("/bin/nmap", destDir, result)
			res = localShell.scp("/bin/acc3ss", destDir, result)
			res = localShell.scp("/bin/ipscan", destDir, result)
			res = localShell.scp("/bin/hide", destDir, result)
			res = localShell.scp("/bin/decipher", destDir, result)
			res = localShell.scp("/bin/solve", destDir, result)
			res = localShell.scp("/bin/scanrouter", destDir, result)
			res = localShell.scp("/bin/ssh-server", destDir, result)
			if useGuestHomeDir then destDir = guestHomeDir else destDir = "/usr/bin/"
			print("Uploading files /usr/bin/")
			res = localShell.scp("/usr/bin/ScanLan.exe", destDir, result)
			res = localShell.scp("/usr/bin/AdminMonitor.exe", destDir, result)
			if useGuestHomeDir then destDir = guestHomeDir else destDir = "/lib/"
			print("Uploading files /lib/")
			res = localShell.scp("/lib/crypto.so", destDir, result)
			res = localShell.scp("/lib/metaxploit.so", destDir, result)
			res = localShell.scp("/lib/acc3ss.txt", destDir, result)
			break
		else if action == "next" then
			print("Downloading /var/system.log from "+ip_address);
			localShell = get_shell
			res = result.scp("/var/system.log", "/root", localShell)
			print("scp res: "+res);
			if not res then exit("Could not get system.log")
			localSysLog = localShell.host_computer.File("/root/system.log")
			if not localSysLog then exit("Could not local file /root/system.log") else exit("Done");
			//print("file content: "+localSysLog.get_content);
		else
			res = result.launch("/bin/cat", "/etc/passwd")
			print("res: "+res);
		end if
	end for
else if computerExps.len > 0 then
	print("No shell exploits. Getting computer files")
	compExp = computerExps[0]
	memory = compExp[0]
	exploit = compExp[1]
	print("Running exploit: "+exploit+" memory: "+memory+" ip_address: "+ip_address)
	result = metaLib.overflow(memory, exploit, ip_address)
	homeFolder = result.File("/home")
	if not homeFolder then exit("Cannot get home folder")
	for userFolder in homeFolder.get_folders
		if userFolder.name == "guest" then continue
		print("user: "+userFolder.name)
		bankFile = result.File(userFolder.path+"/Config/Bank.txt")
		mailFile = result.File(userFolder.path+"/Config/Mail.txt")
		print(bankFile.get_content)
		print(mailFile.get_content)
		filesFound = userFolder.get_files;
		fileNames = "";
		for fileFound in filesFound
			fileNames = fileNames +" "+fileFound.name
		end for
		if fileNames then print("filesFound: "+fileNames)
		print("")
	end for
end if
