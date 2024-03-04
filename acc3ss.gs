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
cached = [ // need to populate these
	"kernel_router.so:1.0.4:0x4968FC8C,0x6406C347",
	"kernel_router.so:1.2.0:0x31D78604",
	"libssh.so:1.0.6:0x31D7A725,0x1FA084E6,0x645B4E3,0x5F6102CB,0x1C735608,0x1DFDF04E",
	"libssh.so:1.0.9:0x222C5D3E,0x3616B5A4,0x645B4E3,0x32F69C1E,0x6FF61E10,0x5F3BF993",
	"libhttp.so:1.0.1:0x21525E72,0x3AFC2A9,0x27C269F1,0x6D7E74C4",
	"libhttp.so:1.0.4:0x587318F1,0x3AFC2A9,0x2AB6927D,0x55C308A0,0x19F2F5A2",
	"libsql.so:1.0.0:0x3A2521F,0x23630392,0x5287D9BF,0x637DFCAF,0x50BB2F20",
	"libsql.so:1.0.1:0x3A2521F,0x23630392,0x5287D9BF,0x744F8A7C,0x198665E9",
	"libsmtp.so:1.0.1:0x7C3E70BE,0x49245130,0x2E8EDD23,0x765CE65A,0x421CF2B2",
	"libsmtp.so:1.0.2:0x7C3E70BE,0x7143A80B,0xE6F889,0x6B66B09D",
	"aptclient.so:1.0.2:0x753E5299,0x2C559E9E,0x7A658887,0x23B0B80C,0x1B74F7D6,0x7D39D477",
	"aptclient.so:1.1.3:0x4E7E9AEC,0x227869C,0x3E042E35,0xE9D606B,0x3E95A5AF",
	"init.so:1.0.1:0x1BF52FB7,0x23DFEEF4",
	"init.so:1.1.0:0x4C96D16D,0xE0136EC,0xB6BBB30,0x3361FFCC,0x181DF186",
	"libcam.so:1.0.3:0x2C9A511,0x6D558D2C,0x5FA97DFD,0x4EE92509,0x55B25F3A,0x47071A1",
	"libcam.so:1.0.4:0x2C9A511,0x6D558D2C,0x5FA97DFD,0x4EE92509,0x5D6E5157,0x67D791C5",
	"libchat.so:1.0.0:0x56A978D7,0x7C720496,0x8EF889B",
	"librepository.so:1.0.0:0x4076EFB8,0x65EE6BB3,0x4B0B11ED",
	"librepository.so:1.0.9:0x4A367C8",
	"librshell.so:1.0.0:0x46C1B893,0x73B0BC5B,0x18F8B516,0x75CD23FD,0x6615D5E6,0x5A7546BC,0x658BDF7",
	"librshell.so:2.4.1:0x4F520ABA,0x16B60406,0x22ECCE6E",
	"net.so:1.2.2:0x1E38CD39,0x79483B24,0x6D7457D2,0x1DA1843A,0x252952DE",
]
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
	print(cacheKey+":"+mems.join(","))
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
			res = localShell.scp("/bin/nmap", destDir, result)
			print("scp res1: "+res)
			res = localShell.scp("/bin/acc3ss", destDir, result)
			res = localShell.scp("/bin/ipscan", destDir, result)
			res = localShell.scp("/bin/hide", destDir, result)
			res = localShell.scp("/bin/decipher", destDir, result)
			res = localShell.scp("/bin/solve", destDir, result)
			res = localShell.scp("/bin/scanrouter", destDir, result)
			res = localShell.scp("/bin/ssh-server", destDir, result)
			if useGuestHomeDir then destDir = guestHomeDir else destDir = "/usr/bin/"
			res = localShell.scp("/usr/bin/ScanLan.exe", destDir, result)
			print("scp res2: "+res)
			res = localShell.scp("/usr/bin/AdminMonitor.exe", destDir, result)
			if useGuestHomeDir then destDir = guestHomeDir else destDir = "/lib/"
			res = localShell.scp("/lib/crypto.so", destDir, result)
			print("scp res3: "+res)
			res = localShell.scp("/lib/metaxploit.so", destDir, result)
			break
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
