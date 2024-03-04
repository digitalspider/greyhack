if params.len < 1 or params[0] == "-h" or params[0] == "--help" then 
	exit("<b>Usage: " + program_path.split("/")[-1] + " [ip_address] [?libName.so] [?memory] [?vuln]</b>")
end if

ip_address = params[0]

if params.len > 1 then libName = params[1] else libName = "init.so"
if params.len > 2 then memory = params[2] else memory = "0x23DFEEF4"
if params.len > 3 then vuln = params[3] else vuln = "this"

if not libName.is_match("\.so$") then exit("Invalid libName")

metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then
    metaxploit = include_lib(current_path + "/metaxploit.so")
end if
if not metaxploit then exit("Error: Can't find metaxploit library in the /lib path or the current folder")

crypto = include_lib("/lib/crypto.so")
if not crypto then
    crypto = include_lib(current_path + "/crypto.so")
end if
if not crypto then exit("Error: Missing crypto library")

print("lodaing local lib: /lib/"+libName)
metaLib = metaxploit.load("/lib/"+libName)
if not metaLib then exit("Can't find " + "/lib/"+libName)

print("Running overflow memory: "+memory+" vuln: "+vuln+" ip: "+ip_address)
result = metaLib.overflow(memory, vuln, ip_address)
print("result "+result);
if not result then exit("Program ended")

printFile = function(file, userName)
	if not file then return("Error. File not found for user: "+userName)
	if not file.has_permission("r") then return("Error. user: "  + userName +". Can't access to file contents. Permission denied")
	contents = file.get_content
	parts = contents.split(":")
	//pass = crypto.decipher(parts[1])
	//print("Printing file "+file.name+" for user: "+userName+"...\n" + parts[0]+":"+pass)
	print("Printing file "+file.name+" for user: "+userName+"...\n" + parts[0]+":"+parts[1])
end function
		
AccessBankComputer = function(computer)
	print("Accesing to Bank.txt files...\nSearching users...")
	homeFolder = computer.File("/home")
	if not homeFolder then exit("Error. No home folder")
	mailFiles = []
	for user in homeFolder.get_folders
		if user.name == "guest" then continue
		bankFile = computer.File("/home/"+user.name+"/Config/Bank.txt")
		mailFile = computer.File("/home/"+user.name+"/Config/Mail.txt")
		printFile(bankFile, user.name)
		mailFiles.push(mailFile)
	end for
	print("\nMail files")
	for mailFile in mailFiles
		print(mailFile.get_content)
	end for
end function

AccessBankFile = function(homeFolder)
	print("Accesing to Bank.txt files...\nSearching users...")
	folders = homeFolder.get_folders
	for user in folders
		print("user: "+user.name)
		if user.name == "guest" then continue
		for userFolder in user.get_folders
			if userFolder.name != "Config" then continue
			for file in userFolder.get_files
				if file.name == "Mail.txt" then printFile(file, user.name)
				if file.name == "Bank.txt" then printFile(file, user.name)
			end for
		end for
	end for
	if folders.len == 0 then print("No users found. Program aborted")
end function

findHomeFolder = function(folder)
	print("Searching home folder...")
	while not folder.path == "/"
		folder = folder.parent
	end while

	folders = folder.get_folders
	for folder in folders
		if folder.path == "/home" then
			return folder
		end if
	end for
end function

if typeof(result) == "file" then
	if not result.is_folder then exit("Error: expected folder, obtained file: " + result.path)
	if not result.has_permission("r") then exit("Error: can't access to " + result.path + ". Permission denied." )
	if result.path == "/home" then
		homeFolder = result
	else
		homeFolder = findHomeFolder(result)
	end if
	AccessBankFile(homeFolder)
else if typeof(result) == "computer" then
	AccessBankComputer(result)
else
	exit("Error: expected file, obtained: " + result)
end if