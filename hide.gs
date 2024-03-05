comp = get_shell().host_computer
fileNames = [
  "/usr/bin/AdminMonitor.exe",
  "/usr/bin/ScanLan.exe",
  "/lib/crypto.so",
  "/lib/metaxploit.so",
  "/lib/acc3ss.txt",
  "/bin/hide",
  "/bin/nmap",
  "/bin/bank",
  "/bin/parkl",
  "/bin/ipscan",
  "/bin/acc3ss",
  "/bin/solve",
  "/bin/decipher",
  "/bin/ssh-server",
  "/bin/scanrouter",
]

for fileName in fileNames
	filePath = "/usr/bin"
	if fileName.matches("^/lib") then 
		filePath = "/lib"
	else if fileName.matches("^/bin") then
		filePath = "/bin"
	end if
	shortFileName = fileName.replace(filePath+"/", "")
	guestFile = comp.File("/home/guest/"+shortFileName)
	print(filePath+"/"+shortFileName)
	if guestFile then guestFile.move(filePath, shortFileName)
	file = comp.File(fileName)
	if file then
		file.set_owner("root")
		file.set_group("root")
	end if
end for
