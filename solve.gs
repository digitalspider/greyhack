if params.len < 1 or params[0] == "-h" or params[0] == "--help" then 
    exit("<b>Usage: " + program_path.split("/")[-1] + " [(user:pass)]</b>")
end if

crypto = include_lib("/lib/crypto.so")
if not crypto then
    crypto = include_lib(current_path + "/crypto.so")
end if
if not crypto then exit("Error: Can't find crypto library in the /lib path or the current folder")

arg = params[0]

input = get_shell.host_computer.File(arg)
// It's not a file, its a user:pass string
if not input then
	encdata = arg.split(":")
	password = crypto.decipher(encdata[1])
	if not password then
		exit("Error: No password found")
	end if
	print(encdata[0] + ":" + password)
else
	//crypto.decipher_file(input)
	exit("Cannot decrypt file, use the program: decipher")
end if
