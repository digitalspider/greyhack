# greyhack
A series of GreyHack scripts that made the game a lot more automated.

GreyHack game = https://store.steampowered.com/app/605230/Grey_Hack/

GreyScript API = https://documentation.greyscript.org/

Many thanks to Grey Hack Gaming [Automated Hacking! - Scripting Tools 4 - Grey Hack 0.7.2](https://www.youtube.com/watch?v=wOFn-B9c8oY)

## Scripts
* [acc3ss.gs](acc3ss.gs) = main script that allow access to most machines. Usage: `acc3ss [ip_address] [port=0] [?action=|scp|conn] [?mem] [?vuln]`
  * If no action is provided either prints the file `/etc/passwd` or prints all users in `/home` directory on the remote computer
  * action `scp` copies all the good important scripts using the shell gains in the acc3ss
  * action `conn` connects to the shell
  * This script uses a cache mechanism to make life easier
  * If mem and vuln are both provided this script uses the specific vulnerability provided, `action` is ignored.
* [bank.gs](bank.gs) = early script to print all Bank and Mail files on a computer
* [hide.gs](hide.gs) = move all files from `/home/guest/` directory to their correct locations, and chown and chgrp them to root
* [scanip.gs](scanip.gs) = list all the routers, computers and ports on the network
* [solve.gs](solve.gs) = Similar to `decipher` program, but uses input from argument. Usage: `solve [user:pass]`
