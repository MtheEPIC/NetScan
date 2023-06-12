#!/bin/bash

# Define the programs to check and install
programs=("geoip-bin" "tor" "sshpass" "nipe")
# rm_programs=("whois" "nmap") #"geoip-bin" "curl") #"nipe")
# Get the username using 'logname' command
username=$(logname)
# Regular expression patterns for IP address and domain
ip_pattern='^(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)(\.(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)){3}$'
domain_pattern='^([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
# Define path for the nipe program installation
#nipe_path="/home/$username/nipe"
nipe_path="/usr/bin/nipe"
nipepl_path="/usr/bin/nipe/nipe.pl"
#clone_path="/usr/bin"
# remote connection type
rm_mode="1" # 0-localhost 1-in lan 2-public 3-hidden service
# values for SSH
rm_ip="10.0.0.70"
rm_user="michael"
rm_pass="michael"
# Get the directory path of the bash script
script_dir="$(dirname "$0")"
[[ $script_dir == "." ]] && script_dir=$(pwd)
# Construct the absolute path to ssh key
ssh_key_path="$script_dir/id_rsa"

init_checks() {
	if [[ $UID -ne 0 ]]; then
		echo "[!] This script requires root privileges. Please run with sudo."
		exit 1
	fi
	if [ "$1" == "-r" ]; then
		if [ ! -d "$nipe_path" ]; then
			echo "[!] Can't stop the service that isn't installed"
			exit 1
		fi
	
		cd "$nipe_path"
		local nipe_status=$(sudo perl nipe.pl status | grep -oP '(?<=Status: ).*')
		if [ $nipe_status = "false" ]; then
			echo "[!] Can't stop the service if it isn't running"
			exit 1
		fi
	
		revert_to_default
		exit 0
	fi
}

# check for internet connectivity without getting blocked
check_connectivity() {
	return 0
	#TODO remove the top return
	nslookup google.com > /dev/null && return 0
	echo "[!] No internet connection available!" && exit 1
}

handle_nipe() {
	[ -f "$nipepl_path" ] && echo "[#] nipe is already installed." && return 0
	
	echo "[*] Installing nipe..."
	check_connectivity

	# Download
	git clone https://github.com/htrgouvea/nipe $nipe_path >/dev/null 2>&1
	cd $nipe_path

	# Install libs and dependencies
	cpanm --installdeps .

	# Nipe must be run as root
	perl nipe.pl install

	# # || { echo "[!] Nipe installation failed"; exit 1; }
}

check_installed() {
	np="nipe"
	if [ "$1" == "$np" ]; then
		handle_nipe
		return 0
	else
		#if command -v "$1" >/dev/null 2>&1; then 
		if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; then
			echo "[#] $1 is already installed."
			return 0  # Program is already installed
		else
			return 1  # Program is not installed
		fi
	fi
}

# Loop through the programs array and check/install each program
install_programs() {
	for program in "${programs[@]}"; do
		if check_installed "$program"; then
			continue  # Skip installation if program is already >
		fi

		echo "[*] Installing $program..."
		check_connectivity
		sudo apt-get update >/dev/null 2>&1
		sudo apt-get install -y "$program" >/dev/null 2>&1
	done
}
 
revert_to_default() {
	cd $nipe_path
	sudo perl nipe.pl stop
	echo "[*] nipe is disabled"
}

check_domain_format() {
	read -p "[?] Specify a Domain/IP address to scan: " user_input

	if [[ $user_input =~ $ip_pattern ]]; then
		target_domain=$(host "$user_input" | awk '{print $NF}'| sed 's/\.$//')
		return 0
	elif [[ $user_input =~ $domain_pattern ]]; then
		target_domain=$user_input
		return 0
	else
		echo "Invalid input. Please enter a valid IP address or domain."
		return 1
	fi
}

spoof_address() {
	cd "$nipe_path"
	nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")
	[[ $nipe_status == "true" ]] && echo "[#] nipe is already running." && return 0

	sudo perl nipe.pl start 
	
	nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")

	[[ $nipe_status == "true" ]] && return 0

	#if [ $nipe_status == "false" ]; then
	echo "[!] Unexpected Error while starting nipe service"
	sudo perl nipe.pl stop
	exit 1
	#fi
}

get_spoofed_value() {
	#cd "$nipe_path" && sudo perl nipe.pl status || { echo "[*] atempting to reinstall"; sudo perl nipe.pl install; sudo perl nipe.pl status 2>/dev/null || exit 1; }
	country=$(sudo perl nipe.pl status | xargs geoiplookup)
	country=$(echo "$country" | cut -d ' ' -f 5-)
	output=$(sudo perl nipe.pl status)
	ip=$(echo "$output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')

	echo -e "[*] You are anonymous.. Connecting to the remote Server.\n"
	echo "[*] Your Spoofed IP address is: $ip, Spoofed country: $country"
}

get_public_ip() {
remote_ip=$(curl -s ifconfig.me)

if ! [[ $remote_ip =~ $ip_pattern ]]; then
	echo "[!] Public IP test request was blocked, atempting a differnt test.."
	remote_ip=$(curl -s api.ipify.org)
	echo "$remote_ip"
	if [[ $remote_ip =~ $ip_pattern ]]; 
		then echo "good"
	else
		echo "[!] Public IP tests FAILED, check access to ifconfig.me or api.ipify.org"
		exit 1
	fi
fi

echo "Uptime:$(uptime)"
echo "IP address: $remote_ip"
echo "Country: $(geoiplookup $remote_ip)"
}

remote_script() {
	local log_dir="/var/log/NR"
	local rm_programs=("whois" "nmap" "geoip-bin") # "curl") #"nipe")

	local sudo_pass="michael"

	echo "$sudo_pass" | sudo -S mkdir $log_dir 2>/dev/null
	cd $log_dir


	for program in "${rm_programs[@]}"; do
		if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -vq "ok installed"; then
			echo "[*] Instaling $program"
			echo "$sudo_pass" | sudo -S apt install -y $program >/dev/null 2>&1
		fi
	done

	local remote_ip=141.136.36.110 #TODO use nipe
	
	cat <<EOF
	Uptime:$(uptime)
    IP address: $remote_ip
    Country: $(geoiplookup $remote_ip)

EOF

	echo "[*] Whoising victim's address:"
	# whois $1 #>/dev/null 2>&1

	echo "[*] Scanning victims's address:"
	# -A = -O -sV -sC --traceroute
	# nmap -vvv -T4 $1 -oN nmap_$1.log >/dev/null 2>&1
}

#########################################################

init_checks $@

echo "[?] To revert the settings back to normal run the script with -r flag"

install_programs

spoof_address
get_spoofed_value


target_domain=""
while [ -z "$target_domain" ]
do
	check_domain_format
done
echo "$target_domain"


echo -e "\n[*] Connecting to Remote Server:"

# use sshpass
sshpass -p $rm_pass ssh -o StrictHostKeyChecking=no $rm_user@$rm_ip "$(declare -f remote_script); $(declare -f get_public_ip); remote_script $target_domain"

# api.ipify.org
# curl ipinfo.io/ip
# curl ifconfig.me/ip
# geoiplookup $(curl ifconfig.me/ip)

##############################################################
#setup_hidden_service
#setup_ssh

