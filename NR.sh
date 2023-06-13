#!/bin/bash

# Define the programs to check and install
declare -gra programs=("geoip-bin" "tor" "sshpass" "nipe")
declare -gra rm_programs=("whois" "nmap" "geoip-bin") # "curl") #"nipe")
# Get the username using 'logname' command
declare -gr username=$(logname)
# Regular expression patterns for IP address and domain
declare -rg ip_pattern='^(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)(\.(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)){3}$'
declare -rg domain_pattern='^([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
# Define path for the nipe program installation
#nipe_path="/home/$username/nipe"
declare -rg nipe_path="/usr/bin/nipe"
declare -rg nipepl_path="/usr/bin/nipe/nipe.pl"
# remote connection type
rm_mode="1" # 0-localhost 1-in lan 2-public 3-hidden service
# values for SSH
rm_ip="10.0.0.70"
rm_user="michael"
rm_pass="michael"
# Get the directory path of the bash script
script_dir="$(dirname "$0")"
[[ $script_dir == "." ]] && script_dir=$(pwd)
# path to the scripts log file
declare -rg LOG_PATH="/var/log/nr.log"


# # Construct the absolute path to ssh key
#ssh_key_path="$script_dir/id_rsa"

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

check_installed() {
	np="nipe"
	if [ "$1" == "$np" ]; then
		[ -f "$nipepl_path" ] && echo "[#] nipe is already installed." && return 0 || return 1
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
	local array=("$@")

	for program in "${array[@]}"; do
		if check_installed "$program"; then
			continue  # Skip installation if program is already >
		fi

		# check_connectivity #TODO make run once
		
		echo "[*] Installing $program..."
		if [ $program == "nipe" ]; then
			# Download
			git clone https://github.com/htrgouvea/nipe $nipe_path >/dev/null 2>&1
			cd $nipe_path

			# Install libs and dependencies
			cpanm --installdeps .

			sudo perl nipe.pl install
		else
			sudo apt-get update >/dev/null 2>&1
			sudo apt-get install -y "$program" >/dev/null 2>&1
		fi
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
		# target_domain=$(host "$user_input" | awk '{print $NF}'| sed 's/\.$//')
		target_domain=$user_input
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
	[[ $nipe_status == "true" ]] && return 0 #echo "[#] nipe is already running." && return 0

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

############REMOTE-SCRIPTS####################

remote_script() {
	local log_dir="/var/log/NR"
	local rm_programs=("whois" "nmap" "geoip-bin") # "nipe")
	local sudo_pass="michael"
	local target=$1
	local programs=("${@:2}")

	echo "$sudo_pass" | sudo -S mkdir $log_dir 2>/dev/null
	cd $log_dir

	install_programs -q ${programs[@]} >/dev/null 2>&1

	local remote_ip=141.136.36.110 #TODO use nipe
	local country_ip=$(geoiplookup $remote_ip | cut -d " " -f 5-)

	echo "Uptime:$(uptime)"
	echo "IP address: $remote_ip"
	echo "Country: $country_ip"
}




get_whois() {
	local target=$1
	local whoislog="whois_$target"

	echo -e "\n[*] Whoising victim's address:"
	sudo touch $whoislog
	sudo chmod a+w $whoislog
	whois $target > $whoislog

}

get_nmap() {
	local target=$1
	local nmaplog="nmap_$target"
	
	echo -e "\n[*] Scanning victims's address:"
	sudo touch $nmaplog
	# -A = -O -sV -sC --traceroute
	sudo nmap -vvv -T4 $target -oN $nmaplog >/dev/null 2>&1
}

#########################################################

init_checks $@

# echo "[?] To revert the settings back to normal run the script with -r flag"

install_programs ${programs[@]}

spoof_address
get_spoofed_value

declare -g target_domain=""
while [ -z "$target_domain" ]
do
	check_domain_format
done

echo -e "\n[*] Connecting to Remote Server:"


array_string=$(printf "%s " "${rm_programs[@]}")
# use sshpass
sshpass -p $rm_pass ssh -o StrictHostKeyChecking=no $rm_user@$rm_ip "$(declare -f remote_script); $(declare -f install_programs); $(declare -f check_installed); remote_script $target_domain $array_string" 


declare -g whoislog="whois_$target_domain"
declare -g nmaplog="nmap_$target_domain"

cd $script_dir

get_whois $target_domain

sudo sshpass -p $rm_pass scp $rm_user@$rm_ip:/var/log/NR/$whoislog ./
echo "[@] Whois data was saved into $script_dir/$whoislog."

get_nmap $target_domain

sudo sshpass -p $rm_pass scp $rm_user@$rm_ip:/var/log/NR/$nmaplog ./
echo "[@] Nmap data was saved into $script_dir/$nmaplog."






# cd $LOG_PATH


# cat /var/log/nr.log
# echo "$(date)- [*] whois data collected for: $target_domain" >> $LOG_PATH
# echo "$(date)- [*] Nmap data collected for: $target_domain" >> $LOG_PATH


# get target for remote
# nmap -p 22 --exclude 10.0.0.50 10.0.0.50/24 | grep -B 4 "open" |  awk '/Nmap scan/{print $NF}' | head -n 1
# hydra -l michael -P temp ssh://10.0.0.70 -o rm_creds >/dev/null 2>&1

