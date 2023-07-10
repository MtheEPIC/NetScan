#!/bin/bash

################################################################################
#                                                                              #
# NR.sh																	       #
#                                                                              #
# version: 1.1.0                                                               #
#                                                                              #
# Network Research - Remote target scanning using tor and a remote server      #
#																			   #
# Srudent Name - Michael Ivlev												   #
# Student Code - S11														   #
# Class Code - HMagen773616													   #
# Lectures Name - Eliran Berkovich											   #
#																			   #
# GNU GENERAL PUBLIC LICENSE                                                   #
#                                                                              #
# This program is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation, either version 3 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        #
#                                                                              #
################################################################################

# Define the programs to check and install
declare -rga programs=("cowsay" "geoip-bin" "tor" "sshpass" "nipe")
declare -rga rm_programs=("whois" "nmap" "geoip-bin") # "curl") #"nipe")
# Regular expression patterns for IP address and domain
declare -rg IP_PATTERN='^(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)(\.(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)){3}$'
declare -rg DOMAIN_PATTERN='^([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
# Define path for the nipe program installation
#NIPE_PATH="/home/$username/nipe"
# Get the directory path of the bash script
script_dir="$(dirname '$0')"
declare -rg HNAME_PATH="/etc/hostname"
declare -rg HNAME_BAK="$script_dir/hostname.bak"
declare -rg NIPE_PATH="/usr/bin/nipe"
declare -rg nipepl_path="/usr/bin/nipe/nipe.pl"
declare -rg COWSAY_PATH="/usr/games/cowsay"
declare -rg COWTHINK_PATH="/usr/games/cowthink"
# remote connection type
declare -gi rm_mode="1" # 0-localhost 1-in lan 2-public 3-hidden service
# values for SSHPASS
declare -g rm_ip
declare -g rm_user
declare -g rm_pass
declare -g rm_port
[[ $script_dir == "." ]] && script_dir=$(pwd)
# path to the scripts log file
declare -rg LOG_PATH="/var/log/nr.log"
# path to saved scans
declare -rg SCAN_PATH="$(pwd)/scans"

is_cow_time=true

# Function to cycle through a pattern and make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word_and_chars() {
	local word=$1 #"loading..."
	local chars="-\|/"
	
	local j=0
	while true; do
		for (( i=0; i< ${#word}; i++ )); do
			if [[ ! ${word:i:1} =~ [[:alpha:]] ]]; then continue; fi
				
			curr_word="${word:0:i}$(echo ${word:i:1} | tr '[:lower:]' '[:upper:]')${word:i+1}"
			echo -ne "\r$curr_word${chars:j:1}"
			(( j++ ))
			(( $j < ${#chars} )) || j=0
			(($i + 1 < ${#word} )) && sleep .1
		done

		read -n 1 -t .1 -s && exit 0
	done
}

# Function to make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word() {
	local word="loading"
	while true; do
		for (( i=0; i< ${#word}; i++ )); do
			curr_word="${word:0:i}$(echo ${word:i:1} | tr '[:lower:]' '[:upper:]')${word:i+1}"
			printf "%s\r" "$curr_word"
			sleep .1
		done
	
		read -n 1 -t .1 -s && exit 0
	done
}

# Function to cycle through a pattern 
cycle_char() {
	local chars="-\|/"
	local word=$1
	while true; do
		for (( i=0; i< ${#chars}; i++ )); do
			echo -ne "\r$word${chars:i:1}"
			sleep .1
		done
	
		read -n 1 -t .1 -s && exit 0
	done
}

# Function to display the correct way to run the script
usage() {
	local script_name=$(basename "$0")
cat << EOF
Usage: $script_name [Options] {target_domain}
-h Describe how to run the script
-r Revert the network setting (i.e. before routing trafic through the tor network)
-m Choose the remote level of abstraction:
	0 localhost 
	1 lan range
	2 public ip range 
	3 hidden service
 
EOF

cycle_word_and_chars "loading..."

}

# Function to check the init condition
init_checks() {
	[ $UID -ne 0 ] && echo "[!] This script requires root privileges. Please run with sudo." && exit 1
	[ ! -d $SCAN_PATH ] && mkdir $SCAN_PATH
	[ ! -f $LOG_PATH ] && sudo touch $LOG_PATH
	
	while getopts ":hrm:" opt; do # TODO more flags (for sshapss creds)
		case $opt in
			h)
				usage
				exit 0
				;;
			r)
				revert_to_default
				exit $?
				;;
			m)
				! [[ $OPTARG =~ ^[0-3]$ ]] && echo "unexpected value, see -h" && exit 1
				rm_mode=$OPTARG
				echo "$rm_mode"
				;;
			\?)
				echo "[!] Invalid option: -$OPTARG"
				usage
				exit 1
				;;
			:)
				[ $OPTARG == "m" ] && echo "-m requires a value" && exit 1
				;;
		esac
	done

	shift $((OPTIND - 1))
}

# Function to check for internet connectivity without getting blocked
check_connectivity() {
	return 0
	#TODO remove the top return
	nslookup google.com > /dev/null && return 0
	echo "[!] No internet connection available!" && exit 1
}

# Function to check if an app is already installed
# Parameters:
#	$1: app name to check
check_installed() {
	local np="nipe"
	if [ "$1" == "$np" ]; then
		[ -f "$nipepl_path" ] && echo "[#] nipe is already installed." && return 0 || return 1
	else
		#if command -v "$1" >/dev/null 2>&1; then 
		if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; then
			tee_audit "[#] $1 is already installed."
			return 0  
		else
			audit "[#] $1 isn't installed."
			return 1  
		fi
	fi
}

# Function to Loop through the programs array and check/install each program
# Paramets:
#	$1: array of function to install
install_programs() {
	local array=("$@")

	for program in "${array[@]}"; do
		# Skip installation if program is already installed
		check_installed "$program" && continue 
			
		cycle_word_and_chars "[*] Installing $program..." &
		local load_msg_pid=$!
		if [ $program == "nipe" ]; then
			# Install libs and dependencies
			! command -v cpanm && curl -L https://cpanmin.us | sudo perl - App::cpanminus

			# Download
			[ -z "$NIPE_PATH" ] && NIPE_PATH="$(pwd)/nipe"
			sudo git clone https://github.com/htrgouvea/nipe $NIPE_PATH >/dev/null 2>&1
			cd $NIPE_PATH 

			sudo cpanm --installdeps . >/dev/null 2>&1
			sudo perl nipe.pl install >/dev/null 2>&1
		else
			sudo apt-get update >/dev/null 2>&1 #TODO RUN ONCE
			sudo apt-get install -y "$program" >/dev/null 2>&1
		fi
		kill $load_msg_pid
		echo -e "\r[*] Installing $program... "
		audit "[*] $program has been installed"
	done
}

# Function to revert spoofed settings to default
revert_to_default() {
	[ -f "$HNAME_BAK" ] && cat $HNAME_BAK > $HNAME_PATH && rm $HNAME_BAK

	[ ! -d "$NIPE_PATH" ] && echo "[!] Can't stop the service that isn't installed" && return 1

	sudo perl $NIPE_PATH/nipe.pl stop >/dev/null 2>&1
	echo "[*] nipe is disabled"
	return 0
}

# Function to create a new audit
audit() {
	echo "$(date)- $1" >> $LOG_PATH
}

# Function to create a new audit and display to the std
tee_audit() {
	echo $1
	audit "$1"
}

# Function wrapper to use a fancy echo when a flag is used
say() {
	$is_cow_time && (figlet $1 -cf slant | $COWSAY_PATH -n) || echo $1
}

# Function wrapper to use a fancy echo when a flag is used
think() {
	$is_cow_time && (figlet $1 -k | $COWTHINK_PATH -n) || echo $1
}

# Function to check the validity of the given target address
# Parameters:
#	$1: The given target address
# Return:
#	0 if the input is valid
#	1 if the input is invalid
check_domain_format() {
	local user_input=$1
	[[ $user_input =~ $IP_PATTERN || $user_input =~ $DOMAIN_PATTERN ]] && echo "$user_input" && return 0 || return 1
}

# Function to get a target address from the user
get_target() {
	declare -g target_domain=""
	while true;
	do
		read -p "[?] Specify a Domain/IP address to scan: " target_domain
		check_domain_format "$target_domain"
		[ $? -eq 0 ] && return 0 || echo "Invalid input. Please enter a valid IP address or domain."
	done
}

# Function to reset the tor circut inorder to fix any issues caused by the current setup
reset_circuit() {
	cd $NIPE_PATH
	sudo perl nipe.pl stop
	
	echo "Changing tor circuit"
	
	local tor_pid=$(sudo netstat -tulep | awk '/:9050/ {print $NF}' | cut -d '/' -f 1)
	[ -n "$tor_pid" ] && sudo kill $tor_pid
	
	tor --controlport 9052 & #TODO sed auth hash
	local pid=$!
	sleep 7
	sudo kill $pid

	sudo perl nipe.pl start
}

# Function to spoof the local identifiers
# Note:
#	The function should spoof IP, Hostname, MAC
#	currently the MAC spoofing isn't implemented
spoof_address() {
	local msg="[*] Spoofing local identifiers..."
	cycle_word_and_chars "$msg" &
	local load_msg_pid=$!

	# cat /usr/share/wireshark/manuf

	local mac=$(printf "%012x" $(shuf -i 0-$((16 ** 12 - 1)) -n 1) | sed 's/../&:/g; s/:$//')
	local adapter=$(route -n | awk 'NR>2 {print $2" "$NF}' | awk '!/0.0.0.0/ {print $NF}') 

	# echo "$adapter: $mac"

	# sudo ip link set dev $adapter down
	# sudo ip link set dev $adapter address $mac
	# sudo ip link set dev $adapter up


	[ ! -f "$HNAME_BAK" ] && cp $HNAME_PATH $HNAME_BAK
	echo $RANDOM > $HNAME_PATH

	cd "$NIPE_PATH"
	local nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")
	[[ $nipe_status == "true" ]] && kill $load_msg_pid && echo -e "\r$msg " && return 0 #echo "[#] nipe is already running." && return 0

	sudo perl nipe.pl start 
	

	while [ "$nipe_status" != "true" ]
	do
		reset_circuit >/dev/null 2>&1
		nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")
	done
	
	kill $load_msg_pid
	echo -e "\r$msg "

	return 0
}

# Function to display the current:
#	1. public IP
#	2. country
get_spoofed_value() {
	local country=$(sudo perl nipe.pl status | xargs geoiplookup | cut -d ' ' -f 5-)
	local ip=$(sudo perl nipe.pl status | awk '/Ip:/ {print $NF}')

	echo -e "[*] You are anonymous.. Connecting to the remote Server.\n"
	echo "[*] Your Spoofed IP address is: $ip, Spoofed country: $country"
}

# Function to request the user to input the remote server credentials
# Note:
#	the password field is hidden in order to protect the user from over the sholder attacks
#	the port field may be skiped and assumed as the default
get_remote_creds() {
	read -p "[?] Enter remote user: " rm_user
	read -s -p "[?] Enter remote password: " rm_pass; echo
	read -p "[?] Enter remote address: " rm_ip
	read -p "[?] Enter remote port: " rm_port; [ -z "$rm_port" ] && rm_port=22
}

# Function to initiate run a remote scan on the previously defined target 
remote_scan() {
	local readonly whois_scan="whois_$target_domain"
	local readonly nmap_scan="nmap_$target_domain"
	local array_string=$(printf "%s " "${rm_programs[@]}")

	get_remote_creds

	audit "[*] Starting remote scan"
	sshpass -p $rm_pass ssh -o StrictHostKeyChecking=no $rm_user@$rm_ip "$(declare -f remote_script); $(declare -f install_programs); $(declare -f check_installed); remote_script $target_domain $rm_pass $array_string" >/dev/null 2>&1 

	echo -e "\n[*] Whoising victim's address:"
	sshpass -p $rm_pass ssh -p $rm_port -o StrictHostKeyChecking=no $rm_user@$rm_ip whois $target_domain > $SCAN_PATH/$whois_scan
	echo "[@] Whois data was saved into $SCAN_PATH/$whois_scan."
	audit "[*] whois data collected for: $target_domain"
	
	echo -e "\n[*] Scanning victims's address:"
	sshpass -p $rm_pass ssh -p $rm_port -o StrictHostKeyChecking=no $rm_user@$rm_ip nmap -vvv -T4 $target_domain > $SCAN_PATH/$nmap_scan
	echo "[@] Nmap data was saved into $SCAN_PATH/$nmap_scan."
	audit "[*] Nmap data collected for: $target_domain"
}

# Function that runs on the remote server itself
# Installes the needed apps
# Anonymize the connection
# Displayes the spoofed values
remote_script() {
	local programs=("whois" "nmap" "geoip-bin" "git" "curl" "build-essential" "nipe")
	local sudo_pass=$2
	local target=$1

	echo "$sudo_pass" | sudo -S install_programs ${programs[@]} 

	sudo perl $NIPE_PATH/nipe.pl start
	local status=$(sudo perl $NIPE_PATH/nipe.pl status) # TODO handel a failed status
	

	local remote_ip=$(echo $status | awk '/Ip:/ { print $NF } ')
	local country_ip=$(geoiplookup $remote_ip | cut -d " " -f 5-)

	echo "Uptime:$(uptime)"
	echo "IP address: $remote_ip"
	echo "Country: $country_ip"
}

# Main function to run the entire script
main() {
	init_checks $@
	
	check_connectivity


	install_programs ${programs[@]}  #>/dev/null 2>&1

	spoof_address #>/dev/null 2>&1 
	get_spoofed_value

	get_target
	
	echo -e "\n[*] Connecting to Remote Server:"
	
	start_date=$(date +%s)
	remote_scan
	(( $(date +%s) - $start_date > 30 )) && think "well... that was a long wait"
	
	say "Have a good day"
	
	revert_to_default >/dev/null 2>&1
}

main "${@}"
