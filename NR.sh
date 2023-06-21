#!/bin/bash

# Define the programs to check and install
declare -rga programs=("cowsay" "geoip-bin" "tor" "sshpass" "nipe")
declare -rga rm_programs=("whois" "nmap" "geoip-bin") # "curl") #"nipe")
# Regular expression patterns for IP address and domain
declare -rg ip_pattern='^(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)(\.(25[0-5]|2[0-4][0-9]|[1-9][0-9]?|0)){3}$'
declare -rg domain_pattern='^([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
# Define path for the nipe program installation
#nipe_path="/home/$username/nipe"
declare -rg HNAME_PATH="/etc/hostname"
declare -rg HNAME_BAK="$script_dir/hostname.bak"
declare -rg nipe_path="/usr/bin/nipe"
declare -rg nipepl_path="/usr/bin/nipe/nipe.pl"
declare -rg COWSAY_PATH="/usr/games/cowsay"
declare -rg COWTHINK_PATH="/usr/games/cowthink"
# remote connection type
declare -gi rm_mode="1" # 0-localhost 1-in lan 2-public 3-hidden service
# values for SSHPASS
rm_ip="10.0.0.70"
rm_user="michael"
rm_pass="michael"
rm_port="22"
# Get the directory path of the bash script
script_dir="$(dirname "$0")"
[[ $script_dir == "." ]] && script_dir=$(pwd)
# path to the scripts log file
declare -rg LOG_PATH="/var/log/nr.log"
# path to saved scans
declare -rg SCAN_PATH="$(pwd)/scans"


# # Construct the absolute path to ssh key
#ssh_key_path="$script_dir/id_rsa"

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
}

init_checks() {
	[ $UID -ne 0 ] && echo "[!] This script requires root privileges. Please run with sudo." && exit 1
	[ ! -d $SCAN_PATH ] && mkdir $SCAN_PATH
	[ ! -f $LOG_PATH ] && sudo touch $LOG_PATH
	
	while getopts ":hrm:" opt; do # TODO more falgs (for sshapss creds)
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
		# Skip installation if program is already installed
		check_installed "$program" && continue 
		
		# check_connectivity #TODO make run once
		
		echo "[*] Installing $program..."
		if [ $program == "nipe" ]; then
			# Install libs and dependencies
			! command -v cpanm >/dev/null && curl -L https://cpanmin.us | sudo perl - App::cpanminus

			# Download
			[ -z "$nipe_path" ] && nipe_path="$(pwd)/nipe"
			sudo git clone https://github.com/htrgouvea/nipe $nipe_path
			cd $nipe_path # Must cd for the script to find modules

			
			sudo cpanm --installdeps .
			# sudo cpanm install Nipe::Engine::Stop
			sudo perl nipe.pl install
		else
			sudo apt-get update #TODO RUN ONCE
			sudo apt-get install -y "$program"
		fi
	done
}
 
revert_to_default() {
	[ -f "$HNAME_BAK" ] && cat $HNAME_BAK > $HNAME_PATH

	[ ! -d "$nipe_path" ] && echo "[!] Can't stop the service that isn't installed" && return 1

	sudo perl $nipe_path/nipe.pl stop >/dev/null 2>&1
	echo "[*] nipe is disabled"
	return 0
}

say() {
	figlet $1 -cf slant | $COWSAY_PATH -n
}

think() {
	figlet $1 -k | $COWTHINK_PATH -n
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
	[ ! -f "$HNAME_BAK" ] && cp $HNAME_PATH $HNAME_BAK
	echo $RANDOM > HNAME_PATH

	cd "$nipe_path"
	nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")
	[[ $nipe_status == "true" ]] && return 0 #echo "[#] nipe is already running." && return 0

	sudo perl nipe.pl start 
	
	nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")

	[[ $nipe_status == "true" ]] && return 0

	echo "[!] Unexpected Error while starting nipe service"

	think "mmm... maybe try again..."

	sudo perl nipe.pl stop
	exit 1
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

remote_scan() {
	local rm_scans="/home/michael" #TODO change to dynamic
	local rm_port=22
	local whois_scan="whois_$target_domain"
	local nmap_scan="nmap_$target_domain"
	local array_string=$(printf "%s " "${rm_programs[@]}")

	sshpass -p $rm_pass ssh -o StrictHostKeyChecking=no $rm_user@$rm_ip "$(declare -f remote_script); $(declare -f install_programs); $(declare -f check_installed); remote_script $target_domain $array_string" 

	echo -e "\n[*] Whoising victim's address:"
	sshpass -p $rm_pass ssh -p $rm_port -o StrictHostKeyChecking=no $rm_user@$rm_ip whois $target_domain > $SCAN_PATH/$whois_scan
	echo "[@] Whois data was saved into $SCAN_PATH/$whois_scan."
	# Log Audit 
	echo "$(date)- [*] whois data collected for: $target_domain" >> $LOG_PATH
	
	echo -e "\n[*] Scanning victims's address:"
	sshpass -p $rm_pass ssh -p $rm_port -o StrictHostKeyChecking=no $rm_user@$rm_ip nmap -vvv -T4 $target_domain > $SCAN_PATH/$nmap_scan
	echo "[@] Nmap data was saved into $SCAN_PATH/$nmap_scan."
	# Log Audit
	echo "$(date)- [*] Nmap data collected for: $target_domain" >> $LOG_PATH
}

#####################REMOTE-SCRIPTS####################

remote_script() {
	local programs=("whois" "nmap" "geoip-bin" "git" "curl" "build-essential" "nipe")
	local sudo_pass="michael"
	local target=$1

	echo "$sudo_pass" | sudo -S ls >/dev/null 2>&1

	echo "$sudo_pass" | sudo -S mkdir $log_dir 2>/dev/null

	install_programs ${programs[@]} >/dev/null 2>&1

	sudo perl $nipe_path/nipe.pl start
	local status=$(sudo perl $nipe_path/nipe.pl status) # TODO handel a failed status
	

	local remote_ip=$(echo $status | awk '/Ip:/ { print $NF } ')
	local country_ip=$(geoiplookup $remote_ip | cut -d " " -f 5-)

	echo "Uptime:$(uptime)"
	echo "IP address: $remote_ip"
	echo "Country: $country_ip"
}

get_whois() {
	local target=$1
	local rm_pass=$2
	local scan_path="whois_$target"

	pwd
	echo "$rm_pass" | sudo -S touch $scan_path
	sudo chmod a+w $scan_path
	whois $target > $scan_path	
}

#########################################################

main() {
	init_checks $@
	
	install_programs ${programs[@]} </dev/null 2>&1
	
	spoof_address
	get_spoofed_value
	
	declare -g target_domain=""
	while [ -z "$target_domain" ]
	do
		check_domain_format
	done
	
	echo -e "\n[*] Connecting to Remote Server:"
	
	start_date=$(date +%s)
	# remote_scan
	(( $(date +%s) - $start_date > 30 )) && think "well... that was a long wait"
	
	say "Have a good day"
	
	revert_to_default
}

main "{@}"

# get target for remote
# nmap -p 22 --exclude 10.0.0.50 10.0.0.50/24 | grep -B 4 "open" |  awk '/Nmap scan/{print $NF}' | head -n 1
# hydra -l michael -P temp ssh://10.0.0.70 -o rm_creds >/dev/null 2>&1

