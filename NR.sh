#!/bin/bash

# Define the programs to check and install
programs=("geoip-bin" "tor" "sshpass" "nipe")
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
		nipe_status=$(sudo perl nipe.pl status | grep -oP '(?<=Status: ).*')
		if [ $nipe_status = "false" ]; then
			echo "[!] Can't stop the service if it isn't running"
			exit 1
		fi
	
		revert_to_default
		exit 0
	fi
}


check_connectivity() {
	! ping -c 1 google.com > /dev/null 2>&1 && echo "[!] No internet connection available!" && exit 1
}

handle_nipe() {
	[ -f "$nipepl_path" ] && echo "[#] nipe is already installed." && return 0
	
	echo "[*] Installing nipe..."
	check_connectivity

	#mkdir "$nipe_path"
	git clone https://github.com/GouveaHeitor/nipe.git "$nipe_path" #> /dev/null 2>&1
	cd "$nipe_path"
		
	sudo cpan install Try::Tiny Config::Simple JSON 1>/dev/null
	sudo perl nipe.pl install || { echo "[!] Nipe installation failed"; exit 1; }
	# sudo perl nipe.pl install > /dev/null
	
	#if [ $? -ne 0 ]; then
	#	echo "Installation failed"
	#fi
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
		sudo apt-get update > /dev/null
		sudo apt-get install -y "$program" > /dev/null
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
		#echo "$user_input"
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


setup_ssh() {
	# Generate SSH key pair
	ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""

	# Set correct permissions for SSH keys
	chmod 700 ~/.ssh
	chmod 600 ~/.ssh/id_rsa
	
	# Configure SSH to allow key-based authentication only
	#sudo tee -a /etc/ssh/sshd_config > /dev/null <<EOT
	#PasswordAuthentication no
	#ChallengeResponseAuthentication no
	#EOT

	# Restart SSH service
	sudo service ssh restart
	
	# Extract the Tor Hidden Service hostname
	tor_hostname=$(sudo cat /var/lib/tor/hidden_service/hostname)

	# SSH into the hidden service using private key
	ssh -p 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/.ssh/id_rsa user@$tor_hostname
}

nipe_start() {
	cd "$nipe_path"
	nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")
	[ $nipe_status == "true" ] && echo "[#] nipe is already running." && return 0

	sudo perl nipe.pl start
	
	nipe_status=$(sudo perl nipe.pl status | grep -oP "(?<=Status: )\b(true|false)\b")

	[ $nipe_status == "true" ] && return 0

	#if [ $nipe_status == "false" ]; then
	echo "[!] Unexpected Error while starting nipe service"
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

#########################################################

init_checks $@

echo "[?] To revert the settings back to normal run the script with -r flag"

install_programs

nipe_start
get_spoofed_value

figlet "done"
exit 0

target_domain=""
while [ -z "$target_domain" ]
do
	check_domain_format
done
#echo "$target_domain"


echo -e "\n[*] Connecting to Remote Server:"

##############################################################
#setup_hidden_service
#setup_ssh

