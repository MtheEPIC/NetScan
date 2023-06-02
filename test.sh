#!/bin/bash

# Test Case 1: Test running without sudo
test_not_sudo() {
	output=$(./NR.sh)
	expected_output="[!] This script requires root privileges. Please run with sudo."
	if [ "$expected_output" == "$output" ];
	then echo "PASS Case 1"
	else echo "FAIL Case 1: expected $expected_output got $output"
	fi
}

# Test Case 2: Test running with sudo
test_sudo() {
	output=$(sudo ./NR.sh)
	expected_output="[!] This script requires root privileges. Please run with sudo."
	if [ "$expected_output" != "$output" ];
	then echo "PASS Case 2"
	else echo "FAIL Case 2: expected $expected_output got $output"
	fi
}

# Test Case 3: Test running with sudo
test_sudo() {

}

# Run the tests
test_not_sudo
test_sudo
