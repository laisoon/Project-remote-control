#!/bin/bash

#NETWORK RESEARCH PROJECT - REMOTE CONTROL 
#STUDENT: GAN LAI SOON S19
#TRAINER: JAMES LIM
#PROJECT OBJECTIVE: TO WRITE A SCRIPT TO ALLOW A HOST COMPUTER(LOCAL) TO LOG INTO A REMOTE SSH SERVER TO RUN NMAP/WHOIS 
#(CONT)           : COMMANDS ON A GIVEN DOMAIN/IP ADDRESS; SAVING BOTH COMMANDS RESULTS INTO FILES INTO THE LOCAL COMPUTER
#(CONT)           : WHICH WILL BE SAVED IN A LOG FOR AUDIT PURPOSES

# Checking whether all necessary applications like geoiplookup,tor, sshpass and nipe are installed
if ! command -v geoiplookup &> /dev/null; then
    echo "[*] geoip-bin is not installed. Installing..."
    sudo apt-get install -y geoip-bin
else
    echo "[#] Geoip-bin is already installed."
fi

if ! command -v tor &> /dev/null; then
    echo "[*] Tor is not installed. Installing..."
    sudo apt-get install -y tor
else
    echo "[#] Tor is already installed."
fi

if ! command -v sshpass &> /dev/null; then
    echo "[*] sshpass is not installed. Installing..."
    sudo apt-get install -y sshpass
else
    echo "[#] SSHpass is already installed."
fi

# Checking if nipe is already installed on local machine
if [ ! -d "nipe" ]; then
    echo "[*] Nipe is not installed. Installing..."
    git clone https://github.com/htrgouvea/nipe
    cd nipe
    
    sudo cpan install Try::Tiny Config::Simple JSON 
    sudo perl nipe.pl install 
else
    echo "[#] Nipe is already installed."
fi

# Changing directory to /home/kali/nipe
cd nipe

# Run Nipe to make the network connection anonymous
sudo perl nipe.pl start
sudo perl nipe.pl restart

# Checking if the network connection is anonymous
check_status=$(sudo perl nipe.pl status)

if echo "$check_status" | grep -q "Status: false"; then
    # Connection is not anonymous
    echo "[*] Network connection is not anonymous. Exiting."
    exit 1
else
    # Connection is anonymous
    echo "[*] Network connection is anonymous."
    
    # Extracting the IP address
    ip=$(echo "$check_status" | grep Ip: | awk '{print $3}')
    
    # Extracting the country with whois
    country=$(geoiplookup "$ip" | awk '/Country/{print $4, $5, $6}')
    
    echo "[*] Your Spoofed IP address is: $ip"
    echo "[*] Spoofed country: $country"
fi

#Getting the ip address of the SSH server
read -p "[?] Please enter the IP address of the SSH server: "  ipaddress  

# Ask for the username
read -p "[?] Enter the username: " username

# Ask for the password
read -s -p "[?] Enter the password: " password
echo



# Connecting to the remote server
echo "[*] Connecting to the remote server..."
sshpass -p "$password" ssh -t "$username@$ipaddress" 
  
  
# Displaying uptime, country, and IP address of the remote connection
 
echo "Uptime: $(uptime)"
echo "Country: $(whois $ipaddress | grep -i country | awk -F': ' '{print $2}')"
echo "IP Address: $ipaddress"


# Specify a Domain/IP Address to scan - by requirement - 8.8.8.8 / scanme.nmap.com / I am using 8.8.8.8 for submission
toscan="8.8.8.8"
echo "[?] Specify a Domain/IP Address to scan: $toscan"
  


# Execute whois scan command and save the output on home directory
# Display the file paths where the scan files are saved on your local machine
echo '[*] Whoising now running on this target IP'
echo "[@] Whois scan data saved to: ~/whois_scanresults.txt"
whois "$toscan" > ~/whois_scanresults.txt

# Execute nmap scan and save the output on home directory
# Display the file paths where the scan files are saved on your local machine
echo '[*] Scanning this target IP address with nmap'
echo "[@] Nmap scan data saved to: ~/nmap_scanresults.txt"
nmap "$toscan" > ~/nmap_scanresults.txt


sudo chmod o+w /var/log

# Creating a Log file path
log_file="/var/log/scan_log.txt"

# Function to log the data collection process
log_data() {
   sudo echo "$(date): $1" >> "$log_file"
}

# Perform whois scan and save the output
log_data "Running whois scan on target IP: $toscan"
echo "[#] Whois scan now running on target IP: $toscan"
whois "$toscan" > ~/whois_scanresults.txt
log_data "Whois scan completed for target IP: $toscan"

# Perform nmap scan and save the output
log_data "Running nmap scan on target IP: $toscan"
echo "[#] Scanning target IP address with nmap: $toscan"
nmap "$toscan" > ~/nmap_scanresults.txt
log_data "Nmap scan completed for target IP: $toscan"


# Display log file path
echo "[@] Scan log saved to: $log_file"
