# Internship
Cyber security intership 
Task 1: Scan Your Local Network for Open Ports



 - In this task we are looking in our network for open ports so firts we have to know our local ip range 
 - **ip a ** this is the command we are using to find our local ip range 
 - after we find the ip range then we can scan the network for any open ports
 - to scan the network we are using Nmap tool 
 - Nmap is a network scaning tool 
 - **nmap -sS 192.168.20.7/24 ** this is the command for scaning 
 - in my local network there are 4 hosts are up '192.168.20.1', '192.168.20.4', '192.168.20.13' and '192.168.20.7'
 - in the first host there is 3 open ports and in the other three there is none 
 - the open ports are 23,53 and 80 
 - Telnet service running in the 23 port 
 - Domian service is running in the 53 port
 - http service is running in the 80 port.

 - Telnet is a network protocol that enables remote access to devices and servers
 - Domain is essential for translating human-readable domain names (like google.com) into numerical IP addresses that computers use to locate and connect to websites
 -  HTTP service is running in the 80 port. HTTP is the foundation of web Browse 


 1. Port 23/tcp - Telnet (Open)

This is the most critical and highest risk among your findings.

    Plaintext Communication: Major Risk. Telnet transmits all data, including usernames, passwords, and commands, in unencrypted plain text. Anyone with access to the local network (or who can intercept traffic) can easily "sniff" this data and compromise the credentials, gaining full access to the device. This makes it highly susceptible to:
        Man-in-the-Middle (MITM) attacks: An attacker can intercept, read, and even modify the communication between your client and the Telnet server without either party knowing.
        Credential Theft: Login credentials are sent in the clear, making them trivial to capture.
    Weak Authentication: Telnet's authentication mechanisms are typically very basic and vulnerable to brute-force attacks (repeatedly guessing usernames and passwords) or dictionary attacks.
    Lack of Integrity: There's no mechanism to ensure that the data hasn't been tampered with during transmission.
    Outdated Protocol: Telnet is an ancient protocol (from the 1970s) and lacks modern security features. It has largely been replaced by more secure alternatives.

Recommendation: Disable Telnet immediately. Replace it with SSH (Secure Shell), which uses Port 22, for any remote command-line access. SSH encrypts all communication and provides stronger authentication methods.

2. Port 53/tcp - Domain (DNS) (Open)

While DNS is essential for network communication, an open and improperly secured DNS server can pose significant risks:

    DNS Cache Poisoning/Spoofing: An attacker can inject false DNS records into the DNS server's cache. This can redirect users from legitimate websites (e.g., your bank's website) to malicious, look-alike sites controlled by the attacker (phishing).
    DNS Amplification Attacks (if UDP 53 is also open and resolver is open recursive): Although your scan showed TCP 53, if UDP 53 is also open and configured as an open recursive resolver, attackers can use it to launch Distributed Denial of Service (DDoS) attacks. They send a small query to your DNS server, which then sends a much larger response to a spoofed victim IP address, effectively amplifying the attack traffic.
    DNS Tunneling: Malicious actors can encapsulate other protocols (like malware command and control traffic) within DNS queries and responses. This can bypass firewalls that only inspect higher-level protocols, allowing data exfiltration or remote control.
    Information Disclosure: Misconfigured DNS servers might reveal internal network structure or sensitive domain information that aids an attacker in mapping your network.
    Vulnerabilities in DNS Software: Like any software, DNS server software (e.g., BIND, Microsoft DNS) can have vulnerabilities that, if unpatched, can be exploited for remote code execution or other attacks.

Recommendation: Ensure the DNS server is configured securely. If it's a local device (like a router), ensure it's not acting as an "open recursive resolver" to the internet. Keep DNS server software updated.

3. Port 80/tcp - HTTP (Open)

HTTP is the foundation of the web, but its unencrypted nature poses risks:

    Plaintext Communication: Major Risk for Sensitive Data. Like Telnet, standard HTTP transmits all data (including login credentials, personal information, credit card numbers, etc.) in unencrypted plain text. This means anyone on the network can sniff the traffic and steal sensitive data.
    Web Application Vulnerabilities: If there's a web application running on this port (e.g., a router's admin panel, a local server), it can be vulnerable to a wide range of web application attacks:
        SQL Injection: Injecting malicious SQL code to manipulate or extract data from databases.
        Cross-Site Scripting (XSS): Injecting malicious scripts into web pages viewed by other users.
        Cross-Site Request Forgery (CSRF): Tricking authenticated users into executing unwanted actions.
        Directory Traversal: Accessing files outside the intended web server directory.
        Remote Code Execution (RCE): Exploiting flaws in the web application or server software to run arbitrary code on the server.
    Brute-Force Attacks: If the web application has a login page, it's susceptible to brute-force attacks against its credentials.
    Outdated Web Server/Application Software: Unpatched web servers (Apache, Nginx, IIS) or web applications can have known exploits.

Recommendation:

    Always use HTTPS (Port 443) for any web service that handles sensitive information. Implement an SSL/TLS certificate to encrypt traffic.
    Ideally, configure Port 80 to redirect all traffic to HTTPS (Port 443).
    Keep the web server software and any running web applications fully patched and securely configured.




Nmap done: 256 IP addresses (4 hosts up) scanned in 37.94 seconds
ain.txt…]()

    
