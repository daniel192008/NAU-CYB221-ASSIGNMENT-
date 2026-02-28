SCAN REPORT
Name: Emeka Daniel Chimuanya
Reg No: 2024924010
Dept: Cyber Security
Course Work: CYB 221 Assignment
PORTS
OPEN PORTS
Ports Exposed/ Local-only Why It Is Open
123 Exposed The system is synchronizing
time automatically.
135 Exposed Windows internal service
communication
137 Exposed Network discovery
5353 Exposed Device discovery.
138 Exposed Network device messaging
139 Exposed File/printer sharing support
445 Exposed Windows file sharing
service is ongoing.
3306 Exposed The database is running.
49664 - 49674 Exposed Temporary
communications.
52663 - 52672 Exposed Temporary
communications.
63303 Exposed Temporary
communications.
55908 Local-only Temporary
communications.
42050 Local-only Temporary
communications.
65077 Exposed Temporary
communications.
1900 Local-only Finds devices on network.
7680 Exposed Shares update files locally.
33060 Exposed MySQL database.
17500 / 17600 Exposed Logitech software
5050 Exposed Web tools or apps.
3331 Local-only Application specific
service.
5040 Exposed Windows or third-party
service.
843 Local-only Specialized or legacy apps
services.
SECURITY CONTROLS TO REDUCE RISKS
Several security controls can reduce risks associated with open ports.
Firewalls can restrict which systems are allowed to connect, preventing unauthorized
access even when a service is listening.
Binding services to localhost limits access to the local machine only, eliminating remote
attack vectors.
Disabling unnecessary services reduces the number of open ports and therefore
decreases the attack surface.
Keeping software updated, enforcing strong authentication, and monitoring network
activity further strengthen security by preventing exploitation and enabling rapid detection
of suspicious behavior.
