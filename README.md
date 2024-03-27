# penetration-testing-and-scanning
Familiarity with penetration testing and scanning
The project consists of two parts.
The first part includes the study of the scanning phase in the discussion of penetration testing and the implementation of a network scanning tool using the Python language.
The second part includes testing and verifying the correctness of the functionality of the written tool, as well as familiarization with scanning tools.

## Part 1
In this section, we used the Python programming language to create a network scanning tool and implement The desired tool should include the following capabilities: 
1. Scan an IP range and find active machines
2. Scan the open TCP and UDP ports of an active machine
3. Identification of the service executed on the open ports of an active machine
4. Show the report to the user and save it in a file in t format

** IMPORTANT NOTES:** 
The following command format is used to implement the CLI part of the tool:
```
scanner.py --ipscan –m 24 –ip 192.168.1.1 192.168.1.254
```
The first address for the start of the domain range and the second address for the end and switch -m to specify the subnet mask:
```
scanner.py –portscan –tcp 1 1000
```
```
scanner.py –portscan –udp 1 1000
```
The first number is for the beginning of the port range and the second number is for the end of the port number range.

## Part 2
In this section using the information in the Nmap-security-cookbook.pdf file provided you can check the accuracy of the information provided by the python code.
