# System Memory

## Overview
- Target: 10.129.167.141
- Target type: linux_server
- Scope: this a ctf and those task can help you to capture the flag Task 1  When visiting the web service using the IP address, what is the domain that we are being redirected to? Task 2  Which scripting language is being used on the server to generate webpages? Task 3  What is the name of the URL parameter which is used to load different language versions of the webpage? Task 4  Which of the following values for the page parameter would be an example of exploiting a Local File Include (LFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "mimikatz.exe" Task 5  Which of the following values for the page parameter would be an example of exploiting a Remote File Include (RFI) vulnerability: "french.html", "//10.10.14.6/somefile", "./../../../../../../../windows/system32/drivers/etc/hosts", "mimikatz.exe" Task 6  What does NTLM stand for? Task 7  Which flag do we use in the Responder utility to specify the network interface? Task 8  There are several tools that take a NetNTLMv2 challenge/response and try millions of passwords to see if any of them generate the same response. One such tool is often referred to as john, but the full name is what?. Task 9  What is the password for the administrator user? Task 10 Task 11 Submit Flag

## Grouped Static Gathering
### Service Inventory
- Status: skipped
- Summary: No tool execution produced usable results. Both planned actions (route_topology and custom curl command) returned empty output.
- Key findings:
  - No tool execution produced usable results. Both planned actions (route_topology and custom curl command) returned empty output.
- Open questions:
  - Is the target server 10.129.167.141 reachable and serving HTTP responses?
  - Are there network-level restrictions preventing curl from completing the request?
- Tool outcomes:
  - route_topology: No routing data collected.
  - run_custom: curl -v http://10.129.167.141: No HTTP response received.

### Exposure Posture
- Status: skipped
- Summary: The 'Exposure Posture' block was intentionally skipped as it was deemed irrelevant to the CTF's focus on web service behavior, parameter discovery, and scripting language identification. Database enumeration tools were excluded to avoid unnecessary noise.
- Key findings:
  - The 'Exposure Posture' block was intentionally skipped as it was deemed irrelevant to the CTF's focus on web service behavior, parameter discovery, and scripting language identification. Database enumeration tools were excluded to avoid unnecessary noise.
- Tool outcomes:
  - __block__: Block marked incompatible or unauthorized for this target; no execution performed.


## Session And Surface Context
- Anonymous routes discovered: 1

## Stored Checklist
- Phase 1 Reconnaissance
  - Validate whether the target server 10.129.167.141 is reachable and serving HTTP responses by re-attempting a curl request with verbose output and extended timeouts. (P1)
  - Test the root endpoint (`http://10.129.167.141/`) to observe the domain redirection behavior (Task 1). (P1)
  - Inspect HTTP response headers and page source for clues about the scripting language used to generate webpages (Task 2). (P1)
  - Enumerate URL parameters (e.g., `page`, `lang`, `file`) to identify the parameter used for loading different language versions of the webpage (Task 3). (P1)
- Phase 2 Vulnerability Discovery
  - Validate whether the identified parameter is vulnerable to LFI by testing common sensitive files (e.g., `/etc/passwd`, `/etc/hosts`, or web application configuration files). (P1)
  - Test for RFI by attempting to include a file from an external server (e.g., `http://attacker.com/test.txt`) and observing server behavior. (P1)
  - Assess whether the server is vulnerable to PHP wrappers (e.g., `php://filter/convert.base64-encode/resource=index.php`) if the scripting language is PHP (Task 2). (P2)
  - Test for Server-Side Request Forgery (SSRF) by manipulating the parameter to make requests to internal services (e.g., `http://localhost`, `http://127.0.0.1`). (P2)
- Phase 3 Exploitation
  - Exploit LFI vulnerability to read sensitive files (e.g., `/etc/shadow`, web application source code, or configuration files) and extract flags (Task 11). (P1)
  - Exploit RFI vulnerability to include a remote malicious file (e.g., a web shell) and gain code execution on the server (Task 11). (P1)
  - Use LFI or RFI to leak the server's environment variables or configuration files (e.g., `config.php`, `.env`) for sensitive data (e.g., database credentials). (P2)
  - Test for command injection by chaining commands (e.g., `; ls`, `| cat /etc/passwd`) if the parameter allows execution of system commands. (P2)
