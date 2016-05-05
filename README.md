# IsItBad
This is a simple, but useful, web application that will gather metadata on a suspicious file and return to you the following:
- What Yara rules were matched against this file.
- What data VirusTotal has on this file.
- Name and size of said suspicious file.
- Logged metadata in 'IsItBad.log' in application root directory.

This web application requires the following:
-Python 2.7+
-Yara and Yara-Python
-Requests
-Flask

This is a quick triage for unknown/untrusted files leveraging Yara and VirusTotal. This is designed to run locally and is a proof of concept (BETA) at this time. 

To-Do:
- Include auto-update mechanism for Yara Rules.
- Make the CSS look pretty. Bootstrap probably.
- Configure Docker container:
    - Alpine Linux
    - Python 2.7 / PIP
    - Nginx load balancer
    - HTTPS