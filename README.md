# SMAT - Simple Malware Analysis Tool
SMAT is a simple web application written in Python. It leverages Flask, Yara-Python and the Requests module as well as OSINT sources such as VirusTotal. SMAT's purpose is simple from a user perspective: Feed it a suspicious file and SMAT will return back data you need for quick triage!

:
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
- Configure Docker container:
    - Alpine Linux
    - Python 2.7 / PIP
    - Nginx load balancer
    - HTTPS