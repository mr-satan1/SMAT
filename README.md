# SMAT - Simple Malware Analysis Tool
SMAT is a simple web application written in Python. It leverages Flask, Yara-Python and the Requests module as well as OSINT sources such as VirusTotal. SMAT's purpose is simple from a user perspective: Feed it a suspicious file and SMAT will return back data you need for quick triage!


<img width="1281" alt="screen shot 2016-05-07 at 6 27 51 pm" src="https://cloud.githubusercontent.com/assets/11253216/15095566/861dc0b4-1481-11e6-92c0-4306a5bfb435.png">

## Overview
- What Yara rules were matched against this file.
- What data VirusTotal has on this file.
- Name and size of said suspicious file.
- Logged metadata in 'IsItBad.log' in application root directory.
- SQLite database ('smat.db') backend.

## Built With
This web application requires the following:
- Python 2.7
- Yara and Yara-Python
- Requests
- Flask
- SQLite 

This is a quick triage for unknown/untrusted files leveraging Yara and VirusTotal. This is designed to run locally and is a proof of concept (BETA) at this time. 

## Installation & Usage
<code> git clone https://github.com/mr-satan1/SMAT.git </code>
<code> cd SMAT </code>
<code> pip install -r requirements.txt </code>
<code> python app.py </code>


## To Do
- Include auto-update mechanism for Yara Rules.
- Configure Docker container:
    - Alpine Linux
    - Python 2.7 / PIP
    - Nginx load balancer
    - HTTPS
