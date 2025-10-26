# SSTI Scanner

**SSTI Scanner** is a Python script designed to detect and exploit **Server-Side Template Injection (SSTI)** vulnerabilities in web applications. It automates the process of identifying SSTI, detecting the template engine (Python/Jinja2, PHP/Twig/Smarty, or Java/Freemarker/Velocity), and attempting to execute commands  and return a shell. 

This tool is intended for use in **Capture The Flag (CTF)** competitions ONLY or authorized security testing environments.

**Disclaimer**: This tool is for educational and ethical purposes only. Use it only on systems you have explicit permission to test. Unauthorized use may violate laws and ethical guidelines.

## Features

- **SSTI Detection**: Tests for SSTI vulnerabilities using generic payloads.
- **Template Engine Identification**: Detects the template engine by testing specific payloads for Python (Jinja2), PHP (Twig/Smarty), and Java (Freemarker/Velocity).
- **Command Execution**: Attempts to execute system commands to obtain an interactive shell.
- **Flexible Form Handling**: Supports forms with multiple keys, including nested keys and additional form fields.

## Prerequisites

- **Python 3.6+**
- **Required Python library**:
  ```bash
  pip install requests
  ```
## Usage
  ```bash
python3 scantemplate.py -u <URL> -k <KEY> -n <NUMBER_OF_KEYS> [-ok <OTHER_KEYS>]

# Url must be the url of your post request, key the form key you want to inject your  
# payloads to, and other_keys the other keys required on the request -ok must be under this format "key1=value1.key2=value2.key3=value3"

# Example : python3 scantemplate.py -u http://myprofile/preview -k content -ok title=profile.bio=helloworld

# This will test all kind of template injections on the content key of the request
  ```
  
  ### Next Update : 
    - Adding a blind mode to test blind injections 