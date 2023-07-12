import colorama
import datetime
import requests
import sys
import re
import urllib.parse
from colorama import Fore, Back, Style
from bs4 import BeautifulSoup
from references import *
from sql import SQLSPECIFIC


invalidANS = True
loop = True
#------------------------------------------------------------#
#####Functions
def load(item, string, time):
    if item == string:
        print(Fore.BLUE + time + Fore.RESET)

#Graphic User Interface
def GUI():
    invalidANS = True
    print(Fore.YELLOW + "------------------------------- Release Version 1.2 --------------------------------")
    print("  _________              __  .__              .__    _________                     ")
    print(" /   _____/ ____   _____/  |_|__| ____ _____  |  |  /   _____/ ____  _____    ____  ")
    print(" \_____  \_/ __ \ /    \   __\  |/    \\ __  \ |  |  \_____  \_/ ___\ \__  \ /     \ ")
    print(" /        \  ___/|   |  \  | |  |   |  \/ __ \|  |__/        \  \___ / __ \|   |  \ ")
    print("/_______  /\___  >___|  /__| |__|___|  (____  /____/_______  /\___  >____  /___|  /")
    print("        \/     \/     \/             \/     \/             \/     \/     \/     \/ ")
    print("--------------------------- Web App Vulnerability Scanner ---------------------------")
    print(Fore.LIGHTBLACK_EX + "Note: XSS Scan may have false positives." + Fore.RESET)
    print(Fore.LIGHTBLACK_EX + "Note: Added SQL Vulnerability Scan to target an known form" + Fore.RESET)

    print(" ")
#SQL Injection Vulnerabilities
def SQLSCAN(url):
    doesExist = False
    for payload in sqlpayloads:

        load(payload, "'));waitfor delay '0:0:__TIME__'--", "10%")
        load(payload, " AS INJECTX WHERE 1=1 AND 1=0--", "30%")
        load(payload, "WHERE 1=1 AND 1=1#", "60%")
        load(payload, "ORDER BY 9#", "80%")
        load(payload, "and (select substring(@@version,3,1))='X'", "100%")

        # Inject the payload into the search field and submit the form
        search_field = soup.find('input', {'name': 'search'})
        if search_field is None:
            search_field = soup.find('input', {'name': 'q'})
            if search_field is None:
                search_field = soup.find('input', {'name': 's'})
                if search_field is None:
                    search_field = soup.find('input', {'name': 'toolbarInput'})
                    if search_field is None:
                        search_field = soup.find('input', {'name': 'toolbar'})
                        if search_field is None:
                            search_field = soup.find('input', {'name': 'input'})

        if search_field is None:
            print(Fore.LIGHTWHITE_EX + "-------- Results --------")
            print(Fore.WHITE + "> " + Fore.YELLOW + "SQL Injection Error: Could not find search field on page")
            return
        # Get the response from the webpage
        search_field['value'] = payload
        response = requests.post(url, data={'search': payload})

        # Check if the payload was reflected in the response, if it is, it shows the input was not properly sanitized
        if payload in response.text:
            print(Fore.LIGHTWHITE_EX + "-------- Results --------")
            print(Fore.RED + "> SQL injection vulnerability detected with payload:", payload)
            doesExist = True
    if doesExist == False:
        print(Fore.LIGHTWHITE_EX + "-------- Results --------")
        print(Fore.YELLOW + "> No SQL Injection vulnerability found.")

def AUTHSCAN(url):
    auth_token = None
    auth_headers = None

    # Check for auth token pattern in response text
    for pattern in auth_token_patterns:
        match = re.search(pattern, response.text, re.IGNORECASE)
        if match:
            auth_token = match.group(1)
            break

    # Check if URL requires authentication
    if auth_token:
        auth_headers = {"Authorization": "Token " + auth_token}
        auth_response = requests.get(url, headers=auth_headers)

        # Check if authentication bypass vulnerability exists
        # Code 200 means success
        if auth_response.status_code == 200:
            print(Fore.RED + "> Authentication bypass vulnerability detected.")
        else:
            print(Fore.YELLOW + "> No authentication vulnerabilities detected.")

    # No auth token pattern found
    else:
        print(Fore.YELLOW + "> No authentication vulnerabilities detected.")

def XSSSCAN(url):
    found = False
    for pattern in xss_patterns:
        matches = len(re.findall(pattern, response.text, re.IGNORECASE))
        if matches > 0:
            print(Fore.MAGENTA + "> *Potential* XSS vulnerability detected with pattern:", pattern)
            found = True
    if not found:
        print(Fore.YELLOW + "> No XSS vulnerability detected.")

def CSRFSCAN(url):
    csrf_token = None
    csrf_payload = None
    found = False
    for pattern in csrf_token_patterns:
        match = re.search(pattern, response.text, re.IGNORECASE)
        if match:
            csrf_token = match.group(1)
            break
    if csrf_token:
        csrf_payload['csrf_token'] = csrf_token
        csrf_response = requests.post(url, data=csrf_payload)
        if "Welcome, admin" in csrf_response.text:
            print(Fore.RED + "> CSRF vulnerability detected at URL:", url)
            found = True
    if not found:
        print(Fore.YELLOW + "> No CSRF vulnerability detected.")
#-------------------------------------------------------------#
###### Main Execute

GUI()
while(loop):
    print(Fore.GREEN + "[1] Extensive Web App Vulnerability Scan")
    print(Fore.RED + "[2] Exit")
    print(Fore.CYAN + "[3] SQL Form Targeted Scan")
    print(Fore.YELLOW + "[4] Help")
    option = input(Fore.WHITE + ">> ")

    if option == "1" or option == "3":
        print(Fore.LIGHTGREEN_EX + "> Please provide a url to scan.")
        invalidANS = False
        while True:
            urltarget = input(Fore.WHITE + ">> ")
            if urltarget == "2":
                sys.exit()
            try:
                result = urllib.parse.urlparse(urltarget)
                if all([result.scheme, result.netloc]):
                    # The input is a valid URL
                    break
                else:
                    print(Fore.RED + "> Invalid URL. Please try again.")
            except ValueError:
                print(Fore.RED + "> Invalid URL. Please try again.")

    if option == "2":
        invalidANS = False
        sys.exit()

    if option == "4":
        print(" ")
        print(Fore.YELLOW + "SentinelScan >>" + Fore.WHITE + " Hi, I am a CyberSecurity specialist who is currently an undergraduate studying Computer Science/Cybersecurity")
        print("I have created this Web Application Scanner aswell as a filtered packet sniffer with some Intrustion Detection integrated")
        print("Basically it runs a SQL/XSS/Authentication/CSRF scan by searching for patterns in responses given specific datasets to compare from")
        print(Fore.LIGHTBLACK_EX + "If you would like to contact me: mikestiuso98@gmail.com")
        print(" ")

    # If performing a scan option 1 or 3, continue to scan url
    if option == "1" or option == "3":
        # Request for target URL and parse
        response = requests.get(urltarget)
        soup = BeautifulSoup(response.text, 'html.parser')
        start_time = datetime.datetime.now()

        if option == "1":
            print(" ")
            print(Fore.BLUE + "> Scanning...")
            print(" ")
            SQLSCAN(urltarget)
            AUTHSCAN(urltarget)
            XSSSCAN(urltarget)
            CSRFSCAN(urltarget)
            end_time = datetime.datetime.now()
            elapsed_time = (end_time - start_time).total_seconds()
            minutes, seconds = divmod(elapsed_time, 60)
            elapsed_time_str = "{:02d}:{:02d}".format(int(minutes), int(seconds))
            print(Fore.LIGHTBLACK_EX + "Elapsed time: ", elapsed_time_str)
            print(" ")

        if option == "3":
            print(Fore.LIGHTGREEN_EX + "> Please provide a form name to target.")
            sqltarget = input(Fore.WHITE + "> ")

            print(" ")
            print(Fore.BLUE + "> Scanning...")
            print(" ")
            SQLSPECIFIC(urltarget, sqltarget)
            print(" ")
            print(" ")





