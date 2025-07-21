import requests
import whois
import threading
import socket
import json 
import ipinfo
import os
import time 
import ipaddress
from termcolor import colored
from subdomain import count_subdomains
from pyfiglet import figlet_format
from dotenv import load_dotenv
from urllib.parse import urlparse 



url = ''
count = 0
lock = threading.Lock()
ip = 0

# Define color codes
red = '\033[91m'
cyan = '\033[96m'
yellow = '\033[93m'
blue = '\033[94m'
green = '\033[92m'
reset = '\033[0m'
version = "1.0"

# Generate ASCII art for 'Url Analyzer'
ascii_art = figlet_format("URL ANALYZER", font="slant")  # You can change 'slant' to any supported pyfiglet font

# Compose the banner
logo = f"""
{cyan}{ascii_art}{yellow}
                   [ v{version}]
{green}                      by R05HAN
{reset}
"""

print(logo)






# get token
load_dotenv()
token = os.getenv("ipInfo_token")


# private ip not scanning [SSRRF protection]

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return True  # safest default
    


def url_handle(url):
    output = ("\n ---Result for: " + url + " ---\n")

    
    #Send req  
    print()
    try:
        try:
            response = requests.get(url, timeout=5) 
        except requests.exceptions.RequestException as e :
            with lock:
                print(f"\n---Result for: {url} ---\nRequest Failed: {e}\n")
                return

        output += "Url Response: \n"

        if 200 <= response.status_code <=299:
            output += "Success"

        else :
            output += f"Status Code: {response.status_code}"

    except requests.exceptions.RequestException as e :
        output += f"Error: {str(e)}"

    print()


    # URL INFORMATION
    url_break = urlparse(url) #Breaking(parsing) the url
    output += f"Domain Name: {url_break.netloc}" #Gets the Domain Name

    try:

        domain_info = str(whois.whois(url_break.netloc)) #Domain Info
        
        json_response = "No JSON Content"
        try :
            json_response = response.json() 
        except ValueError:
            output +="No JSON content"

        with lock: 
            # Saves the info in a file 
            with open("url_info.log", "a") as f:
                f.write(f"Url: {url} \n DOMAIN: {url_break.netloc} \n JSON Content: {json_response} \n\n {domain_info}")
                f.write("\n\n-----------------------------------------------\n\n\n")
            
    
    except Exception as e:
        output +=f"Error while getting domain info \n {e} " 

    with lock:
        print(output)


    
# -----------------------------------------------------------------------
    # Ip Info 
    ip = socket.gethostbyname(urlparse(url).netloc)
    output += f"\n Ip = {ip}"

    if not token  :
        raise ValueError("IP info token not found")

    else:
        handler = ipinfo.getHandler(token)
    
        details = handler.getDetails(ip)
        ipDetails_json = json.dumps(details.all, indent = 4)

        with lock:        
            with open ("ip.log", "a", encoding="utf-8") as f:
                f.write(ipDetails_json)
                f.write("\n\n-----------------------------------------------\n\n\n")

# SSRF Protection
    # ip = socket.gethostbyname(urlparse(url).netloc)
    if is_private_ip(ip):
        with lock:
            print(f"⚠️ Skipped private/internal IP: {ip}")
        return

# -----------------------------------------------------------------------



n = int(input("Number of Urls: "))


threads = []

for i in range (n) :
    url = str(input(f"URL {i+1}: "))
    parsed = urlparse(url)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #THREADING   
    try:
        thread = threading.Thread(target=url_handle, args=(url,))
        thread.start()
        threads.append(thread)
    except Exception as e :
        print(f"Thread Error: {e}")

# Phishing Detection
    # url length
    # CONDITION 1
    if (len(url) >= 100 ):
        for _ in range(3):
            print(colored("Url length exceeds 100 characters", 'red', attrs=['bold']))   
            os.system('cls' if os.name == 'nt' else 'clear')  # clears the screen
            time.sleep(1)        
        count += 1
    else :
        pass

    # http url 
    # CONDITION 2
    for _ in range(3):

        if parsed.scheme not in ['http', 'https'] or not parsed.netloc:
            print(colored("❌ Invalid or unsupported URL", 'red', attrs=['bold']))
            continue
        else:
            pass

    # Subdomains count
    # CONDITION 3

    if int(count_subdomains(url)) >=2 :
        print(colored("❌ Invalid or unsupported URL", 'red', attrs=['bold']))
        count += 1
   




# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



for thread in threads :

    thread.join()


if count >=2 :
    print(colored("❌ Invalid or unsupported URL", 'red', attrs=['bold']))
    