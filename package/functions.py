from pymetasploit3.msfrpc import MsfRpcClient
import time
import re
import json
from colorama import Fore
import requests
from packaging import version

# connect to the server
client = MsfRpcClient(password = 'password', ssl = False, server = '192.168.81.130', port = 55553)

######################### GLOBAL VARIABLES #########################

api_key = 'oksE5dReaT7UqU7ZAcnPYSlOCMQkGGBttlvdAFIsgxI'
open_ports = []
wp_check, joomla_check, wp_version, joomla_version = False, False, "", ""
endpoints = []
users, accounts = [], []
slugs, slugs_version = [], []

def printRed(skk, end="\n"):
    print("\033[91m{}\033[0m".format(skk), end=end)

def printGreen(skk, end="\n"):
    print("\033[92m{}\033[0m".format(skk), end=end)

######################### Functions #########################

# 1) scan port
def funcScanPort(domain):
    global open_ports
    for i in range(3):
        open_ports = portScan(domain)
        if open_ports != []:
            for port in open_ports:
                printGreen("Open port: " + port)
            return
    printRed("Warning: Not found port or input error!")
    exit()
# 2) CMS check
def funcCheckCMS(domain, port):
    global wp_check, joomla_check, wp_version, joomla_version
    for i in range(4):
        wp_check, joomla_check, wp_version, joomla_version = checkCMS(domain, port)
        if wp_check or joomla_check:
            return
    printRed("Warning: Not found CMS or input error!")
    exit()
# 3) Information disclosure check
def funcWPInforDisScan(domain, port):
    global endpoints
    for i in range(3):
        endpoints = wpInforDisScan(domain, port)
        if endpoints != []:
            for endpoint in endpoints:
                printGreen("Information disclosure at: " + endpoint)
            return
    printRed("Warning: Not found infomation disclosure or input error!")
    exit()
# 4) Brute force WP account
def funcWPAccountEnum(domain, port):
    global users, accounts
    for i in range(3):
        users, accounts = wpAccountEnum(domain, port)
        if users != []:
            for user in users:
                printGreen("User found: " + user)
            printGreen("Account found:\nUsername list: ", end = "")
            printGreen(str(accounts["username"]))
            printGreen("Password list: ", end = "")
            printGreen(str(accounts["password"]))
            return
    printRed("Warning: Not found weak account or input error!")
    exit()
# 5) Plugin version check
def funcWPPluginScan(domain, port):
    global slugs, slugs_version
    for i in range(3):
        slugs, slugs_version = wpPluginScan(domain, port)
        if slugs != []:
            for slug, version in zip(slugs, slugs_version):
                printGreen("Plugin found: " + str(slug) + " - Version: " + str(version))
            return
    printRed("Warning: Not found plugins or input error!")
    exit()

######################### Auto scan for all #########################
def autoAll(domain):
    funcScanPort(domain)
    # for each port, check
    for port in open_ports:
        funcCheckCMS(domain, port)
        if wp_check:
            printRed("Wordpress information disclosure vulnerabilities scan ...")
            # WordPress old version CVE check
            CVE_wp = getWordpressCVE(wp_version, api_key)
            print(CVE_wp)
            funcWPInforDisScan(domain, port)
            funcWPAccountEnum(domain, port)
            funcWPPluginScan(domain, port)
            for slug, version in zip(slugs, slugs_version):
                plugin_vulnerabilities = getPluginCVE(slug, api_key)
                plugin_filtered_vulnerabilities = filterVulnerabilities(plugin_vulnerabilities, version)
                print(plugin_filtered_vulnerabilities)
        if joomla_check:
            joomlaScan(domain, port)

def wpPluginAdminScan(domain, wp_username, wp_password, port):
    global slugs, slugs_version
    printRed("Admin WP plugins scan ...")
    cookies = wpLogin(wp_username, wp_password, domain, port)
    slugs, slugs_version = getActivePlugins(cookies, domain, port)

def wpLogin(log, pwd, domain, port):
    url = f"http://{domain}:{port}/wp-login.php"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"log": log, "pwd": pwd, "wp-submit": "Log In"}
    try:
        response = requests.post(url=url, headers=headers, data=data, allow_redirects=False)
        if response.status_code == 302:
            cookies = '; '.join([f"{cookie.name}={cookie.value}" for cookie in response.cookies])
            return cookies
        else:
            print("Login fail.")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def getActivePlugins(cookie, domain, port):
    url = f"http://{domain}:{port}/wp-admin/plugins.php"
    headers = {
        'Cookie': cookie
    }
    plugins = []
    versions = []
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            # Get plugin form response
            if "_wpUpdatesItemCounts" not in response.text:
                printRed("Error!")
                return plugins, versions
            plugin_data = response.text.split('var _wpUpdatesItemCounts = ')[1]
            plugin_data = plugin_data.split(';')[0]
            plugin_data = plugin_data.replace('\\"', '"').replace("\\'", "'")
            plugin_info = eval(plugin_data)
            # Get active plugin
            active_plugins = plugin_info['plugins']['active']
            for plugin in active_plugins:
                # print(plugin)
                plugin_name = plugin.split('\\')[0]
                plugins.append(plugin_name)
                plugin_version = getPluginVersion(plugin_name, domain, port)
                versions.append(plugin_version)
                printGreen("Plugin found: " + plugin_name + " - Version: " + plugin_version)
            return plugins, versions
        else:
            print("Fail")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def wpInforDisScan(domain, port):
    destroyCurrentConsole(client)
    time.sleep(3)
    
    printRed("Information disclosure scan ...")
    module = 'auxiliary/customs/information_disclosure'
    console_id = client.consoles.console().cid
    command = f"use {module}\nset RHOSTS {domain}\nset RPORT {port}\nrun"
    client.consoles.console(console_id).write(command)
    endpoints = []
    count = 0
    while True:
        time.sleep(3)
        count += 3
        if count == 15:
            break
        result = client.consoles.console(console_id).read()
        if "Auxiliary module execution completed" in result["data"]:
            if "[+]" in result["data"]:
                regex = r'(\[\+\].*200)'
                matches = re.findall(regex, result["data"])
                for match in matches:
                    endpoint = match.split('Status')[0][:-2].split('at')[2].strip()
                    endpoints.append(endpoint)
                    response = getResponse(domain, port, endpoint)
                    target = None
                    result_json = resultJSON(domain, port, module, response, target)
                    print(result_json)
            break

    client.consoles.console(console_id).destroy()
    destroyCurrentConsole(client)
    return endpoints

def getPluginCVE(plugin_name, api_key):
    url = f"https://wpscan.com/api/v3/plugins/{plugin_name}"
    headers = {
        "Authorization": f"Token token={api_key}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
        # return data.get('vulnerabilities', [])
    else:
        print("Failed to fetch data:", response.status_code)
        return []

def filterVulnerabilities(plugin_data, max_version):
    plugin_name = list(plugin_data.keys())[0]
    vulnerabilities = plugin_data[plugin_name]['vulnerabilities']
    filtered_vulnerabilities = []
    for vulnerability in vulnerabilities:
        if 'fixed_in' in vulnerability and vulnerability['fixed_in']:
            if version.parse(vulnerability['fixed_in']) > version.parse(max_version):
                filtered_vulnerabilities.append(vulnerability)
    return filtered_vulnerabilities

def getPluginVersion(plugin_name, domain, port):
    url = f"http://{domain}:{port}/wp-content/plugins/{plugin_name}/readme.txt"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            version_match = re.search(r'Stable tag: (\d+(?:\.\d+)*)', response.text)
            if version_match:
                return version_match.group(1)
        else:
            print(f"Can not access: {plugin_name}")
    except requests.exceptions.RequestException as e:
        print(f"Error {plugin_name}: {e}")
    return None

def wpPluginScan(domain, port):
    destroyCurrentConsole(client)
    
    printRed("WP plugins scan ...")
    module = 'auxiliary/customs/wp_plugin_detect'
    slugs = []
    versions = []
    console_id = client.consoles.console().cid
    command = f"use {module}\nset RHOSTS {domain}\nset RPORT {port}\nset PLUGINSLUGLIST /tmp/plugin.txt\nrun"
    client.consoles.console(console_id).write(command)
    count = 0
    while True:
        time.sleep(3)
        count += 3
        if count == 15:
            break
        result = client.consoles.console(console_id).read()
        if "Auxiliary module execution completed" in result["data"]:
            # print(result["data"])
            if "[+]" in result["data"]:
                regex = r'(\[\+\].*200)'
                matches = re.findall(regex, result["data"])
                for match in matches:
                    slug = match.split(' ')[3]
                    slugs.append(slug)
                    version = getPluginVersion(slug, domain, port)
                    versions.append(version)
            break
    client.consoles.console(console_id).destroy()
    destroyCurrentConsole(client)
    return slugs, versions

def wpAccountEnum(domain, port):
    destroyCurrentConsole(client)
    
    printRed("Account enumerate ...")
    module = 'auxiliary/scanner/http/wordpress_login_enum'
    time.sleep(3)
    console_id = client.consoles.console().cid
    command = f"use {module}\nset RHOSTS {domain}\nset RPORT {port}\nset USER_FILE /tmp/username.txt\nset PASS_FILE /tmp/password.txt\nrun"
    client.consoles.console(console_id).write(command)
    timeout = 0
    users = []
    accounts = {"username": [], "password": []}
    while True:
        time.sleep(3)
        timeout += 3
        if timeout == 15:
            break
        result = client.consoles.console(console_id).read()
        if "Auxiliary module execution completed" in result["data"]:
            # print(result["data"])
            regex1 = r'(\[\+\].*VALID)'
            regex2 = r'(\[\+\].*SUCCESSFUL.*)'
            if "VALID" in result["data"]:
                user_matches = re.findall(regex1, result["data"])
                for match in user_matches:
                    user = match.split("-")[3].split(":")[1].strip()
                    users.append(user)
            if "SUCCESSFUL" in result["data"]:
                account_matches = re.findall(regex2, result["data"])
                for match in account_matches:
                    match = match.split("-")[2].split("for")[1]
                    username = match.split(":")[0].strip()
                    password = match.split(":")[1].strip()
                    accounts["username"].append(username)
                    accounts["password"].append(password)
            break
    client.consoles.console(console_id).destroy()
    destroyCurrentConsole(client)
    # result
    if users != []:
        response = accounts
        result_json = resultJSON(domain, port, module, response, None)
        print(result_json)
    return users, accounts

def getWordpressCVE(version, api_key):
    printRed("Searching Wordpress CVE in version: " + version)
    version = version.replace(".", "")
    url = f"https://wpscan.com/api/v3/wordpresses/{version}"
    headers = {
        "Authorization": f"Token token={api_key}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print("Failed to fetch data:", response.status_code)
        return []

def wordpressScan(domain):
    destroyCurrentConsole(client)
    
    modules = ['auxiliary/scanner/http/robots_txt', 'auxiliary/customs/git_expose', 'auxiliary/customs/admin_expose', 'auxiliary/customs/phpinfo_expose', 'auxiliary/customs/htaccess_expose', 'auxiliary/customs/solr_endpoint']
    # for testing 
    # modules = ['auxiliary/customs/admin_expose']
    vuls = []
    responses = []
    for module in modules:
        time.sleep(3)
        print("================================================================")
        printGreen("Module: " + module)
        print("================================================================")
        console_id = client.consoles.console().cid
        client.consoles.console(console_id).destroy()
        console_id = client.consoles.console().cid
        command = f"use {module}\nset RHOSTS {domain}\nrun"
        client.consoles.console(console_id).write(command)
        while True:
            timeout += 3
            if timeout == 30:
                printRed("Some error occured, please try again!")
                break
            time.sleep(3)
            result = client.consoles.console(console_id).read()
            if "Auxiliary module execution completed" in result["data"]:
                # print(result["data"])
                regex = r'(RHOSTS =>(.*\n)*\[\*] Auxiliary module execution completed)'
                match = re.search(regex, result["data"])
                print(match.group(0))
                if "[+]" in result["data"]:
                    # print(Fore.RED + infor_data[module])
                    regex = r'(===Response start===(.*\n)*===Response end===)'
                    match = re.search(regex, result["data"])
                    # value insert to database if have bug
                    response = match.group(0).split('===')[2]
                    print(Fore.RED + "--------Result--------")
                    print(Fore.RED + "Target: " + target)
                    print(Fore.RED + "Module: " + module)
                    print(Fore.RED + "Response: " + response)
                break
        client.consoles.console(console_id).destroy()
        destroyCurrentConsole(client)

def portScan(domain):
    destroyCurrentConsole(client)
    
    printRed("Port scan ...")
    module = 'auxiliary/scanner/portscan/tcp'
    console_id = client.consoles.console().cid
    command = f"use {module}\nset RHOSTS {domain}\nset PORTS 80,1337\nrun"
    client.consoles.console(console_id).write(command)
    timeout = 0
    open_ports = []
    while True:
        time.sleep(3)
        timeout += 3
        if timeout > 10:
            break
        result = client.consoles.console(console_id).read()
        if "Auxiliary module execution completed" in result["data"]:
            # print(result["data"])
            regex = r'(\[\+\].*)'
            matches = re.findall(regex, result["data"])
            for match in matches:
                port = match.split("-")[1].split(":")[1].strip()
                open_ports.append(port)
            break
    client.consoles.console(console_id).destroy()
    return open_ports

def checkCMS(domain, port):
    printRed("CMS check, domain: %s, port: %s" % (domain, port))
    wp_check, wp_version = wordpressCheck(domain, port)
    if wp_check == True:
        printGreen("Wordpress CMS detected! Version: " + wp_version)
    joomla_check, joomla_version = joomlaCheck(domain, port)
    if joomla_check == True:
        printGreen("Joomla CMS detected!")
    return wp_check, joomla_check, wp_version, joomla_version

def wordpressCheck(domain, port):
    destroyCurrentConsole(client)
    check = False
    module_name = "auxiliary/scanner/http/wordpress_scanner"
    console_id = client.consoles.console().cid
    command = f"use {module_name}\nset RHOSTS {domain}\nset RPORT {port}\nrun"
    client.consoles.console(console_id).write(command)
    timeout = 0
    wp_version = ""
    while timeout < 15:
        timeout += 3
        time.sleep(3)
        result = client.consoles.console(console_id).read()
        if "Auxiliary module execution completed" in result["data"]:
            # print(result["data"])
            if "Detected Wordpress" in result["data"]:
                regex = r'(Detected Wordpress \d+\.\d+(\.\d+)?)'
                match = re.search(regex, result["data"])
                # print(match.group(0))
                wp_version = match.group(0).split("Wordpress")[1].strip()
                check = True
            break
    client.consoles.console(console_id).destroy()
    destroyCurrentConsole(client)
    if check == True:
        return True, wp_version
    else:
        return False, wp_version

def joomlaCheck(domain, port):
    destroyCurrentConsole(client)
    check = False
    module_name = "auxiliary/scanner/http/joomla_version"
    console_id = client.consoles.console().cid
    command = f"use {module_name}\nset RHOSTS {domain}\nset RPORT {port}\nrun"
    client.consoles.console(console_id).write(command)
    timeout = 0
    joomla_version = ""
    while timeout < 10:
        time.sleep(1)
        timeout += 1
        result = client.consoles.console(console_id).read()
        if "Auxiliary module execution completed" in result["data"]:
            # print(result["data"])
            if "Joomla version" in result["data"]:
                regex = r'(Joomla version\: \d+\.\d+(\.\d+)?)'
                match = re.search(regex, result["data"])
                # print(match.group(0))
                joomla_version = match.group(0).split("Joomla")[1].strip()
                check = True
    client.consoles.console(console_id).destroy()
    destroyCurrentConsole(client)
    if check == True:
        return True, joomla_version
    else:
        return False, joomla_version

def destroyCurrentConsole(client):
    consoles = client.consoles.list
    if not consoles:
        return
    current_console = consoles[-1]
    console_id = current_console['id']
    # print(console_id)
    client.consoles.console(console_id).destroy()

# Joomla scan
def joomlaScan(domain, port):
    printRed("Joomla information disclosure vulnerabilities scan ...")
    destroyCurrentConsole(client)
    joomla_auxiliary_modules = ['auxiliary/scanner/http/joomla_gallerywd_sqli_scanner','auxiliary/admin/http/joomla_registration_privesc','auxiliary/scanner/http/joomla_pages','auxiliary/gather/joomla_com_realestatemanager_sqli','auxiliary/gather/joomla_contenthistory_sqli','auxiliary/gather/joomla_weblinks_sqli','auxiliary/scanner/http/joomla_ecommercewd_sqli_scanner']
    for joomla_module in joomla_auxiliary_modules:
        printRed("[*] Module: " + joomla_module)
        console_id = client.consoles.console().cid
        command = f"use {joomla_module}\nset RHOSTS {domain}\nSET RPORT {port}\nrun"
        client.consoles.console(console_id).write(command)
        count = 0
        while True:
            time.sleep(3)
            count += 3
            if count == 15:
                break
            result = client.consoles.console(console_id).read()
            if "Auxiliary module execution completed" in result["data"]:
                regex = r'(\[\+\].*)'
                matches = re.findall(regex, result["data"])
                for match in matches:
                    print("Result: " + match)
                break
        client.consoles.console(console_id).destroy()
        destroyCurrentConsole(client)

# result in json
def resultJSON(domain, port, module, response, target):
    url = "http://" + domain + ":" + port
    result = {
    "url": url,
    "module_name": module,
    "reponse": response,
    "target": target
    }
    return result

# getResponse
def getResponse(domain, port, endpoint):
    response = requests.get(url = "http://" + domain + ":" + port + endpoint)
    # response_data = {
    #     'status_code': response.status_code,
    #     'headers': dict(response.headers),
    #     'body': response.text
    # }
    response_data = "Status code: " + str(response.status_code) + "\n"
    for key, value in response.headers.items():
        response_data += " " + key + ": " + value + "\n"
    response_data += str(response.text)
    return response_data
