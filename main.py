from pymetasploit3.msfrpc import MsfRpcClient
from package.arguments import *
from package.functions import *

if args.search:
    search_keyword = args.search
    search_module(search_keyword)

if args.infor:
    module_name = {}
    parts = args.infor.split('/', 1)
    module_name['type'] = parts[0]
    module_name['module_name'] = parts[1]
    infor_module(module_name)

if args.portscan:
    port_scan()

if args.d2ip:
    domain = args.d2ip
    print(ip_from_domain(domain))

def main():
    domain = "172.22.31.104"

    # Auto all
    # autoAll(domain)

    ############ dành cho kiểm thử ############
    #
    # Function 1: Port scan
    # funcScanPort(domain)
    #
    # Function 2: CMS check
    # port = "1337"
    # funcCheckCMS(domain, port)
    #
    # Function 3: Information disclosure check
    port = "1337"
    funcWPInforDisScan(domain, port)
    #
    # Function 4: Brute force WP account
    # port = "1337"
    # funcWPAccountEnum(domain, port)
    #
    # Function 5: Plugin version check
    # port = "1337"
    # funcWPPluginScan(domain, port)
    #
    # Function 6: Get WP CVE
    # wp_version = "4.6"
    # CVE_wp = getWordpressCVE(wp_version, api_key)
    # print(CVE_wp)
    #
    # Function 7: Get WordPress plugin CVE
    # slug = "contact-form-7"
    # version = "4.3"
    # plugin_vulnerabilities = getPluginCVE(slug, api_key)
    # plugin_filtered_vulnerabilities = filterVulnerabilities(plugin_vulnerabilities, version)
    # print(plugin_filtered_vulnerabilities)
    #
    # Function 8: WP login
    # log, pwd = "admin", "admin"
    # port = "1337"
    # cookie = wpLogin(log, pwd, domain, port)
    # print(cookie)
    # 
    # Function 9: getActivePlugins (admin)
    # log, pwd = "admin", "admin"
    # port = "1337"
    # cookie = wpLogin(log, pwd, domain, port)
    # plugins, versions = getActivePlugins(cookie, domain, port)
    # 
    # Function 10: WP admin plugin scan
    # wp_username, wp_password = "admin", "admin"
    # port = "1337"
    # wpPluginAdminScan(domain, wp_username, wp_password, port)
    #############################################


main()