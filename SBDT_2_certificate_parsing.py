#!/usr/bin/env python3
#encoding: utf-8

# Copyright@SecuritySoftware Team(Chu Chen etc. github.com/secsoftware)
# If your project uses or refer to our code, please cite as follows. Thank you!
"""
Chu Chen, Pinghong Ren, Zhenhua Duan, Cong Tian, Xu Lu, and Bin Yu. 2023. 
SBDT: Search-Based Differential Testing of Certificate Parsers in SSL/TLS Implementations. 
In Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA ’23), July
17–21, 2023, Seattle, WA, USA. ACM, New York, NY, USA, 13 pages. 
https://doi.org/10.1145/3597926.3598110
""" 

import os
import sys
import subprocess
import time

abs_path = os.getcwd()
sys.path.append(abs_path)

dir_certs = "../certs/"    
dir_cp_tmp = "../cp_tmp/"  
dir_cp_tmp_openssl = dir_cp_tmp + "OpenSSL/"  
dir_cp_tmp_zcertificate = dir_cp_tmp + "ZCertificate/"
dir_cp_tmp_gnutls = dir_cp_tmp + "GnuTLS/"
dir_cp_uniform = "../cp_uniform/"  
dir_cp_uniform_openssl = dir_cp_uniform + "OpenSSL/" 
dir_cp_uniform_zcertificate = dir_cp_uniform + "ZCertificate/"
dir_cp_uniform_gnutls= dir_cp_uniform + "GnuTLS/"
dir_result = "../result/" 


def does_dir_exist(target):
    """ To judge whether a target file/folder exists.
    @param target: A target file or folder;
    @return: Notification of absence of the target file/folder.
    """
    if not os.path.exists(target):
        print("The folder/file "+target+" does not exist!")
        exit()


def create_dir(target):
    """ To create/initialize the target folder.
    @param target: A target folder;
    @return: NA. 
    """
    if os.path.exists(target):
        ret = os.system("rm -rf "+target+"*")
    if not os.path.exists(target):
        os.makedirs(target)


def operate_dirs():
    """ To judge whether desired folders exist. If not, create them; otherwise, clean them.
    @return: Empty directories.
    """
    does_dir_exist(dir_certs)
    create_dir(dir_cp_tmp)
    create_dir(dir_cp_tmp_openssl)
    create_dir(dir_cp_tmp_zcertificate)
    create_dir(dir_cp_tmp_gnutls)
    create_dir(dir_cp_uniform)
    create_dir(dir_cp_uniform_openssl)
    create_dir(dir_cp_uniform_zcertificate)
    create_dir(dir_cp_uniform_gnutls)
    create_dir(dir_result)


def OpenSSL_parse_certs():
    """ To call OpenSSL to parse certs and get readable contents. Attention: some certs may be not loadable.
    @return: Parsed results or information.
    """
    cannot_parse = dir_cp_tmp_openssl + "cannot_parsed_by_openssl.txt"
    cert_list = os.listdir(dir_certs)
    cert_list.sort()
    fhw = open(cannot_parse, 'w')    
    fhw.close()
    for cert in cert_list:
        return_value = os.system("openssl x509 -in "+dir_certs+cert+" -noout -text 1> "+dir_cp_tmp_openssl+os.path.splitext(cert)[0]+".openssl"+" 2>&1")
        if return_value:
            with open(cannot_parse, 'a') as fhw:
                fhw.write(os.path.splitext(cert)[0]+'\n')


def ZCertificate_parse_certs():
    """ To call ZCertificate to parse certs and get readable contents.
    @return: Parsed results or information.
    """
    path_to_zcert = "../go/bin/zcertificate"
    cannot_parse = dir_cp_tmp_zcertificate + "cannot_parsed_by_zcertificate.txt"
    cert_list = os.listdir(dir_certs)
    cert_list.sort()
    fhw = open(cannot_parse, 'w')    
    fhw.close()
    for cert_no, cert in enumerate(cert_list):
        path_to_cert = dir_cp_tmp_zcertificate+os.path.splitext(cert)[0]+".zcertificate"
        sp_cmd = [path_to_zcert, dir_certs+cert, "|", "jq"]
        sp = subprocess.Popen(sp_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sp.communicate()
        if not stdout:
            with open(cannot_parse, 'a') as fhw:
                fhw.write(os.path.splitext(cert)[0]+'\n')
            with open(path_to_cert, 'w') as fhw:
                fhw.write(str(stderr))
        else:
            os.system(path_to_zcert+' '+dir_certs+cert+" 1> "+path_to_cert+" 2>null")


def GnuTLS_parse_certs():
    """ To call GnuTLS to parse certs and get readable contents.
    @return: Parsed results or information.
    """
    cannot_parse = dir_cp_tmp_gnutls + "cannot_parsed_by_gnutls.txt"
    cert_list = os.listdir(dir_certs)
    cert_list.sort()
    fhw = open(cannot_parse, 'w')    
    fhw.close()
    for cert in cert_list:
        return_value = os.system("certtool -i --infile "+dir_certs+cert+" 1> "+dir_cp_tmp_gnutls+os.path.splitext(cert)[0]+".gnutls"+" 2>&1")
        if return_value:
            with open(cannot_parse, 'a') as fhw:
                fhw.write(os.path.splitext(cert)[0]+'\n')


def SBDT_certificate_parsing_main():
    """ To call OpenSSL_parse_certs(), ZCertificate_parse_certs(), and
    GnuTLS_parse_certs(). 
    """
    begin_time = time.time()
    operate_dirs()
    OpenSSL_parse_certs()
    ZCertificate_parse_certs()
    GnuTLS_parse_certs()
    end_time = time.time()
    print("SBDT_2_certificate_parsing succeeds!".center(60, '*'))
    print(("Time elapsed: "+str(end_time-begin_time)+" seconds.").center(60, '*'))

if __name__ == "__main__":
    SBDT_certificate_parsing_main()
    