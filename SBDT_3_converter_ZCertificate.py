#!/usr/bin/env python3
#encoding:utf-8

# Copyright@SecuritySoftware Team(Chu Chen etc. github.com/secsoftware)
# If your project uses our code, please cite as follows. Thank you!
"""
Chu Chen, Pinghong Ren, Zhenhua Duan, Cong Tian, Xu Lu, and Bin Yu. 2023. 
SBDT: Search-Based Differential Testing of Certificate Parsers in SSL/TLS Implementations. 
In Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA ’23), July
17–21, 2023, Seattle, WA, USA. ACM, New York, NY, USA, 13 pages. 
https://doi.org/10.1145/3597926.3598110
""" 

import os
import time
import sys
abs_path = os.getcwd()
sys.path.append(abs_path) 

import re
import json

# -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
dir_cp_tmp_zcertificate = "../cp_tmp/ZCertificate/"
dir_cp_uniform_zcertificate = "../cp_uniform/ZCertificate/"
# -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
debug_mode = 1 


def get_ready_zcert():
    file_list = os.listdir(dir_cp_tmp_zcertificate)
    file_list.remove("cannot_parsed_by_zcertificate.txt")
    file_list.sort()
    file_list_cannot_parsed_by_zcertificate = []
    with open(dir_cp_tmp_zcertificate+"cannot_parsed_by_zcertificate.txt") as fhr:
        for f in fhr.readlines():
            file_list_cannot_parsed_by_zcertificate.append(os.path.splitext(f)[0].replace('\n', '')+".zcertificate")
    parsable_file_list = list(set(file_list)-set(file_list_cannot_parsed_by_zcertificate))
    parsable_file_list.sort()
    return(parsable_file_list)


def SBDT_converter_ZCertificate_main():
    """ To convert results parsed by ZCertificate to a uniform format.
    @param None: None;
    @return: A uniform format.
    """
    begin_time = time.time()
    
    parsable_file_list = get_ready_zcert()
    
    for ff in parsable_file_list:
        path_file = dir_cp_tmp_zcertificate + ff
        with open(path_file) as fhr:
            file_content = fhr.read()
            raw_parsed_zlint_dict = json.loads(file_content)
            parsed_dict = raw_parsed_zlint_dict['parsed']

            secondary_treatment_or_duplicate_fields = ["issuer", 
                                                       "subject", 
                                                       "fingerprint_md5", 
                                                       "fingerprint_sha1",
                                                       "fingerprint_sha256", 
                                                       "tbs_noct_fingerprint", 
                                                       "spki_subject_fingerprint", 
                                                       "tbs_fingerprint", 
                                                       "validation_level", 
                                                       "redacted"]
            truncated_parsed_dict = {}
            for k in parsed_dict.keys():
                if not k in secondary_treatment_or_duplicate_fields:
                    if k in ["issuer_dn", "subject_dn"]:
                        reserved_k = re.split("_", k)[0] 
                        parsed_dict[k] = parsed_dict[k].split(', ')
                        parsed_dict[k].sort()
                        parsed_dict[k] = ','.join(parsed_dict[k])
                    elif re.sub("_", '', k):  
                        reserved_k = re.sub("_", ' ', k)
                        if reserved_k == "subject key info":
                            reserved_k = "subject public key info"
                        if reserved_k == "extensions":
                            reserved_k = "X509v3 extensions"
                        if reserved_k == "serial number":
                            parsed_dict[k] = int(parsed_dict[k])
                    else:
                        pass
                    truncated_parsed_dict[reserved_k] = parsed_dict[k]
            uniform_dict = {}
            tbsCertificate_dict = {}
            sig_name_dict = {}
            sig_value_dict = {}
            for t in truncated_parsed_dict:
                if t in ["version", "serial number"]:
                    tbsCertificate_dict[t] = truncated_parsed_dict[t]
                elif t in ["subject", "issuer"]:
                    tbsCertificate_dict[t] = truncated_parsed_dict[t]
                elif t == "signature algorithm":
                    tbsCertificate_dict[t] = truncated_parsed_dict[t]["name"]
                elif t == "validity":
                    tbsCertificate_dict[t] = truncated_parsed_dict[t]["start"] + '-' + truncated_parsed_dict[t]["end"]
                elif t == "subject public key info":
                    public_key_name = truncated_parsed_dict[t]["key_algorithm"]["name"]
                    if public_key_name.casefold() == "RSA".casefold():
                        tbsCertificate_dict[t] = {"public key algorithm":public_key_name, 
                                                  "length":truncated_parsed_dict[t]["rsa_public_key"]["length"], 
                                                  "modulus":truncated_parsed_dict[t]["rsa_public_key"]["modulus"], 
                                                  "exponent":truncated_parsed_dict[t]["rsa_public_key"]["exponent"]}
                    else:
                        tbsCertificate_dict[t] = {"public key algorithm":public_key_name}
                        for sub_key in truncated_parsed_dict[t]:
                            if sub_key != "key_algorithm" and not sub_key.startswith("fingerprint"):
                                if truncated_parsed_dict[t][sub_key].keys():
                                    for sub_sub_key in truncated_parsed_dict[t][sub_key].keys():
                                        tbsCertificate_dict[t][sub_sub_key] = truncated_parsed_dict[t][sub_key][sub_sub_key]
                                else:
                                    tbsCertificate_dict[t][sub_key] = truncated_parsed_dict[t][sub_key]
                elif t == "X509v3 extensions":
                    x509v3_ext = []  
                    for k, v in truncated_parsed_dict[t].items():
                        ext_name = ''
                        ext_critical = ''
                        ext_value = []
                        k_tmp = re.sub('_', ' ', k)

                        if k_tmp == "authority key id":
                            ext_name = "authority key identifier"
                            value_part = truncated_parsed_dict[t][k]
                            if isinstance(value_part, dict):
                                for kk, vv in value_part:
                                    if kk == "critical": 
                                        if vv == True: 
                                            ext_value.append("critical")
                                        else:
                                            ext_value.append('') 
                                    else:
                                        ext_value.append({kk:vv})
                            elif isinstance(value_part, list):
                                for ll in value_part:
                                    ext_value.append(ll)
                            else:
                                ext_value = value_part

                        elif k_tmp == "subject key id":
                            ext_name = "subject key identifier"
                            value_part = truncated_parsed_dict[t][k]
                            if isinstance(value_part, dict):
                                for kk, vv in value_part:
                                    if kk == "critical":
                                        if vv == True: 
                                            ext_value.append("critical")
                                        else:
                                            ext_value.append('')
                                    else:
                                        ext_value.append({kk:vv})
                            elif isinstance(value_part, list):
                                for ll in value_part:
                                    ext_value.append(ll)
                            else:
                                ext_value = value_part

                        elif k_tmp == "key usage": 
                            ext_name = k_tmp
                            if "is_critical" in truncated_parsed_dict[t][k].keys():
                                if truncated_parsed_dict[t][k]["is_critical"] == True: 
                                    ext_value.append('critical')
                                else:
                                    ext_value.append('')
                            else:
                                ext_value.append('')
                            for f, v in truncated_parsed_dict[t][k].items():
                                if f != "value" and f != "is_critical":  
                                    
                                    if f == "content_commitment":
                                        ext_value.append("non repudiation")
                                    else:
                                        ext_value.append(re.sub('_', ' ', f)) 

                        elif k_tmp == "certificate policies": 
                            ext_name = k_tmp
                            ext_value = []
                            ext_value.insert(0, '')
                            for policy in truncated_parsed_dict[t][k]: 
                                policy_key = "Policy"
                                policy_value = [] 

                                policy_id_or_name = ''
                                cps_list = [] 
                                user_notice_list = [] 

                                for f, v in policy.items(): 
                                    user_notice = {}
                                    if f == "critical": 
                                        if v == True: 
                                            ext_value[0] = "critical"
                                        else:
                                            pass
                                    elif f == "id":
                                        policy_id_or_name = v
                                    elif f == "cps":
                                        cps_list.extend(v) 
                                    elif f == "user_notice":
                                        for un in v: 
                                            for explicit_text_and_notice_reference, et_nf_value in un.items():
                                                if explicit_text_and_notice_reference == "explicit_text":
                                                    user_notice["Explicit text"] = et_nf_value
                                                if explicit_text_and_notice_reference == "notice_reference":
                                                    for notice_reference in et_nf_value:
                                                        for nr_key, nr_value in notice_reference.items():
                                                            if nr_key == "organization":
                                                                user_notice[nr_key] = nr_value
                                                            elif nr_key == "notice_numbers":
                                                                if isinstance(nr_value, list):
                                                                    nr_value_str = [str(nrv) for nrv in nr_value]
                                                                    user_notice[nr_key] = ','.join(nr_value_str)
                                                                else:
                                                                    user_notice[nr_key] = nr_value
                                        user_notice_list.append({"User Notice":user_notice})
                                if not (cps_list or user_notice_list): 
                                    policy_value.append(policy_id_or_name)
                                else:
                                    policy_value.append(policy_id_or_name)
                                    if cps_list:
                                        for c in cps_list:
                                            policy_value.append({"CPS":c})
                                    if user_notice_list:
                                        for u in user_notice_list:
                                            policy_value.append(u)
                                ext_value.append({"Policy":policy_value})

                        elif k_tmp == "policy mappings":
                            ext_name = k_tmp
                            pass

                        elif k_tmp == "subject alt name":
                            ext_name = "subject alternative name"
                            for f, v in truncated_parsed_dict[t][k].items():
                                if f == "directory_names":
                                    ext_value.append({"DirName":v})
                                elif f == "email_addresses":
                                    ext_value.append({"email":v})
                                elif f == "dns_names":
                                    ext_value.append({"DNS":v})
                                elif f == "uniform_resource_identifiers":
                                    ext_value.append({"URI":v})
                                elif f == "ip_address":
                                    ext_value.append({"IP Address":v})    
                                else:
                                    ext_value.append({f:v})

                        elif k_tmp == "issuer alt name":
                            ext_name = "issuer alternative name"
                            for f, v in truncated_parsed_dict[t][k].items():
                                if f == "directory_names":
                                    ext_value.append({"DirName":v})
                                elif f == "email_addresses":
                                    ext_value.append({"email":v})
                                elif f == "dns_names":
                                    ext_value.append({"DNS":v})
                                elif f == "uniform_resource_identifiers":
                                    ext_value.append({"URI":v})
                                elif f == "ip_address":
                                    ext_value.append({"IP Address":v})    
                                else:
                                    ext_value.append({f:v})

                        elif k_tmp == "subject directory attributes":
                            ext_name = k_tmp
                            pass

                        elif k_tmp == "basic constraints":
                            ext_name = k_tmp
                            for f, v in truncated_parsed_dict[t][k].items():
                                if f == "is_ca":
                                    if v == True:
                                        ext_value.append({"CA":"TRUE"})
                                    else:
                                        ext_value.append('')
                                elif f == "max_path_len":
                                    ext_value.append({"pathlen":v})
                                else:
                                    ext_value.append({f:v})

                        elif k_tmp == "name constraints":
                            ext_name = k_tmp
                            permitted = {}
                            excluded = {}
                            for f, v in truncated_parsed_dict[t][k].items():
                                if f == "critical":
                                    if v == True:
                                        ext_value.append("critical")
                                    else:
                                        ext_value.append('')
                                elif f == "permitted_names":
                                    permitted.update({"DNS":v})
                                elif f == "permitted_email_addresses":
                                    permitted.update({"email":v})
                                elif f == "permitted_ip_addresses":
                                    permitted.update({"IP":v})        
                                elif f == "excluded_names":
                                    excluded.update({"DNS":v})
                                elif f == "excluded_email_addresses":
                                    excluded.update({"email":v})
                                elif f == "excluded_ip_addresses":
                                    excluded.update({"IP":v})    
                                else:
                                    ext_value.append({f:v})
                            ext_value.append(permitted)
                            ext_value.append(excluded)        

                        elif k_tmp == "policy constraints":
                            ext_name = k_tmp
                            pass

                        elif k_tmp == "extended key usage":
                            ext_name = k_tmp
                            for f, v in truncated_parsed_dict[t][k].items():
                                if f == "unknown":
                                    if isinstance(v, list):
                                        ext_value.extend(v)
                                    else:
                                        ext_value.append(v)
                                elif f == "server_auth":
                                    ext_value.append("TLS Web Server Authentication")
                                elif f == "client_auth":
                                    ext_value.append("TLS Web Client Authentication")
                                elif f == "email_protection":
                                    ext_value.append("E-mail Protection")           
                                elif v == True:
                                    ext_value.append(re.sub('_', ' ', f))
                                else:
                                    pass

                        elif k_tmp == "crl distribution points":
                            ext_name = k_tmp
                            ext_value = truncated_parsed_dict[t][k]

                        elif k_tmp == "inhibit anyPolicy":
                            ext_name = k_tmp
                            pass

                        elif k_tmp == "freshest crl":
                            ext_name = k_tmp
                            ext_value = truncated_parsed_dict[t][k]
                            pass

                        elif k_tmp == "authority info access":
                            ext_name = "authority information access"
                            value_part = truncated_parsed_dict[t][k]
                            for kk, vv in value_part.items():
                                if kk == "ocsp_urls":
                                    ext_value.append({"OCSP - URI":vv})
                                elif kk == "issuer_urls":
                                    ext_value.append({"CA Issuers - URI":vv})
                                else:
                                    ext_value.append({kk:vv})

                        elif k_tmp == "subject info access":
                            ext_name = "subject information access"
                            value_part = truncated_parsed_dict[t][k]
                            for kk, vv in value_part.items():
                                if kk == "ocsp_urls":
                                    ext_value.append({"OCSP - URI":vv})
                                elif kk == "issuer_urls":
                                    ext_value.append({"CA Issuers - URI":vv})
                                else:
                                    ext_value.append({kk:vv})

                        elif k_tmp == "Netscape Cert Type":
                            ext_name = "Netscape Cert Type"
                            value_part = truncated_parsed_dict[t][k]
                            for kk, vv in value_part.items():
                                ext_value.append({kk:vv})
                                pass

                        else:
                            pass

                        if not ext_name.lower() in ["authority information access", "subject information access", "netscape cert type", "netscape comment"]:
                            ext_name = "X509v3 " + ext_name
                        x509v3_ext.append({ext_name:ext_value})
                        tbsCertificate_dict.update({"X509v3 extensions":x509v3_ext})
                    pass

                elif t == "unknown extensions": 
                    if not "X509v3 extensions" in tbsCertificate_dict.keys():
                        tbsCertificate_dict["X509v3 extensions"] = []
                    for u_ext in truncated_parsed_dict[t]:
                        ext_id = ''
                        ext_critical = ''
                        ext_value = []
                        for k, v in u_ext.items():
                            if k == "id":
                                ext_id = v
                            elif k.lower() == "critical":
                                if v == False:
                                    ext_critical = ''
                                else:
                                    ext_critical = "critical"
                                ext_value.append(ext_critical)
                            else:
                                ext_value.append({k:v})
                        tbsCertificate_dict["X509v3 extensions"].append({ext_id:ext_value})

                elif t == "signature":
                    hash_encrypt = truncated_parsed_dict[t]["signature_algorithm"]["name"]
                    value = truncated_parsed_dict[t]["value"]
                    sig_name_dict["signature algorithm"] = hash_encrypt
                    sig_value_dict["signature value"] = value
                else:
                    pass

            uniform_dict["tbsCertificate"] = tbsCertificate_dict
            uniform_dict.update(sig_name_dict)
            uniform_dict.update(sig_value_dict)


            def set_default(obj):
                if isinstance(obj, set):
                    return(list(obj))
                raise TypeError


            json_str = json.dumps(uniform_dict, default=set_default)
            with open(dir_cp_uniform_zcertificate+ff, 'w') as fhw:
                fhw.write(json_str)
    end_time = time.time()
    print("SBDT_3_converter_ZCertificate succeeds!".center(60, '*'))
    print(("Time elapsed: "+str(end_time-begin_time)+" seconds.").center(60, '*'))


def read_zcert(cert_dir, cert_list):
    """ To read dicts parsed by Zcertificate
    @param cert_dir: A directory storing certs;
    @param cert_list: A cert list;
    @return: JSON.
    """
    for p in cert_list:
        path_p = cert_dir + p
        with open(path_p) as fhr:
            cert_content = fhr.read()
        zcert_str = json.loads(cert_content)["parsed"]
        print(json.dumps(zcert_str, indent=2))


if __name__ == "__main__":
    SBDT_converter_ZCertificate_main()
