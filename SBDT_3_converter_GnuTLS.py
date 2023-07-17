#!/usr/bin/env python3
#encoding:utf-8

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
import time
import re
import json
import sys
abs_path = os.getcwd()
sys.path.append(abs_path)   

# -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
tlsimpl = "GnuTLS"
dir_cp_tmp_tlsimpl = "../cp_tmp/" + tlsimpl + "/"
dir_cp_uniform_tlsimpl = "../cp_uniform/" + tlsimpl + "/"
cannot_parsed_by_tlsimpl = "cannot_parsed_by_" + tlsimpl.lower() + ".txt"
# -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ontology = {"certificate signing":"certficate sign", 
            "crl signing":"crl sign", 
            "key encipher only":"encipher only", 
            "key decipher only":"decipher only", 
            "tls www server":"tls web server authentication",
            "tls www client":"tls web client authentication",
            "dnsname":"dns",
            "ipaddress":"ip address",
            "ip_addresses":"ip addresses", 
            "key purpose":"extended key usage"}


def obtain_parsable_cert_list(tlsimpl):
    """ To obtain parsable certificate file list.
    @param tlsimpl: The TLS Implementation;
    @return: A list of parsable file. 
    """
    file_list = os.listdir(dir_cp_tmp_tlsimpl)
    if file_list.count(cannot_parsed_by_tlsimpl) > 0:
        file_list.remove(cannot_parsed_by_tlsimpl)
    file_list.sort()
    file_list_cannot_parsed_by_tlsimpl = []
    with open(dir_cp_tmp_tlsimpl+cannot_parsed_by_tlsimpl) as fhr:
        for f in fhr.readlines():
            file_list_cannot_parsed_by_tlsimpl.append(os.path.splitext(f)[0].replace('\n', '')+'.'+tlsimpl.lower())
    parsable_file_list = list(set(file_list)-set(file_list_cannot_parsed_by_tlsimpl))
    parsable_file_list.sort()
    return(parsable_file_list)


def obtain_cert_info(cert_file):
    """ To obtain cert info.
    @param cert_file: The cert file to be obtained info;
    @return: Cert info or error info.
    """
    path_to_cert_file = dir_cp_tmp_tlsimpl + cert_file
    with open(path_to_cert_file, 'r') as fhr:
        cert_content = fhr.read()
        re_split_list = re.split("Other Information:", cert_content)
        if re_split_list: 
            cert_info =re_split_list[0]
            return(cert_info)
        else:
            print("There is no \"Other Information\"!")
            return("error")


def obtain_cert_fields(cert_info):
    """ To obtain fields.
    @param cert_info: The cert info;
    @return: The fields. 
    """
    p = r"\n\t(?!\t+)"
    cert_field_list = re.split(p, cert_info)
    return(cert_field_list[1:])


def convert_validity(not_x): 
    """ To convert not_x to a standard form.
    @param not_x: Not Before or Not After ;
    @return: The standard form of not_x.
    """

    p = r"\w+ *(\w+) *(\d+) *(\d{2}:\d{2}:\d{2}.*?) *(\w+) *(\d{4}) *"
    mo_not_x = re.search(p, not_x) 

    not_x = []
    for i in range(1, 6):
        not_x.append(mo_not_x.group(i))
    if len(not_x[1]) == 1:  
        day = '0' + str(not_x[1])
    else:
        day = str(not_x[1])

    months_list = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    if not_x[0][:3] in months_list:
        i = months_list.index(not_x[0]) + 1
        i = str(i)
        if len(i) < 2:
            i = '0' + i
    else:
        i = not_x[0]
    not_x_uniform = not_x[4] + '-' + i + '-' + day + 'T' + not_x[2] + not_x[3]

    return(not_x_uniform)


def reassemble_version(field):
    """ To reassemble the version.
    @param field: The version field;
    @return: The version dict.
    """
    version_value = re.search(r"Version: (\d+)", field).group(1).replace('\n', '')
    if version_value:
        return({"version":int(version_value)})
    else:
        return "ERROR"


def reassemble_serialnumber(field):
    """ To reassemble the serial number.
    @param field: The serial number field;
    @return: The serial number dict.
    """
    version_value = re.search(r"Serial Number \(hex\): *(\w+)", field).group(1).replace('\n', '')
    return({"serial number":int(version_value,16)})


def reassemble_tbssignature(field):
    """ To reassemble tbsCert.Signature.
    @param field: The tbsCert.Signature field;
    @return: The tbsCert.Signature dict.
    """ 
    # GnuTLS does not have this field
    pass


def reassemble_issuer(field):
    """ To reassemble issuer.
    @param field: The issuer field;
    @return: The issuer dict.
    """
    issuer_split = re.split(r"Issuer: ", field)
    if len(issuer_split) > 1: # two lines
        issuer = issuer_split[1].replace('\n', '')
        issuer = issuer.split(',')
        issuer.sort()
        issuer = ','.join(issuer)
        return({"issuer":issuer})
    else:
        return({"issuer":None})
    
    
def reassemble_validity(field):
    """ To reassemble validity.
    @param field: The validity field;
    @return: The validity dict.
    """
    not_x_list = re.split(r"\n\t{2,}", field)
    if len(not_x_list) == 3:
        not_before = re.split("Not Before: ", not_x_list[1])[1].replace('\n', '')
        not_after = re.split("Not After: ", not_x_list[2])[1].replace('\n', '')
        return({"validity":convert_validity(not_before)+'-'+convert_validity(not_after)})
    else:
        return("ERROR")


def reassemble_issueruid(field):
    """ To reassemble issuerUID.
    @param field: The issuerUID field;
    @return: The issuerUID dict.
    """
    issueruid = re.split(r"Issuer Unique Identifier: ", field)[1].replace('\n', '')
    return({"issuer unique identifier":issueruid})


def reassemble_subject(field):
    """ To reassemble subject.
    @param field: The subject field;
    @return: The subject dict.
    """
    subject_split = re.split(r"Subject: ", field)
    if len(subject_split) > 1:
        subject = subject_split[1].replace('\n', '')
        subject = subject.split(',')
        subject.sort()
        subject = ','.join(subject)
        return({"subject":subject})
    else:
        return({"subject":None})


def reassemble_subjectuid(field):
    """ To reassemble subjectUID.
    @param field: The subjectUID field;
    @return: The subjectUID dict.
    """
    subjectuid = re.split(r"Subject Unique Identifier: ", field)[1].replace('\n', '')
    return({"subject unique identifier":subjectuid})


def reassemble_subject_public_key_info(field):
    """ To reassemble subjectPublicKeyInfo.
    @param field: The subjectPublicKeyInfo field;
    @return: The subjectPublicKeyInfo dict.
    """
    if field.startswith("Subject Public Key Algorithm:"):
        algorithm = re.split("Subject Public Key Algorithm: ", field)[1].replace('\n', '')
        return({"subject public key info":{"public key algorithm":algorithm}})
    elif field.startswith("Algorithm Security Level: "):
        bit_modulus_exponent = re.split(r"\n\t{2}(?!\t)", field)
        algo_info_list = []
        for bme in bit_modulus_exponent:
            algo_info_list.append(re.sub("\n\t{3,}", ':', bme).replace('\t', ':'))
        algo_info_dict = {}
        for ai in algo_info_list: # ai: algo_info
            if ai.startswith("Algorithm Security Level: "):
                bit = re.search(r"Algorithm Security Level: \w+? \((\d+) bits\)", ai).group(1)
                algo_info_dict['length'] = int(bit)
            elif ai.startswith("Modulus "):
                modulus_bit = re.search("Modulus \(bits (\d+)\)", ai).group(1)
                if bit != modulus_bit:
                    print("ERROR! The bits are not identical!")
                modulus = int(re.split("Modulus \(bits \d+\)::", ai)[1].replace(':', ''), 16)
                algo_info_dict['modulus'] = modulus
            elif ai.startswith("Exponent "):
                exponent_bit = re.search("Exponent \(bits (\d+)\)", ai).group(1)
                exponent = int(re.split("Exponent \(bits \d+\)::", ai)[1].replace(':', ''), 16)
                algo_info_dict['exponent'] = exponent
            else:
                k, v = re.split("::", ai)
                if v.count(':') > 1:
                    v = int(v.replace(':', ''), 16)
                algo_info_dict[k] = v
        return(algo_info_dict)


def reassemble_ext(field):
    """ To reassemble ext.
    @param field: The ext field;
    @return: The ext dict.
    """
    exts = []
    exts_dict = {"X509v3 extensions":exts}
    ext_list = re.split("\n\t{2}(?!\t)", field)[1:]
    for ext in ext_list:
        current_ext_dict = {}
        current_ext_dict_v = []
        sub_ext_list = re.split("\n\t{3}(?!\t)|\.\n\t{3}(?!\t)", ext)
        
        if sub_ext_list[-1][-1] == ".":
            sub_ext_list[-1] = sub_ext_list[-1][:-1]
        for i, sub_ext in enumerate(sub_ext_list):
            sub_ext_lower = sub_ext.lower()
            if sub_ext_lower in ontology.keys():
                sub_ext_list[i] = ontology[sub_ext_lower]
            if sub_ext_list[i].startswith("IPAddress"):
                sub_ext_list[i] = sub_ext_list[i].replace("IPAddress", "IP Address")
        
        if sub_ext_list[0].startswith("Inhibit anyPolicy skip certs") > 0:
            e_v_c = re.search(r"((.+ *)+:) (\d+) \((.+ *)+\)", sub_ext_list[0])
            if e_v_c:
                ext_name = "X509v3 inhibit any policy"
                ext_critical = e_v_c.group(4)
                if ext_critical == "not critical":
                    ext_critical = ''
                current_ext_dict_v.append(ext_critical)
                current_ext_dict_v.append(e_v_c.group(3))
                current_ext_dict[ext_name] = current_ext_dict_v
                exts.append(current_ext_dict)
            continue
        
        if sub_ext_list[0].find("Key Usage Period") > 0:
            e_v_c = re.search(r"(.+) \((.+)\)", sub_ext_list[0])
            kup_not_before = convert_validity(re.search(r"Not .+: (.*)", sub_ext_list[1]).group(1))
            kup_not_after = convert_validity(re.search(r"Not .+: (.*)", sub_ext_list[2]).group(1))
            ext_name = "X509v3 " + e_v_c.group(1).lower()
            ext_critical = e_v_c.group(2)
            if ext_critical == "not critical":
                ext_critical = ''
            current_ext_dict_v.append(ext_critical)
            current_ext_dict_v.append(kup_not_before+'-'+kup_not_after)
            current_ext_dict[ext_name] = current_ext_dict_v
            exts.append(current_ext_dict)
            continue
        
        mo_extname_critical = re.search("((.+? *)+) \(((.+? *)+)\):", sub_ext_list[0])
        if mo_extname_critical:
            ext_name = mo_extname_critical.group(1).lower()
            ext_name_lower = ext_name.lower()
            if ext_name_lower in ontology.keys():
                ext_name = ontology[ext_name_lower]
            ext_name = "X509v3 " + ext_name
            if ext_name.lower() in ["x509v3 authority information access", "x509v3 subject information access"]:
                ext_name = ext_name.replace("X509v3 ", '')
            ext_name = ext_name.replace("X509v3 unknown extension ", '')
            
            ext_critical = mo_extname_critical.group(3)
            if ext_critical == "critical":
                ext_critical = 'critical'
            elif ext_critical == "not critical":
                ext_critical = ''
            
            current_ext_dict[ext_name] = current_ext_dict_v
            current_ext_dict_v.append(ext_critical)
        else:
            print(mo_extname_critical)

        for sub_ext in sub_ext_list[1:]:
            sub_sub_ext_list = re.split("\n\t{4}(?!\t)", sub_ext)
            
            if len(sub_sub_ext_list) > 1:
                sub_sub_ext_dict = {}
                sub_sub_ext_dict_v_list = []
                for sse_i, sub_sub_ext in enumerate(sub_sub_ext_list[1:]):
                    sub_sub_ext_split = re.split(": ", sub_sub_ext)
                    sub_sub_ext_name_lower = sub_sub_ext_split[0].lower()
                    if sub_sub_ext_name_lower in ontology.keys():
                        sub_sub_ext_split[0] = ontology[sub_sub_ext_name_lower]
                    if sub_sub_ext_split[0] == "ip address":
                        sub_sub_ext_split[0] = "IP"
                    
                    if len(sub_sub_ext_split) > 1:
                        sub_sub_ext_dict_v_list.append({sub_sub_ext_split[0]:sub_sub_ext_split[1]})
                    else:
                        sub_sub_ext_dict_v_list.append(sub_sub_ext)
                sub_sub_ext_dict[sub_sub_ext_list[0]] = sub_sub_ext_dict_v_list
                current_ext_dict_v.append(sub_sub_ext_dict)
            elif len(re.split(": +", sub_ext)) > 1:
                sub_sub_ext_list = re.split(": +", sub_ext, 1)
                if sub_sub_ext_list[1].isdigit():
                    sub_sub_ext_list[1] = int(sub_sub_ext_list[1])
                if sub_sub_ext_list[0] in ["Not Before", "Not After"]:
                    sub_sub_ext_list[1] = convert_validity(sub_sub_ext_list[1])
                if sub_sub_ext_list[0] == "Certificate Authority (CA)":
                    sub_sub_ext_list[0] = "CA"
                elif sub_sub_ext_list[0] == "Path Length Constraint":
                    sub_sub_ext_list[0] = "pathLen"
                elif sub_sub_ext_list[0] == "directoryName":
                    sub_sub_ext_list[0] = "DirName"
                elif sub_sub_ext_list[0] == "RFC822Name":
                    sub_sub_ext_list[0] = "email"
                elif sub_sub_ext_list[0] == "DNSname":
                    sub_sub_ext_list[0] = "DNS"
                current_ext_dict_v.append({sub_sub_ext_list[0]:sub_sub_ext_list[1]})
            else:
                if sub_ext.endswith('.'):
                    current_ext_dict_v.append(sub_ext[:-2])
                else:
                    current_ext_dict_v.append(sub_ext)

        exts.append(current_ext_dict)
    return(exts_dict)


def reassemble_signaturealgorithm(field):
    """ To reassemble signatureAlgorithm.
    @param field: The signatureAlgorithm field;
    @return: The signatureAlgorithm dict.
    """
    mo_sig_algo = re.search(": (\w+)\-(\w+)", field)
    if mo_sig_algo:
        return(mo_sig_algo.group(2).upper()+'-'+mo_sig_algo.group(1))
    else:
        return("ERROR! SIGNATURE ALGORITHM NOT FOUND!")


def reassemble_signaturevalue(field):
    """ To reassemble signatureValue.
    @param field: The signatureValue field;
    @return: The signatureValue dict.
    """
    sig_colon_separated_hex_value = re.split("Signature:", field)[1]
    sig_dec_value = int(re.sub("\n\t{2}", '', sig_colon_separated_hex_value).replace(':', '').replace('\n', ''), 16)
    return(sig_dec_value)


def reassemble(field_list):
    """ To reassemble all fields.
    @param field_list: The list of fields;
    @return: The dict of all fields.
    """
    cert = {}
    tbsCertificate = {}
    for i, f in enumerate(field_list):
        if f.startswith("Version:"):
            tbsCertificate.update(reassemble_version(f))
        elif f.startswith("Serial Number"):
            tbsCertificate.update(reassemble_serialnumber(f))
        # GnuTLS has no "signature" in tbsCertificate
        elif f.startswith("Validity:"):
            tbsCertificate.update(reassemble_validity(f))
        elif f.startswith("Issuer:"):
            tbsCertificate.update(reassemble_issuer(f))
        elif f.startswith("Issuer Unique Identifier:"):
            tbsCertificate.update(reassemble_issueruid(f))
        elif f.startswith("Subject:"):
            tbsCertificate.update(reassemble_subject(f))
        elif f.startswith("Subject Unique Identifier"):
            tbsCertificate.update(reassemble_subjectuid(f))
        elif f.startswith("Subject Public Key Algorithm:"):
            tbsCertificate.update(reassemble_subject_public_key_info(f))
        elif f.startswith("Algorithm Security Level:"):
            public_key_info_dict = tbsCertificate.get("subject public key info")
            public_key_info_dict.update(reassemble_subject_public_key_info(f))
            tbsCertificate.update({"subject public key info":public_key_info_dict})
        elif f.startswith("Extensions:"):
            tbsCertificate.update(reassemble_ext(f))
        elif f.startswith("Signature Algorithm:"):
            cert["tbsCertificate"] = {}
            cert["tbsCertificate"].update(tbsCertificate)
            cert.update({"signature algorithm":reassemble_signaturealgorithm(f)})
        elif f.startswith("Signature:") and i == len(field_list) - 1 :
            cert.update({"signature value":reassemble_signaturevalue(f)})
    return(cert)


def SBDT_converter_GnuTLS_main():
    """ To convert outputs of GnuTLS to a uniform.
    @param None;
    @return: The uniform.
    """
    begin_time = time.time()
    parsable_cert_list = obtain_parsable_cert_list(tlsimpl)
    for pc in parsable_cert_list:
        cert_info = obtain_cert_info(pc)
        cert_field_list = obtain_cert_fields(cert_info)
        cert_dict = reassemble(cert_field_list)
        def set_default(obj):
            if isinstance(obj, set):
                return(list(obj))
            raise TypeError
        
        json_str = json.dumps(cert_dict, default=set_default)
        if json_str.find("Excluded:") > 1:
            json_str = json_str.replace("Excluded:", "Excluded")
            json_str = json_str.replace("RFC822Name", "email")
        if not os.path.exists(dir_cp_uniform_tlsimpl):
            os.mkdir(dir_cp_uniform_tlsimpl)
        with open(dir_cp_uniform_tlsimpl+pc, 'w') as fhw:
            fhw.write(json_str)
    end_time = time.time()
    print("SBDT_3_converter_GnuTLS succeeds!".center(60, '*'))
    print(("Time elapsed: "+str(end_time-begin_time)+" seconds.").center(60, '*'))


def read_dict():
    """ To read a dict.
    @param None;
    @return: The dict.
    """
    uniform_list = os.listdir(dir_cp_uniform_tlsimpl)
    uniform_list.sort()
    for u in uniform_list:
        with open(dir_cp_uniform_tlsimpl+u) as fhr:
            file_content = fhr.read()
        cert_dict = json.loads(file_content)
        print(json.dumps(cert_dict, indent=2))


if __name__ == "__main__":
    SBDT_converter_GnuTLS_main()
    pass
