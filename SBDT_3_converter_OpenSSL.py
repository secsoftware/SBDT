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
import sys
abs_path = os.getcwd()
sys.path.append(abs_path)
import re
import json

# -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
dir_cp_tmp_openssl = "../cp_tmp/OpenSSL/" 
dir_cp_uniform_openssl = "../cp_uniform/OpenSSL/" 
# -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

def get_ready():
    file_list = os.listdir(dir_cp_tmp_openssl)
    file_list.remove("cannot_parsed_by_openssl.txt")
    file_list.sort()
    file_list_cannot_parsed_by_openssl = []
    with open(dir_cp_tmp_openssl+"cannot_parsed_by_openssl.txt") as fhr:
        for f in fhr.readlines():
            file_list_cannot_parsed_by_openssl.append(os.path.splitext(f)[0].replace('\n', '')+".openssl")
    parsable_file_list = list(set(file_list)-set(file_list_cannot_parsed_by_openssl))
    parsable_file_list.sort()
    return(parsable_file_list)


def convert_validity(not_x):
    """ To convert validatity to a uniform format.
    @param not_x: "not before" or "not after";
    @return: A uniform format of validity.
    """
    p = r"(\w+) *(\d+) *(\d{2}:\d{2}:\d{2}) *(\d{4}) *(\w+)"
    mo_not_x = re.search(p, not_x) 

    not_x = []
    for i in range(0, 6):
        not_x.append(mo_not_x.group(i))
    
    if len(not_x[2]) == 1:  
        day = '0' + str(not_x[2])
    else:
        day = str(not_x[2])

    months_list = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    if not_x[0][:3] in months_list:
        month = months_list.index(not_x[0][:3]) + 1
        month = str(month)
        if len(month) < 2:
            month = '0' + month
    else:
        month = not_x[0][:3]
    not_x_uniform = not_x[4] + '-' + month + '-' + day + 'T' + not_x[3] + not_x[5]
    return(not_x_uniform)


def data_part_processing(data_list):
    """ To process data.
    @param data_list: A list of data;
    @return: A uniform format of data.
    """
    Data = {}
    field_list = []

    x509v3_extensions = []

    for s in data_list[1:]:
        if s.lower().startswith("version"):
            version_with_bracket = re.split("Version: *", s)[1]
            version_value = ''
            if version_with_bracket.startswith("Unknown"):
                mo = re.search(" *Unknown +\((.+)\)", version_with_bracket)
                if mo:
                    version_value = mo.group(1)
            else:
                version_value = re.split(" (?=\()", version_with_bracket)[0]
            Data["version"] = int(version_value)

        elif s.lower().startswith("serial number"):
            sn = re.sub("\n {12}|: {1}(?! )", ':\n', s)
            sn_list = re.split(":\n", sn)
            if len(sn_list) > 1:
                serial_number_hex = re.sub(":", '', sn_list[1].replace('\n', ''))
                if serial_number_hex.find("(0x") > 0:
                    serial_number_hex = re.search("\(0x(.+)\)", serial_number_hex).group(1)
                serial_number_dec = int(serial_number_hex, 16)
                Data[sn_list[0].lower().replace(':', '')] = serial_number_dec

        elif s.lower().startswith("signature algorithm"):
            sig_algo = re.findall(r"(\w+)With(\w+)Encryption", s) 
            if sig_algo:
                Data["signature algorithm"] = sig_algo[0][0].upper() + '-' + sig_algo[0][1]
            else:
                sig_algo = re.findall(r"(\w+)-with-(\w+)", s)
                Data["signature algorithm"] = sig_algo[0][1].upper() + '-' + sig_algo[0][0]

        elif s.lower().startswith("issuer:") or s.lower().startswith("subject:"):
            field_name = re.search(r"(\w+):", s).group()
            field_value = re.split("Issuer: |Subject: ", s.replace('\n', ''))
            field_value[1] = re.sub(" = ", '=', field_value[1])
            field_value[1] = field_value[1].split(', ')
            field_value[1].sort()
            field_value[1] = ','.join(field_value[1])
            Data[field_name.lower().replace(':', '')] = field_value[1]

        elif s.lower().startswith("validity"):
            not_before_not_after = re.findall("Not .+: (.*)\n", s)
            not_before = convert_validity(not_before_not_after[0])
            not_after = convert_validity(not_before_not_after[1])
            Data["Validity:".lower().replace(':', '')] = not_before + '-' + not_after

        elif s.lower().startswith("subject public key info"):
            s = s.replace("Subject Public Key Info:\n", '')
            s_list = re.split("\n {16}(?! )", s)

            k = "subject public key info"
            v = {}
            public_key = {k:v}

            for i, e in enumerate(s_list):
                s_list[i] = re.sub(" {12,}(?! )|\n", '', e) 
                kv = re.split(": *", s_list[i], 1) 
                mo_name = re.search("(\w+)Encryption", kv[1])
                mo_length = re.search("(\d+) bit", kv[1])
                if mo_name:
                    v[kv[0].lower()] = mo_name.group(1).upper()
                elif mo_length:
                    v["length"] = int(mo_length.group(1))
                elif kv[0].lower() == "modulus":
                    modulus_hex = re.sub(':', '', kv[1])
                    v["modulus"] = int(modulus_hex, 16)
                elif kv[0].lower() == "exponent":
                    exponent_dec = re.search("(\d+) \(.*", kv[1]).group(1)
                    v[kv[0].lower()] = int(exponent_dec)
                else:
                    v[kv[0]] = kv[1]
            Data[k] = v
        
        elif s.lower().startswith("issuer unique id:") or s.lower().startswith("subject unique id:"):
            field_name = s.lower()
            field_value = re.split("Issuer Unique ID: |Subject Unique ID: ", s.replace('\n', ''))
            Data[field_name.lower().replace(':', '')] = field_value[1]
        
        elif s.lower().startswith("x509v3 extensions"):
            extensions = s

            k = "X509v3 extensions"
            v = []
            x509v3_extensions = {k:v}
            
            ext_list = re.split("\n {12}(?! )", extensions)
            ext_list.remove(ext_list[0]) 
            for i, ext in enumerate(ext_list):
                ext_item_split = re.split("\n {16}(?! )", ext_list[i]) 
                critical_value_subitems = []
                for j, value_item in enumerate(ext_item_split):
                    if j == 0:
                        ext_name_critical_mo_tuple = re.search("(.+): *(.+)", value_item).groups()
                        ext_name = ext_name_critical_mo_tuple[0]
                        critical = ext_name_critical_mo_tuple[1].replace(' ', '')
                        critical_value_subitems.append(critical)
                    else:
                        split_cps_usernotice = re.split("\n {18}(?! )", value_item)
                        cps_usernotice_list = []  
                        if len(split_cps_usernotice) > 1:
                            for k, cps_or_usernotice in enumerate(split_cps_usernotice):
                                item_value_list = []
                                if k == 0:
                                    itemname_itemvalue = re.split(": *", cps_or_usernotice, 1)
                                    if len(itemname_itemvalue) > 1:  
                                        item_name = itemname_itemvalue[0] 
                                        item_value = itemname_itemvalue[1]
                                    else:
                                        item_name = itemname_itemvalue[0] 
                                        item_value = ''
                                else:
                                    split_usernotice_and_orgnumtxt = re.split("\n {20}(?! )", split_cps_usernotice[k])
                                    if len(split_usernotice_and_orgnumtxt) < 2:
                                        split_cps_and_value = re.split(": *", split_cps_usernotice[k], 1)
                                        if len(split_cps_and_value) > 1:
                                            cps_name = split_cps_and_value[0]
                                            cps_value = split_cps_and_value[1]
                                            cps_usernotice_list.append({cps_name:cps_value})
                                    else:
                                        user_notice_dict = {}
                                        user_notice_name = re.sub(": *", '', split_usernotice_and_orgnumtxt[0])
                                        ont_dict = {}
                                        for l, orgnumtxt in enumerate(split_usernotice_and_orgnumtxt):
                                            if l == 0:
                                                pass
                                            else:
                                                ont_name_and_value = re.split(": *", orgnumtxt, 1)
                                                if len(ont_name_and_value) > 1:
                                                    ont_name = ont_name_and_value[0]
                                                    ont_value = ont_name_and_value[1]
                                                    ont_dict[ont_name] = ont_value
                                        user_notice_dict[user_notice_name] = ont_dict
                                        cps_usernotice_list.append(user_notice_dict)
                                item_value_list = [item_value]
                                item_value_list.extend(cps_usernotice_list)
                            critical_value_subitems.append({item_name:item_value_list})
                        else:
                            if ext_name.find("Key Identifier") > 0:
                                if value_item.startswith("keyid:") or value_item.startswith("DirName:") or value_item.startswith("serial:"):
                                    keyid_list = re.split(": *", value_item, 1)
                                    if re.match("keyid|serial", value_item):
                                        if keyid_list[1]:
                                            keyid_list[1] = re.sub(':', '', keyid_list[1])
                                            keyid_list[1] = keyid_list[1].lower()
                                    critical_value_subitems.append({keyid_list[0]:keyid_list[1]})
                                else:
                                    critical_value_subitems.append(value_item.replace(':',''))
                            elif ext_name.find("Key Usage Period") > 0:
                                not_before_not_after = re.search("Not Before: (.*), Not After: (.*)", value_item)
                                not_before = convert_validity(not_before_not_after.group(1))
                                not_after = convert_validity(not_before_not_after.group(2))
                                kup_validity = not_before+'-'+not_after
                                critical_value_subitems.append(kup_validity)
                            else:
                                split_comma = re.split(", *", value_item)
                                item_value_list = [] 
                                if len(split_comma) > 1:
                                    for c in split_comma:
                                        itemname_itemvalue = re.split(": *", c, 1)
                                        if len(itemname_itemvalue) > 1:
                                            item_name = itemname_itemvalue[0]
                                            item_value = itemname_itemvalue[1]
                                            item_value_list.append({item_name:item_value})
                                        else:
                                            tmp_list = re.split(", *", c)
                                            for t in tmp_list:
                                                if type(t) == str:
                                                    item_value_list.append(t.lower())
                                                else:
                                                    item_value_list.append(t)
                                    critical_value_subitems.extend(item_value_list)
                                else:
                                    itemname_itemvalue = re.split(": *", split_comma[0], 1)
                                    if len(itemname_itemvalue) > 1:
                                        item_name = itemname_itemvalue[0]
                                        item_value = itemname_itemvalue[1]
                                        critical_value_subitems.append({item_name:item_value})
                                    else:
                                        tmp_list = re.split(", *", split_comma[0])
                                        tmp_lower_list = []
                                        for t in tmp_list:
                                            if type(t) == str:
                                                tmp_lower_list.append(t.lower()) 
                                        critical_value_subitems.append(tmp_lower_list)
                if critical_value_subitems:
                    v.append({ext_name:critical_value_subitems})
                else:
                    pass
        else:
            s = re.sub('\n', '', s) 
            s_list = re.split(": *", s, 1)
            Data[s_list[0].lower()] = s_list[1]
    if x509v3_extensions:
        Data.update(x509v3_extensions)
    else:
        pass
    return(Data)


def SBDT_converter_OpenSSL_main():
    """ The main function to convert results parsed by OpenSSL to a uniform format.
    @param None: None;
    @return: A uniform format.
    """
    
    parsable_file_list = get_ready()
    
    begin_time = time.time()
    for i, f in enumerate(parsable_file_list):
        with open(dir_cp_tmp_openssl+f) as fhr:
            cert_str = fhr.read()
            cert_parts_list = re.split(r'(?<!.) {4}(?! +)', cert_str)
            
            if len(cert_parts_list) < 3:
                pass
            data_list = re.split(r'(?<!.) {8}(?! )', cert_parts_list[-2])
            data_list[-1] = data_list[-1].replace("\n\n", '\n')

            fields_list = []
            for j, e in enumerate(data_list):
                if j == len(data_list) - 1:
                    fields_list.append(e[:-1])
                else:
                    fields_list.append(e)
            data_dict = data_part_processing(fields_list)
            sig_algo_first_line = re.split(r'\n', cert_parts_list[-1], 1)
            sig_dict = {}
            sig_dict_key = sig_algo_first_line[0].split(': ')[0]
            sig_dict_algo_name_tmp = sig_algo_first_line[0].split(': ')[1]
            sig_dict_algo_name_group = re.search("(\w+)With(\w+)Encryption", sig_dict_algo_name_tmp)
            sig_dict_algo_name = ''
            if sig_dict_algo_name_group:
                sig_dict_algo_name = sig_dict_algo_name_group.group(1).upper()+'-'+sig_dict_algo_name_group.group(2)
            else:
                sig_dict_algo_name = sig_dict_algo_name_tmp
            
            sig_dict_value_tmp = re.sub(r' +|\n', '', sig_algo_first_line[1])
            sig_dict_value = re.sub(':', '', sig_dict_value_tmp) 
            sig_dict_value = int(re.sub(':', '', sig_dict_value_tmp), 16)

            cert_dict = {}
            cert_dict.update({"tbsCertificate": data_dict})
            cert_dict.update({"signature algorithm":sig_dict_algo_name})
            cert_dict.update({"signature value":sig_dict_value})

            def set_default(obj):
                """ To avoid exception in JSON.
                @param obj: Object;
                @return: List object or TypeError.
                """
                if isinstance(obj, set):
                    return(list(obj))
                raise TypeError

            json_str = json.dumps(cert_dict, default=set_default)
            with open(dir_cp_uniform_openssl+f, 'w') as fhw:
                fhw.write(json_str)

    end_time = time.time()
    print("SBDT_3_converter_OpenSSL succeeds!".center(60, '*'))
    print(("Time elapsed: "+str(end_time-begin_time)+" seconds.").center(60, '*'))


def read_dict():
    """ To read a dict.
    @param None: None;
    @return: Output the dict to the screen.
    """
    
    uniform_list = os.listdir(dir_cp_uniform_openssl)
    uniform_list.sort()
    for u in uniform_list:
        with open(dir_cp_uniform_openssl+u) as fhr:
            file_value = fhr.read()
        cert_dict = json.loads(file_value)
        print(json.dumps(cert_dict, indent=2))


if __name__ == "__main__":
    SBDT_converter_OpenSSL_main()
