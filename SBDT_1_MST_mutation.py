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
import subprocess
import json
import hashlib
import random
from OpenSSL import crypto
import cryptography
import ipaddress
import datetime
import shutil
import matplotlib.pyplot as plt

# Cryptography_gen_CRLDP 
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.backends
import cryptography.x509
import traceback
import numpy as np
import pandas as pd
from cryptography import x509
from cryptography.x509.oid import NameOID

import SBDT_2_certificate_parsing  
import SBDT_3_converter_OpenSSL
import SBDT_3_converter_ZCertificate
import SBDT_3_converter_GnuTLS
import SBDT_4_SD_discrepancy_hunter

dir_seeds = "../certs_seed"
dir_mutated_un = "../certs_mutated_un"
dir_mutated_struc = "../certs_mutated_struc"
dir_mutated_value = "../certs_mutated_value"
dir_related = "../certs_related"
file_seeds_hash = dir_related + "../seeds_hash.txt"
dir_certs = "../certs"
dir_certs_tmp = "../cp_tmp"
dir_certs_un = "../cp_uniform"
dir_result = "../result"

MST = {}
mutation_count_bound = {}
mutation_count_dict = {}
consecutive = [] 
ca_private_key = ''
ca_public_key = ''
ec_private_key = ''
ec_public_key = ''


def initialize_dirs(target_dir):
    """ To create the target_dir if it does not exist, or empty it otherwise.
    @param target_dir: A target directory;
    @return: An empty directory. 
    """
    if os.path.exists(target_dir): 
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                os.remove(root+os.sep+f)
    else: 
        os.mkdir(target_dir)         


def ensure_dirs(EMPTY_DIR=False):
    """ To make sure the existence of all necessary directories. 
    @param ENPTY_DIR: BOOLEAN;
    @return (empty) dirs.
    """
    
    if os.path.exists(dir_seeds) and EMPTY_DIR:
        os.system("rm -rf "+dir_seeds+os.sep+'*')
    if not os.path.exists(dir_seeds):
        os.mkdir(dir_seeds)
    
    if os.path.exists(dir_mutated_un) and EMPTY_DIR:
        os.system("rm -rf "+dir_mutated_un+os.sep+'*')
    if not os.path.exists(dir_mutated_un):
        os.mkdir(dir_mutated_un)
            
    if os.path.exists(dir_mutated_struc) and EMPTY_DIR:
        os.system("rm -rf "+dir_mutated_struc+os.sep+'*')
    if not os.path.exists(dir_mutated_struc):
        os.mkdir(dir_mutated_struc)
        
    if os.path.exists(dir_mutated_value) and EMPTY_DIR:
        os.system("rm -rf "+dir_mutated_value+os.sep+'*')
    if not os.path.exists(dir_mutated_value):
        os.mkdir(dir_mutated_value)
    
    if os.path.exists(dir_certs) and EMPTY_DIR:
        os.system("rm -rf "+dir_certs+os.sep+'*')
    if not os.path.exists(dir_certs):
        os.mkdir(dir_certs)
        
    if not os.path.exists(dir_related):
        os.mkdir(dir_related)    
    
    if not os.path.exists(dir_result):
        os.mkdir(dir_result)
        
        
def initialize_MST():
    """ To initialize a Model named MST according to RFC 5280 and legacy in a bottom-up way.
    @param None: None;
    @return: A MST.
    """
    initial_value0 = 0 
    initial_value1 = 1
    initial_value2 = 2
    
    MST = {"cert":{"parent":None, 
                   "tbsCertificate":{"parent":"cert",
                                     "version":{"parent":"tbsCertificate",
                                                "count":{"struc_del":initial_value0, # current: pyOpenSSL; future: DERmutator
                                                         "struc_add":initial_value0, 
                                                         "value_mutate":initial_value0,
                                                         "sum":initial_value0
                                                         },
                                                "dis":{"struc_del":initial_value0, 
                                                       "struc_add":initial_value0, 
                                                       "value_mutate":initial_value0,
                                                       "sum":initial_value0
                                                       },
                                                "fitness":{"struc_del":initial_value0, 
                                                           "struc_add":initial_value0, 
                                                           "value_mutate":initial_value0,
                                                           "total":initial_value0
                                                           },
                                                "earlybound":{"struc_del":initial_value0,
                                                              "struc_add":initial_value0,
                                                              "value_mutate":initial_value1
                                                              },
                                                "hardbound":{"struc_del":initial_value0,
                                                             "struc_add":initial_value0,
                                                             "value_mutate":initial_value2
                                                             }
                                                }, # version
                                     "serial number":{"parent":"tbsCertificate", 
                                                      "count":{"struc_del":initial_value0, 
                                                               "struc_add":initial_value0, 
                                                               "value_mutate":initial_value0,
                                                               "sum":initial_value0
                                                               },
                                                      "dis":{"struc_del":initial_value0, 
                                                             "struc_add":initial_value0, 
                                                             "value_mutate":initial_value0,
                                                             "sum":initial_value0
                                                             },
                                                      "fitness":{"struc_del":initial_value0, 
                                                                 "struc_add":initial_value0, 
                                                                 "value_mutate":initial_value0,
                                                                 "total":initial_value0
                                                                 },
                                                      "earlybound":{"struc_del":initial_value1, 
                                                                    "struc_add":initial_value1, 
                                                                    "value_mutate":initial_value1
                                                                    },
                                                      "hardbound":{"struc_del":initial_value1, 
                                                                   "struc_add":initial_value1, 
                                                                   "value_mutate":initial_value2
                                                                   }
                                                      }, # serial number
                                     "tbsCertSignature":{"parent":"tbsCertificate", 
                                                         "count":{#"struc_del":initial_value0, # this leads to program error without generating any cert 
                                                                  #"struc_add":initial_value0, # checked by all certs generated by pyOpenSSL
                                                                  "value_mutate":initial_value0,
                                                                  "sum":initial_value0
                                                                  },
                                                         "dis":{#"struc_del":initial_value0, 
                                                                #"struc_add":initial_value0, 
                                                                "value_mutate":initial_value0,
                                                                "sum":initial_value0
                                                                },
                                                         "fitness":{#"struc_del":initial_value0, 
                                                                    #"struc_add":initial_value0, 
                                                                    "value_mutate":initial_value0,
                                                                    "total":initial_value0
                                                                    },
                                                         "earlybound":{#"struc_del":initial_value1, # Java
                                                                       #"struc_add":initial_value1, # Java/Python
                                                                       "value_mutate":initial_value1 # Java
                                                                       },
                                                         "hardbound":{#"struc_del":initial_value1, 
                                                                      #"struc_add":initial_value1, 
                                                                      "value_mutate":initial_value2
                                                                      }
                                                         }, # tbsCertificate signature algorithm
                                     "validity":{"parent":"tbsCertificate", 
                                                 "count":{"struc_del":initial_value0, 
                                                          "struc_add":initial_value0, 
                                                          "value_mutate":initial_value0,
                                                          "sum":initial_value0
                                                          },
                                                 "dis":{"struc_del":initial_value0, 
                                                        "struc_add":initial_value0, 
                                                        "value_mutate":initial_value0,
                                                        "sum":initial_value0
                                                        },
                                                 "fitness":{"struc_del":initial_value0, 
                                                            "struc_add":initial_value0, 
                                                            "value_mutate":initial_value0,
                                                            "total":initial_value0
                                                            },
                                                 "earlybound":{"struc_del":initial_value1, 
                                                               "struc_add":initial_value1, 
                                                               "value_mutate":initial_value1
                                                               },
                                                 "hardbound":{"struc_del":initial_value1, 
                                                              "struc_add":initial_value1, 
                                                              "value_mutate":initial_value2
                                                              }
                                                 }, # validity
                                     "issuer":{"parent":"tbsCertificate", 
                                               "count":{"struc_del":initial_value0, 
                                                        "struc_add":initial_value0, 
                                                        "value_mutate":initial_value0,
                                                        "sum":initial_value0
                                                        },
                                               "dis":{"struc_del":initial_value0, 
                                                      "struc_add":initial_value0, 
                                                      "value_mutate":initial_value0,
                                                      "sum":initial_value0
                                                      },
                                               "fitness":{"struc_del":initial_value0, 
                                                          "struc_add":initial_value0, 
                                                          "value_mutate":initial_value0,
                                                          "total":initial_value0
                                                          },
                                               "earlybound":{"struc_del":initial_value1, 
                                                             "struc_add":initial_value1, 
                                                             "value_mutate":initial_value1
                                                             },
                                               "hardbound":{"struc_del":initial_value1, 
                                                            "struc_add":initial_value1, 
                                                            "value_mutate":initial_value2
                                                            }
                                               }, # issuer
                                     "issuer unique identifier":{"parent":"tbsCertificate", 
                                                                 "count":{#"struc_del":initial_value0, # default in all certs generated by pyOpenSSL 
                                                                          "struc_add":initial_value0, 
                                                                          "sum":initial_value0
                                                                         },
                                                                "dis":{#"struc_del":initial_value0, 
                                                                       "struc_add":initial_value0, 
                                                                       "sum":initial_value0
                                                                       },
                                                                "fitness":{#"struc_del":initial_value0, 
                                                                           "struc_add":initial_value0, 
                                                                           "total":initial_value0
                                                                           },
                                                                "earlybound":{#"struc_del":initial_value1, # Python or Java
                                                                              "struc_add":initial_value1, # Java
                                                                              },
                                                                "hardbound":{#"struc_del":initial_value1, 
                                                                             "struc_add":initial_value1, 
                                                                             }
                                                                }, # issuer UID
                                     "subject":{"parent":"tbsCertificate", 
                                                "count":{"struc_del":initial_value0, 
                                                         "struc_add":initial_value0, 
                                                         "value_mutate":initial_value0,
                                                         "sum":initial_value0
                                                        },
                                                "dis":{"struc_del":initial_value0, 
                                                       "struc_add":initial_value0, 
                                                       "value_mutate":initial_value0,
                                                       "sum":initial_value0
                                                       },
                                                "fitness":{"struc_del":initial_value0, 
                                                           "struc_add":initial_value0, 
                                                           "value_mutate":initial_value0,
                                                           "total":initial_value0
                                                           },
                                                "earlybound":{"struc_del":initial_value1, 
                                                              "struc_add":initial_value1, 
                                                              "value_mutate":initial_value1
                                                              },
                                                "hardbound":{"struc_del":initial_value1, 
                                                             "struc_add":initial_value1, 
                                                             "value_mutate":initial_value2
                                                             }
                                                }, # subject
                                     "subject unique identifier":{"parent":"tbsCertificate", 
                                                                  "count":{#"struc_del":initial_value0, # default in all certs generated by pyOpenSSL
                                                                           "struc_add":initial_value0, # Java
                                                                           "sum":initial_value0
                                                                           },
                                                                  "dis":{#"struc_del":initial_value0, 
                                                                         "struc_add":initial_value0, 
                                                                         "sum":initial_value0
                                                                         },
                                                                  "fitness":{#"struc_del":initial_value0, 
                                                                             "struc_add":initial_value0, 
                                                                             "total":initial_value0
                                                                             },
                                                                  "earlybound":{#"struc_del":initial_value1, 
                                                                                "struc_add":initial_value1, 
                                                                                },
                                                                  "hardbound":{#"struc_del":initial_value1, 
                                                                               "struc_add":initial_value1, 
                                                                               }
                                                                  }, # subject UID
                                     "subject public key information":{"parent":"tbsCertificate", 
                                                                       "count":{"struc_del":initial_value0, 
                                                                                "struc_add":initial_value0, 
                                                                                "sum":initial_value0
                                                                                },
                                                                       "dis":{"struc_del":initial_value0, 
                                                                              "struc_add":initial_value0, 
                                                                              "value_mutate":initial_value0,
                                                                              "sum":initial_value0
                                                                              },
                                                                       "fitness":{"struc_del":initial_value0, 
                                                                                  "struc_add":initial_value0, 
                                                                                  "value_mutate":initial_value0,
                                                                                  "total":initial_value0
                                                                                  },
                                                                       "earlybound":{"struc_del":initial_value1, 
                                                                                     "struc_add":initial_value1, 
                                                                                     "value_mutate":initial_value0
                                                                                     },
                                                                       "hardbound":{"struc_del":initial_value1, 
                                                                                    "struc_add":initial_value1, 
                                                                                    "value_mutate":initial_value0
                                                                                    }
                                                                       }, # subject public key information
                                     "extensions":{"parent":"tbsCertificate", 
                                                   "standard extensions":{"parent":"extensions", 
                                                                          "basic constraints":{"parent":"standard extensions", 
                                                                                               "cA":{"parent":"basic constraints", 
                                                                                                     "count":{"struc_add":initial_value0, 
                                                                                                              "struc_dup":initial_value0, 
                                                                                                              "struc_del":initial_value0,
                                                                                                              "sum":initial_value0
                                                                                                              },
                                                                                                     "dis":{"struc_add":initial_value0, 
                                                                                                            "struc_dup":initial_value0, 
                                                                                                            "struc_del":initial_value0,
                                                                                                            "sum":initial_value0
                                                                                                            },
                                                                                                     "fitness":{"struc_add":initial_value0, 
                                                                                                                "struc_dup":initial_value0, 
                                                                                                                "struc_del":initial_value0,
                                                                                                                "total":initial_value0
                                                                                                                },
                                                                                                     "earlybound":{"struc_add":initial_value1, 
                                                                                                                   "struc_dup":initial_value1, 
                                                                                                                   "struc_del":initial_value1
                                                                                                                   },
                                                                                                     "hardbound":{"struc_add":initial_value1, 
                                                                                                                  "struc_dup":initial_value1, 
                                                                                                                  "struc_del":initial_value1
                                                                                                                  }
                                                                                                     }, # cA                                     
                                                                                               "pathLenConstraint":{"parent":"basic constraints", 
                                                                                                                    "count":{"struc_add":initial_value0, 
                                                                                                                             "struc_dup":initial_value0, 
                                                                                                                             "struc_del":initial_value0,
                                                                                                                             "value_mutate":initial_value0,
                                                                                                                             "sum":initial_value0
                                                                                                                             },
                                                                                                                    "dis":{"struc_add":initial_value0, 
                                                                                                                           "struc_dup":initial_value0,
                                                                                                                           "struc_del":initial_value0, 
                                                                                                                           "value_mutate":initial_value0,
                                                                                                                           "sum":initial_value0
                                                                                                                            },
                                                                                                                    "fitness":{"struc_add":initial_value0, 
                                                                                                                               "struc_dup":initial_value0,
                                                                                                                               "struc_del":initial_value0, 
                                                                                                                               "value_mutate":initial_value0,
                                                                                                                               "total":initial_value0
                                                                                                                               },
                                                                                                                    "earlybound":{"struc_add":initial_value1, 
                                                                                                                                  "struc_dup":initial_value1,
                                                                                                                                  "struc_del":initial_value1, 
                                                                                                                                  "value_mutate":initial_value1
                                                                                                                                  },
                                                                                                                    "hardbound":{"struc_add":initial_value1, 
                                                                                                                                 "struc_dup":initial_value1,
                                                                                                                                 "struc_del":initial_value1, 
                                                                                                                                 "value_mutate":initial_value2
                                                                                                                                 }
                                                                                                                     }, # pathLenConstraint 
                                                                                               "count":{"struc_add":initial_value0, 
                                                                                                        "struc_dup":initial_value0, 
                                                                                                        "sum":initial_value0
                                                                                                        },
                                                                                               "dis":{"struc_add":initial_value0, 
                                                                                                      "struc_dup":initial_value0, 
                                                                                                      "sum":initial_value0
                                                                                                      },
                                                                                               "fitness":{"struc_add":initial_value0, 
                                                                                                          "struc_dup":initial_value0, 
                                                                                                          "total":initial_value0
                                                                                                          },
                                                                                               "earlybound":{"struc_add":initial_value1, 
                                                                                                             "struc_dup":initial_value1, 
                                                                                                             },
                                                                                               "hardbound":{"struc_add":initial_value1, 
                                                                                                            "struc_dup":initial_value1, 
                                                                                                            }
                                                                                                 }, # basic constraints
                                                                          "name constraints":{"parent":"standard extensions", 
                                                                                              "permittedSubtrees":{"parent":"name constraints", 
                                                                                                                   "count":{"struc_add":initial_value0, 
                                                                                                                            "value_mutate":initial_value0,
                                                                                                                            "sum":initial_value0
                                                                                                                            },
                                                                                                                   "dis":{"struc_add":initial_value0, 
                                                                                                                          "value_mutate":initial_value0,
                                                                                                                          "sum":initial_value0
                                                                                                                          },
                                                                                                                   "fitness":{"struc_add":initial_value0, 
                                                                                                                              "value_mutate":initial_value0,
                                                                                                                              "total":initial_value0
                                                                                                                              },
                                                                                                                   "earlybound":{"struc_add":initial_value1, 
                                                                                                                                 "value_mutate":initial_value1
                                                                                                                                 },
                                                                                                                   "hardbound":{"struc_add":initial_value1, 
                                                                                                                                "value_mutate":initial_value2
                                                                                                                                }
                                                                                                                   }, # permittedSubtrees                             
                                                                                              "excludedSubtrees":{"parent":"name constraints", 
                                                                                                                  "count":{"struc_add":initial_value0, 
                                                                                                                           "value_mutate":initial_value0,
                                                                                                                           "sum":initial_value0
                                                                                                                           },
                                                                                                                  "dis":{"struc_add":initial_value0, 
                                                                                                                         "value_mutate":initial_value0,
                                                                                                                         "sum":initial_value0
                                                                                                                         },
                                                                                                                  "fitness":{"struc_add":initial_value0, 
                                                                                                                             "value_mutate":initial_value0,
                                                                                                                             "total":initial_value0
                                                                                                                             },
                                                                                                                  "earlybound":{"struc_add":initial_value1, 
                                                                                                                                "value_mutate":initial_value1
                                                                                                                                },
                                                                                                                  "hardbound":{"struc_add":initial_value1, 
                                                                                                                               "value_mutate":initial_value2
                                                                                                                               }
                                                                                                                  }, # exlucdedSubtrees 
                                                                                              "count":{"struc_add":initial_value0, 
                                                                                                       "struc_dup":initial_value0, 
                                                                                                       "sum":initial_value0
                                                                                                       },
                                                                                              "dis":{"struc_add":initial_value0, 
                                                                                                     "struc_dup":initial_value0, 
                                                                                                     "sum":initial_value0
                                                                                                     },
                                                                                              "fitness":{"struc_add":initial_value0, 
                                                                                                         "struc_dup":initial_value0, 
                                                                                                         "total":initial_value0
                                                                                                         },
                                                                                              "earlybound":{"struc_add":initial_value1, 
                                                                                                            "struc_dup":initial_value1, 
                                                                                                            },
                                                                                              "hardbound":{"struc_add":initial_value1, 
                                                                                                           "struc_dup":initial_value1, 
                                                                                                           }
                                                                                              }, # name constraints 
                                                                          "policy constraints":{"parent":"standard extensions", 
                                                                                                "requireExplicitPolicy":{"parent":"policy constraints", 
                                                                                                                         "count":{"struc_add":initial_value0, 
                                                                                                                                  "struc_dup":initial_value0, 
                                                                                                                                  "value_mutate":initial_value0,
                                                                                                                                  "sum":initial_value0
                                                                                                                                  },
                                                                                                                         "dis":{"struc_add":initial_value0, 
                                                                                                                                "struc_dup":initial_value0, 
                                                                                                                                "value_mutate":initial_value0,
                                                                                                                                "sum":initial_value0
                                                                                                                                },
                                                                                                                         "fitness":{"struc_add":initial_value0, 
                                                                                                                                    "struc_dup":initial_value0, 
                                                                                                                                    "value_mutate":initial_value0,
                                                                                                                                    "total":initial_value0
                                                                                                                                    },
                                                                                                                         "earlybound":{"struc_add":initial_value1, 
                                                                                                                                       "struc_dup":initial_value1, 
                                                                                                                                       "value_mutate":initial_value1
                                                                                                                                       },
                                                                                                                         "hardbound":{"struc_add":initial_value1, 
                                                                                                                                      "struc_dup":initial_value1, 
                                                                                                                                      "value_mutate":initial_value2
                                                                                                                                      }
                                                                                                    }, # requireExplicitPolicy                     
                                                                                                "inhibitPolicyMapping":{"parent":"policy constraints", 
                                                                                                                        "count":{"struc_add":initial_value0, 
                                                                                                                                 "struc_dup":initial_value0, 
                                                                                                                                 "value_mutate":initial_value0,
                                                                                                                                 "sum":initial_value0
                                                                                                                                 },
                                                                                                                        "dis":{"struc_add":initial_value0, 
                                                                                                                               "struc_dup":initial_value0, 
                                                                                                                               "value_mutate":initial_value0,
                                                                                                                               "sum":initial_value0
                                                                                                                               },
                                                                                                                        "fitness":{"struc_add":initial_value0, 
                                                                                                                                   "struc_dup":initial_value0, 
                                                                                                                                   "value_mutate":initial_value0,
                                                                                                                                   "total":initial_value0
                                                                                                                                   },
                                                                                                                        "earlybound":{"struc_add":initial_value1, 
                                                                                                                                      "struc_dup":initial_value1, 
                                                                                                                                      "value_mutate":initial_value1
                                                                                                                                      },
                                                                                                                        "hardbound":{"struc_add":initial_value1, 
                                                                                                                                     "struc_dup":initial_value1, 
                                                                                                                                     "value_mutate":initial_value2
                                                                                                                                     }
                                                                                                                        }, # inhibitPolicyMapping 
                                                                                                "count":{"struc_add":initial_value0, 
                                                                                                         "struc_dup":initial_value0, 
                                                                                                         "sum":initial_value0
                                                                                                         },
                                                                                                "dis":{"struc_add":initial_value0, 
                                                                                                       "struc_dup":initial_value0, 
                                                                                                       "sum":initial_value0
                                                                                                       },
                                                                                                "fitness":{"struc_add":initial_value0, 
                                                                                                           "struc_dup":initial_value0, 
                                                                                                           "total":initial_value0
                                                                                                           },
                                                                                                "earlybound":{"struc_add":initial_value1, 
                                                                                                              "struc_dup":initial_value1, 
                                                                                                              },
                                                                                                "hardbound":{"struc_add":initial_value1, 
                                                                                                             "struc_dup":initial_value1, 
                                                                                                             }
                                                                                                }, # policy constraints                                                
                                                                          "authority key identifier":{"parent":"standard extensions", 
                                                                                                      "keyIdentifier":{"parent":"authority key identifier", 
                                                                                                                       "count":{"struc_add":initial_value0, 
                                                                                                                                "struc_del":initial_value0, 
                                                                                                                                "sum":initial_value0
                                                                                                                                },
                                                                                                                       "dis":{"struc_add":initial_value0, 
                                                                                                                              "struc_del":initial_value0, 
                                                                                                                              "sum":initial_value0
                                                                                                                              },
                                                                                                                       "fitness":{"struc_add":initial_value0, 
                                                                                                                                  "struc_del":initial_value0, 
                                                                                                                                  "total":initial_value0
                                                                                                                                  },
                                                                                                                       "earlybound":{"struc_add":initial_value1, 
                                                                                                                                     "struc_del":initial_value1, 
                                                                                                                                     },
                                                                                                                       "hardbound":{"struc_add":initial_value1, 
                                                                                                                                    "struc_del":initial_value1, 
                                                                                                                                    }
                                                                                                                       }, # keyIdentifier
                                                                                                      "authorityCertIssuer":{"parent":"authority key identifier", 
                                                                                                                             "count":{"struc_add":initial_value0, 
                                                                                                                                      "struc_del":initial_value0, 
                                                                                                                                      "sum":initial_value0
                                                                                                                                      },
                                                                                                                             "dis":{"struc_add":initial_value0, 
                                                                                                                                    "struc_del":initial_value0, 
                                                                                                                                    "sum":initial_value0
                                                                                                                                    },
                                                                                                                             "fitness":{"struc_add":initial_value0, 
                                                                                                                                        "struc_del":initial_value0, 
                                                                                                                                        "total":initial_value0
                                                                                                                                        },
                                                                                                                             "earlybound":{"struc_add":initial_value1, 
                                                                                                                                           "struc_del":initial_value1, 
                                                                                                                                           },
                                                                                                                             "hardbound":{"struc_add":initial_value1, 
                                                                                                                                          "struc_del":initial_value1, 
                                                                                                                                          }
                                                                                                                             }, # authorityCertIssuer
                                                                                                      "authorityCertSerialNumber":{"parent":"authority key identifier", 
                                                                                                                                   "count":{"struc_add":initial_value0, 
                                                                                                                                            "struc_del":initial_value0, 
                                                                                                                                            "sum":initial_value0
                                                                                                                                            },
                                                                                                                                   "dis":{"struc_add":initial_value0, 
                                                                                                                                          "struc_del":initial_value0, 
                                                                                                                                          "sum":initial_value0
                                                                                                                                          },
                                                                                                                                   "fitness":{"struc_add":initial_value0, 
                                                                                                                                              "struc_del":initial_value0, 
                                                                                                                                              "total":initial_value0
                                                                                                                                              },
                                                                                                                                   "earlybound":{"struc_add":initial_value1, 
                                                                                                                                                 "struc_del":initial_value1, 
                                                                                                                                                 },
                                                                                                                                   "hardbound":{"struc_add":initial_value1, 
                                                                                                                                                "struc_del":initial_value1, 
                                                                                                                                                }
                                                                                                                                   }, # authorityCertSerialNumber 
                                                                                                      "count":{"struc_add":initial_value0, 
                                                                                                               "struc_dup":initial_value0, 
                                                                                                               "sum":initial_value0  # includes its children data
                                                                                                               },
                                                                                                      "dis":{"struc_add":initial_value0, 
                                                                                                             "struc_dup":initial_value0, 
                                                                                                             "sum":initial_value0  # includes its children data
                                                                                                             },
                                                                                                      "fitness":{"struc_add":initial_value0, 
                                                                                                                 "struc_dup":initial_value0, 
                                                                                                                 "total":initial_value0   # includes its children data
                                                                                                                 },
                                                                                                      "earlybound":{"struc_add":initial_value1, # empty
                                                                                                                    "struc_dup":initial_value1, # duplicate
                                                                                                                    },
                                                                                                      "hardbound":{"struc_add":initial_value1, 
                                                                                                                   "struc_dup":initial_value1, 
                                                                                                                   }
                                                                                                      }, # authority key identifier
                                                                         "subject key identifier":{"parent":"standard extensions", 
                                                                                                   "keyIdentifier2":{"parent":"subject key identifier", 
                                                                                                                     "count":{"struc_add":initial_value0, 
                                                                                                                              "struc_del":initial_value0, 
                                                                                                                              "sum":initial_value0
                                                                                                                              },
                                                                                                                     "dis":{"struc_add":initial_value0, 
                                                                                                                            "struc_del":initial_value0, 
                                                                                                                            "sum":initial_value0
                                                                                                                            },
                                                                                                                     "fitness":{"struc_add":initial_value0, 
                                                                                                                                "struc_del":initial_value0, 
                                                                                                                                "total":initial_value0
                                                                                                                                },
                                                                                                                     "earlybound":{"struc_add":initial_value1, 
                                                                                                                                   "struc_del":initial_value1, 
                                                                                                                                   },
                                                                                                                     "hardbound":{"struc_add":initial_value1, 
                                                                                                                                  "struc_del":initial_value1, 
                                                                                                                                  }
                                                                                                                     }, # keyIdentifier2 # to avoid duplicate AKI keyID 
                                                                                                   "count":{"struc_dup":initial_value0,  # add empty
                                                                                                            "sum":initial_value0
                                                                                                            },
                                                                                                   "dis":{"struc_dup":initial_value0, 
                                                                                                          "sum":initial_value0
                                                                                                          },
                                                                                                   "fitness":{"struc_dup":initial_value0, 
                                                                                                              "total":initial_value0
                                                                                                              },
                                                                                                   "earlybound":{"struc_dup":initial_value1, 
                                                                                                                 },
                                                                                                   "hardbound":{"struc_dup":initial_value1, 
                                                                                                                }
                                                                                                   }, # subject key identifier
                                                                         "key usage":{"parent":"standard extensions", 
                                                                                      "count":{"struc_add":initial_value0, 
                                                                                               "struc_dup":initial_value0, 
                                                                                               "value_mutate":initial_value0,
                                                                                               "sum":initial_value0
                                                                                               },
                                                                                      "dis":{"struc_add":initial_value0, 
                                                                                             "struc_dup":initial_value0, 
                                                                                             "value_mutate":initial_value0,
                                                                                             "sum":initial_value0
                                                                                             },
                                                                                      "fitness":{"struc_add":initial_value0, 
                                                                                                 "struc_dup":initial_value0, 
                                                                                                 "value_mutate":initial_value0,
                                                                                                 "total":initial_value0
                                                                                                 },
                                                                                      "earlybound":{"struc_add":initial_value1, 
                                                                                                    "struc_dup":initial_value1, 
                                                                                                    "value_mutate":initial_value1
                                                                                                    },
                                                                                      "hardbound":{"struc_add":initial_value1, 
                                                                                                   "struc_dup":initial_value1, 
                                                                                                   "value_mutate":initial_value2
                                                                                                    }
                                                                                      }, # key usage
                                                                         "extended key usage":{"parent":"standard extensions", 
                                                                                               "count":{"struc_add":initial_value0, 
                                                                                                        "struc_dup":initial_value0, 
                                                                                                        "sum":initial_value0
                                                                                                        },
                                                                                               "dis":{"struc_add":initial_value0, 
                                                                                                      "struc_dup":initial_value0, 
                                                                                                      "sum":initial_value0
                                                                                                      },
                                                                                               "fitness":{"struc_add":initial_value0, 
                                                                                                          "struc_dup":initial_value0, 
                                                                                                          "total":initial_value0
                                                                                                          },
                                                                                               "earlybound":{"struc_add":initial_value1, 
                                                                                                             "struc_dup":initial_value1, 
                                                                                                             },
                                                                                               "hardbound":{"struc_add":initial_value1, 
                                                                                                            "struc_dup":initial_value1, 
                                                                                                            }
                                                                                               }, # extended key usage
                                                                         "certificate policies":{"parent":"standard extensions", 
                                                                                                 "policyIdentifier":{"parent":"certificate policies", 
                                                                                                                     "count":{"struc_add":initial_value0, 
                                                                                                                              "sum":initial_value0
                                                                                                                              },
                                                                                                                     "dis":{"struc_add":initial_value0, 
                                                                                                                            "sum":initial_value0
                                                                                                                            },
                                                                                                                     "fitness":{"struc_add":initial_value0, 
                                                                                                                                "total":initial_value0
                                                                                                                                },
                                                                                                                     "earlybound":{"struc_add":initial_value1, 
                                                                                                                                   },
                                                                                                                     "hardbound":{"struc_add":initial_value1, 
                                                                                                                                  }
                                                                                                                     }, # policyIdentifier 
                                                                                                 "CPS":{"parent":"certificate policies", 
                                                                                                        "count":{"struc_add":initial_value0, 
                                                                                                                 "struc_dup":initial_value0, 
                                                                                                                 "value_mutate":initial_value0,
                                                                                                                 "sum":initial_value0
                                                                                                                 },
                                                                                                        "dis":{"struc_add":initial_value0, 
                                                                                                               "struc_dup":initial_value0, 
                                                                                                               "value_mutate":initial_value0,
                                                                                                               "sum":initial_value0
                                                                                                               },
                                                                                                        "fitness":{"struc_add":initial_value0, 
                                                                                                                   "struc_dup":initial_value0, 
                                                                                                                   "value_mutate":initial_value0,
                                                                                                                   "total":initial_value0
                                                                                                                   },
                                                                                                        "earlybound":{"struc_add":initial_value1, 
                                                                                                                      "struc_dup":initial_value1, 
                                                                                                                      "value_mutate":initial_value1
                                                                                                                      },
                                                                                                        "hardbound":{"struc_add":initial_value1, 
                                                                                                                     "struc_dup":initial_value1, 
                                                                                                                     "value_mutate":initial_value2
                                                                                                                     }
                                                                                                        }, # CPS
                                                                                                 "userNotice":{"parent":"certificate policies", 
                                                                                                               # pyOpenSSL cannot generate the extension "certificate policies"
                                                                                                               # cryptography generates the extension "certificate policies" but cannot generate the full extension.
                                                                                                               # Java cannot generate noticeRef without explicitText or vice versa. 
                                                                                                               # Hence, the only choice for us is to treat userNotice as a whole.
#                                                                                                                "noticeRef":{"parent":"userNotice", 
#                                                                                                                             "count":{"struc_add":initial_value0, 
#                                                                                                                                      "struc_dup":initial_value0, 
#                                                                                                                                      "value_mutate":initial_value0,
#                                                                                                                                      "sum":initial_value0
#                                                                                                                                     },
#                                                                                                                             "dis":{"struc_add":initial_value0, 
#                                                                                                                                    "struc_dup":initial_value0, 
#                                                                                                                                    "value_mutate":initial_value0,
#                                                                                                                                    "sum":initial_value0
#                                                                                                                                    },
#                                                                                                                             "fitness":{"struc_add":initial_value0, 
#                                                                                                                                        "struc_dup":initial_value0, 
#                                                                                                                                        "value_mutate":initial_value0,
#                                                                                                                                        "total":initial_value0
#                                                                                                                                       },
#                                                                                                                             "earlybound":{"struc_add":initial_value1, 
#                                                                                                                                           "struc_dup":initial_value1, 
#                                                                                                                                           "value_mutate":initial_value1
#                                                                                                                                          },
#                                                                                                                             "hardbound":{"struc_add":initial_value1, 
#                                                                                                                                          "struc_dup":initial_value1, 
#                                                                                                                                          "value_mutate":initial_value2
#                                                                                                                                          }
#                                                                                                                             }, # noticeRef
#                                                                                                                "explicitText":{"parent":"userNotice", 
#                                                                                                                                "count":{"struc_add":initial_value0, 
#                                                                                                                                         "struc_dup":initial_value0, 
#                                                                                                                                         "value_mutate":initial_value0,
#                                                                                                                                         "sum":initial_value0
#                                                                                                                                         },
#                                                                                                                                "dis":{"struc_add":initial_value0, 
#                                                                                                                                       "struc_dup":initial_value0, 
#                                                                                                                                       "value_mutate":initial_value0,
#                                                                                                                                       "sum":initial_value0
#                                                                                                                                        },
#                                                                                                                                "fitness":{"struc_add":initial_value0, 
#                                                                                                                                           "struc_dup":initial_value0, 
#                                                                                                                                           "value_mutate":initial_value0,
#                                                                                                                                           "total":initial_value0
#                                                                                                                                          },
#                                                                                                                                "earlybound":{"struc_add":initial_value1, 
#                                                                                                                                              "struc_dup":initial_value1, 
#                                                                                                                                              "value_mutate":initial_value1
#                                                                                                                                             },
#                                                                                                                                "hardbound":{"struc_add":initial_value1, 
#                                                                                                                                             "struc_dup":initial_value1, 
#                                                                                                                                             "value_mutate":initial_value2
#                                                                                                                                            }
#                                                                                                                                }, # explicitText 
                                                                                                               "count":{"struc_add":initial_value0, # try to add the struc without content
                                                                                                                        "struc_dup":initial_value0, 
                                                                                                                        "value_mutate":initial_value0,
                                                                                                                        "sum":initial_value0
                                                                                                                      },
                                                                                                               "dis":{"struc_add":initial_value0, 
                                                                                                                      "struc_dup":initial_value0, 
                                                                                                                      "value_mutate":initial_value0,
                                                                                                                      "sum":initial_value0
                                                                                                                      },
                                                                                                               "fitness":{"struc_add":initial_value0, 
                                                                                                                          "struc_dup":initial_value0, 
                                                                                                                          "value_mutate":initial_value0,
                                                                                                                          "total":initial_value0
                                                                                                                          },
                                                                                                               "earlybound":{"struc_add":initial_value1, 
                                                                                                                             "struc_dup":initial_value1, 
                                                                                                                             "value_mutate":initial_value1
                                                                                                                             },
                                                                                                               "hardbound":{"struc_add":initial_value1, 
                                                                                                                            "struc_dup":initial_value1, 
                                                                                                                            "value_mutate":initial_value2
                                                                                                                            }
                                                                                                               }, # userNotice 
                                                                                                 "count":{"struc_add":initial_value0, 
                                                                                                          #"struc_dup":initial_value0, # java cannot add the extension twice. 
                                                                                                          "sum":initial_value0
                                                                                                          },
                                                                                                 "dis":{"struc_add":initial_value0, 
                                                                                                        #"struc_dup":initial_value0, 
                                                                                                        "sum":initial_value0
                                                                                                        },
                                                                                                 "fitness":{"struc_add":initial_value0, 
                                                                                                            #"struc_dup":initial_value0, 
                                                                                                            "total":initial_value0
                                                                                                            },
                                                                                                 "earlybound":{"struc_add":initial_value1, 
                                                                                                               #"struc_dup":initial_value1, 
                                                                                                               },
                                                                                                 "hardbound":{"struc_add":initial_value1, 
                                                                                                              #"struc_dup":initial_value1, 
                                                                                                              }
                                                                                                 }, # certificate policies
                                                                         "policy mappings":{"parent":"standard extensions", 
                                                                                            "issuerDomainPolicy":{"parent":"policy mappings", 
                                                                                                                  "count":{"struc_add":initial_value0, 
                                                                                                                           "struc_dup":initial_value0, 
                                                                                                                           "value_mutate":initial_value0,
                                                                                                                           "sum":initial_value0
                                                                                                                           },
                                                                                                                  "dis":{"struc_add":initial_value0, 
                                                                                                                         "struc_dup":initial_value0, 
                                                                                                                         "value_mutate":initial_value0,
                                                                                                                         "sum":initial_value0
                                                                                                                         },
                                                                                                                  "fitness":{"struc_add":initial_value0, 
                                                                                                                             "struc_dup":initial_value0, 
                                                                                                                             "value_mutate":initial_value0,
                                                                                                                             "total":initial_value0
                                                                                                                             },
                                                                                                                  "earlybound":{"struc_add":initial_value0, # pyOpenSSL cannot process it
                                                                                                                                "struc_dup":initial_value0, # pyOpenSSL cannot process it
                                                                                                                                "value_mutate":initial_value0 # pyOpenSSL cannot process it
                                                                                                                                },
                                                                                                                  "hardbound":{"struc_add":initial_value0, # pyOpenSSL cannot process it
                                                                                                                               "struc_dup":initial_value0, # pyOpenSSL cannot process it
                                                                                                                               "value_mutate":initial_value0 # pyOpenSSL cannot process it
                                                                                                                               }
                                                                                                                 }, # issuerDomainPolicy                                     
                                                                                            "subjectDomainPolicy":{"parent":"policy mappings", 
                                                                                                                   "count":{"struc_add":initial_value0, 
                                                                                                                            "struc_dup":initial_value0, 
                                                                                                                            "value_mutate":initial_value0,
                                                                                                                            "sum":initial_value0
                                                                                                                            },
                                                                                                                   "dis":{"struc_add":initial_value0, 
                                                                                                                          "struc_dup":initial_value0, 
                                                                                                                          "value_mutate":initial_value0,
                                                                                                                          "sum":initial_value0
                                                                                                                          },
                                                                                                                   "fitness":{"struc_add":initial_value0, 
                                                                                                                              "struc_dup":initial_value0, 
                                                                                                                              "value_mutate":initial_value0,
                                                                                                                              "total":initial_value0
                                                                                                                              },
                                                                                                                   "earlybound":{"struc_add":initial_value0, # pyOpenSSL cannot process it
                                                                                                                                 "struc_dup":initial_value0, # pyOpenSSL cannot process it
                                                                                                                                 "value_mutate":initial_value0 # pyOpenSSL cannot process it
                                                                                                                                 },
                                                                                                                   "hardbound":{"struc_add":initial_value0, # pyOpenSSL cannot process it
                                                                                                                                "struc_dup":initial_value0, # pyOpenSSL cannot process it
                                                                                                                                "value_mutate":initial_value0 # pyOpenSSL cannot process it
                                                                                                                                }
                                                                                                                   }, # subjectDomainPolicy 
                                                                                            "count":{"struc_add":initial_value0, 
                                                                                                     "struc_dup":initial_value0, 
                                                                                                     "value_mutate":initial_value0,
                                                                                                     "sum":initial_value0
                                                                                                     },
                                                                                            "dis":{"struc_add":initial_value0, 
                                                                                                   "struc_dup":initial_value0,
                                                                                                   "value_mutate":initial_value0,
                                                                                                   "sum":initial_value0
                                                                                                   },
                                                                                            "fitness":{"struc_add":initial_value0, 
                                                                                                       "struc_dup":initial_value0, 
                                                                                                       "value_mutate":initial_value0,
                                                                                                       "total":initial_value0
                                                                                                       },
                                                                                            "earlybound":{"struc_add":initial_value1, 
                                                                                                          "struc_dup":initial_value1,
                                                                                                          "value_mutate":initial_value1 
                                                                                                          },
                                                                                            "hardbound":{"struc_add":initial_value1, 
                                                                                                         "struc_dup":initial_value1, 
                                                                                                         "value_mutate":initial_value1
                                                                                                         }
                                                                                            }, # policy mappings
                                                                         "inhibit anyPolicy":{"parent":"standard extensions", 
                                                                                              "count":{"struc_add":initial_value0, 
                                                                                                       "struc_dup":initial_value0, 
                                                                                                       "value_mutate":initial_value0,
                                                                                                       "sum":initial_value0
                                                                                                      },
                                                                                              "dis":{"struc_add":initial_value0, 
                                                                                                     "struc_dup":initial_value0, 
                                                                                                     "value_mutate":initial_value0,
                                                                                                     "sum":initial_value0
                                                                                                     },
                                                                                              "fitness":{"struc_add":initial_value0, 
                                                                                                         "struc_dup":initial_value0, 
                                                                                                         "value_mutate":initial_value0,
                                                                                                         "total":initial_value0
                                                                                                         },
                                                                                              "earlybound":{"struc_add":initial_value1, 
                                                                                                            "struc_dup":initial_value1, 
                                                                                                            "value_mutate":initial_value1
                                                                                                            },
                                                                                              "hardbound":{"struc_add":initial_value1, 
                                                                                                           "struc_dup":initial_value1, 
                                                                                                           "value_mutate":initial_value2
                                                                                                           }
                                                                                              }, # inhibit anyPolicy
                                                                         "subject alternative name":{"parent":"standard extensions", 
                                                                                                     "count":{"struc_add":initial_value0, 
                                                                                                              "struc_dup":initial_value0, 
                                                                                                              "sum":initial_value0
                                                                                                              },
                                                                                                     "dis":{"struc_add":initial_value0, 
                                                                                                            "struc_dup":initial_value0, 
                                                                                                            "sum":initial_value0
                                                                                                            },
                                                                                                     "fitness":{"struc_add":initial_value0, 
                                                                                                                "struc_dup":initial_value0, 
                                                                                                                "total":initial_value0
                                                                                                                },
                                                                                                     "earlybound":{"struc_add":initial_value1, 
                                                                                                                   "struc_dup":initial_value1, 
                                                                                                                   },
                                                                                                     "hardbound":{"struc_add":initial_value1, 
                                                                                                                  "struc_dup":initial_value1, 
                                                                                                                  }
                                                                                                     }, # subject alternative name 
                                                                         "issuer alternative name":{"parent":"standard extensions", 
                                                                                                    "count":{"struc_add":initial_value0, 
                                                                                                             "struc_dup":initial_value0, 
                                                                                                             "sum":initial_value0
                                                                                                             },
                                                                                                    "dis":{"struc_add":initial_value0, 
                                                                                                             "struc_dup":initial_value0, 
                                                                                                             "sum":initial_value0
                                                                                                           },
                                                                                                    "fitness":{"struc_add":initial_value0, 
                                                                                                               "struc_dup":initial_value0, 
                                                                                                               "total":initial_value0
                                                                                                               },
                                                                                                    "earlybound":{"struc_add":initial_value1, 
                                                                                                                  "struc_dup":initial_value1, 
                                                                                                                  },
                                                                                                    "hardbound":{"struc_add":initial_value1, 
                                                                                                                 "struc_dup":initial_value1, 
                                                                                                                 }
                                                                                                    }, # issuer alternative name
                                                                         "subject directory attributes":{"parent":"standard extensions", 
                                                                                                         "count":{"struc_add":initial_value0, 
                                                                                                                  "sum":initial_value0
                                                                                                                  },
                                                                                                         "dis":{"struc_add":initial_value0, 
                                                                                                                "sum":initial_value0
                                                                                                                },
                                                                                                         "fitness":{"struc_add":initial_value0, 
                                                                                                                    "total":initial_value0
                                                                                                                    },
                                                                                                         "earlybound":{"struc_add":initial_value1, 
                                                                                                                       },
                                                                                                         "hardbound":{"struc_add":initial_value1, 
                                                                                                                      }
                                                                                                         }, # subject directory attributes
                                                                         "CRL distribution points":{"parent":"standard extensions", 
                                                                                                    "distributionPoint":{"parent":"CRL distribution points", 
                                                                                                                         "count":{"struc_add":initial_value0, 
                                                                                                                                  "struc_del":initial_value0, 
                                                                                                                                  #"value_mutate":initial_value0,
                                                                                                                                  "sum":initial_value0
                                                                                                                                  },
                                                                                                                         "dis":{"struc_add":initial_value0, 
                                                                                                                                "struc_del":initial_value0, 
                                                                                                                                #"value_mutate":initial_value0,
                                                                                                                                "sum":initial_value0
                                                                                                                                },
                                                                                                                         "fitness":{"struc_add":initial_value0, 
                                                                                                                                    "struc_del":initial_value0, 
                                                                                                                                    #"value_mutate":initial_value0,
                                                                                                                                    "total":initial_value0
                                                                                                                                    },
                                                                                                                         "earlybound":{"struc_add":initial_value1, 
                                                                                                                                       "struc_del":initial_value1, 
                                                                                                                                       #"value_mutate":initial_value1
                                                                                                                                       },
                                                                                                                         "hardbound":{"struc_add":initial_value1, 
                                                                                                                                      "struc_del":initial_value1, 
                                                                                                                                      #"value_mutate":initial_value2
                                                                                                                                      }
                                                                                                                         }, # distributionPoint                
                                                                                                   "reasons":{"parent":"CRL distribution points", 
                                                                                                              "count":{"struc_add":initial_value0, 
                                                                                                                       "struc_del":initial_value0, 
                                                                                                                        #"value_mutate":initial_value0,
                                                                                                                       "sum":initial_value0
                                                                                                                       },
                                                                                                              "dis":{"struc_add":initial_value0, 
                                                                                                                     "struc_del":initial_value0, 
                                                                                                                     "value_mutate":initial_value0,
                                                                                                                     "sum":initial_value0
                                                                                                                     },
                                                                                                              "fitness":{"struc_add":initial_value0, 
                                                                                                                         "struc_del":initial_value0, 
                                                                                                                         #"value_mutate":initial_value0,
                                                                                                                         "total":initial_value0
                                                                                                                         },
                                                                                                              "earlybound":{"struc_add":initial_value1, 
                                                                                                                            "struc_del":initial_value1, 
                                                                                                                            #"value_mutate":initial_value1
                                                                                                                            },
                                                                                                              "hardbound":{"struc_add":initial_value1, 
                                                                                                                           "struc_del":initial_value1, 
                                                                                                                           #"value_mutate":initial_value2
                                                                                                                           }
                                                                                                              }, # reasons
                                                                                                   "cRLIssuer":{"parent":"CRL distribution points", 
                                                                                                                "count":{"struc_add":initial_value0, 
                                                                                                                         "struc_del":initial_value0, 
                                                                                                                         #"value_mutate":initial_value0,
                                                                                                                         "sum":initial_value0
                                                                                                                         },
                                                                                                                "dis":{"struc_add":initial_value0, 
                                                                                                                       "struc_del":initial_value0, 
                                                                                                                       #"value_mutate":initial_value0,
                                                                                                                       "sum":initial_value0
                                                                                                                       },
                                                                                                                "fitness":{"struc_add":initial_value0, 
                                                                                                                           "struc_del":initial_value0, 
                                                                                                                           #"value_mutate":initial_value0,
                                                                                                                           "total":initial_value0
                                                                                                                           },
                                                                                                                "earlybound":{"struc_add":initial_value1, 
                                                                                                                              "struc_del":initial_value1, 
                                                                                                                              #"value_mutate":initial_value1
                                                                                                                              },
                                                                                                                "hardbound":{"struc_add":initial_value1, 
                                                                                                                             "struc_del":initial_value1, 
                                                                                                                             #"value_mutate":initial_value2
                                                                                                                             }
                                                                                                                }, # cRLIssuer 
                                                                                                    "count":{"struc_add":initial_value0, 
                                                                                                             "struc_del":initial_value0, 
                                                                                                             "sum":initial_value0
                                                                                                            },
                                                                                                    "dis":{"struc_add":initial_value0, 
                                                                                                           "struc_del":initial_value0, 
                                                                                                           "sum":initial_value0
                                                                                                           },
                                                                                                    "fitness":{"struc_add":initial_value0, 
                                                                                                               "struc_del":initial_value0, 
                                                                                                               "total":initial_value0
                                                                                                               },
                                                                                                    "earlybound":{"struc_add":initial_value1, 
                                                                                                                  "struc_del":initial_value1, 
                                                                                                                  },
                                                                                                    "hardbound":{"struc_add":initial_value1, 
                                                                                                                 "struc_del":initial_value1, 
                                                                                                                 }
                                                                                                    }, # CRL distribution points
                                                                         "freshest CRL":{"parent":"standard extensions", 
                                                                                         "distributionPoint2":{"parent":"freshest CRL", 
                                                                                                               "count":{"struc_add":initial_value0, 
                                                                                                                        "struc_del":initial_value0, 
                                                                                                                        #"value_mutate":initial_value0,
                                                                                                                        "sum":initial_value0
                                                                                                                        },
                                                                                                               "dis":{"struc_add":initial_value0, 
                                                                                                                      "struc_del":initial_value0, 
                                                                                                                      #"value_mutate":initial_value0,
                                                                                                                      "sum":initial_value0
                                                                                                                      },
                                                                                                               "fitness":{"struc_add":initial_value0, 
                                                                                                                          "struc_del":initial_value0, 
                                                                                                                          #"value_mutate":initial_value0,
                                                                                                                          "total":initial_value0
                                                                                                                          },
                                                                                                               "earlybound":{"struc_add":initial_value1, 
                                                                                                                             "struc_del":initial_value1, 
                                                                                                                             #"value_mutate":initial_value1
                                                                                                                             },
                                                                                                               "hardbound":{"struc_add":initial_value1, 
                                                                                                                            "struc_del":initial_value1, 
                                                                                                                            #"value_mutate":initial_value2
                                                                                                                            }
                                                                                                               }, # distributionPoint                
                                                                                         "reasons2":{"parent":"freshest CRL", 
                                                                                                     "count":{"struc_add":initial_value0, 
                                                                                                              "struc_del":initial_value0, 
                                                                                                              #"value_mutate":initial_value0,
                                                                                                              "sum":initial_value0
                                                                                                              },
                                                                                                     "dis":{"struc_add":initial_value0, 
                                                                                                            "struc_del":initial_value0, 
                                                                                                            #"value_mutate":initial_value0,
                                                                                                            "sum":initial_value0
                                                                                                            },
                                                                                                     "fitness":{"struc_add":initial_value0, 
                                                                                                                "struc_del":initial_value0, 
                                                                                                                #"value_mutate":initial_value0,
                                                                                                                "total":initial_value0
                                                                                                                },
                                                                                                     "earlybound":{"struc_add":initial_value1, 
                                                                                                                   "struc_del":initial_value1, 
                                                                                                                   #"value_mutate":initial_value1
                                                                                                                   },
                                                                                                     "hardbound":{"struc_add":initial_value1, 
                                                                                                                  "struc_del":initial_value1, 
                                                                                                                  #"value_mutate":initial_value2
                                                                                                                  }
                                                                                                     }, # reasons
                                                                                         "cRLIssuer2":{"parent":"freshest CRL", 
                                                                                                       "count":{"struc_add":initial_value0, 
                                                                                                                "struc_del":initial_value0, 
                                                                                                                #"value_mutate":initial_value0,
                                                                                                                "sum":initial_value0
                                                                                                                },
                                                                                                       "dis":{"struc_add":initial_value0, 
                                                                                                              "struc_del":initial_value0, 
                                                                                                              #"value_mutate":initial_value0,
                                                                                                              "sum":initial_value0
                                                                                                              },
                                                                                                       "fitness":{"struc_add":initial_value0, 
                                                                                                                  "struc_del":initial_value0, 
                                                                                                                  #"value_mutate":initial_value0,
                                                                                                                  "total":initial_value0
                                                                                                                  },
                                                                                                       "earlybound":{"struc_add":initial_value1, 
                                                                                                                     "struc_del":initial_value1, 
                                                                                                                     #"value_mutate":initial_value1
                                                                                                                     },
                                                                                                       "hardbound":{"struc_add":initial_value1, 
                                                                                                                    "struc_del":initial_value1, 
                                                                                                                    #"value_mutate":initial_value2
                                                                                                                    }
                                                                                                      }, # cRLIssuer 
                                                                                          "count":{"struc_add":initial_value0, 
                                                                                                   "struc_del":initial_value0, 
                                                                                                   "sum":initial_value0
                                                                                                   },
                                                                                          "dis":{"struc_add":initial_value0, 
                                                                                                 "struc_del":initial_value0, 
                                                                                                 "sum":initial_value0
                                                                                                 },
                                                                                          "fitness":{"struc_add":initial_value0, 
                                                                                                     "struc_del":initial_value0, 
                                                                                                     "total":initial_value0
                                                                                                     },
                                                                                          "earlybound":{"struc_add":initial_value1, 
                                                                                                        "struc_del":initial_value1, 
                                                                                                        },
                                                                                          "hardbound":{"struc_add":initial_value1, 
                                                                                                       "struc_del":initial_value1, 
                                                                                                       }
                                                                                          }, # freshest CRL 
                                                                         "count":{"sum":initial_value0},
                                                                         "dis":{"sum":initial_value0},
                                                                         "fitness":{"total":initial_value0},
                                                                         "earlybound":{"struc_add":initial_value1},
                                                                         "hardbound":{"struc_add":initial_value1}
                                                                        }, # standard extensions (logical, do not exist in real certificates
                                                  "private Internet extensions":{"parent":"extensions", 
                                                                                 "authority information access":{"parent":"private Internet extensions", 
                                                                                                                 "count":{"struc_add":initial_value0, 
                                                                                                                          "struc_dup":initial_value0, 
                                                                                                                          "sum":initial_value0
                                                                                                                          },
                                                                                                                 "dis":{"struc_add":initial_value0, 
                                                                                                                        "struc_dup":initial_value0, 
                                                                                                                        "sum":initial_value0
                                                                                                                        },
                                                                                                                 "fitness":{"struc_add":initial_value0, 
                                                                                                                            "struc_dup":initial_value0, 
                                                                                                                            "total":initial_value0
                                                                                                                            },
                                                                                                                 "earlybound":{"struc_add":initial_value1, 
                                                                                                                               "struc_dup":initial_value1, 
                                                                                                                               },
                                                                                                                 "hardbound":{"struc_add":initial_value1, 
                                                                                                                              "struc_dup":initial_value1, 
                                                                                                                              }
                                                                                                                }, # authority information access
                                                                                 "subject information access":{"parent":"private Internet extensions", 
                                                                                                               "count":{"struc_add":initial_value0, 
                                                                                                                        "struc_dup":initial_value0, 
                                                                                                                        "sum":initial_value0
                                                                                                                            },
                                                                                                               "dis":{"struc_add":initial_value0, 
                                                                                                                      "struc_dup":initial_value0, 
                                                                                                                      "sum":initial_value0
                                                                                                                      },
                                                                                                               "fitness":{"struc_add":initial_value0, 
                                                                                                                          "struc_dup":initial_value0, 
                                                                                                                          "total":initial_value0
                                                                                                                          },
                                                                                                               "earlybound":{"struc_add":initial_value1, 
                                                                                                                             "struc_dup":initial_value1, 
                                                                                                                             },
                                                                                                               "hardbound":{"struc_add":initial_value1, 
                                                                                                                            "struc_dup":initial_value1, 
                                                                                                                            }
                                                                                                               }, # subject information access   
                                                                                 "count":{"sum":initial_value0},
                                                                                 "dis":{"sum":initial_value0},
                                                                                 "fitness":{"total":initial_value0},
                                                                                 "earlybound":{"struc_add":initial_value1},
                                                                                 "hardbound":{"struc_add":initial_value1}
                                                                                }, # private Internet extensions (logical, do not exist in real certificates)
                                                  "legacy extensions":{"parent":"extensions",  # users have the choice to disable this part
                                                                       "nsComment":{"parent":"legacy extensions", 
                                                                                    "count":{"struc_add":initial_value0, 
                                                                                             "struc_dup":initial_value0, 
                                                                                             "sum":initial_value0
                                                                                             },
                                                                                    "dis":{"struc_add":initial_value0, 
                                                                                           "struc_dup":initial_value0, 
                                                                                           "sum":initial_value0
                                                                                           },
                                                                                    "fitness":{"struc_add":initial_value0, 
                                                                                               "struc_dup":initial_value0, 
                                                                                               "total":initial_value0
                                                                                               },
                                                                                    "earlybound":{"struc_add":initial_value1, 
                                                                                                  "struc_dup":initial_value1, 
                                                                                                  },
                                                                                    "hardbound":{"struc_add":initial_value1, 
                                                                                                 "struc_dup":initial_value1, 
                                                                                                 }
                                                                                    }, # nsComment
                                                                       "nsCertType":{"parent":"legacy extensions", 
                                                                                     "count":{"struc_add":initial_value0, 
                                                                                              "struc_dup":initial_value0, 
                                                                                              "sum":initial_value0
                                                                                              },
                                                                                     "dis":{"struc_add":initial_value0, 
                                                                                            "struc_dup":initial_value0, 
                                                                                            "sum":initial_value0
                                                                                            },
                                                                                     "fitness":{"struc_add":initial_value0, 
                                                                                                "struc_dup":initial_value0, 
                                                                                                "total":initial_value0
                                                                                                },
                                                                                     "earlybound":{"struc_add":initial_value1, 
                                                                                                   "struc_dup":initial_value1, 
                                                                                                   },
                                                                                     "hardbound":{"struc_add":initial_value1, 
                                                                                                  "struc_dup":initial_value1, 
                                                                                                  }
                                                                                    }, # nsCertType 
                                                                        "commonName":{"parent":"legacy extensions", 
                                                                                      "count":{"struc_add":initial_value0, # simple test
                                                                                               "sum":initial_value0
                                                                                               },
                                                                                      "dis":{"struc_add":initial_value0, 
                                                                                             "sum":initial_value0
                                                                                             },
                                                                                      "fitness":{"struc_add":initial_value0, 
                                                                                                 "total":initial_value0
                                                                                                 },
                                                                                      "earlybound":{"struc_add":initial_value1, 
                                                                                                    },
                                                                                      "hardbound":{"struc_add":initial_value1, 
                                                                                                   } #hardbound                                                                            
                                                                                      },  # commonName
                                                                         # other user-defined legacy extensions
                                                                       "count":{"sum":initial_value0},
                                                                       "dis":{"sum":initial_value0},
                                                                       "fitness":{"total":initial_value0}, # The legacy extensions do not exist in real certificates.
                                                                       "earlybound":{"struc_add":initial_value1,},
                                                                       "hardbound":{"struc_add":initial_value1,}
                                                                      }, # legacy extensions
                                                   "count":{"struc_add":initial_value0, 
                                                            "sum":initial_value0
                                                            },
                                                   "dis":{"struc_add":initial_value0, 
                                                          "sum":initial_value0
                                                          },
                                                   "fitness":{"struc_add":initial_value0, 
                                                              "total":initial_value0
                                                              },
                                                   "earlybound":{"struc_add":initial_value1, # add an empty ext
                                                                 },
                                                   "hardbound":{"struc_add":initial_value2, 
                                                                } # dis of extensions
                                                   }, # extensions
                             "count":{"sum":initial_value0},
                             "dis":{"sum":initial_value0},
                             "fitness":{"total":initial_value0},
                             "earlybound":{"struc_add":initial_value1},
                             "hardbound":{"struc_add":initial_value1} # tbsCertificate
                            }, # tbsCertificate
                   "signature algorithm":{"parent":"cert", 
                                          "count":{"struc_del":initial_value0, 
                                                   "struc_add":initial_value0, 
                                                   "sum":initial_value0
                                                  },
                                          "dis":{"struc_del":initial_value0, 
                                                 "struc_add":initial_value0, 
                                                 "sum":initial_value0
                                                 },
                                          "fitness":{"struc_del":initial_value0, 
                                                     "struc_add":initial_value0, 
                                                     "total":initial_value0
                                                     },
                                          "earlybound":{"struc_del":initial_value1, 
                                                        "struc_add":initial_value1, 
                                                        },
                                          "hardbound":{"struc_del":initial_value1, 
                                                       "struc_add":initial_value1, 
                                                       }
                                         }, # signature algorithm
                   "signature value":{"parent":"cert", 
                                      "count":{"struc_del":initial_value0, 
                                               "struc_add":initial_value0, 
                                               "sum":initial_value0
                                               },
                                      "dis":{"struc_del":initial_value0, 
                                             "struc_add":initial_value0, 
                                             "sum":initial_value0
                                             },
                                      "fitness":{"struc_del":initial_value0, 
                                                 "struc_add":initial_value0, 
                                                 "total":initial_value0
                                                 },
                                      "earlybound":{"struc_del":initial_value1, 
                                                    "struc_add":initial_value1, 
                                                    },
                                      "hardbound":{"struc_del":initial_value1, 
                                                   "struc_add":initial_value1, 
                                                   }
                                     }, # signature value
                   "count":{"sum":initial_value0}, 
                   "dis":{"sum":initial_value0}, 
                   "fitness":{"total":initial_value0}, 
                   "earlybound":{"struc_add":initial_value1},   
                   "hardbound":{"struc_add":initial_value1}, 
                   } # cert
           } # MST
    
    return MST


def query_MST(d, query_key):
    """ To query whether a node i.e., 'query_key' exists in a 'd' (i.e., dict) and return the path from root to it.
    @param d: A dict (a MST and any subtree is a dict); 
    @param query_key: A node to be searched;
    @return: A path from root to the node.
    """
    traverse_node_list = []
    if isinstance(d, dict):
        if query_key in d.keys():
            traverse_node_list.extend([query_key])
            return traverse_node_list
        else:
            for k, v in d.items():
                ret = query_MST(v, query_key)
                if ret:
                    traverse_node_list.extend([k])
                    traverse_node_list.extend(ret)
                    return(traverse_node_list)
                else:
                    pass
    else:
        pass


def get_subtrees_from_root_to_node(MST, node_name):
    """ To get a list of subtrees whose root node comes from query_MST i.e., root to node_name.
    @param MST: The model;
    @param node_name: A node name (the root of the lowest level subtree);
    @return: A list of subtrees (a list of dicts).
    """
    desired_subtrees = [] 
    path_from_root = query_MST(MST, node_name) 
    
    if path_from_root:
        father_node_subtree = {}
        for node_name in path_from_root:
            if path_from_root.index(node_name) == 0: 
                father_node_subtree = MST[node_name]
            else:
                father_node_subtree = father_node_subtree[node_name]
            desired_subtrees.append({node_name:father_node_subtree})
        return desired_subtrees
    else:
        return None
    

def select_node_and_muop(cur_tree, cur_root):
    """ To select a node and a mutation operator (abbr. muop). 
    @param cur_tree: Current tree;
    @param cur_root: Current root;
    @return: A selected node and one mutation operator if it does not reach any bound and its fitness is higher than others.
    """
    
    other_children = {"parent", "count", "dis", "fitness", "earlybound", "hardbound"}
    children_keys = cur_tree[cur_root].keys() - other_children
    
    cur_dict = cur_tree[cur_root]
    fitness_dict = cur_dict["fitness"]
    if "earlybound" in cur_dict.keys() and "hardbound" in cur_dict.keys():
        earlybound_dict = cur_dict["earlybound"]
        hardbound_dict = cur_dict["hardbound"]
    
    max_fitness = -1 
    max_fitness_muop = '' 
    
    if len(children_keys) == 0: 
        for muop in fitness_dict.keys() - {"total"}: 
            if earlybound_dict[muop] > 0 and hardbound_dict[muop] > 0:
                if fitness_dict[muop] > max_fitness:
                    max_fitness = fitness_dict[muop]
                    max_fitness_muop = muop
        if max_fitness >= 0:
            return cur_root, max_fitness_muop
        else:
            return None             
    elif len(children_keys) > 0: 
        unsorted_children_fitness = []
        sorted_children_keys = []
        sorted_children_fitness = [] 
        for child_key in children_keys:
            unsorted_children_fitness.append(cur_dict[child_key]["fitness"]["total"])
        pdf1 = pd.DataFrame([unsorted_children_fitness,children_keys])
        pdf2 = pdf1.T
        pdf3 = pdf2.sort_values(by=[0])
        sorted_children_fitness = list(pdf3[0])
        sorted_children_keys = list(pdf3[1])
        
        for child_key in sorted_children_keys:
            child_values = cur_dict[child_key]
            ret = select_node_and_muop({child_key:child_values}, child_key)
            if ret: 
                return ret
            else:
                continue
            
        if len(fitness_dict.keys()) == 1: 
            if earlybound_dict["struc_add"] > 0 and hardbound_dict["struc_add"] > 0:
                return cur_root, fitness_dict["total"] 
            else:
                return None
        else: 
            for muop in fitness_dict.keys() - {"total"}:  
                if muop in earlybound_dict.keys() and muop in hardbound_dict.keys():
                    if earlybound_dict[muop] > 0 and hardbound_dict[muop] > 0:
                        if fitness_dict[muop] > max_fitness:
                            max_fitness = fitness_dict[muop]
                            max_fitness_muop = muop
                        else:
                            pass 
                else:
                    if fitness_dict[muop] > max_fitness:
                        max_fitness = fitness_dict[muop]
                        max_fitness_muop = muop
            if max_fitness >= 0:
                return cur_root, max_fitness_muop
            else:
                return None
        
        
def update_MST(MST, node_name, op, num_dis):
    """ To update dis of a MST in a bottom-up manner.
    @param MST: The model;
    @param node_name: A node name;
    @param op: An operator; 
    @param num_dis: The number of discrepancies found by Hunter;
    @return: An updated MST (its count, dis, fitness, earlybound, and hardbound).
    """
    higher_subtrees = get_subtrees_from_root_to_node(MST, node_name)
    bottom_up_subtrees = higher_subtrees[::-1]
    
    for subtree in bottom_up_subtrees:
        cur_tree = subtree
        if bottom_up_subtrees.index(subtree) == 0: 
            if op == None: 
                if num_dis == 0:
                    cur_tree[node_name]["earlybound"]["struc_add"] -= 1 
                cur_tree[node_name]["hardbound"]["struc_add"] -= 1 
            else: 
                print(node_name, op)
                cur_tree[node_name]["count"][op] += 1
                cur_tree[node_name]["count"]["sum"] += 1
                cur_tree[node_name]["dis"][op] += num_dis
                cur_tree[node_name]["dis"]["sum"] += num_dis
                cur_tree[node_name]["fitness"][op] = cur_tree[node_name]["dis"][op] / cur_tree[node_name]["count"][op]
                cur_tree[node_name]["fitness"]["total"] = cur_tree[node_name]["dis"]["sum"] / cur_tree[node_name]["count"]["sum"]
                if num_dis == 0:
                    cur_tree[node_name]["earlybound"][op] -= 1 
                cur_tree[node_name]["hardbound"][op] -= 1    
        else: 
            for k in cur_tree.keys(): 
                if op == None: 
                    pass
                else: 
                    if len(cur_tree[k]["count"]) > 1: 
                        cur_tree[k]["count"]["sum"] += 1
                        cur_tree[k]["dis"]["sum"] += num_dis
                        cur_tree[k]["fitness"]["total"] = cur_tree[k]["dis"]["sum"] / cur_tree[k]["count"]["sum"]
                    else: 
                        cur_tree[k]["count"]["sum"] += 1
                        cur_tree[k]["dis"]["sum"] += num_dis
                        cur_tree[k]["fitness"]["total"] = cur_tree[k]["dis"]["sum"] / cur_tree[k]["count"]["sum"]
                
                
def mutate_cert(node_name_list, muop, ca_private_key, ec_public_key):
    """ The function employs two parameters i.e., node_name_list and muop to 
    generate a mutated certificate.
    @param node_name_list: A list of node names (one node name if a leaf node is selected; 
    two or more children node names if a root or intermediate node is selected);
    @param muop: A mutation operator of the node;
    @ca_private_key: The private key of CA;
    @ec_public_key: The public key of EC;
    @return: A mutated certificate or None (None if no certificate file is generated).
    """
    node_muop_id = ''
    
    cert = crypto.X509()
    ext = None
    
    if not node_name_list.count("validity"):
        cert.set_notBefore(b"20190619085559Z")
        cert.gmtime_adj_notAfter(60*60*24*365*10)
    
    try:
        if "version" in node_name_list:
            if muop == "struc_del":
                pass # In fact, pyOpenSSL set it to version 1 by default.
                node_muop_id = 1
            elif muop == "struc_add":
                cert.set_version(2)
                node_muop_id = 2
            elif muop == "value_mutate":
                version_value = random.choice([-1, 6])
                cert.set_version(version_value)
                node_muop_id = 3
        if "serial number" in node_name_list:
            if muop == "struc_del":
                pass # In fact, pyOpenSSL set it to default by default.
                node_muop_id = 4
            elif muop == "struc_add":
                serial_number = random.randint(0, 2**160)
                cert.set_serial_number(serial_number)
                node_muop_id = 5
            elif muop == "value_mutate":
                serial_number = random.randint(2**160+1, 2**161)
                cert.set_serial_number(serial_number)
                node_muop_id = 6
        if "tbsCertSignature" in node_name_list:
            if muop == "struc_del":
                pass # In fact, pyOpenSSL set it to default (tbsCertSignature == Cert.signatureAlgorithm)
                node_muop_id = 7
            elif muop == "struc_add":
                pass # call Java program in the main function
                node_muop_id = 8
            # "muop == value_mutate" is executed by Java. 
        if "validity" in node_name_list:
            if muop == "struc_del":
                pass # unable to load certificates
                node_muop_id = 9
            elif muop == "struc_add":
                cert.set_notBefore(b"20190619085559Z") # for simplicity. Deep test will be conducted in DERmutator
                cert.set_notAfter(b"20290619085559Z")
                node_muop_id = 10
            elif muop == "value_mutate":
                cert.set_notBefore(b"20190619085559Z")
                cert.gmtime_adj_notAfter(random.randint(-10,-1)*60*60*24*365)
                node_muop_id = 11   
        random_start = 2
        random_end = 21
        random_int = random.randint(random_start, random_end) 
        if "issuer" in node_name_list:
            issuer = cert.get_issuer()
            issuer.C = "UN"
            issuer.ST = "NYS"
            issuer.O = "UNGA"
            issuer.OU = "UNSC"
            issuer.dnQualifier = "dnQ1"
            issuer.DC = "DC1"
            issuer.CN = "Susan Housley1"
            issuer.serialNumber = "serialNumber1"
            if muop == "struc_del":
                pass
                node_muop_id = 12
            elif muop == "struc_add":
                cert.set_issuer(issuer)
                node_muop_id = 13
            elif muop == "value_mutate":
                issuer.C = "nc" # get_random_str(2) # 3 or longer str is valid in obsolete versions of pyOpenSSL
                issuer.ST = get_random_str(random_int) # some non-English characters
                issuer.L = get_random_str(random_int)
                issuer.O = get_random_str(random_int)
                issuer.OU = get_random_str(random_int)
                issuer.CN = get_random_str(random_int)
                issuer.title = get_random_str(random_int) 
                issuer.SN = get_random_str(random_int)
                issuer.GN = get_random_str(random_int)
                issuer.initials = get_random_str(random_int)
                issuer.pseudonym = get_random_str(random_int)
                issuer.generationQualifier = get_random_str(random_int)
                issuer.DC = get_random_str(random_int)
                issuer.street = get_random_str(random_int)
                issuer.businessCategory = get_random_str(random_int)
                issuer.jurisdictionC = get_random_chars(2)
                issuer.jurisdictionST = get_random_str(random_int)
                issuer.jurisdictionL = get_random_str(random_int)
                issuer.postalAddress = get_random_str(random_int)
                issuer.postalCode = get_random_str(random_int)
                issuer.userId = get_random_str(random_int)
                issuer.uid = get_random_str(random_int)
                issuer.UID = get_random_str(random_int)
                issuer.serialNumber = str(random_int)
                issuer.x500UniqueIdentifier = get_random_str(random_int)
                cert.set_issuer(issuer)
                node_muop_id = 14
        if "subject" in node_name_list: 
            subject = crypto.X509().get_issuer()
            subject.C = 'UN'
            subject.ST = 'New York State'
            subject.O = 'Counter-Terrorism Committee'
            subject.OU = 'network security, Counter-Terrorism Committee'
            subject.dnQualifier = 'dnQ2' 
            subject.DC = 'DC2'
            subject.CN = "Susan Housley2"
            subject.serialNumber = 'serialNumber2'
            if muop == "struc_del":
                pass
                node_muop_id = 15
            elif muop == "struc_add":
                cert.set_subject(subject)
                node_muop_id = 16
            elif muop == "value_mutate":
                subject = crypto.X509Name(crypto.X509().get_subject())
                subject.C = get_random_chars(2)
                subject.ST = get_random_str(random_int)
                subject.L = get_random_str(random_int)
                subject.O = get_random_str(random_int)
                subject.OU = get_random_str(random_int)
                subject.CN = get_random_str(random_int)
                subject.emailAddress = get_random_str(random_int)
                subject.dnQualifier = get_random_str(random_int)
                #subject.T = get_random_str(random_int) #?
                subject.title = get_random_str(random_int)
                subject.SN = get_random_str(random_int)
                subject.GN = get_random_str(random_int)
                subject.initials = get_random_str(random_int)
                subject.pseudonym = get_random_str(random_int)
                subject.generationQualifier = get_random_str(random_int)
                subject.DC = get_random_str(random_int) 
                subject.street = get_random_str(random_int)
                subject.businessCategory = get_random_str(random_int)
                subject.jurisdictionC = get_random_chars(2)
                subject.jurisdictionST = get_random_str(random_int)
                subject.jurisdictionL = get_random_str(random_int)
                subject.postalAddress = get_random_str(random_int)
                subject.postalCode = get_random_str(random_int)
                subject.userId = get_random_str(random_int)
                subject.uid = get_random_str(random_int)
                subject.UID = get_random_str(random_int)
                subject.serialNumber = str(random_int)
                subject.x500UniqueIdentifier = get_random_str(random_int)
                cert.set_subject(subject)
                node_muop_id = 17
        # issuer/subject unique identifier will be processed in the main function. 
        if "subject public key information" in node_name_list:
            if muop == "struc_del":
                pass # nothing to do; the subject public key information will not included in the cert
                node_muop_id = 18
            elif muop == "struc_add":
                cert.set_pubkey(ec_public_key)
                node_muop_id = 19
        exts = []
        if node_name_list == ["cA"]:
            ext_name = b"basicConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"CA:TRUE"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 20
            elif muop == "struc_dup":
                ext_fields = b"CA:TRUE, CA:TRUE"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 21
            elif muop == "struc_del":
                ext_fields = b"pathlen:0"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 22
        if node_name_list == ['pathLenConstraint']:
            ext_name = b"basicConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"pathlen:1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 23
            elif muop == "struc_dup":
                ext_fields = b"pathlen:1, pathlen:2"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 24
            elif muop == "struc_del":
                ext_fields = b"CA:FALSE"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 25
            elif muop == "value_mutate":
                #pathlen_value = random.randint(-2, -1)
                #ext_fields = b"CA:FALSE,pathlen:"+str(pathlen_value)
                ext_fields = b"CA:FALSE,pathlen:-1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 26
        if node_name_list == ["cA", "pathLenConstraint"]:
            ext_name = b"basicConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"CA:FALSE,pathlen:0"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 27
            elif muop == "struc_dup":
                ext_fields = b"CA:FALSE,pathlen:0"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 28
        if node_name_list == ["permittedSubtrees"]:
            ext_name = b"nameConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"permitted;email:un.org"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 29
            elif muop == "value_mutate":
                ext_fields = b"permitted;email:un.org,permitted;DNS:www.a.com,permitted;IP:192.168.123.1/255.255.255.0,permitted;email:un.com"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 30
        if node_name_list == ["excludedSubtrees"]:
            ext_name = b"nameConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"excluded;email:un.com"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 31
            elif muop == "value_mutate":
                ext_fields = b"excluded;email:un.com,excluded;DNS:www.b.com"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 32    
        if node_name_list == ["permittedSubtrees", "excludedSubtrees"]:
            ext_name = b"nameConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"permitted;email:un.org,permitted;DNS:www.a.com,permitted;IP:192.168.123.1/255.255.255.0,\
                excluded;email:un.com,excluded;DNS:www.b.com,excluded;IP:192.168.123.2/255.255.255.0"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 33
            elif muop == "struc_dup":
                ext_fields = b"permitted;email:un.org,permitted;DNS:www.a.com,permitted;IP:192.168.123.1/255.255.255.0,\
                excluded;email:un.com,excluded;DNS:www.b.com,excluded;IP:192.168.123.2/255.255.255.0"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 34
        if node_name_list == ["requireExplicitPolicy"]:
            ext_name = b"policyConstraints"
            ext_critical = random.randint(0, 1) 
            if muop == "struc_add":
                ext_fields = b"requireExplicitPolicy:1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 35
            elif muop == "struc_dup":
                ext_fields = b"requireExplicitPolicy:1,requireExplicitPolicy:2"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 36
            elif muop == "value_mutate":
                ext_fields = b"requireExplicitPolicy:-1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 37
        if node_name_list == ["inhibitPolicyMapping"]:
            ext_name = b"policyConstraints"
            ext_critical = random.randint(0, 1) 
            if muop == "struc_add":
                ext_fields = b"inhibitPolicyMapping:1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 38
            elif muop == "struc_dup":
                ext_fields = b"inhibitPolicyMapping:1,inhibitPolicyMapping:2"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 39
            elif muop == "value_mutate":
                ext_fields = b"inhibitPolicyMapping:1" # -1
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 40
        if node_name_list == ["requireExplicitPolicy", "inhibitPolicyMapping"]:
            ext_name = b"policyConstraints"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"requireExplicitPolicy:1, inhibitPolicyMapping:1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 41
            elif muop == "struc_dup":
                ext_fields = b"requireExplicitPolicy:1, inhibitPolicyMapping:1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields) 
                exts.append(ext) 
                node_muop_id = 42                  
        if node_name_list == ["keyIdentifier"]: 
            ext_name = b"authorityKeyIdentifier"
            ext_critical = random.randint(0, 1)
            if muop == "struc_del":
                ext_fields = b"issuer"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 43
            elif muop == "struc_add":
                ext_fields = b"keyid"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 44
        if node_name_list == ["authorityCertIssuer"]: 
            ext_name = b"authorityKeyIdentifier"
            ext_critical = random.randint(0, 1)
            if muop == "struc_del":
                ext_fields = b"keyid"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 45
            elif muop == "struc_add":
                ext_fields = b"issuer"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 46
        if node_name_list == ["authorityCertSerialNumber"]:
            ext_name = b"authorityKeyIdentifier"
            ext_critical = random.randint(0, 1)
            if muop == "struc_del":
                ext_fields = b"keyid"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 47
            elif muop == "struc_add":
                ext_fields = b"issuer"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 48
        if "keyIdentifier" in node_name_list and "authorityCertIssuer" in node_name_list and "authorityCertSerialNumber" in node_name_list:
            ext_name = b"authorityKeyIdentifier"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"keyid, issuer"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                node_muop_id = 49
            elif muop == "struc_dup":
                ext_fields = b"keyid, issuer"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, issuer=cert)
                exts.append(ext)
                node_muop_id = 50
        if node_name_list == ["keyIdentifier2"]:
            ext_name = b"subjectKeyIdentifier"
            ext_critical = random.randint(0, 1)
            if muop == "struc_del":
                ext_fields = b"hash"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, subject=cert)
                node_muop_id = 51
            elif muop == "struc_add":
                ext_fields = b"hash"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, subject=cert)
                node_muop_id = 52
            elif muop == "struc_dup":
                ext_fields = b"hash"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields, subject=cert)
                exts.append(ext) 
                node_muop_id = 53   
        if node_name_list == ["key usage"]:
            ext_name = b"keyUsage"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"keyCertSign"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 54
            elif muop == "struc_dup":
                ext_fields = b"keyCertSign"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 55
            elif muop == "value_mutate":
                ext_fields = b"keyCertSign, cRLSign, digitalSignature, nonRepudiation, \
                keyEncipherment, dataEncipherment, keyAgreement, encipherOnly, decipherOnly"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 56         
        if node_name_list == ["extended key usage"]:
            ext_name = b"extendedKeyUsage"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"serverAuth, clientAuth, codeSigning, OCSPSigning, emailProtection, timeStamping"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 57
            elif muop == "struc_dup":
                ext_fields = b"serverAuth"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 58
        if node_name_list == ["policy mappings"]: 
            ext_name = b"policyMappings"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"2.5.29.32.1:1.3.5.8"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 59
            elif muop == "struc_dup":
                ext_fields = b"2.5.29.32.1:1.3.5.8"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 60
            elif muop == "value_mutate":
                ext_fields = b"2.5.29.32.1:1.3"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 61
        if node_name_list == ["inhibit anyPolicy"]:
            ext_name = b"inhibitAnyPolicy"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"2"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 62
            elif muop == "struc_dup":
                ext_fields = b"2"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 63
            elif muop == "value_mutate":
                ext_fields = b"-1"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 64
        if node_name_list == ["subject alternative name"]:
            ext_name = b"subjectAltName"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                san_list = ['email:a@un.gov ', "DNS:*.google.ym ", 'IP:169.254.143.151 ', 'IP:fe80:6789:a63a:e94c:791a:b0e5:8f97:1686 ', "URI:https://b.gov/index.html ", 'DN:sth ']
                ext_fields = ''.join(san_list).encode()
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 65
            elif muop == "struc_dup":
                san_list = ['email:a@un.gov ', "DNS:*.google.ym ", 'IP:169.254.143.151 ', 'IP:fe80:6789:a63a:e94c:791a:b0e5:8f97:1686 ', "URI:https://b.gov/index.html ", 'DN:sth ']
                ext_fields = ''.join(san_list).encode()
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext) 
                node_muop_id = 66       
        if node_name_list == ["issuer alternative name"]:
            ext_name = b"issuerAltName"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ian_list = ['email:a@un.gov ', "DNS:*.google.ym ", 'IP:169.254.143.151 ', 'IP:fe80:6789:a63a:e94c:791a:b0e5:8f97:1686 ', "URI:https://b.gov/index.html ", 'DN:sth ']
                ext_fields = ''.join(ian_list).encode()
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 67
            elif muop == "struc_dup":
                ian_list = ['email:a@un.gov ', "DNS:*.google.ym ", 'IP:169.254.143.151 ', 'IP:fe80:6789:a63a:e94c:791a:b0e5:8f97:1686 ', "URI:https://b.gov/index.html ", 'DN:sth ']
                ext_fields = ''.join(ian_list).encode()
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 68
        ##################################
        # subject directory attributes (Neither pyOpenSSL nor Cryptography can process it.) (let's see whether Java can process it.)
        ##################################
        if "distributionPoint" in node_name_list or "reasons" in node_name_list or "cRLIssuer" in node_name_list:
            ret_crypto = Cryptography_gen_CRLDP(node_name_list, muop, ca_private_key)
            if ret_crypto:
                ext, node_muop_id = ret_crypto
            else:
                ext, node_muop_id = None, None
        if "distributionPoint2" in node_name_list or "reasons2" in node_name_list or "cRLIssuer2" in node_name_list:
            ret_crypto = Cryptography_gen_freshestCRL(node_name_list, muop, ca_private_key)  
            if ret_crypto:
                ext, node_muop_id = ret_crypto        
            else:
                ext, node_muop_id = None, None  
        if node_name_list == ["authority information access"]:
            ext_name = b"authorityInfoAccess"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"OCSP;URI:https://www.a.com/b.ext,CA Issuers;URI:http://www.ca-issuer.com/ca-issuer,OCSP;URI:https://www.ocsp.com/ocsp.ext"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 69
            elif muop == "struc_dup":
                ext_fields = b"OCSP;URI:https://www.a.com/b.ext,CA Issuers;URI:http://www.ca-issuer.com/ca-issuer,OCSP;URI:https://www.ocsp.com/ocsp.ext"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 70
        if node_name_list == ["subject information access"]:
            ext_name = b"subjectInfoAccess"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"OCSP;URI:https://www.a.com/b.ext,CA Issuers;URI:http://www.ca-issuer.com/ca-issuer,OCSP;URI:https://www.ocsp.com/ocsp.ext"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 71
            elif muop == "struc_dup":
                ext_fields = b"OCSP;URI:https://www.a.com/b.ext,CA Issuers;URI:http://www.ca-issuer.com/ca-issuer,OCSP;URI:https://www.ocsp.com/ocsp.ext"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 72
        if node_name_list == ["nsComment"]:
            ext_name = b"nsComment"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"a nsComment example"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 73
            elif muop == "struc_dup":
                ext_fields = b"a nsComment example"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 74
        if node_name_list == ["nsCertType"]:
            ext_name = b"nsCertType"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ext_fields = b"client, server"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                node_muop_id = 75
            elif muop == "struc_dup":
                ext_fields = b"client, server"
                ext = crypto.X509Extension(ext_name, ext_critical, ext_fields)
                exts.append(ext)
                node_muop_id = 76
        if node_name_list == ["commonName"]:
            ext_name = b"commonName"
            ext_critical = random.randint(0, 1)
            if muop == "struc_add":
                ret_crypto = Cryptography_gen_commonName(node_name_list, muop, ca_private_key)
                if ret_crypto:
                    ext, node_muop_id = ret_crypto
                else:
                    ext, node_muop_id = None, None
        if ext:
            exts.append(ext)
        if exts:
            print("mu", exts)
            cert.add_extensions(exts)   
        if not "subject public key information" in node_name_list: 
            cert.set_pubkey(ec_public_key)
        cert_base64 = ''
        if node_name_list == ["signature algorithm"] or node_name_list == ["signature value"]:
            if muop == "struc_add": 
                cert.sign(ca_private_key, "sha256")
                cert_base64 = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
                node_muop_id = 77
            elif muop == "struc_del":
                cert_base64 = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
                node_muop_id = 78
        else:
            cert.sign(ca_private_key, "sha256")
            cert_base64 = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()   
        print("00. mu", "node_name_list:", node_name_list, "node_muop_id:", node_muop_id) #####################
        mutated_cert = str(node_muop_id)
        while os.path.exists(dir_certs+os.sep+mutated_cert+".pem"):
            mutated_cert += '+'
        with open(dir_certs+os.sep+mutated_cert+".pem", 'w') as fhw:
            fhw.write(cert_base64)
        return mutated_cert+".pem"
        
    except Exception as e:
        if True:
            traceback.print_exc()

    
def get_cert_data(path_cert):
    """ To get the data of a certificate (abbr. cert) from a certificate file using ZCertificate or OpenSSL (a gold referee).
    @param path_cert: A certificate and a path to access a target cert;
    @return: The data of a certificate.
    """
    
    zcert = "../go/bin/zcertificate"
    sp_cmd = [zcert, path_cert, '|', 'jq']
    sp = subprocess.Popen(sp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    zcert_stdout, zcert_stderr = sp.communicate()
    
    sp_cmd = ["openssl", "x509", "-in", path_cert, "-noout", "-text"]
    sp = subprocess.Popen(sp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    openssl_stdout, openssl_stderr = sp.communicate()
    
    [cert_zcert, cert_openssl] = ['', '']
    
    GET_ERR = True 
    
    if zcert_stdout:
        cert_zcert = json.loads(zcert_stdout.decode())['parsed']
    else: # zcert_stderr
        if GET_ERR:
            err_msg = zcert_stderr.decode().split("level=error")
            if len(err_msg) == 1:
                cert_zcert = ''
            else:
                cert_zcert = err_msg[1].strip()
        else:
            cert_zcert = None
    
    if openssl_stdout:
        cert_openssl = openssl_stdout.decode()
    else: # openssl_stderr
        if GET_ERR:
            cert_openssl = openssl_stderr.decode()
        else:
            cert_openssl = None
    
    return [cert_zcert, cert_openssl]


def flatten_cert_struc(cert_data):
    """ To get the certificate structure from some certificate data recursively.
    @param cert_data: The data of a certificate;
    @return: The flat structure of the input certificate.
    """
    
    struc = ''
    if isinstance(cert_data, dict):
        for k, v in cert_data.items():
            struc += k
            struc += ','
            if v: 
                ret = flatten_cert_struc(v)
                if ret:
                    struc += ret
        return struc
    elif isinstance(cert_data, list):
        for e in cert_data:
            if e: 
                ret = flatten_cert_struc(e)
                if ret:
                    struc += ret
        return struc
    else: 
        return ''
      

def get_hash_value(data, hash_algo="sha256"):
    """ To get a hash value of a certificate data or error message.
    @param data: certificate data or error messages; 
    @param hash algorithm: optional, sha256 by default;
    @return: The hash value;
    @raise exception: hashlib. 
    """
    
    if not isinstance(data, bytes):
        data = data.encode()
    hash_value = ''
    try:
        if hash_algo == "md5":
            hash_value = hashlib.md5(data).hexdigest()
        elif hash_algo == "sha1":
            hash_value = hashlib.sha1(data).hexdigest()
        elif hash_algo == "sha224":
            hash_value = hashlib.sha224(data).hexdigest()
        elif hash_algo == "sha256":
            hash_value = hashlib.sha256(data).hexdigest()
        elif hash_algo == "sha384":
            hash_value = hashlib.sha384(data).hexdigest()
        elif hash_algo == "sha512":
            hash_value = hashlib.sha512(data).hexdigest()
        else:
            hash_value = hashlib.sha256(data).hexdigest()
    except:
        pass
    return hash_value


def get_certs_struc_hash(dir_certs):
    """ To get structural hash values of a certificate set.
    @param dir_certs: A directory storing a certificate set;
    @return: Hash values of certificates.
    """
    
    hash_values = set()
    certs = os.listdir(dir_certs)
    certs.sort()
    for cert in certs:
        cert_zcert, cert_openssl = get_cert_data(dir_certs+os.path.sep+cert)
        cert_struc = flatten_cert_struc(cert_zcert)
        cert_struc_hash = get_hash_value(cert_struc)
        hash_values.add(cert_struc_hash)
    return hash_values


def get_statistics_of_mutation(dir_certs):
    """ To get statistics of mutation for a certificate set:
    (1) Ratio of analyzable certificates to unanalyzable ones;
    (2) Error mutation of unanalyzable certificates;
    (3) Structure mutation of analyzable certificates;
    (4) Value mutation of certificates with common structures.
    @param dir_certs: A directory storing certs;
    @return: statistics of mutation i.e., (parsability, error_mutation, struc_mutation, value_mutation, unanalyzable_cert_err_hash_set, analyzable_cert_struc_hash_set, analyzable_cert_value_hash_set), parsability = (analyzable_num, unanalyzable_num, analyzable_num/certs_num, unanalyzable_num/certs_num), error_mutation = (len(unanalyzable_cert_err_hash_set), len(unanalyzable_cert_err_hash), len(unanalyzable_cert_err_hash_set)/len(unanalyzable_cert_err_hash)), struc_mutation = (len(analyzable_cert_struc_hash_set), len(analyzable_cert_struc_hash), len(analyzable_cert_struc_hash_set)/len(analyzable_cert_struc_hash)), value_mutation = (len(analyzable_cert_value_hash_set), len(analyzable_cert_value_hash), len(analyzable_cert_value_hash_set)/len(analyzable_cert_value_hash)).
    """
    
    certs = os.listdir(dir_certs)
    certs.sort()
    certs_num = len(certs)
    
    analyzable = []
    unanalyzable = []
    unanalyzable_cert_err_hash = [] 
    unanalyzable_cert_err_hash_set = set() 
    
    analyzable_cert_struc_hash = []
    analyzable_cert_struc_hash_set = set()
    
    analyzable_cert_value_hash = []
    analyzable_cert_value_hash_set = set()
    
    for cert in certs:
        path_cert = dir_certs + os.path.sep + cert
        cert_zcert, cert_openssl = get_cert_data(path_cert)
        if isinstance(cert_zcert, dict):
            analyzable.append(cert)
            analyzable_cert_struc = flatten_cert_struc(cert_zcert)
            struc_hash = get_hash_value(analyzable_cert_struc)
            analyzable_cert_struc_hash.append(struc_hash)
            analyzable_cert_struc_hash_set.add(struc_hash)
            value_hash = get_hash_value(str(cert_zcert))
            analyzable_cert_value_hash.append(value_hash)
            analyzable_cert_value_hash_set.add(value_hash)
        else:
            unanalyzable.append(cert)
            unanalyzable_cert_err = cert_zcert
            err_hash = get_hash_value(unanalyzable_cert_err)
            unanalyzable_cert_err_hash.append(err_hash)
            unanalyzable_cert_err_hash_set.add(err_hash)
    
    parsability = ()
    analyzable_num = len(analyzable)
    unanalyzable_num = len(unanalyzable) 
    if analyzable_num + unanalyzable_num == certs_num:
        parsability = (analyzable_num, 
                       unanalyzable_num, 
                       analyzable_num/certs_num, 
                       unanalyzable_num/certs_num)
    
    a = len(unanalyzable_cert_err_hash_set)
    b = len(unanalyzable_cert_err_hash)
    if b != 0:
        error_mutation = (a, b, a/b)
    else:
        error_mutation = (a, b, str(a)+'/0')
    
    a = len(analyzable_cert_struc_hash_set)
    b = len(analyzable_cert_struc_hash)
    struc_mutation = (a, b, a/b)
    
    a = len(analyzable_cert_value_hash_set)
    b = len(analyzable_cert_value_hash)
    value_mutation = (a, b, a/b)
    
    ret = (parsability,
           error_mutation,
           struc_mutation,
           value_mutation,
           unanalyzable_cert_err_hash_set,
           analyzable_cert_struc_hash_set,
           analyzable_cert_value_hash_set
           )
    return ret


def pem2der(path_cert):
    """ To convert a certificate in the format of .pem to .der.
    @param path_cert: A certificate in the format of .pem and the path to it;
    @return: A certificate in the format of .der;
    @raise exception: transforming exception.
    """
    try:
        os.system("openssl x509 -inform pem -in "+path_cert+" -outform der -out "+path_cert.replace(".pem", ".der"))
    except:
        return("pem2der failed")


def read_cert(path_cert):
    """ To read the certificate data from a certificate file.
    @param path_cert: A certificate file with the path to access it;
    @return: The certificate data.
    """
    with open(path_cert, 'br') as fhr:
        return(fhr.read())


def load_pem_or_asn1(path_cert):
    """ To load a PEM or ASN1.
    @param path_cert: A certificate file with the path to access it;
    @return: Certificate data;
    @raise exception: loading cert. 
    """
    cert = read_cert(path_cert)
    if cert.startswith(b"-----BEGIN"):
        try:
            cert_data = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            return cert_data
        except:
            return None
    else:
        try:
            cert_data = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            return cert_data
        except:
            return None

    
def output_zcert_json(path_cert):
    """ To output the certificate data analyzed by ZCertificate in the format of JSON.
    @param path_cert: A certificate file with the path to access it;
    @return: The certificate data analyzed by ZCertificate in the format of JSON.
    """
    cert_data = get_cert_data(path_cert)[0]
    print(json.dumps(cert_data, indent=2))


def gen_keys(ca_keybits=1024, ec_keybits=1024): 
    """ To generate public and private keys.
    @param ca_keybits: Key bits (4096 by default);
    @param ec_keybits: Key bits (4096 by default);
    @return: Two pairs of public and private keys files in the dir_related. One pair for EEC/IEC and the other for CA.
    """
    keys_exist = True
    key_list = ["ca_public_key.pem", "ca_private_key.pem", "ec_public_key.pem", "ec_private_key.pem"]
    for key in key_list:
        path_key = dir_related + os.sep + key
        if not os.path.exists(path_key):
            keys_exist = False
            break
    if keys_exist:
        for i in range(len(key_list)):
            path_key = dir_related + os.sep + key_list[i]
            with open(path_key) as fhr:
                if i%2 == 0:
                    key_list[i] = crypto.load_publickey(crypto.FILETYPE_PEM, fhr.read())
                else:
                    key_list[i] = crypto.load_privatekey(crypto.FILETYPE_PEM, fhr.read())
        return(key_list[0], key_list[1], key_list[2], key_list[3])
    else:
        ko = crypto.PKey()
        ko.generate_key(crypto.TYPE_RSA, ca_keybits)
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, ko)
        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ko)
        with open(dir_related+os.sep+key_list[0], 'w') as fhw:
            fhw.write(public_key.decode())
        with open(dir_related+os.sep+key_list[1], 'w') as fhw:
            fhw.write(private_key.decode())
        ca_public_key = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
        ca_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        
        ko = crypto.PKey()
        ko.generate_key(crypto.TYPE_RSA, ec_keybits)
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, ko)
        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ko)
        with open(dir_related+os.sep+key_list[2], 'w') as fhw:
            fhw.write(public_key.decode())
        with open(dir_related+os.sep+key_list[3], 'w') as fhw:
            fhw.write(private_key.decode())
        ec_public_key = crypto.load_publickey(crypto.FILETYPE_PEM, public_key)
        ec_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
        return(ca_public_key, ca_private_key, ec_public_key, ec_private_key)


def get_random_str(max_len):
    """ To get a random string.
    @param max_len: The maximum length of a favorite string;
    @return: A random string. 
    """
    random_str = ''
    lower_start = ord('a')
    lower_end = ord('z')
    capital_start = ord('A')
    capital_end = ord('Z')
    for i in range(max_len):
        random_str += random.choice([chr(random.randint(lower_start, lower_end)), chr(random.randint(capital_start, capital_end))])
    return random_str


def get_random_chars(len):
    """ To get chars whose length is specified.
    @param len: How many chars are generated.
    @return: Chars.
    """
    random_char1 = chr(random.randint(ord('a'), ord('z')))
    random_char2 = chr(random.randint(ord('A'), ord('Z')))
    return random_char1+random_char2
    

def Cryptography_gen_commonName(node_name_list, muop, ca_private_key):
    """ To generate "commonName" that cannot be done by PyOpenSSL.
    @param node_name_list: A specified node name list of the extension commonName;
    @param muop: A mutation operator on the node list;  
    @param pyo_private_key: A private key generated by PyOpenSSL;
    @return: pyo.get_extension[0]. 
    """
    try:
        pyo_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_private_key)
        private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            pyo_private_key, 
            password=None, 
            backend=cryptography.hazmat.backends.default_backend())
    except:
        print("error")
    
    builder = cryptography.x509.CertificateBuilder()
    
    sn = cryptography.x509.random_serial_number()
    builder = builder.serial_number(sn)
    
    notBefore = datetime.datetime.today() - datetime.timedelta(days=10)
    builder = builder.not_valid_before(notBefore)
    
    notAfter = datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    builder = builder.not_valid_after(notAfter)
    
    c = cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COUNTRY_NAME, U"UN")
    issuer = cryptography.x509.Name([c])
    builder = builder.issuer_name(issuer)
    
    st = cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"NYS")
    subject = cryptography.x509.Name([st])
    builder = builder.subject_name(subject)
    
    node_muop_id = 120
    
    if node_name_list == ["commonName"]:
        if muop == "struc_add":
            extension = x509.extensions.UnrecognizedExtension(NameOID.COMMON_NAME, b"test commonName")
            builder = builder.add_extension(extension, critical=True)
        
    builder = builder.public_key(private_key.public_key())
    cert = builder.sign(private_key=private_key, 
                        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                        backend=cryptography.hazmat.backends.default_backend())
    cert = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
    pyo_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    if pyo_cert.get_extension_count() > 0:
        return pyo_cert.get_extension(0), node_muop_id
    else:
        print("pyo_cert_get_extension_count():", pyo_cert.get_extension_count())
        
            
def Cryptography_gen_CRLDP(node_name_list, muop, ca_private_key):
    """ To generate "crlDistributionPoints" that cannot be done perfectly by PyOpenSSL.
    @param node_name_list: A specified node name list of the extension crlDistributionPoints;
    @param muop: A mutation operator on the node list;  
    @param pyo_private_key: A private key generated by PyOpenSSL;
    @return: pyo.get_extension[0]. 
    """
    try:
        pyo_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_private_key)
        private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            pyo_private_key, 
            password=None, 
            backend=cryptography.hazmat.backends.default_backend())
    except:
        print("error")
    
    builder = cryptography.x509.CertificateBuilder()
    
    sn = cryptography.x509.random_serial_number()
    builder = builder.serial_number(sn)
    
    notBefore = datetime.datetime.today() - datetime.timedelta(days=10)
    builder = builder.not_valid_before(notBefore)
    
    notAfter = datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    builder = builder.not_valid_after(notAfter)
    
    c = cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COUNTRY_NAME, U"UN")
    issuer = cryptography.x509.Name([c])
    builder = builder.issuer_name(issuer)
    
    st = cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"NYS")
    subject = cryptography.x509.Name([st])
    builder = builder.subject_name(subject)
    
    full_name = None
    relative_name = None
    reasons = None
    crl_issuer = []
    node_muop_id = ''
    
    if node_name_list == ["distributionPoint"]:
        if muop == "struc_add":
            one_and_only_one = random.choice(["full_name", "relative_name"])
            if one_and_only_one == "full_name":
                full_name = [
                    cryptography.x509.RFC822Name("e@f.com"),
                    cryptography.x509.DNSName("www.example.com")
                    ]
                relative_name = None
                reasons = None
                crl_issuer = None
                node_muop_id = 100
            elif one_and_only_one == "relative_name":
                full_name = None
                name_attributes = [cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, u"example.com")]
                relative_name = cryptography.x509.RelativeDistinguishedName(name_attributes)
                node_muop_id = 101
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None
            node_muop_id = 102
    if node_name_list == ["reasons"]:
        if muop == "struc_add":
            one_of_three = random.choice(["full_name", "relative_name", "crl_issuer"]) 
            if one_of_three == "full_name":
                full_name = [
                    cryptography.x509.RFC822Name("e@f.com"),
                    cryptography.x509.DNSName("www.example.com")
                    ]
                relative_name = None
                crl_issuer = None
                node_muop_id = 103
            elif one_of_three == "relative_name":
                full_name = None
                name_attributes = [
                    cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, u"example.com")
                    ]
                relative_name = cryptography.x509.RelativeDistinguishedName(name_attributes)
                crl_issuer = None
                node_muop_id = 104
            elif one_of_three == "crl_issuer":
                full_name = None
                relative_name = None
                crl_issuer = [
                    cryptography.x509.RFC822Name("g@h.com"),
                    cryptography.x509.DNSName("www.example.com"),
                    cryptography.x509.UniformResourceIdentifier("www.b.com/c.ext")
                ]
                node_muop_id = 105
            reasons = frozenset([
                cryptography.x509.ReasonFlags.key_compromise,
                cryptography.x509.ReasonFlags.ca_compromise,
                cryptography.x509.ReasonFlags.aa_compromise,
                cryptography.x509.ReasonFlags.certificate_hold,
                cryptography.x509.ReasonFlags.cessation_of_operation,
                cryptography.x509.ReasonFlags.affiliation_changed,
                cryptography.x509.ReasonFlags.superseded,
                cryptography.x509.ReasonFlags.privilege_withdrawn,
                cryptography.x509.ReasonFlags.affiliation_changed
            ])
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None
            node_muop_id = 106
    if node_name_list == ["cRLIssuer"]:
        if muop == "struc_add":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = [
                cryptography.x509.RFC822Name("g@h.com"),
                cryptography.x509.DNSName("www.example.com"),
                cryptography.x509.UniformResourceIdentifier("www.b.com/c.ext")
            ]
            node_muop_id = 107
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None 
            node_muop_id = 108 
    if "distributionPoint" in node_name_list and "reasons" in node_name_list and "cRLIssuer" in node_name_list:
        if muop == "struc_add":
            one_and_only_one = random.choice(["full_name", "relative_name"])
            if one_and_only_one == "full_name":
                full_name = [
                    cryptography.x509.RFC822Name("e@f.com"),
                    cryptography.x509.DNSName("www.example.com")
                    ]
                relative_name = None
                node_muop_id = 109
            elif one_and_only_one == "relative_name":
                full_name = None
                name_attributes = [cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, u"example.com")]
                relative_name = cryptography.x509.RelativeDistinguishedName(name_attributes)
                node_muop_id = 110
            reasons = frozenset([
                cryptography.x509.ReasonFlags.key_compromise,
                cryptography.x509.ReasonFlags.ca_compromise,
                cryptography.x509.ReasonFlags.aa_compromise,
                cryptography.x509.ReasonFlags.certificate_hold,
                cryptography.x509.ReasonFlags.cessation_of_operation,
                cryptography.x509.ReasonFlags.affiliation_changed,
                cryptography.x509.ReasonFlags.superseded,
                cryptography.x509.ReasonFlags.privilege_withdrawn,
                cryptography.x509.ReasonFlags.affiliation_changed
            ])
            crl_issuer = [
                cryptography.x509.RFC822Name("g@h.com"),
                cryptography.x509.DNSName("www.example.com"),
                cryptography.x509.UniformResourceIdentifier("www.b.com/c.ext")
            ]
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None        
            node_muop_id = 111
    
    distribution_point = cryptography.x509.DistributionPoint(full_name, relative_name, reasons, crl_issuer)
    crl_distribution_points = cryptography.x509.CRLDistributionPoints([distribution_point])
    builder = builder.add_extension(crl_distribution_points, critical=False)
        
    builder = builder.public_key(private_key.public_key())
    cert = builder.sign(private_key=private_key, 
                        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                        backend=cryptography.hazmat.backends.default_backend())
    cert = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
    pyo_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    if pyo_cert.get_extension_count() > 0:
        return pyo_cert.get_extension(0), node_muop_id
    else:
        print("pyo_cert_get_extension_count():", pyo_cert.get_extension_count())


def Cryptography_gen_freshestCRL(node_name_list, muop, ca_private_key):
    """ To generate "freshestCRL" that cannot be done perfectly by PyOpenSSL.
    @param node_name_list: A specified node name list of the extension freshestCRL;
    @param muop: A mutation operator on the node list;  
    @param pyo_private_key: A private key generated by PyOpenSSL;
    @return: pyo.get_extension[0]. 
    """
    try:
        pyo_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_private_key)
        private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            pyo_private_key, 
            password=None, 
            backend=cryptography.hazmat.backends.default_backend())
    except:
        print("error")
    
    builder = cryptography.x509.CertificateBuilder()
    
    sn = cryptography.x509.random_serial_number()
    builder = builder.serial_number(sn)
    
    notBefore = datetime.datetime.today() - datetime.timedelta(days=10)
    builder = builder.not_valid_before(notBefore)
    
    notAfter = datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    builder = builder.not_valid_after(notAfter)
    
    c = cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COUNTRY_NAME, U"UN")
    issuer = cryptography.x509.Name([c])
    builder = builder.issuer_name(issuer)
    
    st = cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"NYS")
    subject = cryptography.x509.Name([st])
    builder = builder.subject_name(subject)
    
    full_name = None
    relative_name = None
    reasons = None
    crl_issuer = []
    node_muop_id = ''
    
    if node_name_list == ["distributionPoint2"]:
        if muop == "struc_add":
            one_and_only_one = random.choice(["full_name", "relative_name"])
            if one_and_only_one == "full_name":
                full_name = [cryptography.x509.RFC822Name("e@f.com"), cryptography.x509.DNSName("www.example.com")]
                relative_name = None
                reasons = None
                crl_issuer = None
                node_muop_id = 112
            elif one_and_only_one == "relative_name":
                full_name = None
                name_attributes = [cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, u"example.com")]
                relative_name = cryptography.x509.RelativeDistinguishedName(name_attributes)
                reasons = None
                crl_issuer = None
                node_muop_id = 113
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None
            node_muop_id = 114
    if node_name_list == ["reasons2"]:
        if muop == "struc_add":
            one_of_three = random.choice(["full_name", "relative_name", "crl_issuer"]) 
            if one_of_three == "full_name":
                full_name = [cryptography.x509.RFC822Name("e@f.com"), cryptography.x509.DNSName("www.example.com")]
                relative_name = None
                crl_issuer = None
                node_muop_id = 115
            elif one_of_three == "relative_name":
                full_name = None
                name_attributes = [cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, u"example.com")]
                relative_name = cryptography.x509.RelativeDistinguishedName(name_attributes)
                crl_issuer = None
                node_muop_id = 116
            elif one_of_three == "crl_issuer":
                full_name = None
                relative_name = None
                crl_issuer = [
                    cryptography.x509.RFC822Name("g@h.com"),
                    cryptography.x509.DNSName("www.example.com"),
                    cryptography.x509.UniformResourceIdentifier("www.b.com/c.ext")
                ]
                node_muop_id = 117
            reasons = frozenset([
                cryptography.x509.ReasonFlags.key_compromise,
                cryptography.x509.ReasonFlags.ca_compromise,
                cryptography.x509.ReasonFlags.aa_compromise,
                cryptography.x509.ReasonFlags.certificate_hold,
                cryptography.x509.ReasonFlags.cessation_of_operation,
                cryptography.x509.ReasonFlags.affiliation_changed,
                cryptography.x509.ReasonFlags.superseded,
                cryptography.x509.ReasonFlags.privilege_withdrawn,
                cryptography.x509.ReasonFlags.affiliation_changed
            ])
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None
            node_muop_id = 118
    if node_name_list == ["cRLIssuer2"]:
        if muop == "struc_add":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = [
                cryptography.x509.RFC822Name("g@h.com"),
                cryptography.x509.DNSName("www.example.com"),
                cryptography.x509.UniformResourceIdentifier("www.b.com/c.ext")
            ]
            node_muop_id = 119
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None 
            node_muop_id = 120 
    if "distributionPoint2" in node_name_list and "reasons2" in node_name_list and "cRLIssuer2" in node_name_list:
        if muop == "struc_add":
            one_and_only_one = random.choice(["full_name", "relative_name"])
            if one_and_only_one == "full_name":
                full_name = [
                    cryptography.x509.RFC822Name("e@f.com"),
                    cryptography.x509.DNSName("www.example.com")
                    ]
                relative_name = None
                node_muop_id = 121
            elif one_and_only_one == "relative_name":
                full_name = None
                name_attributes = [cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, u"example.com")]
                relative_name = cryptography.x509.RelativeDistinguishedName(name_attributes)
                node_muop_id = 122
            reasons = frozenset([
                cryptography.x509.ReasonFlags.key_compromise,
                cryptography.x509.ReasonFlags.ca_compromise,
                cryptography.x509.ReasonFlags.aa_compromise,
                cryptography.x509.ReasonFlags.certificate_hold,
                cryptography.x509.ReasonFlags.cessation_of_operation,
                cryptography.x509.ReasonFlags.affiliation_changed,
                cryptography.x509.ReasonFlags.superseded,
                cryptography.x509.ReasonFlags.privilege_withdrawn,
                cryptography.x509.ReasonFlags.affiliation_changed
            ])
            crl_issuer = [
                cryptography.x509.RFC822Name("g@h.com"),
                cryptography.x509.DNSName("www.example.com"),
                cryptography.x509.UniformResourceIdentifier("www.b.com/c.ext")
            ]
        elif muop == "struc_del":
            full_name = None
            relative_name = None
            reasons = None
            crl_issuer = None        
            node_muop_id = 123
    
    distribution_point = cryptography.x509.DistributionPoint(full_name, relative_name, reasons, crl_issuer)
    freshest_distribution_points = cryptography.x509.FreshestCRL([distribution_point])
    builder = builder.add_extension(freshest_distribution_points, critical=False)
        
    builder = builder.public_key(private_key.public_key())
    cert = builder.sign(private_key=private_key, 
                        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                        backend=cryptography.hazmat.backends.default_backend())
    cert = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
    pyo_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    if pyo_cert:
        print(type(pyo_cert), pyo_cert.get_extension_count())
    else:
        print("error in loading pyo_cert")
    if pyo_cert.get_extension_count() > 0:
        return pyo_cert.get_extension(0), node_muop_id
    else:
        print("pyo_cert_get_extension_count() > 0 fails")

     
def plt_record(record, show=False):
    """ To visualize the results
    @param record: Return of mutate_certs() i.e., (record_un_num, record_struc_num, record_value_num) 
    @param show: Indicating whether show figures immediately;
    @return: Visualization. 
    """
    plt.figure()
    plt.plot(record[0], '', record[1], "--", record[2], ":")
    plt.xlabel("Round")
    plt.ylabel("#Unique certificates")
    plt.title("Unique mutated certificates")
    plt.legend(["un", "struc", "value"])
    plt.savefig(dir_result+os.sep+"div_trends.pdf", bbox_inches="tight")
    plt.show()


def plt_comparison(record, xlabel, ylabel, title, legend, pdf_filename, show=False):
    """ To visualize the results
    @param record: Return of mutate_certs() i.e., (record_un_num, record_struc_num, record_value_num) 
    @param show: Indicating whether show figures immediately;
    @return: Visualization. 
    """
    plt.figure()
    plt.plot(record[0], '', record[1], "--")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend(legend)
    plt.savefig(dir_result+os.sep+pdf_filename, bbox_inches="tight")
    if show:
        plt.show()
 
        
def SBDT_MST_mutation_main():
    """ To conduct search-based certificate mutation and discrepancies hunting. 
    (search a node by dis, mutate it depth-first, update dis in the bottom-up manner, bounded mutation count) (Search Directed Differential Testing of Certificate Parsers, SBDT) (Search-based Differential Testing, SDT)
    @param None: None;
    @return: Mutated certificates, updated MST, and discrepancies found in certificate parsers.
    """
    begin_time = time.time()
      
    initialize_dirs(dir_certs)
    initialize_dirs(dir_certs_tmp)
    initialize_dirs(dir_certs_un) 
    
    MST = initialize_MST()
    virtual_node_list = ["cert", "tbsCertificate", "standard extensions", "private Internet extensions", "legacy extensions", "extensions"] # the cases that extensions appears or not have been considered. 
    # To generate keys for future use
    ca_public_key, ca_private_key, ec_public_key, ec_private_key = gen_keys()
    
    sp_cmd = ["java", "-jar", "./JavaGenCerts.jar", "initialize"]
    sp = subprocess.Popen(sp_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = sp.communicate()
    cert_name = ''
    
    i = 1
    pd, sd, cd = 0, 0, 0 
    dpd, dsd, dcd = 0, 0, 0 
    dd = 0 
    pd_list, sd_list, cd_list = [], [], []
    dpd_list, dsd_list, dcd_list = [], [], []
    dd_list = []
    node_list = []
    op_list = []
    while MST["cert"]["earlybound"]["struc_add"] > 0 and MST["cert"]["hardbound"]["struc_add"] > 0:
        ret = select_node_and_muop(MST, "cert")
        consecutive.append(ret)
        print('\n'*2+'+'*10, str(i))
        print("1. SBDT_MST_mutation_main--select_node_and_muop ret:", ret) 
        
        if ret: 
            mutated_cert = ''
            node_name, muop = ret
            node_list.append(node_name)
            op_list.append(muop)
            
            if node_name in virtual_node_list:
                muop = None
            print("2. rectified ret:", node_name, muop) 
            Java_process_list = ["tbsCertSignature", "issuer unique identifier", "subject unique identifier", 
                                 "subject directory attributes", "certificate policies", "policyIdentifier", 
                                 "CPS", "userNotice", "noticeRef", "explicitText"]
            if node_name in Java_process_list:
                sp_cmd = ["java", "-jar", "./JavaGenCerts.jar", node_name, muop]
                sp = subprocess.Popen(sp_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = sp.communicate()
                mutated_cert = out.decode().replace('\n', '')
                print("3. mutated_cert:", mutated_cert) 
            else:
                if node_name == "basic constraints": 
                    node_name_list = ["cA", "pathLenConstraint"]
                elif node_name == "name constraints":
                    node_name_list = ["permittedSubtrees", "excludedSubtrees"]
                elif node_name == "policy constraints":
                    node_name_list = ["requireExplicitPolicy", "inhibitPolicyMapping"]
                elif node_name == "authority key identifier":
                    node_name_list = ["keyIdentifier", "authorityCertIssuer", "authorityCertSerialNumber"]
                elif node_name == "subject key identifier":
                    node_name_list = ["keyIdentifier2"]
                elif node_name == "certificate policies": 
                    node_name_list = ["policyIdentifier", "CPS", "noticeRef", "explicitText"]
                elif node_name == "userNotice":
                    node_name_list = ["noticeRef", "explicitText"]
                elif node_name == "CRL distribution points":
                    node_name_list = ["distributionPoint", "reasons", "cRLIssuer"]
                elif node_name == "freshest CRL":
                    node_name_list = ["distributionPoint2", "reasons2", "cRLIssuer2"]
                else:
                    node_name_list = [node_name]
                if not node_name in virtual_node_list:
                    mutated_cert = mutate_cert(node_name_list, muop, ca_private_key, ec_public_key)
                    print("4. mutated_cert:", mutated_cert) 
            if mutated_cert:
                path_cert = dir_certs + os.sep + mutated_cert
                if os.path.exists(path_cert):
                    print("5. path_cert:", path_cert) 
                    SBDT_2_certificate_parsing.SBDT_certificate_parsing_main()
                    SBDT_3_converter_OpenSSL.SBDT_converter_OpenSSL_main()
                    SBDT_3_converter_ZCertificate.SBDT_converter_ZCertificate_main()
                    SBDT_3_converter_GnuTLS.SBDT_converter_GnuTLS_main()
                    SBDT_4_SD_discrepancy_hunter.SBDT_discrepancy_hunter_main()
                    pd, dpd, sd, dsd, cd, dcd = SBDT_4_SD_discrepancy_hunter.SBDT_discrepancy_hunter_main()
                    print("DCD:", dcd)
                    num_dis = dpd + dsd + dcd
                    dd = num_dis
                    pd_list.append(pd)
                    dpd_list.append(dpd)
                    sd_list.append(sd)
                    dsd_list.append(dsd)
                    cd_list.append(cd)
                    dcd_list.append(dcd)
                    dd_list.append(dd)
                    update_MST(MST, node_name, muop, num_dis)
                    
                else:
                    print("7.", path_cert, " IS NOT FOUND.")
                    pd_list.append(pd_list[-1])
                    dpd_list.append(dpd_list[-1])
                    sd_list.append(sd_list[-1])
                    dsd_list.append(dsd_list[-1])
                    cd_list.append(cd_list[-1])
                    dcd_list.append(dcd_list[-1])
                    dd_list.append(dd_list[-1])
                    update_MST(MST, node_name, muop, 0)
            else:
                update_MST(MST, node_name, muop, 0)
                pd_list.append(pd_list[-1])
                dpd_list.append(dpd_list[-1])
                sd_list.append(sd_list[-1])
                dsd_list.append(dsd_list[-1])
                cd_list.append(cd_list[-1])
                dcd_list.append(dcd_list[-1])
                dd_list.append(dd_list[-1])
                print("8. mutated_cert is None and the node_name_list is:", node_name_list)
        else: 
            print("\nSearch-based certificate mutation and discrepancies hunter end.\n")
            pd_list.append(pd_list[-1])
            dpd_list.append(dpd_list[-1])
            sd_list.append(sd_list[-1])
            dsd_list.append(dsd_list[-1])
            cd_list.append(cd_list[-1])
            dcd_list.append(dcd_list[-1])
            dd_list.append(dd_list[-1])
            exit()
        if len(dcd_list) > 1:
            if dcd_list[-1] < dcd_list[-2]:
                print(dcd_list[-1], dcd_list[-2])
                input("Press any key to continue ...")
        i += 1
        
    with open("../result/sbdt-statistics.txt", 'w') as fhw:
        fhw.write("PD: "+str(pd_list[-1])+'\n')
        fhw.write("DPD: "+str(dpd_list[-1])+'\n')
        fhw.write("SD: "+str(sd_list[-1])+'\n')
        fhw.write("DSD: "+str(dsd_list[-1])+'\n')
        fhw.write("CD: "+str(cd_list[-1])+'\n')
        fhw.write("DCD: "+str(dcd_list[-1])+'\n')
        fhw.write("DD: "+str(dd_list[-1])+'\n')
        fhw.write("Total iterations: "+str(i)+'\n')
        fhw.write("Time elapsed: "+str(time.time()-begin_time))
    
    with open("../result/sbdt.txt", 'w') as fhw:
        for e in pd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
        for e in dpd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
        for e in sd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
        for e in dsd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
        for e in cd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
        for e in dcd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
        for e in dd_list:
            fhw.write(str(e)+',')
        fhw.write('\n')
    with open("../result/nodelist.txt", 'w') as fhw:
        for e in node_list:
            fhw.write(e+',')
    with open("../result/oplist.txt", 'w') as fhw:
        for e in op_list:
            fhw.write(str(e)+',')   
               
if __name__ == "__main__":
    begin_time = time.time()
    SBDT_MST_mutation_main()
    end_time = time.time()
    print("\nTime consumed:", end_time-begin_time, "seconds")
    