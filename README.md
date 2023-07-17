# Introduction
SBDT: a prototype tool of **S**earch-**B**ased **D**ifferential **T**esting of Certificate Parsers in SSL/TLS Implementations.

# Getting Started
## Requirements
+ Oracle VM Virtual Box v6.0.12r133076 (free: https://www.virtualbox.org/)
+ Ubuntu 18.04 x64 or v20.04. x64 (free: https://ubuntu.com/)
+ Oracle JDK or OpenJDK v1.8.0 (free: https://www.oracle.com/java/ or sudo apt-get install openjdk-8-jdk) 
+ Eclipse 2020-12 (4.18.0) Build id: 20201210-1552 (free: https://eclipse.org/ or sudo apt-get install eclipse)
+ pyDev (free: https://www.pydev.org/)
+ Git (sudo ap-get install git)
+ pandas and openpyxl (sudo apt-get install python3-pandas; sudo apt-get install python3-openpyxl) 
+ matplotlib (sudo apt-get install python3-matplotlib) (visualization)
+ OpenSSL (sudo apt-get install openssl; sudo apt-get install libssl-dev or manual installation)
+ GnuTLS (sudo apt-get install gnutls-bin)
+ Golang (manual installation)
+ ZCertificate, ZLint (github.com/zmap)
+ other implementations that users want to test

## Steps to check the basic functionality 
+ Main functionality: Eclipse-->SBDT_1_MST_mutation-->debug (F11) or run (ctrl+F11)
+ Functionality--certificcate parsing: Eclipse-->SBDT_2_certificate_parsing-->debug (F11) or run (ctrl+F11)
+ Functionality--normalize the outputs of GnuTLS: Eclipse-->SBDT_3_converter_GnuTLS-->debug (F11) or run (ctrl+F11)
+ Functionality--normalize the outputs of OpenSSL: Eclipse-->SBDT_3_converter_OpenSSL-->debug (F11) or run (ctrl+F11)
+ Functionality--normalize the outputs of ZCertificate: Eclipse-->SBDT_3_converter_ZCertificate-->debug (F11) or run (ctrl+F11)
+ Functionality--hunt discrepancies: Eclipse-->SBDT_4_SD_discrepancy_hunter-->debug (F11) or run (ctrl+F11)

# Detailed Instructions
+ Main functionality:
  + Users may change the model based on their testing goals.
  + Users may choose which parsers to test. Also, users may write their code to parser other parsers. If so, SBDT_4 should be modified too.
  + We will open a better and extended project which has better performance and functionalities later.

# Copyright and Citation Request
+ Copyright@SecuritySoftware Team(Chu Chen etc. github.com/secsoftware)
+ If your project uses or refers to our code, please cite as follows. 
`Chu Chen, Pinghong Ren, Zhenhua Duan, Cong Tian, Xu Lu, and Bin Yu. 2023. SBDT: Search-Based Differential Testing of Certificate Parsers in SSL/TLS Implementations. In Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA ’23), July 17–21, 2023, Seattle, WA, USA. ACM, New York, NY, USA, 13 pages. https://doi.org/10.1145/3597926.3598110` Thank you!
 
