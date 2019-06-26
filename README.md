# SecureIoT
SIOT - A framework aimed at securing IoT devices using weak or default credentials in a network

**requirements**

**pip3 install flask**

**pip3 install getmac**
**pip3 install sqlalchemy**
**pip3 install pycurl**


**troubleshoot**
If warning about pycurl warning:
**pip3 install pycurl==7.43.0.1 --global-option="--with-nss" --upgrade**

If warning when installing pycurl:
*__main__.ConfigurationError: Could not run curl-config: [Errno 2] No such file or directory: 'curl-config': 'curl-config'
    
    ----------------------------------------
Command "python setup.py egg_info" failed with error code 1 in /tmp/pip-build-mzbbm8iu/pycurl/*

This should solve it:
**sudo apt install libcurl4-openssl-dev libssl-dev**


On Windows:

If error
---     ERROR: Complete output from command python setup.py egg_info:
    ERROR: Please specify --curl-dir=/path/to/built/libcurl
    ----------------------------------------
ERROR: Command "python setup.py egg_info" failed with error code 10 in c:\users\emisor\appdata\local\temp\pip-install-eadztx\pycurl\
 ---
 
 Download pycUr from here: https://www.lfd.uci.edu/~gohlke/pythonlibs/#pycurl
 Install your version with 
 **pip3 install pycurl-7.43.0.3-cp36-cp36m-win32.whl**
