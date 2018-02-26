
Untar or clone repository into remediation_scan/

#### installation
$ cd remediation_scan
$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements

#### usage:
$ python scan.py help

#### port input is not currently used, can be added to scan definition to limit which ports are scanned
$ python scan.py launch 97737 172.26.48.14 443

#### analyze queries individual scan results if scanID is specified
#### otherwise analyze queries the cumulative database
#### results are returned from 'vulnerability' and 'mitigated' views
$ python scan.py analyze 97737 172.26.48.14 443 --scan-id 118

