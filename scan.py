'''
somewhat following example from here:
https://docs.tenable.com/sccv/api_best_practices/Content/ScApiBestPractices/LaunchRemediationScan.htm
the /pluginFamily/<pluginID> call didn't return the family ID as described so using analyze

'''
from securitycenter import SecurityCenter5
from StringIO import StringIO
from zipfile import ZipFile
import json
from time import sleep
POLLING_INTERVAL = 10


class Plugin(object):
    def __init__(self, plugin_id):
        self.plugin_id = plugin_id
        self.plugin = None

    def details(self, sc):
        if self.plugin is None:
            resp = sc.get('plugin/%s' % self.plugin_id)
            self.plugin = json.loads(resp.content)['response']
        return self.plugin

    def analyze(self, sc, repository, address, port, tool='sumid', sourceType='cumulative', scanID=None):
        print("{}, {}, {}".format(repository, address, port))
        if sourceType == 'individual' and scanID is not None:
            vulns = sc.analysis(('ip', '=', address),
                ('port', '=', port),
                ('pluginID', '=', self.plugin_id),
                ('repository', '=', [repository]),
                tool=tool, view='all', sourceType=sourceType, scanID=scanID)
        else:
            vulns = sc.analysis(('ip', '=', address),
                ('port', '=', port),
                ('pluginID', '=', self.plugin_id),
                ('repository', '=', [repository]), tool=tool)
        return vulns


class Policy(object):

    def __init__(self, plugin):
        self.payload = {
            "name": "",
            "description": "",
            "context": "scan",
            "createdTime": 0,
            "modifiedTime": 0,
            "groups": [],
            "policyTemplate": {
                "id": 1
            },
            "auditFiles":[],
            "preferences": {
                "portscan_range": "default",
                "tcp_scanner": "no",
                "syn_scanner": "yes",
                "udp_scanner": "no",
                "syn_firewall_detection": "Automatic (normal)",
                # "tcp_ping_dest_ports": 80,
            },
            "families": [
                {
                    # validate remediation for this plugin
                    "id": plugin['family']['id'],
                    "plugins": [
                        {
                            "id": plugin['id']
                        }
                    ]
                },
                {
                    # this plugin (Nessus Scan Information) must be included on all scans
                    "id": "41",
                    "plugins": [
                        {
                            "id": "19506"
                        }
                    ]
                },
            ]
        }


    def post(self, sc):
        resp = sc.post("/policy", json = self.payload)
        '''
        {
            "name": "",
            "description": "",
            "context": "scan",
            "createdTime": 0,
            "modifiedTime": 0,
            "groups": [],
            "policyTemplate": {
                "id": 1
            },
            "auditFiles":[],
            "preferences": {
                "portscan_range": "default",
                "tcp_scanner": "no",
                "syn_scanner": "yes",
                "udp_scanner": "no",
                "syn_firewall_detection": "Automatic (normal)"
            },
            "families": [
                {
                    "id": self.family_id,
                    "plugins": [
                        {
                            "id": self.plugin_id
                        }
                    ]
                },
                {
                    "id": "41",
                    "plugins": [
                        {
                            "id": "19506"
                        }
                    ]
                },
            ]
        }
        '''
        return json.loads(resp.content)['response']['id']


class Scan(object):

    def __init__(self, name, repository, policy_id, plugin, address, credentials=None, reports=None):
        self.result_id = None
        self.payload = {
            "name": name,
            # send just the credential 'id' after mapping from a string to an integer within the dict
            "credentials": [] if credentials is None else list(map(lambda c: {'id': int(c['id'])}, credentials)),
            "reports": [] if reports is None else reports,
            "pluginID": plugin['id'],
            "ipList": "%s" % address,
            "repository": repository,
            "description": "",
            "context": "",
            "createdTime": 0,
            "modifiedTime": 0,
            "groups": [],
            "schedule": {
                "start": "TZID=America/New_York:20171212T160900",
                "repeatRule": "FREQ=NOW;INTERVAL=1",
                "type": "now"
            },
            "dhcpTracking": "true",
            "emailOnLaunch": "false",
            "emailOnFinish": "false",
            "type": "policy",
            "policy": {
                "id": policy_id
            },
            "timeoutAction": "import",
            # "rolloverType": "template",
            "scanningVirtualHosts": "false",
            "classifyMitigatedAge": 0,
            "assets": [],
            "maxScanTime": "unlimited"
        }

    def launch(self, sc):
        resp = sc.post("/scan", json=self.payload).json()['response']
        self.result_id = resp['scanResultID']
        debug("Launched scan, resultID=%s" % self.result_id, json.dumps(resp, indent=4))
        return self

def wait_until(condition, context=None, interval=POLLING_INTERVAL):
    while True:
        if context is not None and condition(context):
            return True
        elif context is None and condition():
            return True
        sleep(interval)

def get_repository(sc, name):
    resp = sc.get("/repository")
    repos = json.loads(resp.content)['response']
    matches = filter(lambda r: r['name'] == name, repos)
    return matches[0] if matches else {}


def get_credentials(sc):
    resp = sc.get("/credential", params={
        'filter': 'usable',
        'fields': 'id'
    })
    return resp.json()['response']['usable']


def print_debug(label, output):
    print("{}:".format(label.upper()))
    print("{}\n".format(output))
    return True

DEBUG_ON = True
debug = lambda l, o: print_debug(l,o) if DEBUG_ON else False


def launch_remediaton_scan(sc, repository, scan_name, address, port, plugin):

    credentials = get_credentials(sc)
    # print("CREDENTIALS:")
    # print(json.dumps(credentials, indent=4))
    debug("credentials", json.dumps(credentials, indent=4))

    # repo_vulns = vulnerability.analyze(sc, repository_id, tool='sumid')

    # The scan policy requires a name and the family_id from 'plugin'
    policy = Policy(plugin)
    policy_id = policy.post(sc)

    debug("LAUNCHING", scan_name)
    scan = Scan(scan_name, repository, policy_id, plugin, address, credentials)
    scan.launch(sc)

    return scan


def main():
    sc_address = "lab15"
    username = "secmgr"
    password = "TestPassw0rd"

    address = '172.26.48.14'
    port = '445'
    plugin_id = '97737'
    repo_name = "Test Repo"
    name = "Remediation scan of %s:%s for #%s" % (address, port, plugin_id)

    sc = SecurityCenter5(sc_address)
    sc.login(username, password)

    # grab plugin details including family_id needed for policy
    plugin = Plugin(plugin_id)
    plugin_details = plugin.details(sc)
    debug("plugin details", json.dumps(plugin_details, indent=4))

    # need a repository to store the results
    repository = get_repository(sc, repo_name)
    if not repository:
        print("repository '{}', not found".format(repo_name))
        exit(1)


    scan = launch_remediaton_scan(sc, repository, name, address, port, plugin_details)

    def scan_complete(sc):
        status = sc.get('scanResult/%s' % scan.result_id).json()['response']['status']
        return status == 'Completed' or status == 'Error'

    wait_until(scan_complete, sc)
    debug("SCAN COMPLETE", "%s ID=%s" % (name, scan.result_id))
    
    # result = sc.get('scanResult/%s' % scan.result_id).json()['response']
    # debug("Scan results", json.dumps(result, indent=4))

    vulns = plugin.analyze(sc, repository, address, port, tool='vulndetails', sourceType='individual', scanID="101")

    for vuln in vulns:
        print(json.dumps(vuln, indent=4))





if __name__ == '__main__':
    main()
