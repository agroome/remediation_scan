'''
THIS CODE IS FOR EXAMPLE ONLY, IT IS NOT SUPPORTED BY TENABLE, USE AT YOUR OWN RISK

This is an example of performing a remediation scan for a specific plugin
against a specific IP address. The advanced scan template also sends other 
probes to identify the operating system and services. Configuration
settings in the scan definition can be tuned to further control traffic, for 
example, to limit port scans to a specific port.

This was roughly based on this example which is (suggested reading):
https://docs.tenable.com/sccv/api_best_practices/Content/ScApiBestPractices/LaunchRemediationScan.htm

'''
from securitycenter import SecurityCenter5
from getpass import getpass
import json
import click
from time import sleep

SC_ADDRESS = "lab15"
SC_USER = "secmgr"

POLLING_INTERVAL = 10
DEFAULT_REPOSITORY = "Test Repo"

plugin_fields = ','.join([
    "protocol",
    "vulnPubDate",
    "family",
    "checkType",
    "exploitAvailable",
    "srcPort",
    "solution",
    "cvssVector",
    "xrefs",
    "id",
    "pluginPubDate",
    "stigSeverity",
    "copyright",
    "baseScore",
    "pluginModDate",
    "version",
    "type",
    "riskFactor",
    "temporalScore",
    "exploitFrameworks",
    "description",
    "modifiedTime",
    "requiredUDPPorts",
    "dependencies",
    "requiredPorts",
    "dstPort",
    "md5",
    "name",
    "sourceFile",
    "cpe",
    "synopsis",
    "exploitEase",
    "patchPubDate",
    "cvssVectorBF",
    "patchModDate",
    "seeAlso",
])


class Plugin(object):
    def __init__(self, plugin_id):
        self.plugin_id = plugin_id
        self.plugin = None

    def details(self, sc):
        if self.plugin is None:
            resp = sc.get('plugin/%s' % self.plugin_id, params={
                'fields': plugin_fields
            })
            self.plugin = json.loads(resp.content)['response']
        return self.plugin


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
                    # the 'Nessus Scan Information' plugin 19506 must be included on all scans
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
        return { "id": json.loads(resp.content)['response']['id'] }


class Scan(object):

    def __init__(self, name, repository, policy, plugin, address, credentials=None, reports=None):
        self.result_id = None
        self.scan_definition = None
        self.name = name
        self.payload = {
            "name": self.name,
            "credentials": [] if credentials is None else credentials,
            "reports": [] if reports is None else reports,
            "pluginID": plugin['id'],
            "ipList": "%s" % address,
            "assets": [],
            "repository": repository,
            "type": "policy",
            "policy": policy,
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
            "timeoutAction": "import",
            "scanningVirtualHosts": "false",
            "classifyMitigatedAge": 0,
            "maxScanTime": "unlimited"
        }


    def launch(self, sc, blocking=False):
        self.scan_definition = sc.post("/scan", json=self.payload).json()['response']
        self.result_id = self.scan_definition['scanResultID']
        debug("SCAN Launched", json.dumps(self.scan_definition, indent=4))

        if blocking == True:
            def scan_complete_or_error(sc):
               status = sc.get('scanResult/%s' % self.result_id).json()['response']['status']
               return status == 'Completed' or status == 'Error'
            wait_until(scan_complete_or_error, sc)
            debug("SCAN COMPLETE", "%s ID=%s" % (self.name, self.result_id))

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
    credentials = resp.json()['response']['usable']
    debug("Credentials", json.dumps(credentials, indent=4))
    # credential 'id' must be passed as an int, cast before returning
    return list(map(lambda c: {'id': int(c['id'])}, credentials))


DEBUG_ON = True
def debug(label, output=''):
    if DEBUG_ON:
        print("{}:".format(label.upper()))
        print("{}\n".format(output))
        return True
    else:
        return False



def remediation_scan(sc, repository_name, plugin_id, address, port):

    name = "Remediation scan for #%s, %s:%s" % (plugin_id, address, port)

    # grab plugin details including family_id needed for policy
    p = Plugin(plugin_id)
    plugin = p.details(sc)
    debug("plugin details", json.dumps(plugin, indent=4))

    # need a repository to store the results
    repository = get_repository(sc, repository_name)
    if not repository:
        print("repository '{}', not found".format(repository_name))
        exit(1)

    # optionally grab credentials
    credentials = get_credentials(sc)

    # Create and post scan policy
    policy = Policy(plugin).post(sc)

    # Launch the scan
    debug("LAUNCHING", name)
    scan = Scan(name, repository, policy, plugin, address, credentials)
    scan.launch(sc)

    return scan


@click.group()
def cli():
    pass

@cli.command()
@click.argument('plugin_id')
@click.argument('address')
@click.argument('port')
@click.option('--repository', default=DEFAULT_REPOSITORY)
@click.pass_context
def launch(ctx, plugin_id, address, port, repository):
    sc = ctx.obj['sc']
    scan = remediation_scan(sc, repository, plugin_id, address, port)
    click.echo("Scan running scan_result_id is {}".format(scan.result_id))

@cli.command()
@click.argument('plugin_id')
@click.argument('address')
@click.argument('port')
@click.option('--repository', default=DEFAULT_REPOSITORY)
@click.option('--scan-id', default=0)
@click.pass_context
def analyze(ctx, plugin_id, address, port, repository, scan_id):

    sc = ctx.obj['sc']

    def print_results(vulns):
        if vulns is None:
            click.echo("Zero results found.")
        else:
            for vuln in vulns:
                click.echo(json.dumps(vuln, indent=4))

    if scan_id:
        click.echo("Individual Scan Results (ID={}), Vulns:".format(scan_id))
        vulns  = sc.analysis(('ip', '=', address), ('pluginID', '=', plugin_id),
                   tool='sumid', sourceType='individual', scanID=scan_id, view='all')
        print_results(vulns)

        click.echo("Individual Scan Results (ID={}), Remediated:".format(scan_id))
        vulns  = sc.analysis(('ip', '=', address), ('pluginID', '=', plugin_id),
                   tool='sumid', sourceType='individual', scanID=scan_id, view='patched')
        print_results(vulns)
    else:
        click.echo("Cumulative Scan Results (Vulns): ")
        vulns  = sc.analysis(('ip', '=', address), ('pluginID', '=', plugin_id),
               tool='sumid', sourceType='cumulative')
        print_results(vulns)

        click.echo("Cumulative Scan Results (Mitigated): ")
        vulns  = sc.analysis(('ip', '=', address), ('pluginID', '=', plugin_id),
                   tool='sumid', sourceType='patched')
        print_results(vulns)


def main():
    address = raw_input("SecurityCenter[{}]:".format(SC_ADDRESS))
    address = address if address else SC_ADDRESS

    username = raw_input("user[{}]:".format(SC_USER))
    username = username if username else SC_USER

    password = ""
    password = password if password else getpass("password:")

    sc = SecurityCenter5(address)
    sc.login(username, password)

    cli(obj={'sc': sc})



if __name__ == '__main__':
    main()
