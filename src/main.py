import click
import json
import logging
import ovh

from firewalldiff import OvhFirewallRuleChecker, load_firewall_rules
from ovhapi.dedicatedserver import DedicatedServer, IpObject


# command group
@click.group()
def cli():
    pass


# servers command
@cli.command()
def servers():
    logger = logging.getLogger(__name__)
    ovhcli = ovh.Client()
    servers = ovhcli.get('/dedicated/server/')
    for server in servers:
        ds = DedicatedServer(server, ovhcli, logger)
        details = ds.get_server_details()
        print(f"{server} ({ds.displayName}) IP:{ds.ip}\n\tOtherIPs:{[ ipobj.ip for ipobj in ds.iplist]}")

@cli.command()
@click.option('--server', default=None, help="Server name to get details for")
@click.option('--ipservice', default=None, help="IP service to get details for")
@click.option('--ip', default=None, help="IP within IP service to get details for")
def firewall(server, ipservice, ip):
    logger = logging.getLogger(__name__)
    ovhcli = ovh.Client()
    
    if server:
        ds = DedicatedServer(server, ovhcli, logger)
        ds.get_server_details()
        svrip = IpObject(ds.ip, ovhcli, logger)
        svrip.get_ip_details()
        
        fwstat = svrip.get_firewall_status()
        fwrules = svrip.get_firewall_rules()
        print(f"{server} ({ds.displayName}) IP:{ds.ip}\n\tFirewall Status:{fwstat}")
        if fwrules:
            print(f"\tFirewall Rules:")
            for rule in fwrules:
                print(f"\t{rule['sequence']} {rule['rule']}")
    elif ipservice:
        svrip = IpObject(ipservice, ovhcli, logger)
        svrip.get_ip_details()
        
        if ip:
            if ip not in svrip.firewalls:
                print(f"IP {ip} not found in IP service {ipservice}")
                return
            fwstat = svrip.get_firewall_status(ip)
            fwrules = svrip.get_firewall_rules(ip)
            print(f"{ip} in {ipservice})\n\tFirewall Status:{fwstat}")
            if fwrules:
                print(f"\tFirewall Rules:")
                for rule in fwrules:
                    print(f"\t{rule['sequence']} {rule['rule']}")
        else:
            # display all IPs in the IP service
            for ip in svrip.firewalls:
                fwstat = svrip.get_firewall_status(ip)
                fwrules = svrip.get_firewall_rules(ip)
                print(f"{ipservice} IP:{ip}\n\tFirewall Status:{fwstat}")
                if fwrules:
                    print(f"\tFirewall Rules:")
                    for rule in fwrules:
                        print(f"\t{rule['sequence']} {rule['rule']}")

@cli.command()
@click.option('--server', default=None, help="Server name to get details for")
@click.option('--ipservice', default=None, help="IP service to get details for")
@click.option('--ip', default=None, help="IP within IP service to get details for")
@click.option('--rules', default=None, help="JSON file wth firewall rules", required=True)
def checkfirewall(server, ipservice, ip, rules):
    logger = logging.getLogger(__name__)
    ovhcli = ovh.Client()
    
    # load firewall rules
    expected_rules = load_firewall_rules(rules)
    checker = OvhFirewallRuleChecker(expected_rules)
    
    if server:
        ds = DedicatedServer(server, ovhcli, logger)
        ds.get_server_details()
        svrip = IpObject(ds.ip, ovhcli, logger)
        svrip.get_ip_details()
        
        fwstat = svrip.get_firewall_status()
        fwrules = svrip.get_firewall_rules()
        print(f"{server} ({ds.displayName}) IP:{ds.ip}\n\tFirewall Status:{fwstat}")
        checker.check(fwrules)
    elif ipservice:
        svrip = IpObject(ipservice, ovhcli, logger)
        svrip.get_ip_details()
        
        if ip:
            if ip not in svrip.firewalls:
                print(f"IP {ip} not found in IP service {ipservice}")
                return
            fwstat = svrip.get_firewall_status(ip)
            fwrules = svrip.get_firewall_rules(ip)
            print(f"{ip} in {ipservice})\n\tFirewall Status:{fwstat}")
            checker.check(fwrules)
        else:
            # display all IPs in the IP service
            for ip in svrip.firewalls:
                fwstat = svrip.get_firewall_status(ip)
                fwrules = svrip.get_firewall_rules(ip)
                print(f"{ipservice} IP:{ip}\n\tFirewall Status:{fwstat}")
                checker.check(fwrules)


@cli.command()
@click.option('--server', default=None, help="Server name to get details for")
@click.option('--ipservice', default=None, help="IP service to get details for")
@click.option('--ip', default=None, help="IP within IP service to get details for")
@click.option('--rules', default=None, help="JSON file wth firewall rules", required=True)
@click.option('--dryrun', default=True, help="Print but do not perform actions", type=bool)
def updatefirewall(server, ipservice, ip, rules, dryrun):
    logger = logging.getLogger(__name__)
    ovhcli = ovh.Client()
    
    # load firewall rules
    expected_rules = load_firewall_rules(rules)
    
    if server:
        ds = DedicatedServer(server, ovhcli, logger)
        ds.get_server_details()
        svrip = IpObject(ds.ip, ovhcli, logger)
        svrip.get_ip_details()
        
        fwstat = svrip.get_firewall_status()
        print(f"{server} ({ds.displayName}) IP:{ds.ip}\n\tFirewall Status:{fwstat}")
        
        fwactions = svrip.update_firewall_rules(expected_rules, dryrun=dryrun)
        if fwactions:
            print(f"\tFirewall Actions:")
            for action in fwactions:
                print(f"\t{action}")
        else:
            print(f"\tNo firewall actions")
    elif ipservice:
        svrip = IpObject(ipservice, ovhcli, logger)
        svrip.get_ip_details()
        
        if ip:
            if ip not in svrip.firewalls:
                print(f"IP {ip} not found in IP service {ipservice}")
                return
            fwstat = svrip.get_firewall_status(ip)
            print(f"{ip} in {ipservice})\n\tFirewall Status:{fwstat}")
            
            fwactions = svrip.update_firewall_rules(expected_rules, ip=ip, dryrun=dryrun)
            if fwactions:
                print(f"\tFirewall Actions:")
                for action in fwactions:
                    print(f"\t{action}")
            else:
                print(f"\tNo firewall actions")
        else:
            # display all IPs in the IP service
            for ip in svrip.firewalls:
                fwstat = svrip.get_firewall_status(ip)
                print(f"{ipservice} IP:{ip}\n\tFirewall Status:{fwstat}")
                
                fwactions = svrip.update_firewall_rules(expected_rules, ip=ip, dryrun=dryrun)
                if fwactions:
                    print(f"\tFirewall Actions:")
                    for action in fwactions:
                        print(f"\t{action}")
                else:
                    print(f"\tNo firewall actions")

if __name__ == '__main__':
    cli()
