import ovh
import logging
import time
import urllib.parse

from firewalldiff import OvhFirewallRuleChecker, RuleCheckResult
from . import OvhObject


logger = logging.getLogger(__name__)


class IpObject(OvhObject):
    def __init__(self, ip: str, client: ovh.Client, logger: logging.Logger = None):
        super().__init__(client, logger)
        self.ip = ip

    def __repr__(self) -> str:
        return f"<{type(self).__name__} IP:{self.ip}>"

    def get_ip_details(self):
        # urlencode self.ip since it probably has a slash in it
        iparg = urllib.parse.quote_plus(self.ip)
        self.details = self._ovh_api_get(f"/ip/{iparg}")
        self.firewalls = self._ovh_api_get(f"/ip/{iparg}/firewall")
        return self.details

    def get_ip_under_firewall(self, ip: str = None):
        if ip:
            iparg2 = ip
        else:
            iparg2 = self.ip

        # remove the subnet mask if it's there
        if '/' in iparg2:
            iparg2 = iparg2.split('/')[0]
        iparg2 = urllib.parse.quote_plus(iparg2)
        return iparg2

    def get_firewall_status(self, ip: str = None):
        iparg1 = urllib.parse.quote_plus(self.ip)
        iparg2 = self.get_ip_under_firewall(ip)

        fwstat = self._ovh_api_get(f"/ip/{iparg1}/firewall/{iparg2}")
        return fwstat

    def get_firewall_rules(self, ip: str = None):
        iparg1 = urllib.parse.quote_plus(self.ip)
        iparg2 = self.get_ip_under_firewall(ip)

        rules = self._ovh_api_get(f"/ip/{iparg1}/firewall/{iparg2}/rule")
        fwrules = []
        for ruleseq in rules:
            rule = self._ovh_api_get(f"/ip/{iparg1}/firewall/{iparg2}/rule/{ruleseq}")
            fwrules.append(rule)
        fwrules.sort(key=lambda x: x['sequence'])
        return fwrules

    # convert rules from json file into json to be posted to ovh api
    def create_firewall_rule_json(self, rule: dict):
        sourcePort = rule.get('sourcePort')
        destinationPort = rule.get('destinationPort')

        apirule = {
            "sequence": rule['sequence'],
            "action": rule['action'],
            "protocol": rule['protocol'],
            "source": rule['source']
        }
        if sourcePort:
            apirule['sourcePort'] = sourcePort
        if destinationPort:
            apirule['destinationPort'] = destinationPort

        tcp_option = rule.get('tcpOption')
        tcp_fragments = rule.get('fragments')
        if tcp_option or tcp_fragments:
            option_elt = {}
            if tcp_fragments:
                option_elt['fragments'] = True
            else:
                option_elt['fragments'] = None
            if tcp_option:
                option_elt['option'] = tcp_option
            else:
                option_elt['option'] = None
            apirule['tcpOption'] = option_elt
        return apirule

    def update_firewall_rules(self, rules: list, ip: str = None, dryrun: bool = True):
        fwrules = self.get_firewall_rules(ip)

        iparg1 = urllib.parse.quote_plus(self.ip)
        iparg2 = self.get_ip_under_firewall(ip)
        checker = OvhFirewallRuleChecker(rules)
        actions = []

        for seq in range(20):
            checkresult, key = checker.check_rule(seq, fwrules)
            if checkresult == RuleCheckResult.OK or checkresult == RuleCheckResult.NORULE:
                continue
            elif checkresult == RuleCheckResult.UNEXPECTED:
                deluri = f"/ip/{iparg1}/firewall/{iparg2}/rule/{seq}"
                action = {"sequence": seq, "action": "delete", "uri": deluri}
                if not dryrun:
                    # delete rule
                    result = self._ovh_api_delete(deluri)
                    action["apiresult"] = result
                actions.append(action)
            elif checkresult == RuleCheckResult.MISSING:
                posturi = f"/ip/{iparg1}/firewall/{iparg2}/rule"
                missing_rule = checker.find_rule(rules, seq)
                postdata = self.create_firewall_rule_json(missing_rule)
                action = {"sequence": seq, "action": "create", "uri": posturi, "rule": missing_rule, "apidata": postdata}
                if not dryrun:
                    # add rule
                    result = self._ovh_api_post(posturi, postdata)
                    action["apiresult"] = result
                actions.append(action)
            elif checkresult == RuleCheckResult.MISMATCH:
                mismatch_rule = checker.find_rule(rules, seq)
                deluri = f"/ip/{iparg1}/firewall/{iparg2}/rule/{seq}"
                action1 = {"sequence": seq, "action": "delete", "uri": deluri}

                posturi = f"/ip/{iparg1}/firewall/{iparg2}/rule"
                missing_rule = checker.find_rule(rules, seq)
                postdata = self.create_firewall_rule_json(missing_rule)
                action2 = {"sequence": seq, "action": "create", "rule": mismatch_rule, "uri": posturi, "apidata": postdata}

                if not dryrun:
                    # delete rule
                    result = self._ovh_api_delete(deluri)
                    action1["apiresult"] = result

                    # sleep to allow the delete to complete
                    time.sleep(30)

                    # add rule
                    result = self._ovh_api_post(posturi, postdata)
                    action2["apiresult"] = result
                actions.append(action1)
                actions.append(action2)
        return actions


class DedicatedServer(OvhObject):
    def __init__(self, name: str, client: ovh.Client, logger: logging.Logger = None):
        super().__init__(client, logger)
        self.name = name
        self.displayName = None
        self.ip = None
        self.iplist = None

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name:{self.name} display:{self.displayName}>"

    def get_server_details(self):
        self.details = self._ovh_api_get(f'/dedicated/server/{self.name}')
        self.ip = self.details.get('ip')
        svr_iam = self.details.get('iam')
        if svr_iam:
            self.displayName = svr_iam.get('displayName')
        # grab the ips for the server
        iplist = self._ovh_api_get(f"/dedicated/server/{self.name}/ips")
        self.iplist = [IpObject(ip, self.client, self.logger) for ip in iplist]

