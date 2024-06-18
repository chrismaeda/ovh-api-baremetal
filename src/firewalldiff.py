from enum import Enum
import json


def load_firewall_rules(rules: str) -> list:
    with open(rules, 'r') as f:
        expected_rules = json.load(f)
    # 20240617 delete comments in rules
    for rule in expected_rules:
        if 'comment' in rule:
            del rule['comment']
    return expected_rules


class RuleCheckResult(Enum):
    OK = 1
    MISMATCH = 2
    MISSING = 3
    UNEXPECTED = 4
    NORULE = 5


class OvhFirewallRuleChecker:
    def __init__(self, firewall_rules):
        self.firewall_rules = firewall_rules

    def compare_rule(self, expected_rule: dict, actual_rule: dict):
        if expected_rule['sequence'] != actual_rule['sequence']:
            return False, 'sequence'
        for key in expected_rule:
            if key not in actual_rule:
                return False, key
            if expected_rule[key] != actual_rule[key]:
                # special handling for source
                # must be 'null' in the rule file but will return as 'any' from ovh api
                if key == 'source':
                    if not expected_rule[key] and actual_rule[key] == 'any':
                        continue
                # special handling for sourcePort
                # in the rule file, we specify the port number ('123') but it 
                # comes back from the api as 'eq 123'
                if key == 'sourcePort':
                    if actual_rule[key] and actual_rule[key].startswith('eq '):
                        actual_port_val = actual_rule[key][3:]
                        if expected_rule[key] == actual_port_val:
                            continue
                return False, key
        return True, None

    def find_rule(self, rules: list, seqnum: int):
        for rule in rules:
            if rule['sequence'] == seqnum:
                return rule

    def check_rule(self, seq: int, rules: list):
        expected_rule = self.find_rule(self.firewall_rules, seq)
        actual_rule = self.find_rule(rules, seq)
        if expected_rule is None and actual_rule is None:
            return RuleCheckResult.NORULE, None
        if expected_rule is None:
            return RuleCheckResult.UNEXPECTED, None
        if actual_rule is None:
            return RuleCheckResult.MISSING, None
        # compare the rules    
        isequal, key = self.compare_rule(expected_rule, actual_rule)
        if isequal:
            return RuleCheckResult.OK, None
        else:
            return RuleCheckResult.MISMATCH, key

    def check(self, rules: list):
        # ovh firewalls have a sequence number, from 0 to 19
        mismatches = 0
        matches = 0
        for seq in range(20):
            expected_rule = self.find_rule(self.firewall_rules, seq)
            actual_rule = self.find_rule(rules, seq)
            
            checkresult, key = self.check_rule(seq, rules)
            if checkresult == RuleCheckResult.OK:
                matches += 1
                continue
            elif checkresult == RuleCheckResult.NORULE:
                continue
            elif checkresult == RuleCheckResult.UNEXPECTED:
                mismatches += 1
                print(f"\t\t{seq} UNEXPECTED RULE {actual_rule}")
                continue                
            elif checkresult == RuleCheckResult.MISSING:
                mismatches += 1
                print(f"\t\t{seq} MISSING RULE {expected_rule}")
                continue                
            else:
                mismatches += 1
                print(f"\t\t{seq} MISMATCH {key} {expected_rule[key]} != {actual_rule[key]}")
                print(f"\t\t\tEXPECTED {expected_rule}\n\t\t\tACTUAL {actual_rule}")

        print(f"\tTotal Matches: {matches}; Mismatches: {mismatches}")
        return (mismatches == 0)
