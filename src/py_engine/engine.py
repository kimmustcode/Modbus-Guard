import yaml
import socket
import struct

class PolicyEngine:
    def __init__(self, rules_path):
        with open(rules_path, "r") as rules: 
            self.rules_dict = yaml.safe_load(rules)
        pass

    def evaluate(self, packet):
        readableIP = socket.inet_ntoa(struct.pack("<I", packet.src_ip))

        for rule in self.rules_dict['rules']:
            if packet.function_code in rule.get('function_codes', []):
                # If the rule specifies registers, check if the packet's register matches
                if 'registers' in rule:
                    if packet.register_address not in rule['registers']:
                        continue 
                
                if rule['action'] == 'alert':
                    print(f"ALERT ({rule['severity']}): {rule['description']} ({packet.function_code}, {readableIP})")
                return rule['action']

        return self.rules_dict.get('global', {}).get('default_action', 'allow')
