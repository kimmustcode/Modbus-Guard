import yaml

class PolicyEngine:
    def __init__(self, rules_path):
        # TODO: Load rules from YAML
        with open(rules_path, "r") as rules: 
            self.rules_dict = yaml.safe_load(rules)
        pass

    def evaluate(self, packet):
        # TODO: Evaluate a packet against the loaded rules.        
        # Args:
        #    packet: A ModbusPacket ctypes object.
        # Your logic here:
        # 1. Extract FC, Unit ID, Register Address.
        # 2. Iterate through rules.
        # 3. Print alerts for violations.

        print(packet.function_code)
        
        for rule in self.rules_dict['rules']:
            if packet.function_code in rule.get('function_codes', []):
                # If the rule specifies registers, check if the packet's register matches
                if 'registers' in rule:
                    if packet.register_address not in rule['registers']:
                        continue # Function code matches, but register doesn't
                
                if rule['action'] == 'alert':
                    print(f"ALERT: {rule['description']}")
                return rule['action']

        return self.rules_dict.get('global', {}).get('default_action', 'allow')
