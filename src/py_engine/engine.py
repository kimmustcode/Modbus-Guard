import yaml

class PolicyEngine:
    def __init__(self, rules_path):
        # TODO: Load rules from YAML
        with open(rules_path, "r") as rules: 
            self.rules_dict = yaml.safe_load(file)
            print(self.rules_dict)
        pass

    def evaluate(self, packet):
        # TODO: Evaluate a packet against the loaded rules.        
        # Args:
        #    packet: A ModbusPacket ctypes object.
        # Your logic here:
        # 1. Extract FC, Unit ID, Register Address.
        # 2. Iterate through rules.
        # 3. Print alerts for violations.

        pass
