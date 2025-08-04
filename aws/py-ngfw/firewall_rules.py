import pulumi_aws as aws
import pulumi as pulumi

def create_firewall_policy(supernet_cidr: str) -> pulumi.Output[str]:

    drop_remote = aws.networkfirewall.RuleGroup("ngfw-drop-remote",
        capacity=2,
        name="ngfw-drop-remote",
        type="STATELESS",
        rule_group={
            "rules_source": {
                "stateless_rules_and_custom_actions": {
                    "stateless_rules": [
                        {
                            "priority": 1,
                            "rule_definition": {
                                "actions": ["aws:drop"],
                                "match_attributes": {
                                    "protocols": [6],
                                    "sources": [{"address_definition": "0.0.0.0/0"}],
                                    "source_ports": [
                                        {
                                            "from_port": 22,
                                            "to_port": 22,
                                        }
                                    ],
                                    "destinations": [{"address_definition": "0.0.0.0/0"}],
                                    "destination_ports": [
                                        {
                                            "from_port": 22,
                                            "to_port": 22,
                                        }
                                    ],
                                },
                            },
                        }
                    ]
                }
            }
        },
    )

    allow_icmp = aws.networkfirewall.RuleGroup(
        "ngfw-allow-icmp",
        capacity=100,
        type="STATEFUL",
        rule_group={
            "stateful_rule_options": {"rule_order": "STRICT_ORDER"},
            "rules_source": {
                "rules_string": 'pass icmp $SUPERNET any -> $SUPERNET any (msg: "Allowing ICMP packets"; sid:2; rev:1;)'
            },
            "rule_variables": {
                "ip_sets": [
                    {
                        "key": "SUPERNET",
                        "ip_set": {
                            "definitions": [supernet_cidr],
                        },
                    }
                ],
            }
        },
    )

    allow_amazon = aws.networkfirewall.RuleGroup(
        "ngfw-allow-amazon",
        capacity=100,
        name="ngfw-allow-amazon",
        type="STATEFUL",
        rule_group={
            "stateful_rule_options": {"rule_order": "STRICT_ORDER"},
            "rules_source": {
                "rules_string": 'pass tcp any any <> $EXTERNAL_NET 443 (msg:"Allowing TCP in port 443"; flow:not_established; sid:892123; rev:1;)\n'
                + 'pass tls any any -> $EXTERNAL_NET 443 (tls.sni; dotprefix; content:".amazon.com"; endswith; msg:"Allowing .amazon.com HTTPS requests"; sid:892125; rev:1;)'
            }
        },
    )

    ngfw_policy = aws.networkfirewall.FirewallPolicy("ngfw_policy",
        name="ngfw-policy",
        firewall_policy={
            "stateless_default_actions": ["aws:forward_to_sfe"],
            "stateless_fragment_default_actions": ["aws:forward_to_sfe"],
            "stateful_default_actions": ["aws:drop_strict", "aws:alert_strict"],
            "stateful_engine_options": {"rule_order": "STRICT_ORDER"},
            "stateless_rule_group_references": [{"priority": 10, "resource_arn": drop_remote.arn}],
            "stateful_rule_group_references": [
                {
                    "priority": 10,
                    "resource_arn": allow_icmp.arn,
                },
                {
                    "priority": 20,
                    "resource_arn": allow_amazon.arn,
                },
            ],
        })

    return ngfw_policy.arn
