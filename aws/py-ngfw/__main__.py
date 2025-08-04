"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws

from firewall_rules import create_firewall_policy
from inspection import InspectionVpc, InspectionVpcArgs

project = pulumi.get_project()
config = pulumi.Config()

name = config.get("name") or "ngfw"
supernet_cidr = config.get("supernet-cidr") or "10.0.0.0/8"
insp_vpc_cidr = config.get("insp-vpc-cidr") or "10.129.0.0/24"

edge = aws.ec2.Vpc(f"{name}-edge",
    cidr_block="10.0.0.0/16",
    tags={
        "Name": f"{name}-edge",
    })

tgw = aws.ec2transitgateway.TransitGateway(
    f"{name}-tgw",
    aws.ec2transitgateway.TransitGatewayArgs(
        description=f"Transit Gateway - {project} {name}",
        default_route_table_association="disable",
        default_route_table_propagation="disable",
        tags={"Name": f"{name}-pulumi"},
    ),
)

spoke_tgw_route_table = aws.ec2transitgateway.RouteTable(
    f"{name}-spoke-tgw-route-table",
    aws.ec2transitgateway.RouteTableArgs(
        transit_gateway_id=tgw.id,
        tags={
            "Name": f"{name}-spoke-tgw",
        },
    ),
    opts=pulumi.ResourceOptions(
        parent=tgw,
    ),
)

inspection_tgw_route_table = aws.ec2transitgateway.RouteTable(
    f"{name}-insp-tgw-route-table",
    aws.ec2transitgateway.RouteTableArgs(
        transit_gateway_id=tgw.id,
        tags={
            "Name": f"{name}-insp-tgw-route-table",
        },
    ),
    opts=pulumi.ResourceOptions(
        parent=tgw,
    ),
)

firewall_policy_arn = create_firewall_policy(supernet_cidr)

insp_vpc = InspectionVpc(
    f"{name}-inspection",
    InspectionVpcArgs(
        supernet_cidr_block=supernet_cidr,
        vpc_cidr_block=f"{insp_vpc_cidr}",
        tgw_id=tgw.id,
        inspection_tgw_route_table_id=inspection_tgw_route_table.id,
        spoke_tgw_route_table_id=spoke_tgw_route_table.id,
        firewall_policy_arn=firewall_policy_arn,
    ),
)

pulumi.export("nat-gateway-eip", insp_vpc.eip.public_ip)
