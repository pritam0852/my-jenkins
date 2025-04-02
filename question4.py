import boto3
from botocore.exceptions import ClientError
import csv

def get_iam_roles_with_admin_access():
    iam = boto3.client("iam")
    roles_with_admin = []
    for role in iam.list_roles()["Roles"]:
        policies = iam.list_attached_role_policies(RoleName=role["RoleName"])['AttachedPolicies']
        for policy in policies:
            if policy['PolicyName'] == "AdministratorAccess":
                roles_with_admin.append(role["RoleName"])
    return roles_with_admin

def get_users_without_mfa():
    iam = boto3.client("iam")
    users_without_mfa = []
    for user in iam.list_users()["Users"]:
        if not iam.list_mfa_devices(UserName=user["UserName"])['MFADevices']:
            users_without_mfa.append(user["UserName"])
    return users_without_mfa

def get_exposed_security_groups():
    ec2 = boto3.client("ec2")
    exposed_sgs = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for rule in sg["IpPermissions"]:
            for ip_range in rule.get("IpRanges", []):
                if ip_range["CidrIp"] == "0.0.0.0/0":
                    exposed_sgs.append({"GroupId": sg["GroupId"], "Port": rule.get("FromPort", "All")})
    return exposed_sgs

def get_unused_key_pairs():
    ec2 = boto3.client("ec2")
    key_pairs = {kp["KeyName"] for kp in ec2.describe_key_pairs()["KeyPairs"]}
    used_keys = set()
    for reservation in ec2.describe_instances()["Reservations"]:
        for instance in reservation["Instances"]:
            if "KeyName" in instance:
                used_keys.add(instance["KeyName"])
    return list(key_pairs - used_keys)

def generate_security_report():
    filename = "aws_security_report.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Issue", "Details"])
        for role in get_iam_roles_with_admin_access():
            writer.writerow(["Overly Permissive Role", role])
        for user in get_users_without_mfa():
            writer.writerow(["User Without MFA", user])
        for sg in get_exposed_security_groups():
            writer.writerow(["Publicly Accessible Security Group", f"{sg['GroupId']} (Port {sg['Port']})"])
        for key in get_unused_key_pairs():
            writer.writerow(["Unused EC2 Key Pair", key])
    print(f"Security report generated: {filename}")

if __name__ == "__main__":
    generate_security_report()
