"""import os
import json
import argparse
import ast
import boto3
import logging
import boto3
from botocore.exceptions import ClientError
def assume_role(role,region):
    print("role",role,region)
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=role,
        RoleSessionName="AssumeRoleSession1")
    credentials = assumed_role_object['Credentials']
    accesskey = credentials['AccessKeyId']
    secretkey = credentials['SecretAccessKey']
    session1 = credentials['SessionToken']
    client = boto3.client('s3',
                          aws_access_key_id=accesskey,
                          aws_secret_access_key=secretkey,
                          aws_session_token=session1,
                          region_name=region)
    return client
def assume_role_glacier(role,region):
    print("role",role,region)
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=role,
        RoleSessionName="AssumeRoleSession1")
    credentials = assumed_role_object['Credentials']
    accesskey = credentials['AccessKeyId']
    secretkey = credentials['SecretAccessKey']
    session1 = credentials['SessionToken']
    client = boto3.client('glacier',
                          aws_access_key_id=accesskey,
                          aws_secret_access_key=secretkey,
                          aws_session_token=session1,
                          region_name=region)
    return client
def tag(vaultname,role,region,tagname):
    try:
        a = assume_role_glacier(role,region)
        response = a.add_tags_to_vault(
            vaultName=vaultname,
            Tags={
                'new_vault': tagname
            }
        )
    except ClientError as e:
        logging.error(e)
        return None
    return response
def buc_policy(bucketname,policy,role,region):
    a = assume_role(role, region)
    s=a.put_bucket_policy(Bucket=bucketname, Policy=policy)
    print("s",s)
def buc_tag(bucketname,role,region,tagname):
    a = assume_role(role, region)
    print("tagname",type(tagname))
    #tagname=json.loads(tagname)
    response = a.put_bucket_tagging(
        Bucket=bucketname,
        Tagging={
            'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in tagname.items()]
        }
    )
    print("atag",response)

def create_vault(name,role,region):
    #glacier = boto3.resource('glacier')
    try:
        a=assume_role_glacier(role,region)
        vault = a.create_vault(vaultName=name)
        #tag1 = tag(tagname,name)
        #policy = policy1(policy,name)

    except ClientError as e:
        logging.error(e)
        return None
    return vault
def policy1(vaultname,role,region,main):
    a = assume_role_glacier(role,region)
    response = a.set_vault_access_policy(
        accountId='-',
        policy={
            'Policy': main},
        vaultName=vaultname,
    )
def createbucket(bucket,role,region):
    print("r",role,bucket,region)
    a = assume_role(role,region)
    location = {'LocationConstraint': region}
    buck = a.create_bucket(Bucket=bucket,
                           CreateBucketConfiguration=location)
    print(buck)
def main():
    parser = argparse.ArgumentParser(description="A text file manager!")

    parser.add_argument("-create", "--createbucket", type=str, nargs="*",
                        metavar="file_name", default=None,
                        help="Opens and reads the specified text file.")
    parser.add_argument("--bucketpolicy", type=str,
                        metavar="file_name", default=None,
                        help="Opens and reads the specified text file.")
    parser.add_argument("--buckettag", type=ast.literal_eval,
                        metavar="file_name", default=None,
                        help="Opens and reads the specified text file.")
    parser.add_argument("-glacier", "--createvault", type=str, nargs="*",
                        metavar="file_name", default=None,
                        help="Opens and reads the specified text file.")
    parser.add_argument("--policy", help="JSON file to be processed", type=str)
    parser.add_argument("--vaulttag", type=str,
                        metavar="file_name", default=None,
                        help="Opens and reads the specified text file.")
    args = parser.parse_args()
    role='arn:aws:iam::381650921409:role/karthikaec2rem'
    if args.createbucket != None:
        print("arg", args.createbucket)
        buck = {}
        for i in args.createbucket:
            print("i", i)
            key = i.split("=")[0]
            value = i.split("=")[-1]
            buck[key] = value
        print("buck", buck)

        # bucketname=hasattr(cli,args.createbucket[0])
        # print("buckket", bucketname)
        # if bucketname is True:
        #for k, v in buck.items():
            #print("k", k, v)
        if "bucketname" in buck and "region" in buck and "tagname" in buck and "policy" in buck:
            bucketname =buck['bucketname']
            region=buck['region']
            tagname=buck['tagname']
            policy=buck['policy']
            with open(policy) as G:
                bucpolicy = json.load(G)
                print(bucpolicy)
                for val in bucpolicy.values():
                    for k in val:
                        print("k", k)
                        for key, value in k.items():
                            print("key", key)
                            if key == 'Resource':
                                print("val", value)
                                k[key] = "arn:aws:s3:::{}/*".format(bucketname)
                print("val", bucpolicy)
            pol = json.dumps(bucpolicy)
            print("policy", bucpolicy)
            a = createbucket(bucketname, role, region, tagname, pol)
        elif "bucketname" in buck:
            bucketname = buck['bucketname']
            region = "us-east-1"
        if "tagname" in k:
            tagname = v
        else:
            tagname = None
        if "policy" in k:
            with open(v) as G:
                bucpolicy = json.load(G)
                print(bucpolicy)
                for val in bucpolicy.values():
                    for k in val:
                        print("k", k)
                        for key, value in k.items():
                            print("key", key)
                            if key == 'Resource':
                                print("val", value)
                                k[key] = "arn:aws:s3:::{}/*".format(bucketname)
                print("val", bucpolicy)
            policy = json.dumps(bucpolicy)
            print("policy", bucpolicy)
        else:
            policy = None
        a = createbucket(bucketname,role, region, tagname, policy)
        print("a", a)
if __name__ == "__main__":
    m=main()
"""
