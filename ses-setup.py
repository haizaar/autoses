#!/usr/bin/env python

import io
import json
import logging
import pathlib
import zipfile
from types import SimpleNamespace

import boto3
import botocore
import click
import click_log
import retrying

from config import config

logger = logging.getLogger(__name__)


class AWS:

    class LeftoversError(Exception):
        pass

    policy_templates = {
        "s3_bucket": {
            "name": "%(sidprefix)s-sesput-%(bucket)s-%(prefix)s",
            "description": "Allowes SES to store mails in the specific bucket/prefix",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "%(sidprefix)s-sesput-%(bucket)s-%(prefix)s",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ses.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::%(bucket)s/%(prefix)s/*",
                        "Condition": {
                            "StringEquals": {
                                "aws:Referer": "%(awsaccountid)s"
                            }
                        }
                    }
                ]
            }
        },

        # This is not IAM policy, but a S3 Lifecycle rule
        "s3_bucket_lifecycle": {
            "Expiration": {
                "Days": 0,
            },
            "Prefix": "%(prefix)s/",
            "ID": "%(sidprefix)s-%(prefix)s",
            "Status": "Enabled"
        },

        "sqs_queue": {
            "name": "%(sidprefix)s-sns-publish--%(prefix)s",
            "description": "Allows SNS to push SES notifications to specific topic",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "%(sidprefix)s-sns-publish-%(prefix)s",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "SQS:SendMessage",
                        "Resource": "%(queue_arn)s",
                        "Condition": {
                            "ArnEquals": {
                                "aws:SourceArn": "%(topic_arn)s"
                            }
                        }
                    }
                ]
            }
        },

        "user": {
            "name": "%(sidprefix)s-user-%(prefix)s",
            "description": "Allows SNS to push SES notifications to specific topic",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "%(sidprefix)s-usersubscribe-%(prefix)s",
                        "Effect": "Allow",
                        "Action": [
                            "sqs:ChangeMessageVisibility",
                            "sqs:ChangeMessageVisibilityBatch",
                            "sqs:DeleteMessage",
                            "sqs:DeleteMessageBatch",
                            "sqs:GetQueueAttributes",
                            "sqs:GetQueueUrl",
                            "sqs:ReceiveMessage"
                        ],
                        "Resource": [
                            "%(queue_arn)s"
                        ]
                    },
                    {
                        "Sid": "%(sidprefix)s-userget-%(bucket)s-%(prefix)s",
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            "arn:aws:s3:::%(bucket)s/%(prefix)s/*"
                        ]
                    }
                ]
            }
        },

        # This is not IAM policy, but a role definition
        "lambda_role": {
            "name": "%(sidprefix)s-role-trust-%(prefix)s",
            "description": "Allows Lambda function to execute and write logs",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        },

        "lambda_perms": {
            "name": "%(sidprefix)s-lambda-role-%(prefix)s",
            "description": "Allows Lambda function to execute and write logs",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:CreateLogGroup",
                        "Resource": "arn:aws:logs:%(region)s:%(awsaccountid)s:*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": [
                            "arn:aws:logs:%(region)s:%(awsaccountid)s:log-group:/aws/lambda/%(prefix)s:*"
                        ]
                    }
                ]
            },
        },
    }

    def __init__(self, region=config["region"]):
        self.logger = logger

        self.logger.info("Connecting to AWS")
        self.region_name = region
        self.session = boto3.session.Session(region_name=self.region_name)
        self.c = SimpleNamespace()
        self.r = SimpleNamespace()
        self.c.ses = self.session.client("ses")
        self.r.sns = self.session.resource("sns")
        self.c.sns = self.session.client("sns")
        self.r.sqs = self.session.resource("sqs")
        self.r.s3 = self.session.resource("s3")
        self.c.s3 = self.session.client("s3")
        self.r.iam = self.session.resource("iam")
        self.c.lambd = self.session.client("lambda")
        self.c.logs = self.session.client("logs")

    # FIXME: review config
    def create_config(self, profile_name):
        try:
            self.create_s3_bucket(config["s3bucket"])
            self.attach_s3_bucket_policy(profile_name, config["s3bucket"])
            self.attach_s3_bucket_lifecycle(profile_name, config["s3bucket"], config["s3_retention_days"])

            role = self.create_iam_role(profile_name)
            lambda_func = self.create_lambda_function(profile_name, role)
            topic = self.create_sns_topic(profile_name)
            queue = self.create_sqs_queue(profile_name, topic)
            self.subscribe_to_topic(profile_name, topic, queue, lambda_func)

            self.create_default_ruleset(config["ruleset"])
            self.create_receipt_rule(topic, config["ruleset"], profile_name, config["domain"], config["s3bucket"])

            self.create_iam_user(profile_name, config["s3bucket"], queue)
        except self.LeftoversError:
            raise SystemExit(1)

    def delete_config(self, profile_name):
        self.delete_s3_bucket_policy_statement(config["s3bucket"], profile_name)
        self.delete_lambda_function(profile_name)
        self.delete_iam_role(profile_name)
        self.delete_receipt_rule(profile_name)
        self.delete_sns_topic(profile_name)
        self.delete_sqs_queue(profile_name)
        self.delete_iam_user(profile_name)

    def create_default_ruleset(self, ruleset_name):
        try:
            self.c.ses.create_receipt_rule_set(RuleSetName=ruleset_name)
            self.logger.info("Created SES Ruleset %s", ruleset_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "AlreadyExists":
                raise
            self.logger.info("SES Ruleset %s already exists (OK)", ruleset_name)

        default_rs = self.c.ses.describe_active_receipt_rule_set()

        if "Metadata" not in default_rs or default_rs["Metadata"]["Name"] != ruleset_name:
            self.logger.info("Setting %s as default SES Ruleset", ruleset_name)
            self.c.ses.set_active_receipt_rule_set(RuleSetName=ruleset_name)

    def create_s3_bucket(self, bucket_name):
        for bucket in self.r.s3.buckets.all():
            if bucket.name == bucket_name:
                self.logger.info("S3 Bucket %s already exists. Reusing.", bucket_name)
                return

        self.r.s3.Bucket(bucket_name).create()
        self.logger.info("Created S3 Bucket %s", bucket_name)

    def attach_s3_bucket_policy(self, profile_name, bucket_name):
        substs = {"bucket": bucket_name}
        new_policy = self._build_policy(self.policy_templates["s3_bucket"], profile_name, substs=substs)["policy"]
        new_sid = new_policy["Statement"][0]["Sid"]

        policy_obj = self.r.s3.BucketPolicy(bucket_name)
        try:
            policy_obj.load()
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            policy_obj.put(Policy=json.dumps(new_policy))
            self.logger.info("Created new IAM Resource Policy for bucket %s", bucket_name)
            return

        policy = json.loads(policy_obj.policy)
        for stmt in policy["Statement"]:
            if stmt.get("Sid", "") == new_sid:
                self.logger.error("Existing IAM Resource Policy statement found in S3 Bucket %s for profile %s. Please remove it first.",  # NOQA
                                  profile_name)
                raise self.LeftoversError()

        policy["Statement"].extend(new_policy["Statement"])
        policy_obj.put(Policy=json.dumps(policy))
        self.logger.info("Added IAM Resource Policy statement for profile %s of S3 Bucket %s",
                         profile_name, bucket_name)

    def attach_s3_bucket_lifecycle(self, profile_name, bucket_name, retention_days):
        new_rule = self._build_policy(self.policy_templates["s3_bucket_lifecycle"], profile_name)
        new_rule["Expiration"]["Days"] = retention_days

        try:
            rules = self.c.s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)["Rules"]
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchLifecycleConfiguration":
                raise
            rules = []

        new_rules = []
        for rule in rules:
            if rule["ID"] == new_rule["ID"]:
                self.logger.info("Found existing S3 Lifecycle rule %s for S3 Bucket %s - replacing",
                                 rule["ID"], bucket_name)
                continue
            new_rules.append(rule)
        new_rules.append(new_rule)
        self.c.s3.put_bucket_lifecycle_configuration(Bucket=bucket_name,
                                                     LifecycleConfiguration={"Rules": new_rules})
        self.logger.info("Created %d days S3 Lifecycle poilicy %s for S3 Bucket %s",
                         retention_days, new_rule["ID"], bucket_name)

    def create_sns_topic(self, topic_name):
        for topic in self.r.sns.topics.all():
            if topic.arn.split(":")[-1] == topic_name:
                self.logger.error("SNS Topic %s already exists. Please remove it first.", topic_name)
                raise self.LeftoversError

        topic = self.r.sns.create_topic(Name=topic_name)
        self.logger.info("Created SNS Topic %s", topic.arn)
        return topic

    def create_sqs_queue(self, queue_name, topic):
        try:
            self.r.sqs.get_queue_by_name(QueueName=queue_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
                raise
        else:
            self.logger.error("SQS Queue %s already exists. Please remove it first.", queue_name)
            raise self.LeftoversError

        queue = self.r.sqs.create_queue(QueueName=queue_name,
                                        Attributes={
                                            "MessageRetentionPeriod": str(config["sqs"]["message_retention_period"]),
                                            "VisibilityTimeout": str(config["sqs"]["visibility_timeout"]),
                                        })
        self.logger.info("Created SQS Queue %s", queue_name)
        return queue

    def subscribe_to_topic(self, profile_name, topic, queue, lambda_func):
        qarn = queue.attributes["QueueArn"]
        tarn = topic.arn
        farn = lambda_func.arn

        self.c.sns.subscribe(TopicArn=tarn, Protocol="lambda", Endpoint=farn)
        self.logger.info("Subscribed Lambda Function %s to SNS Topic %s", farn, tarn)
        self.c.lambd.add_permission(FunctionName=lambda_func.name,
                                    StatementId="sns-invoke",
                                    Action="lambda:InvokeFunction",
                                    Principal="sns.amazonaws.com",
                                    SourceArn=tarn)
        self.logger.info("Authorized Lambda Function %s to be invoked by SNS Topic %s", farn, tarn)

        self.c.sns.subscribe(TopicArn=tarn, Protocol="sqs", Endpoint=qarn)
        self.logger.info("Subscribed SQS Queue %s to SNS Topic %s", qarn, tarn)

        policy_tmpl = self.policy_templates["sqs_queue"]
        substs = {
            "topic_arn": tarn,
            "queue_arn": qarn,
        }
        policy = self._build_policy(policy_tmpl, profile_name, substs=substs)["policy"]
        queue.set_attributes(Attributes={"Policy": json.dumps(policy)})
        self.logger.info("Authorized SQS Queue %s to recieve messages from SNS Topic %s", qarn, tarn)

    def create_receipt_rule(self, topic, ruleset_name, rule_name, domain, bucket_name):
        try:
            self.c.ses.describe_receipt_rule(RuleSetName=ruleset_name, RuleName=rule_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "RuleDoesNotExist":
                raise
        else:
            self.logger.error("SES Receipt Rule %s already exists in Ruleset %s. Please remove it first.",
                              rule_name, ruleset_name)
            raise self.LeftoversError

        receipient = "{}@{}".format(rule_name, domain)
        self.c.ses.create_receipt_rule(
            RuleSetName=ruleset_name,
            Rule={
                "Name": rule_name,
                "Enabled": True,
                "TlsPolicy": "Optional",
                "Recipients": [
                    receipient,
                ],
                "Actions": [
                    {
                        "S3Action": {
                            "TopicArn": topic.arn,
                            "BucketName": bucket_name,
                            "ObjectKeyPrefix": rule_name,
                        },
                    }
                ]
            }
        )
        self.logger.info("Created SES Receipt Rule for %s", receipient)

    def create_iam_user(self, user_name, bucket_name, queue):
        user = self.r.iam.User(user_name)
        try:
            user.create()
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
            self.logger.error("IAM User %s already exists. Please remove it first.", user_name)
            raise self.LeftoversError
        self.logger.info("Created IAM User %s", user_name)

        policy_tmpl = self.policy_templates["user"]
        substs = {
            "queue_arn": queue.attributes["QueueArn"],
            "bucket": bucket_name,
        }
        profile_name = user_name
        # IAM policies require only alphanum chars in sids
        policy = self._build_policy(policy_tmpl, profile_name, substs=substs, camel_case_sid=True)
        user.create_policy(PolicyName=policy["name"], PolicyDocument=json.dumps(policy["policy"]))
        self.logger.info("Created IAM Policy for IAM User %s", user_name)

        key_pair = user.create_access_key_pair()
        self.logger.info("Generated Access Key Pair for IAM User %s", user_name)
        self.logger.info("   Access key ID: %s", key_pair.access_key_id)
        self.logger.info("   Secret access key: %s", key_pair.secret_access_key)
        self.logger.info("Use them wisely")

    def create_iam_role(self, role_name):
        profile_name = role_name

        policy_tmpl = self.policy_templates["lambda_role"]
        policy = self._build_policy(policy_tmpl, profile_name)
        try:
            role = self.r.iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(policy["policy"]))
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "EntityAlreadyExists":
                raise
            self.logger.error("IAM Role %s already exists. Please remove it first.", role_name)
            raise self.LeftoversError
        self.logger.info("Created IAM Role %s", role_name)

        policy_tmpl = self.policy_templates["lambda_perms"]
        policy = self._build_policy(policy_tmpl, profile_name)
        role_policy = self.r.iam.RolePolicy(role_name, policy["name"])
        role_policy.put(PolicyDocument=json.dumps(policy["policy"]))
        self.logger.info("Created Policy for IAM Role %s", role_name)

        return role

    # Usually it takes some time for role to become usable
    @retrying.retry(wait_exponential_multiplier=1000, wait_exponential_max=10000)
    def create_lambda_function(self, func_name, role):
        bytes_zip = io.BytesIO()
        zfile = zipfile.ZipFile(bytes_zip, mode="w")
        dir_path = pathlib.Path(__file__).parent
        func_file = dir_path.joinpath(config["lambda"]["file_name"])
        zfile.write(str(func_file), arcname=func_file.name)
        zfile.close()

        description = "Writes meta information about incoming mails to CloudWatch Logs"
        try:
            rv = self.c.lambd.create_function(FunctionName=func_name,
                                              Runtime="python2.7",
                                              Role=role.arn,
                                              Handler="{}.{}".format(func_file.stem, config["lambda"]["handler"]),
                                              Code={"ZipFile": bytes_zip.getvalue()},
                                              Description=description)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            self.logger.error("Lambda Function %s already exists. Please remove it first.", func_name)
            raise self.LeftoversError
        self.logger.info("Created Lambda Function %s", func_name)

        func = SimpleNamespace()
        func.name = rv["FunctionName"]
        func.arn = rv["FunctionArn"]

        lg_name = "/aws/lambda/{}".format(func.name)
        try:
            self.c.logs.create_log_group(logGroupName=lg_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                raise
            self.logger.info("CloudWatch Log Group %s already exists. Reusing", lg_name)
        else:
            self.logger.info("Created CloudWatch Log Group %s", lg_name)
        self.c.logs.put_retention_policy(logGroupName=lg_name, retentionInDays=config["log_retention_days"])
        self.logger.info("Set retention policy of %s days on CloudWatch Log Group %s",
                         config["log_retention_days"], lg_name)

        return func

    ###########################
    #         DELETES         #
    ###########################
    def delete_receipt_rule(self, rule_name):
        try:
            self.c.ses.describe_receipt_rule(RuleSetName=config["ruleset"], RuleName=rule_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] not in ("RuleSetDoesNotExist", "RuleDoesNotExist"):
                raise
            self.logger.info("SES Receipt Rule %s does not exist (OK)", rule_name)
            return

        self.c.ses.delete_receipt_rule(RuleSetName=config["ruleset"], RuleName=rule_name)
        self.logger.info("SES Receipt Rule %s deleted successfully", rule_name)

    def delete_sns_topic(self, topic_name):
        subscriptions_count = 0
        for topic in self.r.sns.topics.all():
            if topic.arn.split(":")[-1] == topic_name:
                for subscription in topic.subscriptions.all():
                    subscription.delete()
                    subscriptions_count += 1
                topic.delete()
                self.logger.info("Deleted SNS Topic %s with %s subscription(s)", topic_name, subscriptions_count)
                return

        self.logger.info("SNS Topic %s does not exist (OK)", topic_name)

    def delete_sqs_queue(self, queue_name):
        try:
            queue = self.r.sqs.get_queue_by_name(QueueName=queue_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
                raise
            self.logger.info("SQS Queue %s does not exist (OK)", queue_name)
            return
        queue.delete()
        self.logger.info("Deleted SQS Queue %s", queue_name)

    def delete_iam_user(self, user_name):
        user = self.r.iam.User(user_name)
        try:
            user.load()
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
            self.logger.info("IAM User %s does not exist (OK)", user_name)
            return

        for policy in user.attached_policies.all():
            user.detach_policy(PolicyArn=policy.arn)
            self.logger.info("Detached IAM Policy %s from IAM User %s", policy.policy_name, user_name)

        for policy in user.policies.all():
            policy_name = policy.policy_name
            policy.delete()
            self.logger.info("Deleted IAM Policy %s", policy_name)

        for key in user.access_keys.all():
            key.delete()

        user.delete()
        self.logger.info("Deleted IAM User %s", user_name)

    def delete_s3_bucket_policy_statement(self, bucket_name, profile_name):
        policy_obj = self.r.s3.BucketPolicy(bucket_name)
        try:
            policy_obj.load()
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            self.logger.info("No S3 Resource Policy defined for bucket %s (OK)", bucket_name)
            return

        policy = json.loads(policy_obj.policy)
        substs = {"bucket": bucket_name}
        new_policy = self._build_policy(self.policy_templates["s3_bucket"], profile_name, substs=substs)["policy"]
        final_statements = []
        sid = new_policy["Statement"][0]["Sid"]
        for stmt in policy["Statement"]:
            if stmt.get("Sid", "") != sid:
                final_statements.append(stmt)

        if len(final_statements) == len(policy["Statement"]):
            return  # No policy statement to remove

        if not final_statements:  # we are the last policy
            policy_obj.delete()
            self.logger.info("Deleted S3 Resource Policy from %s bucket", bucket_name)
            return

        policy["Statement"] = final_statements
        policy_obj.put(Policy=json.dumps(policy))
        self.logger.info("Deleted statement %s from S3 Resource Policy of S3 bucket %s", sid, bucket_name)

    def delete_lambda_function(self, function_name):
        try:
            self.c.lambd.delete_function(FunctionName=function_name)
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            self.logger.info("Lambda Function %s does not exist (OK)", function_name)
            return
        self.logger.info("Deleted Lambda Function %s", function_name)

    def delete_iam_role(self, role_name):
        role = self.r.iam.Role(role_name)
        try:
            role.load()
        except botocore.exceptions.ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
            self.logger.info("IAM Role %s does not exist (OK)", role_name)
            return

        for policy in role.policies.all():
            policy_name = policy.policy_name
            policy.delete()
            self.logger.info("Deleted IAM Role Policy %s", policy_name)

        # NOTE: We can encounter attached policies here one day
        role.delete()
        self.logger.info("Deleted IAM Role %s", role_name)

    def _delete_iam_policy(self, policy):
        for version in policy.versions.all():
            if not version.is_default_version:
                version.delete()
        policy.delete()

    def _build_policy(self, policy_tmpl, profile_name, substs=None, camel_case_sid=False):
        thesubsts = {
            "sidprefix": config["sidprefix"],
            "awsaccountid": config["awsaccountid"],
            "prefix": profile_name,
            "region": self.region_name,
        }
        if substs:
            thesubsts.update(substs)

        policy = json.loads(json.dumps(policy_tmpl) % thesubsts)

        if camel_case_sid:
            for stmt in policy["policy"]["Statement"]:
                if "Sid" not in stmt:
                    continue
                stmt["Sid"] = "".join(s.capitalize() for s in stmt["Sid"].split("-"))

        return policy


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = super().get_command(ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx) if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return super().get_command(ctx, matches[0])
        ctx.fail("Too many matches: %s" % ", ".join(sorted(matches)))


@click.command("create-config")
@click.argument("profile")
@click.pass_obj
def create_config(aws, profile):
    """Creates SES configuration named PROFILE"""
    AWS().create_config(profile)


@click.command("delete-config")
@click.argument("profile")
@click.pass_obj
def delete_config(aws, profile):
    """Deletes SES configuration named PROFILE"""
    AWS().delete_config(profile)


@click.group(cls=AliasedGroup)
@click.pass_context
@click_log.simple_verbosity_option()
@click_log.init(__name__)
def cli(ctx):
    pass

cli.add_command(create_config)
cli.add_command(delete_config)


if __name__ == "__main__":
    cli()
