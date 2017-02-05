#
# This is the code of lambda function used by SES
# to write meta information about incoming emails
# in CloudWatch Logs.
#
# NOTE: Python 2.7
#

import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    message = json.loads(event["Records"][0]["Sns"]["Message"])
    notification_type = message["notificationType"]
    handlers.get(notification_type, handle_unknown_type)(message)


def handle_received(message):
    ses_message_id = message["mail"]["messageId"]
    if ses_message_id == "AMAZON_SES_SETUP_NOTIFICATION":
        logger.info("Got Amazon SET setup message %s", ses_message_id)
        return

    subject = message["mail"]["commonHeaders"]["subject"]
    message_id = message["mail"]["commonHeaders"]["messageId"]
    delivery_timestamp = message["mail"]["timestamp"]
    bucket = message["receipt"]["action"]["bucketName"]
    key = message["receipt"]["action"]["objectKey"]
    object_path = "s3://" + os.path.join(bucket, key)
    logger.info("Message-ID: %s, Subject: `%s' was delivered successfully at %s to %s",
                message_id, subject, delivery_timestamp, object_path)


def handle_unknown_type(message):
    logger.info("Unknown message type:\n%s", json.dumps(message, indent=2))
    raise Exception("Invalid message type received: %s" %
                    message["notificationType"])


handlers = {"Received": handle_received}
