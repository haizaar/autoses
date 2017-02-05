# autoses
Configure AWS SES mail receival with ease.

Creates fine-tuned configurations for recieving mail through AWS SES. Configures SES, S3, SNS, SQS, Lambda+CloudWatchLogs and creates dedicated users to receive email through SQS/S3.

Usage:

```
pip install -r requirements.txt
editor config.py    # Make sure to set awsaccountid, domiain and s3bucket

# Creates configuration to recieve email for foobar@<your domain>
./ses-setup.py create-config foobar  
  
# Removes all of the previously created configurion, except for for S3 data and Cloudwatch logs
./ses-setup.py delete-config foobar

# Searches all of the log streams for given profile for a specified message.
./logsearch.py foobar my-message-id
```

