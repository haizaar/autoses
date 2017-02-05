config = {
    "domain": "example.com",
    "ruleset": "autoses",
    "s3bucket": "autoses-incoming",
    "sidprefix": "sid-autoses",

    "awsaccountid": "<FILL ME>",
    "region": "us-east-1",

    "sqs": {
        "message_retention_period": 14 * 24 * 3600,
        "visibility_timeout": 60,
    },
    "lambda": {
        "file_name": "lambda_function.py",  # Relative to current directory of the running script
        "handler": "lambda_handler",  # Name of the entrypoint function
    },
    "log_retention_days": 90,
    "s3_retention_days": 90,
}
