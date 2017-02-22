#!/usr/bin/env python

import logging
from datetime import datetime

import boto3
import click
import click_log

logger = logging.getLogger(__name__)

class Searcher:
    def __init__(self):
        self.cwl = boto3.client('logs')

    def search(self, profile, event_filter):
        group_name = "/aws/lambda/{}".format(profile)

        pattern = '"{}"'.format(event_filter)

        for log_streams_chunk in self.get_log_streams(group_name):
            resp = self.cwl.filter_log_events(logGroupName=group_name,
                                              filterPattern=pattern,
                                              logStreamNames=log_streams_chunk,
                                              interleaved=True)

            self.log_response(resp)

            while "nextToken" in resp:
                resp = self.cwl.filter_log_events(logGroupName=group_name,
                                                  filterPattern=pattern,
                                                  nextToken=resp["nextToken"],
                                                  logStreamNames=log_streams_chunk,
                                                  interleaved=True)
                self.log_response(resp)

    def log_response(self, resp):
        for e in resp["events"]:
            logger.debug("Stream: %s, timestamp: %s",
                         e["logStreamName"], datetime.fromtimestamp(e["timestamp"] / 1000.0))
            logger.info("Found event: %s", e["message"])
        for stream in resp["searchedLogStreams"]:
            if stream["searchedCompletely"]:
                logger.debug("Done searching %s", stream["logStreamName"])

    def get_log_streams(self, group_name):
        resp = self.cwl.describe_log_streams(logGroupName=group_name, orderBy="LastEventTime", descending=True)
        yield [s["logStreamName"] for s in resp["logStreams"]]

        while "nextToken" in resp:
            resp = self.cwl.describe_log_streams(logGroupName=group_name,
                                                 orderBy="LastEventTime",
                                                 descending=True,
                                                 nextToken=resp["nextToken"])
            yield [s["logStreamName"] for s in resp["logStreams"]]


@click.command("log-search")
@click.argument("profile")
@click.argument("event_filter")
@click_log.simple_verbosity_option()
@click_log.init(__name__)
def logsearch(profile, event_filter):
    """Search log data for given profile for specified data"""
    Searcher().search(profile, event_filter)

if __name__ == "__main__":
    logsearch()
