import json
import boto3
import logging


logger = logging.getLogger()
logger.setLevel("INFO")

def lambda_handler(event, context):

    #Request and Log Stream Id Extraction

    logger.info(f"successfully received event {event}")
 