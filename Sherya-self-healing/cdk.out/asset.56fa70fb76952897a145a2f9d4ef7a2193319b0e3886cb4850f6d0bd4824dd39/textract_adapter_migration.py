import boto3
import json
import logging
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_client(service, region):
    return boto3.client(service, region_name=region)

def parse_s3_path(s3_path):
    parsed = urlparse(s3_path)
    return parsed.netloc, parsed.path.lstrip('/')

def copy_s3_objects(s3_source, s3_dest, source_path, dest_path):
    source_bucket, source_prefix = parse_s3_path(source_path)
    dest_bucket, dest_prefix = parse_s3_path(dest_path)

    paginator = s3_source.get_paginator('list_objects_v2')
    copied_count = 0
    for page in paginator.paginate(Bucket=source_bucket, Prefix=source_prefix):
        for obj in page.get('Contents', []):
            source_key = obj['Key']
            dest_key = source_key.replace(source_prefix, dest_prefix)
            s3_dest.copy_object(
                CopySource={'Bucket': source_bucket, 'Key': source_key},
                Bucket=dest_bucket,
                Key=dest_key
            )
            copied_count += 1
            if copied_count % 100 == 0:
                logger.info(f"Copied {copied_count} objects...")
    logger.info(f"Finished copying {copied_count} objects")

def validate_and_fix_annotations(s3_client, s3_path):
    bucket, prefix = parse_s3_path(s3_path)
    manifest_key = f"{prefix}/manifest.jsonl"

    try:
        manifest_obj = s3_client.get_object(Bucket=bucket, Key=manifest_key)
        manifest_content = manifest_obj['Body'].read().decode('utf-8')
        manifest_lines = manifest_content.split('\n')
        
        fixed_manifest_lines = []
        for line in manifest_lines:
            if line.strip():
                entry = json.loads(line)
                
                # Ensure 'annotations' key exists and is a list
                if 'annotations' not in entry or not isinstance(entry['annotations'], list):
                    entry['annotations'] = []
                
                # Ensure each annotation has required keys
                for annotation in entry['annotations']:
                    if 'label' not in annotation:
                        annotation['label'] = 'DEFAULT_LABEL'
                    if 'value' not in annotation:
                        annotation['value'] = ''
                
                fixed_manifest_lines.append(json.dumps(entry))
        
        fixed_manifest_content = '\n'.join(fixed_manifest_lines)
        s3_client.put_object(Bucket=bucket, Key=manifest_key, Body=fixed_manifest_content)
        logger.info("Validated and fixed manifest file")
    except Exception as e:
        logger.error(f"Error validating and fixing manifest: {str(e)}")
        raise

def main():
    source_region = 'us-west-2'
    destination_region = 'us-east-2'
    source_adapter_id = '6f86490d8c64'
    destination_adapter_id = '440caa44a8ea'
    
    source_path = "s3://textract-adapters-us-west-2-e2f21b24-d629-4c9b-b530-18b7632c6ad/adapters/6f86490d8c64"
    dest_path = "s3://textract-adapters-us-east-2-e4c62b93-7f3b-42a9-8f61-11871662573/adapters/440caa44a8ea"

    try:
        s3_source = create_client('s3', source_region)
        s3_dest = create_client('s3', destination_region)
        textract_dest = create_client('textract', destination_region)

        logger.info(f"Copying dataset from {source_path} to {dest_path}")
        copy_s3_objects(s3_source, s3_dest, source_path, dest_path)

        logger.info("Validating and fixing annotations")
        validate_and_fix_annotations(s3_dest, dest_path)

        logger.info("Starting training for new adapter version")
        new_version = textract_dest.create_adapter_version(
            AdapterId=destination_adapter_id,
            DatasetConfig={
                'ManifestS3Object': {
                    'Bucket': parse_s3_path(dest_path)[0],
                    'Name': f"{parse_s3_path(dest_path)[1]}/manifest.jsonl"
                }
            },
            OutputConfig={
                'S3Bucket': parse_s3_path(dest_path)[0],
                'S3Prefix': f"adapters-output/{destination_adapter_id}/"
            }
        )
        
        logger.info(f"Started training new adapter version: {new_version['AdapterVersion']}")
        logger.info(f"Adapter ID: {destination_adapter_id}")
        logger.info(f"Version: {new_version['AdapterVersion']}")
        logger.info("Training is in progress. Check the AWS Console or use the GetAdapterVersion API to monitor the status.")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        logger.error("Full error details:", exc_info=True)

if __name__ == "__main__":
    main()