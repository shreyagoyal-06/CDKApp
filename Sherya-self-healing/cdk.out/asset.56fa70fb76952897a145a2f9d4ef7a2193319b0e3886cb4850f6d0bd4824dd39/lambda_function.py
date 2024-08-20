import json
import boto3
import fitz 
from io import BytesIO
from PIL import Image, ImageDraw
import os
import requests
from subprocess import call
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re
application_json='application/json'
logger = logging.getLogger()
logger.setLevel("INFO")
s3 = boto3.client('s3')
textract_client = boto3.client('textract')
secretsmangerclient = boto3.client('secretsmanager')
environment_type = os.environ["environment_type"]
                
def lambda_handler(event, context):

    #Request and Log Stream Id Extraction
    log_stream_id = context.log_stream_name.split('LATEST')[-1].strip(']')
    api_gateway_request_id = event["requestContext"]["requestId"]
    lambda_context_request_id = context.aws_request_id

    logger.info(f"API Gateway Request Id: {api_gateway_request_id}")
    logger.info(f"Lambda Log Stream Id: {log_stream_id}")
    logger.info(f"Lambda Request Id: {lambda_context_request_id}")

    #Request Body Validation
    try:
        body = json.loads(event['body'])
    except Exception as e:
        logger.info('Bad Request')
        return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
                'body': json.dumps({'message': 'Bad Request'})
            }
    logger.info(f"Request body: {body}")
    
    #S3 Presigned URL Validation
    s3_presigned_url = body.get('s3_presigned_url')
    if not s3_presigned_url:
            logger.info('s3_presigned_url is not found in the request body')
            return {
                'statusCode': 400,
                'body': json.dumps({'message':'s3_presigned_url is not found in the request body'})
            }
    
    #Filename extraction and Validation fron Pre-Signed URL        
    try:
        filename = os.path.basename(s3_presigned_url)
        filename = filename.split("?")[0]
        logger.info(f"Downloaded Filename: {filename}")
        ext=filename.split(".")[-1]
    except Exception as e:
        logger.error(e)
        return {
                'statusCode': 500,
                'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
                'body': json.dumps({'message': 'Internal Error'})
            }
    try:
        file_content = download_file_from_s3(s3_presigned_url,filename, ext)
        filename = event["requestContext"]["requestId"]
    except Exception as e:
        return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
                'body': json.dumps({'message': str(e)})
            }
        
    #Form Template Validation
    formtemplate = body.get('formtemplate')
    if 'formtemplate' not in body or body['formtemplate'] is None:
        logger.info('Formtemplate is not found in the request body')
        return {
            'statusCode': 400,
            'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
            'body': json.dumps({'message': 'formtemplate is not found in the request body'})
        }
    if not isinstance(formtemplate.get('sections'), list):
        logger.info('Invalid format for formtemplate: "sections" key not found or not a list')
        return {
            'statusCode': 400,
            'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
            'body': json.dumps({'message': 'Invalid format for formtemplate: "sections" key not found or not a list'})
        }
    # Check if the first section contains 'fields' key and is a list
    if len(formtemplate['sections']) < 1 or not isinstance(formtemplate['sections'][0], list) or not isinstance(formtemplate['sections'][0][1].get('fields'), list):
        logger.info('Invalid format for formtemplate, first section must contain a list of fields')
        return {
            'statusCode': 400,
            'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
            'body': json.dumps({'message': 'Invalid format for formtemplate, first section must contain a list of fields'})
        }
    
    #External ID Validation
    externalId = body.get('externalId')
    if 'externalId' not in body or body['externalId'] is None:
            logger.info('ExternalId is not found in the request body')
            return {
                'statusCode': 400,
                'body': json.dumps({'message':'externalId is not found in the request body'})
            }
    
    secrets_response = secretsmangerclient.get_secret_value(
            SecretId= environment_type+'/ecz/s3'
            )
    s3_secrets = json.loads(secrets_response['SecretString'])
    S3_BUCKET = s3_secrets['ocrbucket']
    
    #Config File Retrieval from S3
    config_file_path = '/tmp/config_tmp.json'   
    s3.download_file(S3_BUCKET, 'dependencies/config.json', config_file_path)
    with open(config_file_path, 'r') as json_file:
        config = json.load(json_file)
    
    #Form template Fields validation against Pre-defined config
    form_fields=[]
   
    for section in formtemplate['sections']:
        for field in section[1]['fields']:
            if field[1]['type'] == "lookup":
                for additional_field in field[1]['pdfAdditionalFields']:
                    form_fields.append(additional_field['pdfFieldName'])
            elif field[1]['type'] == "radio":
                for option in field[1]['options']:
                    form_fields.append(option['name'])
            else:
                form_fields.append(field[0])

    if externalId not in config:
        logger.info(f'OCR is not yet configured for this form: {externalId}')
        return {
            'statusCode': 400,
            'headers': {
                    "Access-Control-Allow-Origin" : "*", 
                    "Access-Control-Allow-Credentials" : True
                },
            'body': json.dumps({'message': f'OCR is not yet configured for the form with externalId: {externalId}'})
        }
   
    # logger.info(f"Incoming form is mapped to {config[externalId]['title']}")
    queries = []
   
    # logger.info("Queries:")
    for i in range(len(config[externalId]['Batch'])):
        logger.info(config[externalId]["Batch"][i]["QueriesConfig"]["Queries"])
        queries.extend(config[externalId]["Batch"][i]["QueriesConfig"]["Queries"])
    
    logger.info(f"queries:{queries}")    
    missing_fields=[]
    for Query in queries:
        if Query["Alias"] not in form_fields and Query["Alias"] not in ["patient_first_name","patient_middle_initial","patient_last_name"]:  #Added these name keys because we need Full name and we are getting independent names from OCR
            missing_fields.append(Query.get("Alias"))
    if missing_fields:
        logger.info(f'Missing Fields: {missing_fields}')
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": True
            },
            'body': json.dumps({'message': 'Formtemplate mismatch', 'missing_fields': missing_fields})
        }
        
    #Result Key Value Map
    result = {"key_value_pairs":[],"signature_keys":[], "table_signatures":[], "additional_signatures":[]}
    
    #Extracting Adapters Config for the incoming Form title
    secrets_response = secretsmangerclient.get_secret_value(
            SecretId= environment_type+'/ocr/adapters'
            )
    s3_secrets = json.loads(secrets_response['SecretString'])
    adapters_config = s3_secrets[externalId]
    logger.info(f"Adapters Config: {adapters_config}")

    #Store request file in S3
    s3.put_object(Body=file_content, Bucket=S3_BUCKET, Key=f"{log_stream_id}-{lambda_context_request_id}/incoming-file.{ext}")
    #File-Based Processing
    if ext == 'pdf':
        process_pdf(file_content, S3_BUCKET, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config)
    elif ext == 'tiff':
        process_tiff(file_content, S3_BUCKET, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config)
    elif ext == 'jpeg' or ext == 'jpg' or ext == 'png' :
        textract(file_content, S3_BUCKET, 0, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config)
    if "sign_map" in result:
        logger.info(result["sign_map"])
        for name,sign_i in result["sign_map"].items():
            logger.info(f'Generating presigned URL for label {name} and mapped the file {result["signature_keys"][sign_i]} to it')
            signature_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET, 'Key': result["signature_keys"][sign_i]},
            ExpiresIn=3600  # Set the expiration time for the URL (in seconds)
            )
            result["key_value_pairs"].append({"key":name, "value":signature_url, "confidence": "100.0"})
    
    
    if result["table_signatures"]:
        for table in result["table_signatures"]:
            for label, key in table.items():
                # Generate presigned URLs for each table in table_signatures
                logger.info(f'Generating presigned URL for label {label}')
                signature_url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': S3_BUCKET, 'Key': key},
                    ExpiresIn=3600  # Set the expiration time for the URL (in seconds)
                )
                # Add the presigned URL to key_value_pairs
                result["key_value_pairs"].append({"key": label, "value": signature_url, "confidence": "100.0"})
    

    if result["additional_signatures"]:
        for additional_signature in result["additional_signatures"]:
            for label, key in additional_signature.items():
                logger.info(f'Generating presigned URL for label {label}')
                url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': S3_BUCKET, 'Key': key},
                    ExpiresIn=3600  # Set the expiration time for the URL (in seconds)
                )
                # Add the presigned URL to key_value_pairs
                result["key_value_pairs"].append({"key": label, "value": url, "confidence": "100.0"})

    response_data = result["key_value_pairs"]
    #Config File Removal
    if os.path.exists(config_file_path):
            os.remove(config_file_path) 
            logger.info(f"Deleted {config_file_path} successfully")
            logger.info("Execution completed successfully")
            
    return {
        'statusCode': 200,  # HTTP status code
        'body': json.dumps(response_data),  # Response body
        'headers': {
            'Content-Type': application_json # Response headers
        }
    }
    

def download_file_from_s3(s3_presigned_url, filename, ext):
    logger.info(f'File extension received: {ext}')
    allowed_extensions = [".pdf", ".jpg", ".jpeg", ".png", ".tiff"]
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        logger.info(f'File extension not allowed: {filename.lower().endswith(ext)}')
        raise ValueError(f"File extension not allowed. Allowed extensions are {allowed_extensions}")

    response = requests.get(s3_presigned_url, stream=True)
    if response.status_code == 200:
        file_content = BytesIO()
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                file_content.write(chunk)
        return file_content.getvalue()  
    else:
        logger.info(f"Failed to download file from S3: {s3_presigned_url}")
        raise ValueError("Failed to download file from S3")

def process_pdf(pdf_content, S3_BUCKET, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config):
    pdf_document = fitz.open(stream=pdf_content)
    with ThreadPoolExecutor() as executor:
        futures = []
        for page_num in range(pdf_document.page_count):
            future = executor.submit(process_page, pdf_document, S3_BUCKET, page_num, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config)
            futures.append(future)
        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                logger.info(f"Error in thread: {e}")
        pdf_document.close()


def process_tiff(tiff_content, S3_BUCKET, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config):
    tif_image = Image.open(BytesIO(tiff_content))
    with ThreadPoolExecutor() as executor:
        futures = []
        for i in range(tif_image.n_frames):
            tif_image.seek(i)
            current_image = tif_image.copy()
            future = executor.submit(process_page, current_image,S3_BUCKET , i, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config)
            futures.append(future)
        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                logger.info(f"Error in thread: {e}")

def process_page(pdf_document, S3_BUCKET, page_num, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config):
    try:
        temp_pdf_path = f"/tmp/{log_stream_id} {page_num + 1}.png"
        pdf_to_image(pdf_document, temp_pdf_path,page_num, ext)
        with open(temp_pdf_path, 'rb') as temp_pdf_file:
            page_content = temp_pdf_file.read()
        textract(page_content, S3_BUCKET, page_num, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config)
    except Exception as e:
        logger.info(f"Error analyzing page {page_num + 1}: {e}")
    finally:
        if os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)   


def pdf_to_image(document, png_path,page_num, ext):
    if ext == "tiff":
        page = document.seek(page_num)
        image = BytesIO()
        document.save(image, format = "PNG")
        with open(png_path, "wb") as f:
            f.write(image.getvalue())
    else:    
        page = document[page_num]
        pix = page.get_pixmap(dpi=300)
        image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        image.save(png_path, "PNG")

def textract(page_content, S3_BUCKET, page_num, result, ext, log_stream_id, lambda_context_request_id, formtemplate, config, externalId, adapters_config):
    try :
        with ThreadPoolExecutor() as executor:
            futures = []
            logger.info(f'Number of batches: {len(config[externalId]["Batch"])}')
            for batch in range(len(config[externalId]["Batch"])):
                try:
                    logger.info(f'Batch: {batch}')
                    logger.info(f'config[externalId]["Batch"][batch]: {config[externalId]["Batch"][batch]}')    
                    logger.info(f'adapters_config[batch]: {adapters_config[batch]}')
                    future = executor.submit(analyze_document, page_content, S3_BUCKET, log_stream_id, lambda_context_request_id, batch,config[externalId]["Batch"][batch]["QueriesConfig"], adapters_config[batch], result, config, externalId)
                    futures.append(future)
                except Exception as e:
                    logger.error(f"Error processing batch {batch}: {str(e)}")
            logger.info(f'All batches submitted: {len(futures)} futures')
            future = executor.submit(analyze_document_signatures_and_tables, page_content, S3_BUCKET, page_num, result, ext, log_stream_id, lambda_context_request_id, config, externalId)
            futures.append(future)
            for completed_future in as_completed(futures):
                try:
                    completed_future.result()
                except Exception as e:
                    logger.info(f"Error in thread: {e}")
    except Exception as e:
        logger.info(e)


def analyze_document(page_content, S3_BUCKET, log_stream_id, lambda_context_request_id, batch, queriesConfig, adaptersConfig, result, config, externalId):
    response = textract_client.analyze_document(
        Document={'Bytes': page_content},
        FeatureTypes=["QUERIES"],
        QueriesConfig=queriesConfig,
        AdaptersConfig=adaptersConfig
    )
    s3.put_object(
        Bucket= S3_BUCKET,
        Key= f"{log_stream_id}-{lambda_context_request_id}/batch-{batch}-queries-response.json",
        Body=json.dumps(response, indent=4).encode('utf-8'),
        ContentType=application_json
    )
    logger.info(f"in this {batch}, Raw response for Adapter Config {adaptersConfig} asked Queries were {queriesConfig} was {response}")
    extracted_response = get_query_results(response)
    logger.info(f"For Adapter Config {adaptersConfig} asked Queries were {queriesConfig} and extracted response is {extracted_response}")
    result["key_value_pairs"].extend(extracted_response)
    
    
def analyze_document_signatures_and_tables(page_content, S3_BUCKET, page_num, result, ext, log_stream_id, lambda_context_request_id, config, externalId):
    response = textract_client.analyze_document(
        Document={'Bytes': page_content},
        FeatureTypes=["SIGNATURES", "TABLES"]
    )
    s3.put_object(
        Bucket= S3_BUCKET,
        Key= f"{log_stream_id}-{lambda_context_request_id}/tables-and-signatures-response.json",
        Body=json.dumps(response,indent=4).encode('utf-8'),
        ContentType=application_json
    )
    #logger.info(f"Signature Response: {response}")
    key,signs_coord=crop_img(response, page_content, S3_BUCKET, page_num,ext,log_stream_id, lambda_context_request_id)
    result["signature_keys"]=key
    sign_map=get_kv_map(response,signs_coord, page_content, S3_BUCKET, page_num, ext, config, externalId, log_stream_id, lambda_context_request_id)
    result["sign_map"]=sign_map
    table_config = config.get(externalId, {}).get("table")
    if table_config:
        #Table Signatures Extraction
        blocks_data = {block["Id"]: block for block in response["Blocks"]}
        result["table_signatures"].append(table_extraction(blocks_data, page_content, log_stream_id, lambda_context_request_id, config, externalId, S3_BUCKET))
    additional_intials_config = config.get(externalId, {}).get("additional_initials")
    if additional_intials_config:
        result["additional_signatures"].append(additional_signature_extraction(page_content, log_stream_id, lambda_context_request_id, config, externalId, S3_BUCKET))

def additional_signature_extraction(page_content, log_stream_id, lambda_context_request_id, config, externalId, S3_BUCKET):
    additional_signature_keys = {}
    try:
        
        response = textract_client.analyze_document(
            Document={'Bytes': page_content},
            FeatureTypes=["FORMS"]
        )
        s3.put_object(
        Bucket= S3_BUCKET,
        Key= f"{log_stream_id}-{lambda_context_request_id}/additional_initials_response.json",
        Body=json.dumps(response, indent=4).encode('utf-8'),
        ContentType=application_json
    )
        additional_initials = config[externalId]["additional_initials"]
        blocks_data = {block["Id"]: block for block in response["Blocks"]}
        word_ids_list = []

        # Regex Pattern for the additional initial images
        patterns = {key: re.compile(f'^{re.escape(value.lower())}') for key, value in additional_initials.items()}

        # Loop through the blocks to extract word IDs and geometry
        for label, text in additional_initials.items():
            found = False
            for block in response["Blocks"]:
                # Check if the block is a LINE type
                if block.get("BlockType") == "LINE":
                    # Loop through search items to check for matches
                    for key, pattern in patterns.items():
                        if pattern.match(block.get("Text", "").lower()):
                            word_ids_list.extend(block.get("Relationships", [])[0].get("Ids", []))               

                # Check if the block is a KEY_VALUE_SET type
                elif block.get("BlockType") == "KEY_VALUE_SET" and "KEY" in block.get("EntityTypes", {}):
                    relationships = block.get("Relationships", {})
                    for relationship in relationships:
                        if relationship.get("Type") == "CHILD":
                            key_ids = relationship.get("Ids", [])
                    # Check if any of the key IDs are in the word IDs list
                    if any(key_id in word_ids_list for key_id in key_ids):
                        # Initialize the key_text variable to store the text associated with key IDs
                        key_text = ""
                        # Iterate through word IDs list to concatenate the text associated with key IDs
                        for word_id in word_ids_list:
                            key_text += blocks_data.get(word_id, {}).get("Text", "")
                        # Value Geometry extraction
                        for relationship in relationships:
                            if relationship.get("Type") == "VALUE":
                                geometry = blocks_data.get(relationship.get("Ids", [])[0], {}).get("Geometry")
                                if geometry:
                                    page_content = Image.open(BytesIO(page_content))
                                    left, top, width, height = get_bounding_box(geometry["BoundingBox"], page_content)
                                    left, top, right, bottom = map(int, (left, top, left + width, top + height))
                                    signature_image = page_content.crop((left, top, right, bottom))
                                    cropped_stream = BytesIO()
                                    signature_image.save(cropped_stream, format='PNG')
                                    # Upload cropped image to S3 using the key_text as the key
                                    s3_key = f"{log_stream_id}-{lambda_context_request_id}/additional-initials-{label}.png"
                                    s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=s3_key)
                                    additional_signature_keys[label] = s3_key
                        found = True
            if not found:
                logger.info(f"No block found for additional_initials with label: {label}")
    except Exception as e:
        logger.error(f"Error in additional_signature_extraction: {e}")
    return additional_signature_keys
             

# Check which are being detected as CELLS and MERGED_CELLS
# CELLS -> RED
# MERGED_CELLS -> GREEN
def dryrun(original_image, blocks_dict, merged_cell_ids, cell_ids, execution_flag, S3_BUCKET, log_stream_id, lambda_context_request_id):
    original_image = Image.open(BytesIO(original_image))
    dryrun_image = original_image.copy()
    draw = ImageDraw.Draw(dryrun_image)
    for cell_id in cell_ids:
        geometry = blocks_dict.get(cell_id, {}).get("Geometry", {})
        left, top, width, height = get_bounding_box(geometry["BoundingBox"], dryrun_image)
        left, top, right, bottom = map(int, (left, top, left + width, top + height))
        draw.rectangle([left, top, right, bottom], outline="red", width=3)

    for merged_cell_id in merged_cell_ids:    
        geometry = blocks_dict.get(merged_cell_id, {}).get("Geometry", {})
        left, top, width, height = get_bounding_box(geometry["BoundingBox"], dryrun_image)
        left, top, right, bottom = map(int, (left, top, left + width, top + height))
        draw.rectangle([left, top, right, bottom], outline="green", width=3)
    
    with BytesIO() as output:
        dryrun_image.save(output, format="PNG")
        image_bytes = output.getvalue()

    s3.put_object(
        Bucket= S3_BUCKET,
        Key= f"{log_stream_id}-{lambda_context_request_id}/dryrun-{execution_flag}.png",
        Body= image_bytes
    )

def table_extraction(blocks_dict, original_image, log_stream_id, lambda_context_request_id, config, externalId, S3_BUCKET):
        
    logger.info(f"Starting table identification for externalId: {externalId}")

    table_identification_word = config[externalId]["table"]["table_identification_word"]
    logger.info(f"Table identification word: {table_identification_word}")
    
    # Find the ID of the word "Assessment/diagnosis"
    table_word_id = next((block_id for block_id, block in blocks_dict.items() if block.get("BlockType") == "WORD" and block.get("Text") == table_identification_word), None)
    logger.info(f"Table word ID: {table_word_id}")
    
    # Find the ID of the cell containing the word "Assessment/diagnosis"
    cell_id = next((block_id for block_id, block in blocks_dict.items() if block.get("BlockType") == "CELL" and any(relationship.get("Type") == "CHILD" and table_word_id in relationship.get("Ids") for relationship in block.get("Relationships", []))), None)
    logger.info(f"Cell ID containing table identification word: {cell_id}")
    
    # Find the ID of the table containing the cell
    table_id = next((block_id for block_id, block in blocks_dict.items() if block.get("BlockType") == "TABLE" and any(relationship.get("Type") == "CHILD" and cell_id in relationship.get("Ids") for relationship in block.get("Relationships", []))), None)
    logger.info(f"Table ID: {table_id}")
    
    # Collect merged cell IDs and cell IDs related to the table
    merged_cell_ids = blocks_dict.get(table_id, {}).get("Relationships", [])[1].get("Ids", [])
    logger.info(f"Merged cell IDs: {merged_cell_ids}")
    
    cell_ids = blocks_dict.get(table_id, {}).get("Relationships", [])[0].get("Ids", [])
    logger.info(f"Cell IDs: {cell_ids}")
    # Raw Textract Response Visualization. i.e, Dry Run Check before mapping logic
    dryrun(original_image, blocks_dict, merged_cell_ids, cell_ids, "pre", S3_BUCKET, log_stream_id, lambda_context_request_id)

    # Define the search lines with their corresponding result labels
    # Note put the words containing in the line after target cell 
    search_lines = config[externalId]["table"]["search_lines"]

    # This array detects which are being considered as merged cells. All others are considered as cells.
    merged_cell_blocks = config[externalId]["table"]["merged_cell_blocks"]
    # Initialize dictionaries to store the result geometries and merged cell IDs for each search word
    result_data_merged_cell = {}
    result_data_cell = {}
    
    # Iterate through search words
    for search_line, result_label in search_lines.items():
        # Initialize variables to hold the previous merged cell geometry and ID
        previous_merged_cell_id = None
        previous_cell_id = None

        # Iterate through merged cell IDs
        if result_label in merged_cell_blocks:
            for merged_cell_id_to_check in merged_cell_ids:
                child_cell_ids = blocks_dict[merged_cell_id_to_check].get("Relationships", [])[0].get("Ids", [])
                for cell_id_to_check in child_cell_ids:
                    word_ids = blocks_dict[cell_id_to_check].get("Relationships", [])[0].get("Ids", []) if blocks_dict[cell_id_to_check].get("Relationships") else []
                    for word_id in word_ids:
                        for block_id,block in blocks_dict.items():
                            if block.get("BlockType") == "LINE" and search_line.lower() == block.get("Text").lower() and word_id in block.get("Relationships", [])[0].get("Ids", []):
                                result_data_merged_cell[result_label] = {
                                    "merged_cell_id": previous_merged_cell_id
                                }
                previous_merged_cell_id = merged_cell_id_to_check              
        else:
            # Iterate through cell IDs
            for cell_id_to_check in cell_ids:
                word_ids = blocks_dict[cell_id_to_check].get("Relationships", [])[0].get("Ids", []) if blocks_dict[cell_id_to_check].get("Relationships") else []
                for word_id in word_ids:
                    for block_id,block in blocks_dict.items():
                        if block.get("BlockType") == "LINE" and search_line.lower() == block.get("Text").lower() and word_id in block.get("Relationships", [])[0].get("Ids", []):
                            result_data_cell[result_label] = {
                                "cell_id": previous_cell_id
                            }
                previous_cell_id = cell_id_to_check                         

    logger.info(f"result_data_cell: {result_data_cell}")
    logger.info(f"result_data_merged_cell: {result_data_merged_cell}")

    # Retrieve and store geometries for each merged cell ID in result_data_merged_cell
    for result_label, data in result_data_merged_cell.items():
        merged_cell_id = data["merged_cell_id"]
        merged_cell = blocks_dict[merged_cell_id]
        # Find the geometry of the merged cell ID
        if merged_cell.get("BlockType") == "MERGED_CELL":
            geometry = merged_cell.get("Geometry")
            # Store the geometry
            result_data_merged_cell[result_label]["geometry"] = geometry

    # Retrieve and store geometries for each cell ID in result_data_cell
    for result_label, data in result_data_cell.items():
        cell_id = data["cell_id"]
        cell = blocks_dict[cell_id]
        # Find the geometry of the cell ID
        if cell.get("BlockType") == "CELL":
            geometry = cell.get("Geometry")
            # Store the geometry
            result_data_cell[result_label]["geometry"] = geometry

    # Combine result data from both dictionaries
    result_data = {**result_data_merged_cell, **result_data_cell}

    #Image Extraction and Sending to s3 
    table_signatures_key_map = crop_and_send_to_s3(result_data, original_image, S3_BUCKET, log_stream_id, lambda_context_request_id)

    # Check which are being detected as CELLS and MERGED_CELLS
    # CELLS -> GREEN
    # MERGED_CELLS -> RED
    dryrun(original_image, blocks_dict, [data['merged_cell_id'] for data in result_data_merged_cell.values() if 'merged_cell_id' in data], [data['cell_id'] for data in result_data_cell.values() if 'cell_id' in data], "post", S3_BUCKET, log_stream_id, lambda_context_request_id)

    return table_signatures_key_map

#Image Extraction and Sending to s3 
def crop_and_send_to_s3(result_data, original_image, S3_BUCKET, log_stream_id, lambda_context_request_id):
    signature_keys = {}
    original_image = Image.open(BytesIO(original_image))
    with ThreadPoolExecutor() as executor:
        futures = []
        for result_label, data in result_data.items():
            geometry = data.get("geometry")
            if geometry:
                left, top, width, height = get_bounding_box(geometry["BoundingBox"], original_image)
                left, top, right, bottom = map(int, (left, top, left + width, top + height))
                signature_image = original_image.crop((left, top, right, bottom))
                cropped_stream = BytesIO()
                signature_image.save(cropped_stream, format='PNG')
                key = f"{log_stream_id}-{lambda_context_request_id}/cropped-signature-{result_label}.png"
                futures.append(executor.submit(check_and_save_signature, cropped_stream, key, S3_BUCKET, signature_keys, result_label))
        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                logger.info(f"Error in thread: {e}")
    
    # Remove whitespace from cropped signature images
    with ThreadPoolExecutor() as executor:
        futures = []
        for result_label, key in signature_keys.items():
            futures.append(executor.submit(remove_whitespace, S3_BUCKET, key))
            logger.info(f"Removing whitespace from cropped signature image: {key}")
        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                logger.info(f"Error in thread: {e}")
    
    return signature_keys


def check_and_save_signature(cropped_stream, key, S3_BUCKET, signature_keys, result_label):
    if has_signature(cropped_stream):
        s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=key)
        signature_keys[result_label] = key
        return key
    return None

def has_signature(cropped_stream):
    response = textract_client.analyze_document(
        Document={'Bytes': cropped_stream.getvalue()},
        FeatureTypes=["SIGNATURES"]
    )
    for block in response["Blocks"]:
        if block.get("BlockType") == "SIGNATURE":
            return True
    return False

def get_kv_map(response,signs_coord, page_content, S3_BUCKET, page_num, ext, config, externalId, log_stream_id, lambda_context_request_id):
    sign_map={}
    sign_count=0
    for block in response.get("Blocks", []):
        block_type = block.get("BlockType", "")
        if block_type == "WORD":
            txt=block.get("Text", "")
            if(txt.lower()=="signature"):
                if not config[externalId]["signature"][sign_count] :
                    sign_count+=1
                    continue
                word_polygon_coords = [(point['X'], point['Y']) for point in block.get("Geometry", "").get("Polygon", "")]
      
                result = [(x1 + x2, y1 + y2) for (x1, y1), (x2, y2) in zip(eval(config[externalId]["signature"][sign_count]["padding"]), word_polygon_coords)]
                # To Crop Fields after adding padding
                #cropFields(result, page_content, S3_BUCKET, page_num,ext,log_stream_id,lambda_context_request_id, response)
                for i,sign_coord in enumerate(signs_coord):
                    is_inside = any(is_point_inside_polygon(x, y, result) for x, y in sign_coord)
                    if is_inside:
                        sign_map[config[externalId]["signature"][sign_count]["name"]]=i
                sign_count+=1 
    logger.info(f'Form has {sign_count} signature words in it')
    return sign_map
    

def cropfields(coordinates, file_stream, S3_BUCKET, page_num,ext,log_stream_id,lambda_context_request_id, res):
    keys=[]
    if ext == 'pdf':
        pdf_document = fitz.open(stream=file_stream, filetype="pdf")
        page = pdf_document[0]
        x_values = [coord[0] for coord in coordinates]
        y_values = [coord[1] for coord in coordinates]
        left = min(x_values)*page.rect.width
        top = min(y_values)*page.rect.height
        left_plus_width = max(x_values)*page.rect.width
        top_plus_height = max(y_values)*page.rect.height
        key = f'crop-{log_stream_id}-{lambda_context_request_id}_signature_of_page_{page_num + 1}_item.png'
        keys.append(key)
        img_matrix = fitz.Matrix(4, 4)
        pix = page.get_pixmap(matrix=img_matrix, clip=(left, top, left_plus_width, top_plus_height))
        signature_image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        cropped_stream = BytesIO()
        signature_image.save(cropped_stream, format='PNG')
        s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=key)
        pdf_document.close()
    elif ext in ['png', 'jpeg', 'jpg', 'tiff']:
        try:
            original_image = Image.open(BytesIO(file_stream))
            # Continue with your image processing code
        except Exception as e:
            logger.info("Error:", e)
        i = 0
        for item in res["Blocks"]:
            if item["BlockType"] == "SIGNATURE":
                left, top, width, height = get_bounding_box(item['Geometry']['BoundingBox'], original_image)
                key = f'crop-{log_stream_id}-{lambda_context_request_id}_signature_of_item_{i+1}.png'
                keys.append(key)
                left, top, right, bottom = map(int, (left, top, left + width, top + height))
                signature_image = original_image.crop((left, top, right, bottom))
                cropped_stream = BytesIO()
                signature_image.save(cropped_stream, format='PNG')
                s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=key)
                i += 1
     # Remove whitespace from cropped signature images
    with ThreadPoolExecutor() as executor:
        futures = []
        for key in keys:
            futures.append(executor.submit(remove_whitespace, S3_BUCKET, key))
        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                logger.info(f"Error in thread: {e}")
    return keys

def is_point_inside_polygon(x, y, poly):
    n = len(poly)
    inside = False
    p1x, p1y = poly[0]
    for i in range(n + 1):
        p2x, p2y = poly[i % n]
        if y > min(p1y, p2y):
            if y <= max(p1y, p2y):
                if x <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or x <= xinters:
                        inside = not inside
        p1x, p1y = p2x, p2y
    return inside
    

def get_query_results(response):
    query_map={}
    answer_map={}
    confidence_map={}
    qa_map=[]
    full_name=''
    for block in response.get("Blocks", []):
        block_type = block.get("BlockType", "")
        block_id = block.get("Id", "")
        confidence = block.get("Confidence", 0)
        entity_types = block.get("EntityTypes", [])
        relationships = block.get("Relationships", [])
        if block_type == "QUERY":
            for relation in relationships:
                if relation["Type"] == "ANSWER":
                    answer_id = relation.get("Ids", [])
                    query = block.get("Query").get("Alias","")
                    query_map[query]= answer_id
        elif block_type == "QUERY_RESULT":
            confidence_map[block_id]=str(block.get("Confidence", ""))
            answer_map[block_id]=block.get("Text", "")
    for query, answer_id in query_map.items():
        c="".join([confidence_map.get(k, "") for k in answer_id])
        answer= "".join([answer_map[id] for id in answer_id])
        qa_map.append({"key":query, "value":answer,'confidence':c})
        if "patient_first_name" == query:
            qa_map.pop()
            full_name+=answer
        if "patient_middle_initial" == query:
            qa_map.pop()
            if full_name !='':
                full_name=full_name+" "
            full_name+=answer
        if "patient_last_name" == query:
            qa_map.pop()
            if full_name !='':
                full_name=full_name+" "
            full_name+=answer
    if full_name != '':
        qa_map.append({"key":"PATIENT_FULL_NAME", "value":full_name})       
    
    return qa_map


def crop_img(res, file_stream, S3_BUCKET, page_num,ext,log_stream_id, lambda_context_request_id):
    keys=[]
    Signs_coord=[]
    if ext == 'pdf':
        pdf_document = fitz.open(stream=file_stream, filetype="pdf")
        i = 0
        page = pdf_document[0]
        for item in res["Blocks"]:
            if item["BlockType"] == "SIGNATURE":
                Signs_coord.append([(point['X'], point['Y']) for point in item['Geometry']['Polygon']])
                left, top, width, height = get_bounding_box(item['Geometry']['BoundingBox'], page.rect)
                key = f'{log_stream_id}-{lambda_context_request_id}/signature_of_page-{page_num + 1}-item-{i+1}.png'
                keys.append(key)
                img_matrix = fitz.Matrix(1, 1)
                pix = page.get_pixmap(matrix=img_matrix, clip=(left, top, left + width, top + height))
                signature_image = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                cropped_stream = BytesIO()
                signature_image.save(cropped_stream, format='PNG')
                s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=key)
                i += 1
        pdf_document.close()
    elif ext in ['png', 'jpeg', 'jpg', 'tiff']:
        try:
            original_image = Image.open(BytesIO(file_stream))
            # Continue with your image processing code
        except Exception as e:
            logger.info("Error:", e)
        i = 0
        for item in res["Blocks"]:
            if item["BlockType"] == "SIGNATURE":
                
                left, top, width, height = get_bounding_box(item['Geometry']['BoundingBox'], original_image)
                Signs_coord.append([(point['X'], point['Y']) for point in item['Geometry']['Polygon']])
                key = f'{log_stream_id}-{lambda_context_request_id}/signature_of_item_{i+1}.png'
                keys.append(key)
                logger.info(f"key:{key}")
                left, top, right, bottom = map(int, (left, top, left + width, top + height))
                signature_image = original_image.crop((left, top, right, bottom))
                cropped_stream = BytesIO()
                signature_image.save(cropped_stream, format='PNG')
                s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=key)
                i += 1
    logger.info(f"keys:{keys}")
    with ThreadPoolExecutor() as executor:
        futures = []
        for key in keys:
            futures.append(executor.submit(remove_whitespace, S3_BUCKET, key))
            logger.info(f"Removing whitespace from cropped signature image: {key}")
        for completed_future in as_completed(futures):
            try:
                completed_future.result()
            except Exception as e:
                logger.info(f"Error in thread: {e}")
    return keys,Signs_coord 


def get_bounding_box(geometry, rect):
    left = geometry['Left'] * rect.width
    top = geometry['Top'] * rect.height
    width = geometry['Width'] * rect.width
    height = geometry['Height'] * rect.height
    return left, top, width, height
    
def remove_whitespace(S3_BUCKET, key):
    # Download the cropped signature image from S3
    response = s3.get_object(Bucket=S3_BUCKET, Key=key)
    cropped_stream = BytesIO(response['Body'].read())
    # Process the cropped signature image using Textract
    response = textract_client.analyze_document(
        Document={'Bytes': cropped_stream.getvalue()},
        FeatureTypes=["SIGNATURES"]
    )
    
    # Find the tighter bounding box of the signature
    signature_block = next((block for block in response["Blocks"] if block["BlockType"] == "SIGNATURE"), None)
    if signature_block:
        signature_image = Image.open(cropped_stream)
        updated_left, updated_top, updated_width, updated_height = get_bounding_box(signature_block['Geometry']['BoundingBox'], signature_image)
        updated_left, updated_top, updated_right, updated_bottom = map(int, (updated_left, updated_top, updated_left + updated_width, updated_top + updated_height))
        signature_image = signature_image.crop((updated_left, updated_top, updated_right, updated_bottom))
        cropped_stream = BytesIO()
        signature_image.save(cropped_stream, format='PNG')
        
        # Upload the updated signature image to S3 with the same key
        s3.put_object(Body=cropped_stream.getvalue(), Bucket=S3_BUCKET, Key=key)