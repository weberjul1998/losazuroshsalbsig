import logging
import json
import azure.functions as func
from azure.storage.queue import (QueueClient,BinaryBase64EncodePolicy,BinaryBase64DecodePolicy)
import os, uuid
from azure.identity import *
from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    result = None
    status_code = None
    message = ""
    credential = AzureCliCredential()
    key_client = KeyClient(vault_url="https://vaultlosazuros.vault.azure.net/", credential=credential)
    secret_client = SecretClient(vault_url="https://vaultlosazuros.vault.azure.net/", credential=credential)
    retrieved_secret = secret_client.get_secret("Secretlosazuros")
    print('Name des Geheimnisses:' + retrieved_secret.name)
    print('Geheimnis-ID: ' + retrieved_secret.id)
    connect_str  = retrieved_secret.value
    print('Geheimniswert: ' + connect_str[:85])
    queue_name = 'warteschlangelosazuros'
    queue_client = QueueClient.from_connection_string(connect_str, queue_name)
    print("Adding message: " + message)

    try:
        req_body = req.get_json()
        print("Req-Body" + str(req_body))
    except ValueError:
        get_trace = None
        req_body = None
    else:
        #print("RequestBody Wert: " + req_body)
        if req_body is None or req_body == {} or req_body == "":
            get_trace = None
        else:
            get_trace = req_body.get('returnvalues')
            print("Test")
    if get_trace:
        message = req_body
        queue_client.send_message(message)
    else:
        message = "-"
        queue_client.send_message(message)

    if get_trace == 1:
        logging.info('Python get a trace')
        result = str(json.dumps({
                'method': req.method,
                'url': req.url,
                'name': 'Felix Meinhardt',
                'function_id': context.invocation_id,
                'function_name': context.function_name})
        )
        result_status = 201
    else:
        logging.info('Parameter "returnvalues" is not correct !=1')
        
        result = str(json.dumps({
                'info': "no returnvalues parameter passed in the correct format",
	            'bodyfromrequest': get_trace})
        )
        result_status = 400

    if result:
        return func.HttpResponse(result,status_code=result_status)
    