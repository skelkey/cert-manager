#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
cert_manager.py: show the status of certificate inside an HashiCorp vault
instance
"""

__author__    = "Edouard Camoin"
__copyright__ = "Copyright 2022, Edouard Camoin"
__credits__   = [ "Edouard Camoin" ]

__license__   = "Apache 2"
__version__   = "1.0.0"
__maintener__ = "Edouard Camoin"
__email__     = "edouard.camoin@gmail.com"
__status__    = "Production"

import hvac
import OpenSSL
import termcolor
import argparse
import configparser
import validators
import re
import sys
import os

def get_status(cert, revocation_status):
    '''
    Return the status of a certificate.

    Parameters:
        cert (OpenSSL.crypto.X509): a certificate to check
        revocation_status (int): the timestamp of certificate revocation

    Returns:
        status (str): a string describe the state of the certificate
    '''
    if(revocation_status > 0):
        return("REVOKED")
    if(cert.has_expired()):
        return("EXPIRED")
    return("VALID")

def authenticate(url, token):
    '''
    Return a connector to a vault instance.

    Parameters:
        url (str): the URL where the vault instance is located
        token (str): the token for authentication on vault instance

    Returns:
        client (hvac.v1.Client): the connector to vault instance
    '''
    client = hvac.Client(url=url)
    client.token = token
    return client

def list_certificates(mount_point):
    '''
    Return the list of certificates stored at a mount_point

    Parameters:
        mount_point (str): the mount_point where certificates are stored

    Returns:
        response (list): the list of certificates
    '''
    response = client.secrets.pki.list_certificates(mount_point=mount_point)
    return response['data']['keys']

def get_certificate(data, mount_point):
    '''
    Return the information about an x509 cert in vault

    Paramaters:
        data (str): the serial number of the certificate
        mount_point (str): the mount_point where certificate are stored

    Returns:
        cert (dict): the decoded X509 certificate
    '''
    x509_cert = client.secrets.pki.read_certificate(
        mount_point=mount_point,
        serial=data)
    return OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        x509_cert['data']['certificate'])

def get_certificate_revocation_status(data, mount_point):
    '''
    Return the revocation status of a certificate inside vault instance

    Parameters:
        data (str): the serial number of the certificate
        mount_point (str): the mount_point where certificate are stored

    Returns:
        revocation_time (int): the timestamp when the certificate was revoked
    '''
    x509_cert = client.secrets.pki.read_certificate(
        mount_point=mount_point,
        serial=data)
    return x509_cert['data']['revocation_time']

def check_certificate_status(cert, revocation_status):
    '''
    Return the information needed about a certificate

    Parameters:
        cert (OpenSSL.crypto.X509): an X509 certificate
        revocation_status (int): the timestamp when certificate was revoked

    Returns:
        cert (dict): the information about certificate
    '''
    subject = cert.get_subject().commonName
    status  = get_status(cert, revocation_status)
    serial  = cert.get_serial_number()
    return { 'subject': subject, 'status': status, 'serial': serial }

def get_colored_status(status):
    '''
    Return a colored POSIX status for the certificate status

    Parameters:
        status (str): the status to color

    Returns:
        status (str): the colored POSIX status
    '''
    if status == "VALID":
        return termcolor.colored(status, "green")
    if status == "EXPIRED":
        return termcolor.colored(status, "red")
    return termcolor.colored(status,"red", attrs=['reverse'])

def get_hex_serial_number(serial):
    '''
    Return an integer serial in hexadecimal serial

    Paramaters:
        serial (int): the serial to convert in hexadecimal format

    Returns:
        serial (str): the converted serial
    '''
    s = hex(serial)[2:]
    return '-'.join(a+b for a,b in zip(s[::2], s[1::2]))

def get_options():
    '''
    Return structured arguments from command-line

    Returns:
        args (argparse.Namespace): the arguments from command-line
    '''
    parser = argparse.ArgumentParser(
        prog="cert_manager",
        description="Get the state of x509 certificates from a vault instance")
    parser.add_argument("--cn", help="Common name of certificate", type=str)
    parser.add_argument("-p", "--path", help="Path of the PKI in vault",
                        type=str, required=True)
    parser.add_argument("-e", "--endpoint", help="Vault endpoint", type=str)
    parser.add_argument("-t", "--token", help="Vault access token", type=str)
    parser.add_argument("-c", "--config", help="Configuration file", type=str)
    return parser.parse_args()

def validate_endpoint(endpoint):
    '''
    Return a validated endpoint URL or None

    Parameters:
        endpoint (str): the URL to validate as a correct URL

    Returns:
        endpoint (str): the validated URL or None
    '''
    if validators.url(endpoint):
        return endpoint
    return None

def validate_token(token):
    '''
    Return a correctly formatted vault token or None

    Parameters:
        token (str): the token to validate as a correctly formatted token

    Returns:
        token (str): the validated token or None
    '''
    if re.match(r"(hb)*[s|b|r]\.(\w)+", token):
        return token
    return None

def load_config(path):
    '''
    Return configuration loaded from a config file

    Parameters:
        path (str): the path to the config file to read

    Returns:
        config (dict): the configuration read from the config file
    '''
    config = configparser.ConfigParser()
    config.read(path)
    if 'global' in config:
        return {
            'endpoint': validate_endpoint(config['global']['endpoint']),
            'token': validate_token(config['global']['token'])
        }
    return None

def get_all_certificates_status(client, mount_point):
    '''
    Print the status of all certificates present in mount_point

    Parameters:
        client (hvac.v1.Client): the connector to a vault instance
        mount_point (str): the mount_point where certificate are stored

    Returns:
        exit_code (int): the status code of the treatment for OS
    '''
    try:
        response = list_certificates(mount_point)
    except hvac.exceptions.InvalidPath:
        print("error: there is no certificate in this mount point")
        return os.EX_UNAVAILABLE
    for elem in response:
        status = check_certificate_status(
            get_certificate(elem, mount_point),
            get_certificate_revocation_status(elem, mount_point))
        print("{:60s} {:7s} {:50s}".format(
            get_hex_serial_number(status['serial']),
            get_colored_status(status['status']),
            status['subject']))
    return os.EX_OK

def get_certificate_status(client, mount_point, cn):
    '''
    Print the status of a certificate in mount_point

    Parameters:
        client (hvac.v1.Client): the connector to a vault instance
        mount_point (str): the mount_point where certificate are stored
        cn(str): the CN stored in certificate

    Returns:
        exit_code (int): the status code of the treatment for OS
    '''
    cpt = 0
    try:
        response = list_certificates(mount_point)
    except hvac.exceptions.InvalidPath:
        print("error: there is no certificate in this mount point")
        return os.EX_UNAVAILABLE
    for elem in response:
        status = check_certificate_status(
            get_certificate(elem, mount_point),
            get_certificate_revocation_status(elem, mount_point))
        if(status['subject'] == cn):
            cpt +=1
            print("{:60s} {:7s} {:50s}".format(
                get_hex_serial_number(status['serial']),
                get_colored_status(status['status']),
                status['subject']))
    if(cpt < 1):
        print("info: no certificate with this commonName in mount point")
    return os.EX_OK


if __name__ == "__main__":
    args = get_options()
    config = {}
    if args.config:
        config = load_config(args.config)
    if args.endpoint: config['endpoint'] = validate_endpoint(args.endpoint)
    if args.token: config['token'] = validate_token(args.token)
    if not config['endpoint']:
        print("error: missing endpoint in configfile or in command-line")
        sys.exit(os.EX_USAGE)
    if not config['token']:
        print("error: missing token in configfile or in command-line")
        sys.exit(os.EX_USAGE)

    client = authenticate(config['endpoint'],
                          config['token'])
    if client.is_authenticated():
        if args.cn:
            sys.exit(get_certificate_status(client, args.path, args.cn))
        else:
            sys.exit(get_all_certificates_status(client, args.path))
    else:
        print("error: authentication failed")
        sys.exit(os.EX_NOPERM)

