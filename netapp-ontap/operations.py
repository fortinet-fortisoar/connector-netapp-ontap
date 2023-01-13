""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
import requests
from requests.auth import HTTPBasicAuth
import datetime
from connectors.core.connector import get_logger, ConnectorError
from .constants import *

logger = get_logger('netapp-ontap')


class NetAppOntap():
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')

        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url

        self.auth = HTTPBasicAuth(config.get('username'), config.get('password'))
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None, json=None):

        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)

        logger.info('Request URL {0}'.format(url))
        headers = {"Accept": "application/json", 'Content-Type': 'application/json'}
        try:
            response = requests.request(method=method, auth=self.auth, url=url, params=params, data=data, json=json,
                                        headers=headers, verify=self.verify_ssl)

            if response.ok:
                result = response.json()
                return result
            elif messages_codes.get(response.status_code):
                logger.error('{0}'.format(response.content))
                raise ConnectorError('{0}'.format(messages_codes.get(response.status_code)))
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url),
                                                                                        str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url),
                                                                                       str(response.content),

                                                                                       str(response.reason)))

        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(messages_codes.get('timeout_error')))
        except Exception as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def check_health(config):
    try:
        logger.info("Invoking check_health")
        akamai = NetAppOntap(config)
        response = akamai.make_api_call(endpoint='/api/security/accounts')
        if response:
            return True
    except Exception as err:
        logger.exception('{0}'.format(err))
        raise ConnectorError('{0}'.format(err))


def handle_datetime(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%dT%H:%M:%S+0000")


def get_security_accounts(config, params):
    netapp = NetAppOntap(config)
    if params.get('fields'):
        params['fields'] = [x.strip() for x in params.get('fields').split(',')]
    if params.get('order_by'):
        params['order_by'] = [sort_order_mapping.get(params.get('order_by'))]

    response = netapp.make_api_call(endpoint='/api/security/accounts', params=params)
    return response


def get_security_audit_messages(config, params):
    netapp = NetAppOntap(config)
    if params.get('timestamp'):
        params['timestamp'] = handle_datetime(params.get('timestamp'))
    if params.get('fields'):
        params['fields'] = [x.strip() for x in params.get('fields').split(',')]
    if params.get('order_by'):
        params['order_by'] = [sort_order_mapping.get(params.get('order_by'))]

    response = netapp.make_api_call(endpoint='/api/security/audit/messages', params=params)
    return response


def get_security_roles(config, params):
    netapp = NetAppOntap(config)
    if params.get('fields'):
        params['fields'] = [x.strip() for x in params.get('fields').split(',')]
    if params.get('order_by'):
        params['order_by'] = [sort_order_mapping.get(params.get('order_by'))]

    response = netapp.make_api_call(endpoint='/api/security/roles', params=params)
    return response


def update_user_password(config, params):
    netapp = NetAppOntap(config)

    payload = {
        "name": params.get('name'),
        "password": params.get('password')
    }
    if params.get('owner_name'):
        payload.update({"owner": {"name": params.get('owner_name')}})
    if params.get('owner_uuid'):
        payload.update({"owner": {"uuid": params.get('owner_uuid')}})

    response = netapp.make_api_call(endpoint='/api/security/authentication/password', data=json.dumps(payload))
    return {'message': 'Created', 'status': 'Success'}


operations = {
    'get_security_accounts': get_security_accounts,
    'get_security_audit_messages': get_security_audit_messages,
    'get_security_roles': get_security_roles,
    'update_user_password': update_user_password
}
