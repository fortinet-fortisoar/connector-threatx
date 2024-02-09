""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import time

from connectors.core.connector import get_logger, ConnectorError
from connectors.core.connector import Connector


logger = get_logger('threatx')


class ThreatX():
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            self.server_url = self.server_url.strip('/') + '/tx_api/v1'
        else:
            self.server_url = 'http://{0}'.format(self.server_url) + '/tx_api/v1'
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')
        self.token = None

    def make_api_call(self, method, endpoint=None, params=None, data=None, json=None):
        headers = {'Content-Type': 'application/json'}
        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)

        logger.info('Request URL {}'.format(url))
        try:
            response = requests.request(method=method, url=url, params=params, data=data, json=json, headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                result = response.json()
                return result
            elif response.status_code == 401:
                logger.error('Unauthorized: Invalid credentials')
                raise ConnectorError('Unauthorized: Invalid credentials')
            elif response.status_code == 500 or response.status_code == 404:
                logger.error('Invalid input')
                raise ConnectorError('Invalid input')
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url), str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url), str(response.content),
                                                                                       str(response.reason)))
        except requests.exceptions.SSLError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format('SSL certificate validation failed'))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format('The request timed out while trying to connect to the remote server'))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))

    def login(self):
        data = {
            "command": "login",
            "api_token": self.api_key
        }
        try:
            json_resp = self.make_api_call(method='POST', data=data)
            self.token = json_resp.get('token')
        except Exception as err:
            logger.exception('{0}'.format(err))
            raise ConnectorError('{0}'.format(err))


def build_payload(params):
    result = {k: v for k, v in params.items() if v is not None and v != ''}
    return result


def check_health(config):
    obj = ThreatX(config)
    try:
        if obj.login():
            return True
        else:
            logger.exception('Error occured while connecting server')
            raise ConnectorError('Error occured while connecting server')
    except Exception as Err:
        logger.exception('Error occured while connecting server: {}'.format(str(Err)))
        raise ConnectorError('Error occured while connecting server: {}'.format(Err))


def block_ip(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        ip_address = params.get('ip_address')
        description = params.get('description')
        payload = {
            "command": "new_blocklist",
            "api_token": obj.token,
            "customer_name": customer_name,
            "entry": {"ip": ip_address, "description": description, "created": int(time.time())}
        }
        return obj.make_api_call(method='POST', endpoint='/lists', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def unblock_ip(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        ip_address = params.get('ip_address')
        payload = {
            "command": "delete_blocklist",
            "api_token": obj.token,
            "customer_name": customer_name,
            "ip": ip_address
        }
        return obj.make_api_call(method='POST', endpoint='/lists', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def blacklist_ip(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        ip_address = params.get('ip_address')
        description = params.get('description')
        payload = {
            "command": "new_blacklist",
            "token": obj.token,
            "customer_name": customer_name,
            "entry": {"ip": ip_address, "description": description, "created": int(time.time())}
        }
        return obj.make_api_call(method='POST', endpoint='/lists', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def unblacklist_ip(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        ip_address = params.get('ip_address')
        payload = {
            "command": "delete_blacklist",
            "token": obj.token,
            "customer_name": customer_name,
            "ip": ip_address
        }
        return obj.make_api_call(method='POST', endpoint='/lists', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def whitelist_ip(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        ip_address = params.get('ip_address')
        description = params.get('description')
        payload = {
            "command": "new_whitelist",
            "token": obj.token,
            "customer_name": customer_name,
            "entry": {"ip": ip_address, "description": description, "created": int(time.time())}
        }
        return obj.make_api_call(method='POST', endpoint='/lists', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def unwhitelist_ip(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        ip_address = params.get('ip_address')
        payload = {
            "command": "delete_whitelist",
            "token": obj.token,
            "customer_name": customer_name,
            "ip": ip_address
        }
        return obj.make_api_call(method='POST', endpoint='/lists', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_entities(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        params_payload = build_payload(params)
        payload = {
            "command": "list",
            "token": obj.token,
            "customer_name": customer_name,
            "query": {}
        }
        if params_payload.get('ip_addresses'):
            payload['query'].update({'ip_addresses': params_payload.get('ip_addresses')})
        if params_payload.get('entity_ids'):
            payload['query'].update({'entity_ids': params_payload.get('entity_ids')})
        if params_payload.get('codenames'):
            payload['query'].update({'codenames': params_payload.get('codenames')})
        if params_payload.get('actor_ids'):
            payload['query'].update({'actor_ids': params_payload.get('actor_ids')})
        if params_payload.get('attack_ids'):
            payload['query'].update({'attack_ids': params_payload.get('attack_ids')})
        if params_payload.get('first_seen'):
            payload['query'].update({'first_seen': params_payload.get('first_seen')})

        return obj.make_api_call(method='POST', endpoint='/entities', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_entity_notes(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        entity_id = params.get('entity_id')
        payload = {
            "command": "notes",
            "token": obj.token,
            "customer_name": customer_name,
            "id": entity_id
        }
        return obj.make_api_call(method='POST', endpoint='/entities', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def add_entity_note(config, params):
    try:
        obj = ThreatX(config)
        customer_name = config.get('customer_name')
        entity_id = params.get('entity_id')
        content = params.get('content')
        payload = {
            "command": "new_note",
            "token": obj.token,
            "customer_name": customer_name,
            "note": {"entity_id": entity_id, "content": content}
        }
        return obj.make_api_call(method='POST', endpoint='/entities', data=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


operations = {'block_ip': block_ip,
              'unblock_ip': unblock_ip,
              'blacklist_ip': blacklist_ip,
              'unblacklist_ip': unblacklist_ip,
              'whitelist_ip': whitelist_ip,
              'unwhitelist_ip': unwhitelist_ip,
              'get_entities': get_entities,
              'get_entity_notes': get_entity_notes,
              'add_entity_note': add_entity_note
              }
