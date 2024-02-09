""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import *

logger = get_logger('threatx')


class Connector_ThreatX(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            return operation(config, params, **kwargs)
        except Exception as Err:
            logger.error('Exception occurred: {}'.format(Err))
            raise ConnectorError(Err)

    def check_health(self, config):
        logger.info('starting health check')
        return check_health(config)

