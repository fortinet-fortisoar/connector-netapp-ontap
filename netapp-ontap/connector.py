""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import check_health, operations

logger = get_logger('netapp-ontap')


class NetAppOntap(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation:[{}]'.format(operation))
        try:
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as Err:
            logger.exception('{0}'.format(str(Err)))
            raise ConnectorError('{0}'.format(Err))

    def check_health(self, config):
        logger.info('starting health check')
        return check_health(config)
