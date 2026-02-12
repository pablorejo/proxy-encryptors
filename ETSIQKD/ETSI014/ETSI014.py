
from typing import Optional, List, Any, Dict

from pydantic import ValidationError

from ETSIQKD import ETSI_message
from ETSIQKD.ETSI014 import (ETSI014_getKeyWithKeyIDs, ETSI014_Status,
                             ETSI014_getStatus, ETSI014_getKey,
                             ETSI014_KeyContainer, ETSI014_Error)


class ETSI014:
    """ Factory to build ETSI014 Message """

    AVAILABLE_ERROR_CODES: List[int] = [400, 501, 503]

    @staticmethod
    def from_network(message: Any) -> Optional[ETSI_message]:
        """
        ETSI014 Message builder from network messages

        :param Network_message message: The network message used for building
        :return Optional[ETSI_message]: The ETSI014 message if one could be built, otherwise none
        """
        is_response = False
        try:
            is_response = message.get('isResponse') if isinstance(message, dict) else getattr(message, 'isResponse', False)
        except Exception:
            is_response = False

        endpoint = None
        try:
            endpoint = message.get('endpoint') if isinstance(message, dict) else getattr(message, 'endpoint', None)
        except Exception:
            endpoint = None

        status_code = None
        try:
            status_code = message.get('status_code') if isinstance(message, dict) else getattr(message, 'status_code', None)
        except Exception:
            status_code = None

        if is_response:
            try:
                # Parse network message response into an ETSI014 message
                if endpoint in ['status', 'enc_keys', 'dec_keys'] \
                    and status_code in ETSI014.AVAILABLE_ERROR_CODES:
                    return ETSI014_Error.from_network(message)
                if endpoint == 'status':
                    return ETSI014_Status.from_network(message)
                elif endpoint in ['enc_keys', 'dec_keys']:
                    return ETSI014_KeyContainer.from_network(message)
            except ValidationError:
                return None
        else:
            try:
                # Network message is a request to the server
                if endpoint == 'status':
                    return ETSI014_getStatus.from_network(message)
                elif endpoint == 'enc_keys':
                    return ETSI014_getKey.from_network(message)
                elif endpoint == 'dec_keys':
                    return ETSI014_getKeyWithKeyIDs.from_network(message)
            except ValidationError:
                return ETSI014_Error(message='failed', details=[{
                    'request_not_understood': 'KME cannot parse the submitted request.'
                }])

        return None  # No message could be built
