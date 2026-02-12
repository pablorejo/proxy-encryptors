import json
from typing import List

from pydantic import Field

from ETSIQKD import ETSI_message
from ETSIQKD.ETSI014 import ETSI014_KeyIDs, ETSI014_KeyID



class ETSI014_getKeyWithKeyIDs(ETSI_message):
    """
    Returns Key container from the KME to the calling slave SAE. Key container contains keys
    matching those previously delivered to a remote master SAE based on the Key IDs supplied
    from the remote master SAE in response to its call to Get key.

    The KME shall reject the request with a 401 HTTP status code if the SAE ID of the requestor
    was not an SAE ID supplied to the "Get key" method each time it was called resulting in the
    return of any of the Key IDs being requested. 

    :param str endpoint: The URL endpoint associated with this message.
    :param List[str] available_access_methods: HTTP methods supported.
    :param str access_method: The current HTTP method used
    :param str SAE_id: The master SAE identifier of the key
    :param ETSI014_KeyIDs key_IDs: The keys retrieved
    """

    endpoint: str = Field('/dec_keys', frozen=True, exclude=True)
    available_access_methods: List[str] = Field(['POST', 'GET'], frozen=True, exclude=True)
    access_method: str = Field('POST', frozen=True, exclude=True)

    SAE_id: str
    key_IDs: ETSI014_KeyIDs

    def __str__(self):
        json_data = json.loads(self.to_json())
        return (
            f"ETSI014_getKeyWithKeyIDs Details:\n"
            + "\n".join([f"- {key.replace('_', ' ').capitalize()}: {value}" for key, value in json_data.items()])
        )

    def get_endpoint_url(self, host: str):
        return f'{host}/api/v1/keys/{self.SAE_id}{self.endpoint}'

    def get_ids(self) -> List[ETSI014_KeyID]:
        """
        Retrieve the key ids of the request
        
        :return List[ETSI014_KeyID]: A list with the KeyIDs
        """
        return self.key_IDs.key_IDs

    @classmethod
    def from_network(cls, message):
        method = message.get('method') if isinstance(message, dict) else getattr(message, 'method', None)
        path = message.get('path') if isinstance(message, dict) else getattr(message, 'path', '')
        url_parameters = message.get('url_parameters') if isinstance(message, dict) else getattr(message, 'url_parameters', {})
        data = message.get('data') if isinstance(message, dict) else getattr(message, 'data', None)

        if method == 'GET':
            try:
                return cls(
                    SAE_id=path.split('/')[-2],
                    access_method='POST',
                    key_IDs=ETSI014_KeyIDs(
                        key_IDs=[ETSI014_KeyID(key_ID=url_parameters['key_ID'])]
                    )
                )
            except KeyError:
                return None

        return cls(
            SAE_id=path.split('/')[-2],
            access_method=method,
            key_IDs=ETSI014_KeyIDs.from_json(data)
        )

    def to_json(self) -> str:
        # Override to_json method to show only key request (as per current tests)
        return self.key_IDs.to_json()
