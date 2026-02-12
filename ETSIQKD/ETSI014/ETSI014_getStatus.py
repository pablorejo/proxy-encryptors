from typing import List
from pydantic import Field

from ETSIQKD import ETSI_message


class ETSI014_getStatus(ETSI_message):
    """
    Returns Status from a KME to the calling SAE. Status contains information
    on keys available to be requested by a master SAE for a specified slave SAE. 

    :param str endpoint: The URL endpoint associated with this message.
    :param List[str] available_access_methods: HTTP methods supported.
    :param str access_method: The current HTTP method used
    :param SAE_id: The slave SAE identifier.
    """

    endpoint: str = Field('/status', frozen=True, exclude=True)
    available_access_methods: List[str] = Field(['GET'], frozen=True, exclude=True)
    access_method: str = Field('GET', frozen=True, exclude=True)
    SAE_id: str

    def get_endpoint_url(self, host: str) -> str:
        return f'{host}/api/v1/keys/{self.SAE_id}{self.endpoint}'

    @classmethod
    def from_network(cls, message):
        path = message.get('path') if isinstance(message, dict) else getattr(message, 'path', '')
        return cls(SAE_id=path.split('/')[-2])

    def to_json(self):
        return ''
