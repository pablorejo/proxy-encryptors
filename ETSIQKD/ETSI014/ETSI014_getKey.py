
from typing import List, Optional
from pydantic import Field


from ETSIQKD import ETSI_message
from ETSIQKD.ETSI014 import ETSI014_KeyRequest


class ETSI014_getKey(ETSI_message):
    """
    Returns Key container data from the KME to the calling master SAE. Key container data
    contains one or more keys. The calling master SAE may supply Key request data to specify
    the requirement on Key container data. The slave SAE specified by the slave_SAE_ID
    parameter may subsequently request matching keys from a remote KME using key_ID
    identifiers from the returned Key container. 

    :param str endpoint: The URL endpoint associated with this message.
    :param List[str] available_access_methods: HTTP methods supported.
    :param str access_method: The current HTTP method used
    :param str SAE_id: The slave SAE identifier
    :param ETSI014_KeyRequest request: The key request data
    """

    endpoint: str = Field('/enc_keys', frozen=True, exclude=True)
    available_access_methods: List[str] = Field(['POST','GET'], frozen=True, exclude=True)
    access_method: str = Field('POST', exclude=True)

    SAE_id: str
    request: Optional[ETSI014_KeyRequest] = Field(None)

    def get_endpoint_url(self, host: str) -> str:
        return f'{host}/api/v1/keys/{self.SAE_id}{self.endpoint}'

    @classmethod
    def from_network(cls, message):
        method = message.get('method') if isinstance(message, dict) else getattr(message, 'method', None)
        path = message.get('path') if isinstance(message, dict) else getattr(message, 'path', '')
        url_parameters = message.get('url_parameters') if isinstance(message, dict) else getattr(message, 'url_parameters', {})
        data = message.get('data') if isinstance(message, dict) else getattr(message, 'data', None)

        if method == 'GET':
            return cls(
                SAE_id=path.split('/')[-2],
                access_method=method,
                request=ETSI014_KeyRequest(
                    number=url_parameters.get('number', 1),
                    size=url_parameters.get('size', 256)
                )
            )

        return cls(
            SAE_id=path.split('/')[-2],
            access_method=method,
            request=ETSI014_KeyRequest.from_json(data)
        )

    def to_json(self) -> str:
        # Override to_json method to show only key request (as per current tests)
        if not self.request:
            return '{}'  # TODO: Fixme

        return self.request.to_json()
