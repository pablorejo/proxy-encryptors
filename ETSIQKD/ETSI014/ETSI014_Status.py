
from typing import Literal, Optional, Any, Dict

from pydantic import Field

from ETSIQKD import ETSI_message


class ETSI014_Status(ETSI_message):
    """
    Status data format is used for a response data model of API "Get status"
    method

    :param str source_KME_ID: Source KME identifier
    :param str target_KME_ID: Target KME identifier
    :param str master_SAE_ID: Master SAE identifier
    :param str slave_SAE_ID: Slave SAE identifier
    :param int key_size: The default length of the keys
    :param int stored_key_count: The number of currently stored keys
    :param int max_key_count: The maximum number of stored keys
    :param int max_key_per_request: The max number of keys available per request.
    :param int max_key_size: The max length a key can have
    :param int min_key_size: The minimum length a key can have
    :param int max_SAE_ID_count: The maximum number of slave that can be connected to this master
    :param Optional[Dict[str, Any]] status_extension: Status extension data
    """

    source_KME_ID: str
    target_KME_ID: str
    master_SAE_ID: str
    slave_SAE_ID: str
    key_size: int = Field(ge=0)
    stored_key_count: int = Field(ge=0)
    max_key_count: int = Field(ge=0)
    max_key_per_request: int = Field(ge=0)
    max_key_size: int = Field(ge=0)
    min_key_size: int = Field(ge=0)
    max_SAE_ID_count: int = Field(ge=0)
    status_extension: Optional[Dict[str, Any]] = Field(None)

    # For compatibility with current tests
    endpoint: Literal['/status'] = Field('/status', frozen=True, exclude=True)
    access_method: str = Field('GET', exclude=True)

    def get_endpoint_url(self, host: str) -> str:
        return f'{host}/api/v1/keys{self.endpoint}'
