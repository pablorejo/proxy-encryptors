
from typing import List, Literal, Optional, Any, Dict

from pydantic import Field

from ETSIQKD import ETSI_message
from ETSIQKD.ETSI014 import ETSI014_Key


class ETSI014_KeyContainer(ETSI_message):
    """
    Key container data format is used for a response data model of API "Get key"
    method and "Get key with key IDs" method.

    :param List[ETSI014_Key] keys: A List of ETSI014 keys
    :param None | Dict[str, Any] key_container_extension: Extension data for the keys
    """
    keys: List[ETSI014_Key] = Field(min_length=1)
    key_container_extension: Optional[Dict[str, Any]] = Field(None)

    def get_keys(self) -> List[ETSI014_Key]:
        """
        Get the keys available on this container

        :return List[ETSI014_Key]: A list of all keys on this container 
        """
        return self.keys

    # For compatibility with current tests
    endpoint: Literal['/enc_keys', '/dec_keys'] = Field('/enc_keys', frozen=True, exclude=True)
    access_method: List[str] = Field(['GET', 'POST'], exclude=True)

    def get_endpoint_url(self, host: str) -> str:
        return f'{host}/api/v1/keys{self.endpoint}'
