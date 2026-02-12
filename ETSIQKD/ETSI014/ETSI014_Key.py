
from uuid import UUID
from typing import Optional, Any, Dict

from pydantic import Field, Base64Bytes

from ETSIQKD import ETSI_message


class ETSI014_Key(ETSI_message):
    """
    Key data format for ETSI014
    
    :param UUID key_ID: Key identifier
    :param None | Dict[str, Any] key_ID_extension: The extension data for the key_ID
    :param Base64Bytes key: The key value
    :param None | Dict[str, Any] key_extension: The extension data for the key
    """
    key_ID: UUID
    key_ID_extension: Optional[Dict[str, Any]] = Field(None)
    key: Base64Bytes = Field(min_length=1)
    key_extension: Optional[Dict[str, Any]] = Field(None)


    def get_key(self) -> str:
        """
        Returns the key in string format

        :return str: The key
        """
        return self.model_dump()['key'].decode()
