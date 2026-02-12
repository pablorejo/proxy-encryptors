
from typing import Optional, List, Any, Dict

from pydantic import Field

from ETSIQKD import ETSI_message


class ETSI014_KeyRequest(ETSI_message):
    """
    Key request data format is used for a request data model of API 
    "Get key" method

    :param Optional[int] number: Number of keys to retrieve
    :param Optional[int] size: Length of the keys
    :param Optional[List[str]] additional_slave_SAE_IDs: A list of additional SAE to send keys to
    :param Optional[List[Dict[str, Any]]] extension_mandatory: A list of mandatory extensions
    :param Optional[List[Dict[str, Any]]] extension_optional: A list of optional extensions.
    """
    number: Optional[int] = Field(1, ge=1)
    size: Optional[int] = Field(256, gt=0)
    additional_slave_SAE_IDs: Optional[List[str]] = Field(None, min_length=1)
    extension_mandatory: Optional[List[Dict[str, Any]]] = Field(None)
    extension_optional: Optional[List[Dict[str, Any]]] = Field(None)
