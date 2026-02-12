
from typing import List, Optional, Any, Dict

from pydantic import Field

from ETSIQKD import ETSI_message
from ETSIQKD.ETSI014 import ETSI014_KeyID


class ETSI014_KeyIDs(ETSI_message):
    """
    Key IDs data format is used for a request data model of API "Get key with 
    key IDs" method

    :param List[ETSI014_KeyID] key_IDs: Key Identifier
    :param None | Dict[str, Any] key_IDs_extension: Extension data for the keys
    """

    key_IDs: List[ETSI014_KeyID]
    key_IDs_extension: Optional[Dict[str, Any]] = Field(None)
