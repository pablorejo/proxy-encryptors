from uuid import UUID
from typing import Optional, Any, Dict
from pydantic import Field

from ETSIQKD import ETSI_message


class ETSI014_KeyID(ETSI_message):
    """
    Key ID data format

    :param UUID key_ID: Key Identifier
    :param None | Dict[str, Any] key_ID_extension: Extension data for the key
    """

    key_ID: UUID
    key_ID_extension: Optional[Dict[str, Any]] = Field(None)
