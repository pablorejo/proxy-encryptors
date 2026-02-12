
from typing import Optional, Union, List, Any

from pydantic import Field

from ETSIQKD import ETSI_message


class ETSI014_Error(ETSI_message):
    """
    Error data format is used for an error response data model of API "Get status" 
    method, "Get key" method, and "Get key with key IDs" method.

    :param str message: The error message
    :param None | List[Dict[str, Any]] | List[str] details: A list of details for the current error
    """
    message: str
    details: Optional[Union[
        List[dict[str, Any]],
        List[str]
    ]] = Field(None)
