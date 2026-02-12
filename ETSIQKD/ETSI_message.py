
from typing import List, Union, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, ValidationInfo



class ETSI_message(BaseModel):
    """
    Parent class of all received message in NetworkInterface. No functionality needed.

    :param str endpoint: The URL endpoint associated with this message.
    :param List[str] available_access_methods: HTTP methods supported.
    :param str access_method: The current HTTP method used
    """
    endpoint: str = Field('', frozen=True, exclude=True)
    available_access_methods: List[str] = Field([], frozen=True, exclude=True)
    access_method: str = Field('', frozen=True, exclude=True)

    class Config:
        """ Extra configuration for pydantic schemas """
        validate_assignment = True  # Validate message after each update

    @field_validator('access_method')
    def is_access_method_available(cls,  # pylint: disable=no-self-argument
                                   access_method: str,
                                   info: ValidationInfo) -> str:
        """ Access method validator """
        if access_method not in info.data['available_access_methods']:
            raise ValueError('Invalid access method')
        return access_method

    def to_json(self) -> str:
        """
        Return the JSON representation of the ETSI message
        
        :return str: The JSON representation of the message
        """
        return self.model_dump_json(exclude_none=True)

    def get_endpoint_url(self, host: str) -> str:
        """
        Return the full endpoint for the current message
        
        :param str host: The host for the full url
        """
        return ''


    @classmethod
    def from_json(cls, json_data: Union[str, Dict[str, Any]]) -> Optional["ETSI_message"]:
        """
        Create a ETSI messages from json str or dict

        :param dict[str, Any] | str json_data: Either a dictionary or a JSON string with valid ETSI data
        :return ETSI_message | None: An ETSI_message if one could be built, otherwise none.
        """
        if isinstance(json_data, str):
            return cls.model_validate_json(json_data)

        if isinstance(json_data, dict):
            return cls(**json_data)

        return None

    # Redefinition of magic functions
    def __repr__(self) -> str:
        return self.model_dump_json(exclude_none=True, indent=2)

    def __str__(self) -> str:
        return self.model_dump_json(exclude_none=True, indent=2)
