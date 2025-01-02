from dataclasses import dataclass, field
from typing import Optional, List
from dataclasses_json import dataclass_json, config


@dataclass_json
@dataclass
class GroheTokensDTO:
    access_token: str
    expires_in: int
    refresh_expires_in: int
    refresh_token: str
    token_type: str
    id_token: str
    session_state: str
    scope: str
    not_before_policy: int = field(metadata=config(field_name='not-before-policy'))
    partialLogin: Optional[bool] = None


@dataclass_json
@dataclass
class GrohePressureMeasurementId:
    id: str


@dataclass_json
@dataclass
class GrohePressureMeasurementStart:
    code: int
    message: str
    fields: Optional[List[GrohePressureMeasurementId]] = None
