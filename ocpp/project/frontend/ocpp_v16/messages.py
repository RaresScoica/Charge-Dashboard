from __future__ import annotations

import decimal
import json
import os
from dataclasses import asdict, is_dataclass
from typing import Callable, Dict, Union

from jsonschema import Draft4Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError

from ocpp.exceptions import (
    FormatViolationError,
    NotImplementedError,
    OCPPError,
    PropertyConstraintViolationError,
    ProtocolError,
    TypeConstraintViolationError,
    UnknownCallErrorCodeError,
    ValidationError,
)

_validators: Dict[str, Draft4Validator] = {}


class _DecimalEncoder(json.JSONEncoder):
    
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float("%.1f" % obj)
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError as e:
            try:
                return obj.to_json()
            except AttributeError:
                raise e


class MessageType:
    #: Call identifies a request.
    Call = 2

    #: CallResult identifies a successful response.
    CallResult = 3

    #: CallError identifies an erroneous response.
    CallError = 4


def unpack(msg):
    try:
        msg = json.loads(msg)
    except json.JSONDecodeError:
        raise FormatViolationError(
            details={"cause": "Message is not valid JSON", "ocpp_message": msg}
        )

    if not isinstance(msg, list):
        raise ProtocolError(
            details={
                "cause": (
                    "OCPP message hasn't the correct format. It "
                    f"should be a list, but got '{type(msg)}' "
                    "instead"
                )
            }
        )

    for cls in [Call, CallResult, CallError]:
        try:
            if msg[0] == cls.message_type_id:
                return cls(*msg[1:])
        except IndexError:
            raise ProtocolError(
                details={"cause": "Message does not contain MessageTypeId"}
            )
        except TypeError:
            raise ProtocolError(details={"cause": "Message is missing elements."})

    raise PropertyConstraintViolationError(
        details={"cause": f"MessageTypeId '{msg[0]}' isn't valid"}
    )


def pack(msg):
    return msg.to_json()


def get_validator(
    message_type_id: int, action: str, ocpp_version: str, parse_float: Callable = float
) -> Draft4Validator:
    
    if ocpp_version not in ["1.6", "2.0", "2.0.1"]:
        raise ValueError

    schemas_dir = "v" + ocpp_version.replace(".", "")

    schema_name = action
    if message_type_id == MessageType.CallResult:
        schema_name += "Response"
    elif message_type_id == MessageType.Call:
        if ocpp_version in ["2.0", "2.0.1"]:
            schema_name += "Request"

    if ocpp_version == "2.0":
        schema_name += "_v1p0"

    cache_key = schema_name + "_" + ocpp_version
    if cache_key in _validators:
        return _validators[cache_key]

    dir, _ = os.path.split(os.path.realpath(__file__))
    relative_path = f"{schemas_dir}/schemas/{schema_name}.json"
    path = os.path.join(dir, relative_path)

    with open(path, "r", encoding="utf-8-sig") as f:
        data = f.read()
        validator = Draft4Validator(json.loads(data, parse_float=parse_float))
        _validators[cache_key] = validator

    return _validators[cache_key]


def validate_payload(message: Union[Call, CallResult], ocpp_version: str) -> None:
    if type(message) not in [Call, CallResult]:
        raise ValidationError(
            "Payload can't be validated because message "
            f"type. It's '{type(message)}', but it should "
            "be either 'Call'  or 'CallResult'."
        )

    try:
        if ocpp_version == "1.6" and (
            (
                type(message) == Call
                and message.action in ["SetChargingProfile", "RemoteStartTransaction"]
            )  # noqa
            or (
                type(message) == CallResult and message.action == "GetCompositeSchedule"
            )
        ):
            validator = get_validator(
                message.message_type_id,
                message.action,
                ocpp_version,
                parse_float=decimal.Decimal,
            )

            message.payload = json.loads(
                json.dumps(message.payload), parse_float=decimal.Decimal
            )
        else:
            validator = get_validator(
                message.message_type_id, message.action, ocpp_version
            )
    except (OSError, json.JSONDecodeError):
        raise NotImplementedError(
            details={"cause": f"Failed to validate action: {message.action}"}
        )

    try:
        validator.validate(message.payload)
    except SchemaValidationError as e:
        if e.validator == "type":
            raise TypeConstraintViolationError(
                details={"cause": e.message, "ocpp_message": message}
            )
        elif e.validator == "additionalProperties":
            raise FormatViolationError(
                details={"cause": e.message, "ocpp_message": message}
            )
        elif e.validator == "required":
            raise ProtocolError(details={"cause": e.message})

        elif e.validator == "maxLength":
            raise TypeConstraintViolationError(
                details={"cause": e.message, "ocpp_message": message}
            ) from e
        else:
            raise FormatViolationError(
                details={
                    "cause": f"Payload '{message.payload}' for action "
                    f"'{message.action}' is not valid: {e}",
                    "ocpp_message": message,
                }
            )


class Call:

    message_type_id = 2

    def __init__(self, unique_id, action, payload):
        self.unique_id = unique_id
        self.action = action
        self.payload = payload

        if is_dataclass(payload):
            self.payload = asdict(payload)

    def to_json(self):
        return json.dumps(
            [
                self.message_type_id,
                self.unique_id,
                self.action,
                self.payload,
            ],
            separators=(",", ":"),
            cls=_DecimalEncoder,
        )

    def create_call_result(self, payload):
        call_result = CallResult(self.unique_id, payload)
        call_result.action = self.action
        return call_result

    def create_call_error(self, exception):
        error_code = "InternalError"
        error_description = "An unexpected error occurred."
        error_details = {}

        if isinstance(exception, OCPPError):
            error_code = exception.code
            error_description = exception.description
            error_details = exception.details

        return CallError(
            self.unique_id,
            error_code,
            error_description,
            error_details,
        )

    def __repr__(self):
        return (
            f"<Call - unique_id={self.unique_id}, action={self.action}, "
            f"payload={self.payload}>"
        )


class CallResult:
    
    message_type_id = 3

    def __init__(self, unique_id, payload, action=None):
        self.unique_id = unique_id
        self.payload = payload

        self.action = action

    def to_json(self):
        return json.dumps(
            [
                self.message_type_id,
                self.unique_id,
                self.payload,
            ],
            separators=(",", ":"),
            cls=_DecimalEncoder,
        )

    def __repr__(self):
        return (
            f"<CallResult - unique_id={self.unique_id}, "
            f"action={self.action}, "
            f"payload={self.payload}>"
        )


class CallError:

    message_type_id = 4

    def __init__(self, unique_id, error_code, error_description, error_details=None):
        self.unique_id = unique_id
        self.error_code = error_code
        self.error_description = error_description
        self.error_details = error_details

    def to_json(self):
        return json.dumps(
            [
                self.message_type_id,
                self.unique_id,
                self.error_code,
                self.error_description,
                self.error_details,
            ],
            # By default json.dumps() adds a white space after every separator.
            # By setting the separator manually that can be avoided.
            separators=(",", ":"),
            cls=_DecimalEncoder,
        )

    def to_exception(self):
        for error in OCPPError.__subclasses__():
            if error.code == self.error_code:
                return error(
                    description=self.error_description, details=self.error_details
                )

        raise UnknownCallErrorCodeError(
            f"Error code '{self.error_code}' is not defined by the"
            " OCPP specification"
        )

    def __repr__(self):
        return (
            f"<CallError - unique_id={self.unique_id}, "
            f"error_code={self.error_code}, "
            f"error_description={self.error_description}, "
            f"error_details={self.error_details}>"
        )
