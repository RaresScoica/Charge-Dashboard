from dataclasses import dataclass
from typing import List, Optional

from ocpp.v16.enums import (
    AuthorizationStatus,
    ChargingProfileKindType,
    ChargingProfilePurposeType,
    ChargingRateUnitType,
    CiStringType,
    HashAlgorithm,
    Location,
    Measurand,
    Phase,
    ReadingContext,
    RecurrencyKind,
    UnitOfMeasure,
    ValueFormat,
)


@dataclass
class IdTagInfo:

    status: AuthorizationStatus
    parent_id_tag: Optional[str] = None
    expiry_date: Optional[str] = None


@dataclass
class AuthorizationData:
    id_tag: str
    id_tag_info: Optional[IdTagInfo] = None


@dataclass
class ChargingSchedulePeriod:
    start_period: int
    limit: float
    number_phases: Optional[int] = None


@dataclass
class ChargingSchedule:
    charging_rate_unit: ChargingRateUnitType
    charging_schedule_period: List[ChargingSchedulePeriod]
    duration: Optional[int] = None
    start_schedule: Optional[str] = None
    min_charging_rate: Optional[float] = None


@dataclass
class ChargingProfile:
    charging_profile_id: int
    stack_level: int
    charging_profile_purpose: ChargingProfilePurposeType
    charging_profile_kind: ChargingProfileKindType
    charging_schedule: ChargingSchedule
    transaction_id: Optional[int] = None
    recurrency_kind: Optional[RecurrencyKind] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None


@dataclass
class KeyValue:
    key: str
    readonly: bool
    value: Optional[str] = None

    def __post_init__(self):
        if len(self.key) > CiStringType.ci_string_50:
            msg = "Field key is longer than 50 characters"
            raise ValueError(msg)

        if self.value and len(self.value) > CiStringType.ci_string_500:
            msg = "Field key is longer than 500 characters"
            raise ValueError(msg)


@dataclass
class SampledValue:
    value: str
    context: ReadingContext
    format: Optional[ValueFormat] = None
    measurand: Optional[Measurand] = None
    phase: Optional[Phase] = None
    location: Optional[Location] = None
    unit: Optional[UnitOfMeasure] = None


@dataclass
class MeterValue:
    timestamp: str
    sampled_value: List[SampledValue]

@dataclass
class CertificateHashData:
    hash_algorithm: HashAlgorithm
    issuer_name_hash: str
    issuer_key_hash: str
    serial_number: str


@dataclass
class Firmware:
    location: str
    retrieve_date_time: str
    signing_certificate: str
    install_date_time: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class LogParameters:
    remote_location: str
    oldest_timestamp: Optional[str] = None
    latest_timestamp: Optional[str] = None
