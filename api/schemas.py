"""Typed API request and response models."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from domain_guard.validation import is_valid_domain


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(min_length=3, max_length=253)

    @field_validator("domain")
    @classmethod
    def check_domain(cls, value):
        name = value.strip().lower()
        if not is_valid_domain(name):
            raise ValueError("Enter a domain name such as example.com")
        return name


class NetworkResult(BaseModel):
    safe: bool
    addresses: list[str]
    message: str


class HttpsResult(BaseModel):
    success: bool
    status_code: int | None
    message: str
    headers: dict[str, str] = Field(default_factory=dict)


class TlsResult(BaseModel):
    valid: bool
    expires: str | None
    days_remaining: int | None
    message: str


class DnsLookup(BaseModel):
    status: str
    values: list[str]


class DnsResult(BaseModel):
    records: dict[str, DnsLookup]
    spf: DnsLookup
    dmarc: DnsLookup


class HeaderFinding(BaseModel):
    status: str
    value: str | None = None
    message: str


class HeaderResult(BaseModel):
    status: str
    checks: dict[str, HeaderFinding]
    message: str


class RedirectResult(BaseModel):
    status: str
    http_status: int | None
    location: str | None
    message: str


class ScanResponse(BaseModel):
    domain: str
    scanned_at: datetime
    network: NetworkResult
    https: HttpsResult
    tls: TlsResult
    dns: DnsResult
    headers: HeaderResult
    redirects: RedirectResult
