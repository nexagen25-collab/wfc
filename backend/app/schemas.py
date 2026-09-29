"""Request/response schemas.

These are the trust boundary. Anything a browser sends is hostile input until
validated here, and any money value sent by a client is ignored entirely —
prices are always looked up server-side from the database.
"""
from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ServiceMode(str, Enum):
    DINEIN = "dinein"
    PICKUP = "pickup"
    DELIVERY = "delivery"


class PaymentMode(str, Enum):
    RAZORPAY = "razorpay"
    COD = "cod"


class StrictModel(BaseModel):
    # Reject unknown keys instead of ignoring them, so a client cannot smuggle
    # extra fields past us and have them silently dropped or later trusted.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CartItemIn(StrictModel):
    product_id: UUID
    # strict=True stops Pydantic from silently coercing "2" or 2.9 into a number.
    qty: Annotated[int, Field(strict=True, ge=1, le=20)]

    # NOTE: there is deliberately no `price` field. extra="forbid" means a client
    # that tries to send {"product_id": "...", "qty": 1, "price": 1} is rejected,
    # so nobody can talk the server into charging ₹1 for a ₹300 burger.


class OrderCreate(StrictModel):
    service_mode: ServiceMode
    payment_mode: PaymentMode
    items: Annotated[list[CartItemIn], Field(min_length=1, max_length=50)]
    coupon_code: Annotated[str, Field(max_length=24)] | None = None
    address_id: UUID | None = None
    # An order over this size is either a mistake or an abuse attempt.
    max_total: Annotated[int, Field(ge=1, le=50_000)] | None = None

    @field_validator("coupon_code")
    @classmethod
    def normalise_coupon(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().upper()
        if not v.isalnum() or not 2 <= len(v) <= 24:
            raise ValueError("Coupon code must be 2-24 letters or digits.")
        return v

    def validate_for_mode(self) -> None:
        """Delivery needs an address; dine-in and pickup must not carry one."""
        if self.service_mode is ServiceMode.DELIVERY and self.address_id is None:
            raise ValueError("Delivery orders require a saved address.")
        if self.service_mode is not ServiceMode.DELIVERY and self.address_id is not None:
            raise ValueError("Dine-in and pickup orders cannot have a delivery address.")


class RegisterIn(StrictModel):
    name: Annotated[str, Field(min_length=2, max_length=80)]
    email: Annotated[str, Field(max_length=254)]
    phone: Annotated[str, Field(pattern=r"^[6-9]\d{9}$")]
    password: Annotated[str, Field(min_length=8, max_length=128)]

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or v.startswith("@") or v.endswith("@") or " " in v:
            raise ValueError("Invalid email address.")
        return v


class OtpRequestIn(StrictModel):
    phone: Annotated[str, Field(pattern=r"^[6-9]\d{9}$")]


class OtpVerifyIn(StrictModel):
    phone: Annotated[str, Field(pattern=r"^[6-9]\d{9}$")]
    otp: Annotated[str, Field(pattern=r"^\d{4,6}$")]


class LoginIn(StrictModel):
    # min_length stops an empty string being treated as a valid login attempt.
    email: Annotated[str, Field(min_length=3, max_length=254)]
    password: Annotated[str, Field(min_length=1, max_length=128)]


class AddressIn(StrictModel):
    label: Annotated[str, Field(min_length=2, max_length=24)]
    line: Annotated[str, Field(min_length=5, max_length=200)]
    area: Annotated[str, Field(min_length=2, max_length=80)]

    @field_validator("label", "area", "line")
    @classmethod
    def strip_tags(cls, v: str) -> str:
        # Every stored field gets checked, not just some. An unescaped field is
        # a stored-XSS waiting to be rendered inside the admin panel.
        lowered = v.lower()
        for bad in ("<", ">", "script", "onerror", "onload", "javascript:"):
            if bad in lowered:
                raise ValueError("Markup is not allowed in address fields.")
        return v


class CategoryOut(BaseModel):
    id: UUID
    name: str
    slug: str
    is_active: bool


class ProductOut(BaseModel):
    id: UUID
    category_id: UUID
    name: str
    description: str | None = None
    price: int
    is_available: bool


class OrderOut(BaseModel):
    order_number: str
    status: str
    payment_status: str
    subtotal: int
    discount: int
    total: int
    created_at: datetime
