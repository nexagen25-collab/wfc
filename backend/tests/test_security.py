"""Attack tests for the validation layer. Run: python -m tests.test_security

Every test here is a real attack a customer could send. A pass means the layer
rejected it. These are not proof the app is secure, only that this boundary holds.
"""
from uuid import uuid4

from pydantic import ValidationError

from app.schemas import (
    AddressIn, CartItemIn, LoginIn, OrderCreate, OtpRequestIn, OtpVerifyIn, RegisterIn,
)

PID = str(uuid4())
results: list[tuple[str, bool, str]] = []


def expect_rejected(name: str, fn) -> None:
    try:
        fn()
        results.append((name, False, "ACCEPTED - HOLE!"))
    except (ValidationError, ValueError) as e:
        results.append((name, True, f"rejected: {str(e).splitlines()[0][:70]}"))


def expect_accepted(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, "accepted (valid input)"))
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"WRONGLY REJECTED: {e}"))


def ok_order(**over):
    base = {
        "service_mode": "pickup",
        "payment_mode": "cod",
        "items": [{"product_id": PID, "qty": 1}],
    }
    base.update(over)
    return OrderCreate(**base)


# --- Price tampering: the highest-value attack in a food app ---
expect_rejected("client sends price field", lambda: OrderCreate(
    service_mode="pickup", payment_mode="cod",
    items=[{"product_id": PID, "qty": 1, "price": 1}]))
expect_rejected("client sends total field", lambda: ok_order(total=1))
expect_rejected("client sends discount field", lambda: ok_order(discount=9999))
expect_rejected("client smuggles role=admin", lambda: ok_order(role="admin"))
expect_rejected("client smuggles user_id", lambda: ok_order(user_id=str(uuid4())))

# --- Quantity abuse ---
expect_rejected("negative qty", lambda: CartItemIn(product_id=PID, qty=-5))
expect_rejected("zero qty", lambda: CartItemIn(product_id=PID, qty=0))
expect_rejected("absurd qty (1000)", lambda: CartItemIn(product_id=PID, qty=1000))
expect_rejected("float qty", lambda: CartItemIn(product_id=PID, qty=1.5))
expect_rejected("string qty", lambda: CartItemIn(product_id=PID, qty="2"))
expect_rejected("empty order", lambda: ok_order(items=[]))
expect_rejected("not a uuid", lambda: CartItemIn(product_id="1 OR 1=1", qty=1))
expect_rejected("sql-ish id", lambda: CartItemIn(product_id="'; DROP TABLE orders;--", qty=1))

# --- Enum / injection ---
expect_rejected("bad service_mode", lambda: ok_order(service_mode="drone"))
expect_rejected("bad payment_mode", lambda: ok_order(payment_mode="paypal"))
expect_rejected("coupon with sql", lambda: ok_order(coupon_code="'; DROP TABLE--"))
expect_rejected("coupon with spaces", lambda: ok_order(coupon_code="WFC 10"))
expect_accepted("coupon normalised to upper", lambda: ok_order(coupon_code="  wfc10 "))

# --- Business rules ---
def delivery_without_address():
    o = ok_order(service_mode="delivery")
    o.validate_for_mode()


def pickup_with_address():
    o = ok_order(service_mode="pickup", address_id=str(uuid4()))
    o.validate_for_mode()


expect_rejected("delivery with no address", delivery_without_address)
expect_rejected("pickup with an address", pickup_with_address)
expect_accepted("pickup, no address (valid)", lambda: ok_order(service_mode="pickup").validate_for_mode())

# --- Auth payloads ---
expect_rejected("short password", lambda: RegisterIn(
    name="Test", email="a@b.com", phone="9876543210", password="abc"))
expect_rejected("bad phone (starts 1)", lambda: RegisterIn(
    name="Test", email="a@b.com", phone="1234567890", password="abcd1234"))
expect_rejected("phone with spaces", lambda: OtpRequestIn(phone="98765 43210"))
expect_rejected("otp too short", lambda: OtpVerifyIn(phone="9876543210", otp="12"))
expect_rejected("otp with letters", lambda: OtpVerifyIn(phone="9876543210", otp="abcd"))
expect_rejected("empty email", lambda: LoginIn(email="", password="x"))
expect_rejected("empty password", lambda: LoginIn(email="a@b.com", password=""))
expect_accepted("valid register", lambda: RegisterIn(
    name="Warsi", email="Owner@WFC.com", phone="9876543210", password="abcd1234"))

# --- Stored XSS via address fields ---
expect_rejected("script tag in label", lambda: AddressIn(
    label="<script>", line="Bhadurpura 5", area="Bhadurpura"))
expect_rejected("img onerror in line", lambda: AddressIn(
    label="Home", line="<img src=x onerror=alert(1)>", area="Bhadurpura"))

# --- Report ---
print("=" * 78)
print("WFC VALIDATION-LAYER ATTACK TESTS")
print("=" * 78)
passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<34} {detail}")
print("=" * 78)
print(f"  {passed}/{len(results)} passed")
print("=" * 78)
raise SystemExit(0 if passed == len(results) else 1)
