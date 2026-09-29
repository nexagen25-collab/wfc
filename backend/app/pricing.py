"""Server-side price calculation. The only place a total is ever produced.

The rule this module exists to enforce: a browser may send product ids and
quantities, and nothing else. Every price comes from `app/menu.py`. There is no
code path by which a caller-supplied amount reaches a total.

Money is integer rupees throughout. Floats are never used, because
0.1 + 0.2 != 0.3 and a shop that disagrees with itself about money is a support
incident. Percentages use `floor(a * p / 100)` on integers, which is exact and
matches the frontend's `Math.floor` bit for bit.
"""
from dataclasses import dataclass

from .menu import (
    ITEMS,
    MAX_LINES,
    MAX_ORDER_VALUE,
    MAX_QTY_PER_ITEM,
    UNAVAILABLE,
)

# Owner-locked commercial rules. Delivery is free inside 3 km and there is no
# platform or service fee. These are zero on purpose - if a fee is ever added it
# is a business decision that must be made here, in review, not by a client.
DELIVERY_FEE = 0
PLATFORM_FEE = 0
SERVICE_FEE = 0

# The only coupon the owner approved. WFC10 = 10% off orders of 199 or more.
COUPONS: dict[str, dict] = {
    "WFC10": {"percent": 10, "min_order": 199},
}

MAX_QTY = MAX_QTY_PER_ITEM


class PricingError(Exception):
    """Raised with a message safe to show a customer."""


@dataclass(frozen=True)
class Line:
    product_id: str
    name: str
    unit_price: int
    qty: int

    @property
    def line_total(self) -> int:
        return self.unit_price * self.qty


@dataclass(frozen=True)
class Quote:
    lines: tuple[Line, ...]
    subtotal: int
    discount: int
    coupon_applied: str | None
    coupon_rejected: str | None
    delivery_fee: int
    platform_fee: int
    service_fee: int
    total: int


def _resolve_coupon(code: str | None) -> tuple[str | None, str | None]:
    """Return (code_to_apply, rejection_reason)."""
    if code is None:
        return (None, None)
    normalised = code.strip().upper()
    if not normalised:
        return (None, None)
    if normalised not in COUPONS:
        # A made-up code is not an error, it is simply ignored. Telling the
        # caller "unknown code" vs "not eligible" is a free coupon oracle.
        return (None, None)
    return (normalised, None)


def price_cart(cart: dict[str, int], coupon_code: str | None = None) -> Quote:
    """Calculate a quote from product ids and quantities. Never from prices."""
    if not isinstance(cart, dict):
        raise PricingError("Cart must be a mapping of product id to quantity.")

    clean: dict[str, int] = {}
    for product_id, qty in cart.items():
        if not isinstance(product_id, str) or not product_id:
            raise PricingError("Invalid product id.")
        # bool is a subclass of int in Python; True must not become qty=1.
        if isinstance(qty, bool) or not isinstance(qty, int):
            raise PricingError("Quantity must be a whole number.")
        if qty <= 0:
            # A zero or negative quantity is dropped rather than rejected, which
            # matches how a real cart behaves when a customer deletes a line.
            continue
        if qty > MAX_QTY:
            raise PricingError(f"Maximum {MAX_QTY} of any one item per order.")
        clean[product_id] = clean.get(product_id, 0) + qty

    if not clean:
        raise PricingError("Your cart is empty.")
    if len(clean) > MAX_LINES:
        raise PricingError(f"An order can contain at most {MAX_LINES} different items.")

    unknown = [pid for pid in clean if pid not in ITEMS]
    if unknown:
        # Naming the unknown id is safe: it came from the caller, so the caller
        # already knows it. Never echo a price back for it.
        raise PricingError(f"Unknown item: {', '.join(sorted(unknown)[:3])}.")

    sold_out = [pid for pid in clean if pid in UNAVAILABLE]
    if sold_out:
        names = ", ".join(ITEMS[pid].name for pid in sorted(sold_out)[:3])
        raise PricingError(f"Sold out: {names}.")

    lines = tuple(
        Line(pid, ITEMS[pid].name, ITEMS[pid].price, qty)
        for pid, qty in sorted(clean.items())
    )
    subtotal = sum(line.line_total for line in lines)

    if subtotal > MAX_ORDER_VALUE:
        raise PricingError("Order value is too large. Please call the outlet.")

    code, _ = _resolve_coupon(coupon_code)
    discount = 0
    rejected: str | None = None
    if code:
        rule = COUPONS[code]
        if subtotal < rule["min_order"]:
            # Reported plainly to the customer, because a coupon they typed must
            # not silently do nothing.
            rejected = f"{code} needs a minimum order of Rs.{rule['min_order']}."
        else:
            discount = (subtotal * rule["percent"]) // 100

    # A discount can never exceed the subtotal. With today's single coupon this
    # is unreachable, but the guard is the thing that stops a future 200% coupon
    # from paying the customer to take the food.
    if discount > subtotal:
        discount = subtotal

    total = subtotal - discount + DELIVERY_FEE + PLATFORM_FEE + SERVICE_FEE
    if total < 0:
        total = 0

    return Quote(
        lines=lines,
        subtotal=subtotal,
        discount=discount,
        coupon_applied=code if discount else None,
        coupon_rejected=rejected,
        delivery_fee=DELIVERY_FEE,
        platform_fee=PLATFORM_FEE,
        service_fee=SERVICE_FEE,
        total=total,
    )
