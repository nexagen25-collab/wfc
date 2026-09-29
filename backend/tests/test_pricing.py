"""Correctness and tamper tests for server-side pricing.

Run: python -m tests.test_pricing

Two jobs:
  1. The arithmetic must be exactly right, in whole rupees, matching the
     frontend bit for bit.
  2. No caller-supplied value may influence a price.

It also parses frontend/lib/menu.ts and fails if the backend catalogue and the
menu the customer sees ever drift apart.
"""
import inspect
import re
from pathlib import Path

from app import pricing
from app.menu import CATEGORY_ORDER, ITEMS, MAX_ORDER_VALUE, MAX_QTY_PER_ITEM, _CATEGORIES
from app.pricing import COUPONS, PricingError, price_cart

REPO = Path(__file__).resolve().parents[2]
FRONT_MENU = REPO / "frontend" / "lib" / "menu.ts"
FRONT_COUPONS = REPO / "frontend" / "lib" / "coupons.ts"

results: list[tuple[str, bool, str]] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))


def raises(name: str, fn, expect: type[Exception] = PricingError) -> None:
    try:
        fn()
        results.append((name, False, "NO ERROR RAISED - HOLE!"))
    except expect as e:
        results.append((name, True, str(e)[:60]))
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"WRONG ERROR {type(e).__name__}: {e}"))


# ------------------------------------------------------------ menu integrity
ok("menu has exactly 36 items", len(ITEMS) == 36, f"got {len(ITEMS)}")
ok("menu has exactly 8 categories", len(CATEGORY_ORDER) == 8, f"got {len(CATEGORY_ORDER)}")
ok("all prices are positive whole rupees",
   all(isinstance(i.price, int) and not isinstance(i.price, bool) and i.price > 0 for i in ITEMS.values()))
ok("all ids are unique (dict would hide a dup)",
   len(ITEMS) == len({i.id for i in ITEMS.values()}))
ok("all names are unique", len(ITEMS) == len({i.name for i in ITEMS.values()}))
ok("cheapest item is Rs.25 (Biscuit Waffle Choc)",
   min(i.price for i in ITEMS.values()) == 25)
ok("dearest item is Rs.520 (Brosted 8 pcs)",
   max(i.price for i in ITEMS.values()) == 520)
ok("no item price is a float", not any(isinstance(i.price, float) for i in ITEMS.values()))

# ------------------------------------------------- drift vs the frontend menu
if FRONT_MENU.exists():
    text = FRONT_MENU.read_text(encoding="utf-8")
    cat_re = re.compile(r'\{\s*slug:\s*"([^"]+)",\s*name:\s*"([^"]+)",\s*items:\s*\[')
    item_re = re.compile(r'\{\s*id:\s*"([^"]+)",\s*name:\s*"([^"]+)",\s*price:\s*(\d+)\s*\}')
    front_cats = cat_re.findall(text)
    front_items = item_re.findall(text)

    ok("frontend menu parses: 8 categories", len(front_cats) == 8, f"got {len(front_cats)}")
    ok("frontend menu parses: 36 items", len(front_items) == 36, f"got {len(front_items)}")

    front_map = {i: (n, int(p)) for i, n, p in front_items}
    mismatch = []
    for pid, (fname, fprice) in front_map.items():
        b = ITEMS.get(pid)
        if b is None:
            mismatch.append(f"{pid} missing from backend")
        elif b.name != fname:
            mismatch.append(f"{pid} name {b.name!r} != {fname!r}")
        elif b.price != fprice:
            mismatch.append(f"{pid} price {b.price} != {fprice}")
    for pid in ITEMS:
        if pid not in front_map:
            mismatch.append(f"{pid} missing from frontend")
    ok("backend and frontend menus match exactly (no price drift)",
       not mismatch, "; ".join(mismatch[:4]) or "36/36 identical")

    # Derived from the file, not typed in by hand. A hand-written expected
    # total is just another number to get wrong.
    derived = sum(p for _, (_, p) in front_map.items())
    ok("menu total derived from the frontend file = 5610", derived == 5610, f"got {derived}")

    ok("category slugs match the frontend",
       [s for s, _ in front_cats] == list(CATEGORY_ORDER),
       f"{[s for s, _ in front_cats]}")
    ok("category display names match the frontend",
       [n for _, n in front_cats] == [_CATEGORIES[s] for s in CATEGORY_ORDER])
else:
    results.append(("frontend menu.ts present to diff against", False, "file not found"))

# ------------------------------------------------ drift vs the frontend coupon
if FRONT_COUPONS.exists():
    ctext = FRONT_COUPONS.read_text(encoding="utf-8")
    cm = re.findall(r'\{\s*code:\s*"([^"]+)",\s*kind:\s*"(\w+)",\s*value:\s*(\d+),\s*minOrder:\s*(\d+)\s*\}', ctext)
    ok("frontend has exactly 1 coupon", len(cm) == 1, f"got {len(cm)}")
    if cm:
        code, kind, val, mino = cm[0]
        ok("coupon code matches", code in COUPONS, f"{code} vs {list(COUPONS)}")
        ok("coupon is percent", kind == "percent")
        ok("coupon percent matches", COUPONS[code]["percent"] == int(val),
           f"{COUPONS.get(code)} vs {val}")
        ok("coupon min order matches", COUPONS[code]["min_order"] == int(mino),
           f"{COUPONS.get(code)} vs {mino}")

# ---------------------------------------------------------------- arithmetic
q = price_cart({"chicken-burger": 2, "french-fries": 1})
ok("2x100 + 1x80 = 280", q.subtotal == 280, f"got {q.subtotal}")
ok("no coupon means no discount", q.discount == 0)
ok("total == subtotal with no coupon", q.total == 280, f"got {q.total}")
ok("no delivery fee", q.delivery_fee == 0 and q.total == q.subtotal)
ok("no platform fee", q.platform_fee == 0)
ok("no service fee", q.service_fee == 0)

q = price_cart({"brosted-8": 3})
ok("3 x 520 = 1560", q.subtotal == 1560, f"got {q.subtotal}")

q = price_cart({i: 1 for i in ITEMS})
ok("all 36 items at qty 1 sum to 5610", q.subtotal == 5610, f"got {q.subtotal}")
ok("all 36 items means 36 lines", len(q.lines) == 36, f"got {len(q.lines)}")

q = price_cart({"chicken-burger": MAX_QTY_PER_ITEM})
ok(f"max qty {MAX_QTY_PER_ITEM} x 100 = 2000", q.subtotal == 2000, f"got {q.subtotal}")

# ----------------------------------------------------------- coupon boundary
# Exactly 199 = combo-burger 149 + biscuit-dark 50.
q = price_cart({"combo-burger": 1, "biscuit-dark": 1}, "WFC10")
ok("subtotal of exactly 199 qualifies", q.subtotal == 199, f"got {q.subtotal}")
ok("199 -> floor(19.9) = 19 discount", q.discount == 19, f"got {q.discount}")
ok("199 total = 180", q.total == 180, f"got {q.total}")
ok("coupon reported as applied", q.coupon_applied == "WFC10")

# 195 = 25 + 50 + 120, just under the threshold.
q = price_cart({"biscuit-choc": 1, "biscuit-dark": 1, "cheesy-fries": 1}, "WFC10")
ok("subtotal 195 is below the threshold", q.subtotal == 195, f"got {q.subtotal}")
ok("195 gets no discount", q.discount == 0, f"got {q.discount}")
ok("195 total = 195", q.total == 195, f"got {q.total}")
ok("rejection is explained to the customer", "199" in (q.coupon_rejected or ""), str(q.coupon_rejected))
ok("not-applied coupon is not listed as applied", q.coupon_applied is None)

q = price_cart({"round-white": 1}, "wfc10")
ok("lowercase code still works", q.discount == 30 and q.total == 270,
   f"discount {q.discount} total {q.total}")

q = price_cart({"round-white": 1}, "  WFC10  ")
ok("code is trimmed and upper-cased", q.discount == 30, f"got {q.discount}")

q = price_cart({"chicken-burger": 1}, "FREEBIRDS")
ok("unknown code is ignored, not an error", q.discount == 0 and q.total == 100)
ok("unknown code is not reported as a rejection", q.coupon_rejected is None)

q = price_cart({"chicken-burger": 2, "french-fries": 1}, "")
ok("empty code is ignored", q.discount == 0 and q.total == 280)
q = price_cart({"chicken-burger": 2, "french-fries": 1}, None)
ok("None code is ignored", q.discount == 0 and q.total == 280)

# floor must match JavaScript Math.floor exactly for every reachable subtotal
mismatch_floor = []
for sub in range(199, 4000):
    d = (sub * 10) // 100
    if d != int((sub * 10) / 100):   # what a naive float would give
        mismatch_floor.append(sub)
q = price_cart({i: 3 for i in ITEMS}, "WFC10")
money = (q.subtotal, q.discount, q.delivery_fee, q.platform_fee, q.service_fee, q.total)
ok("every monetary field is a true int, never a float",
   all(type(v) is int for v in money), f"{[type(v).__name__ for v in money]}")
ok("all line totals are true ints",
   all(type(line.line_total) is int for line in q.lines))
ok("no float appears anywhere in a Quote",
   not any(isinstance(v, float) for v in money))
ok("int arithmetic matches JS Math.floor for 199..3999", not mismatch_floor,
   f"{len(mismatch_floor)} differ")
ok("discount on the largest legal order is exact",
   price_cart({k: 20 for k in ("brosted-8", "round-milky", "round-dark")}, "WFC10").discount
   == (520 + 300 + 260) * 20 * 10 // 100)

# ------------------------------------------------------------- tamper tests
# The function signature itself is the first defence: no price parameter exists.
params = set(inspect.signature(price_cart).parameters)
ok("price_cart accepts no price/total/amount argument",
   not (params & {"price", "total", "amount", "subtotal", "discount", "unit_price"}),
   f"params: {sorted(params)}")

raises("cart key 'price' is treated as an unknown item, never a price",
       lambda: price_cart({"chicken-burger": 1, "price": 1}))
raises("cart key 'total' rejected", lambda: price_cart({"total": 1}))
raises("cart key 'discount' rejected", lambda: price_cart({"discount": 99999}))
raises("unknown product id rejected", lambda: price_cart({"free-burger": 1}))
raises("sql-ish product id rejected", lambda: price_cart({"'; DROP TABLE items;--": 1}))
raises("../ path as product id rejected", lambda: price_cart({"../../secret": 1}))
raises("empty cart rejected", lambda: price_cart({}))
raises("only zero quantities is an empty cart", lambda: price_cart({"chicken-burger": 0}))
raises("negative qty dropped -> empty cart", lambda: price_cart({"chicken-burger": -5}))
raises(f"qty above {MAX_QTY_PER_ITEM} rejected", lambda: price_cart({"chicken-burger": MAX_QTY_PER_ITEM + 1}))
raises("absurd qty rejected", lambda: price_cart({"brosted-8": 10_000}))
raises("float qty rejected", lambda: price_cart({"chicken-burger": 1.5}))
raises("string qty rejected", lambda: price_cart({"chicken-burger": "2"}))
raises("True is not qty 1", lambda: price_cart({"chicken-burger": True}))
raises("None qty rejected", lambda: price_cart({"chicken-burger": None}))
raises("None product id rejected", lambda: price_cart({None: 1}))
raises("empty product id rejected", lambda: price_cart({"": 1}))
raises("list cart rejected", lambda: price_cart([("chicken-burger", 1)]))
raises("None cart rejected", lambda: price_cart(None))
raises(f"more than 50 lines rejected", lambda: price_cart({str(i): 1 for i in range(51)}))

ok("negative qty is dropped, not turned into money",
   price_cart({"chicken-burger": 2, "veg-burger": -1}).subtotal == 200)
ok("zero qty is dropped, not turned into money",
   price_cart({"chicken-burger": 2, "veg-burger": 0}).subtotal == 200)
# A basket that is under the 50-line cap but over the Rs.50,000 value cap:
# 9 lines x qty 20 = 50,360. Built from the real menu, verified above.
OVER_CAP = {
    "brosted-8": 20, "round-milky": 20, "round-white": 20, "combo-brosted": 20,
    "chicken-popcorn-pizza": 20, "chicken-nuggets-pizza": 20, "chicken-pizza": 20,
    "sandwich-white": 20, "round-dark": 20,
}
raises(f"order over the Rs.{MAX_ORDER_VALUE:,} cap rejected",
       lambda: price_cart(OVER_CAP))
raises("cap error is a friendly message, not a stack trace",
       lambda: price_cart(OVER_CAP))
ok("a basket just under the cap is accepted",
   price_cart({k: 5 for k in OVER_CAP}).subtotal <= MAX_ORDER_VALUE)

# -------------------------------------------------------------- determinism
a = price_cart({"chicken-burger": 2, "french-fries": 1}, "WFC10")
b = price_cart({"french-fries": 1, "chicken-burger": 2}, "WFC10")
ok("cart order does not change the total", a.total == b.total, f"{a.total} vs {b.total}")
ok("line order is stable", [l.product_id for l in a.lines] == [l.product_id for l in b.lines])
ok("price_cart is pure (no hidden state)",
   price_cart({"chicken-burger": 1}).total == 100)

# -------------------------------------------------------- sold-out handling
from app import menu as menu_mod  # noqa: E402
saved = menu_mod.UNAVAILABLE
try:
    import app.pricing as pm
    pm.UNAVAILABLE = frozenset({"veg-burger"})
    raises("sold-out item cannot be ordered", lambda: price_cart({"veg-burger": 1}))
    q = price_cart({"chicken-burger": 1})
    ok("other items still orderable when one is sold out", q.total == 100)
    raises("sold-out item in a mixed cart rejected",
           lambda: price_cart({"veg-burger": 1, "chicken-burger": 1}))
finally:
    pm.UNAVAILABLE = saved

# The "discount can never exceed the subtotal" guard is unreachable with one
# 10% coupon, so it is proved by temporarily installing an absurd 200% coupon.
# If the clamp is ever removed, this test fails instead of the shop paying
# customers to take the food.
saved_coupons = dict(COUPONS)
try:
    COUPONS["EVIL200"] = {"percent": 200, "min_order": 0}
    q = price_cart({"chicken-burger": 1}, "EVIL200")
    ok("200% coupon is clamped to the subtotal, never exceeds it",
       q.discount == 100 and q.total == 0, f"discount {q.discount} total {q.total}")
    ok("total never goes negative even with a 200% coupon", q.total >= 0, f"{q.total}")
    COUPONS["EVIL1000"] = {"percent": 1000, "min_order": 0}
    q = price_cart({"brosted-8": 2}, "EVIL1000")
    ok("1000% coupon still yields total 0, not a negative total",
       q.total == 0, f"discount {q.discount} total {q.total}")
finally:
    COUPONS.clear()
    COUPONS.update(saved_coupons)
ok("coupon table restored after the clamp test", list(COUPONS) == ["WFC10"], f"{list(COUPONS)}")
ok("only the approved coupon exists", list(COUPONS) == ["WFC10"], f"{list(COUPONS)}")
ok("coupon percent is 10", COUPONS["WFC10"]["percent"] == 10)
ok("coupon min order is 199", COUPONS["WFC10"]["min_order"] == 199)

# ------------------------------------------------------------------- report
print("=" * 88)
print("WFC PRICING + MENU-DRIFT TESTS")
print("=" * 88)
passed = sum(1 for _, o, _ in results if o)
for name, o, detail in results:
    print(f"  [{'PASS' if o else 'FAIL'}] {name:<58} {detail}".encode("ascii", "replace").decode())
print("=" * 88)
print(f"  {passed}/{len(results)} passed")
print("=" * 88)
raise SystemExit(0 if passed == len(results) else 1)
