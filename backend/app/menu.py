"""The authoritative menu.

WHY THIS FILE EXISTS SEPARATELY FROM frontend/lib/menu.ts
----------------------------------------------------------
The price the customer sees and the price we charge are two different values
once a database is involved, and if they ever disagree the shop either loses
money or the customer files a complaint. Today the database does not exist, so
this module is the server's copy of the truth and `tests/test_pricing.py`
parses the TypeScript file and asserts the two agree item for item. That drift
check is the safety net; the database replaces this file later.

All 36 items, 8 categories, exactly as approved by the owner on the menu image.
Do not add, rename, re-price or remove anything here without the owner's
explicit confirmation - the frontend and this file must change together.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    id: str
    name: str
    price: int          # whole rupees, never a float
    category: str


def _c(category: str, rows: tuple[tuple[str, str, int], ...]) -> tuple[Item, ...]:
    return tuple(Item(i, n, p, category) for i, n, p in rows)


_CATEGORIES: dict[str, str] = {
    "burgers": "Burgers",
    "wraps": "Wraps",
    "pizzas": "Pizzas",
    "sandwich": "Sandwich",
    "fries": "Fries",
    "brosted": "Brosted Chicken",
    "waffles": "Waffles",
    "combos": "Combos",
}

_ITEMS: tuple[Item, ...] = (
    *_c("burgers", (
        ("chicken-burger", "Chicken Burger", 100),
        ("chicken-cheese-burger", "Chicken Cheese Burger", 120),
        ("zinger-burger", "Zinger Burger", 120),
        ("veg-burger", "Veg Burger", 80),
        ("veg-cheese-burger", "Veg Cheese Burger", 90),
    )),
    *_c("wraps", (
        ("chicken-wrap", "Chicken Wrap", 100),
        ("chicken-zinger-wrap", "Chicken Zinger Wrap", 120),
        ("chicken-nugget-wrap", "Chicken Nugget Wrap", 120),
        ("veg-wrap", "Veg Wrap", 80),
    )),
    *_c("pizzas", (
        ("veg-pizza", "Veg Pizza", 100),
        ("veg-cheese-pizza", "Veg Cheese Pizza", 130),
        ("chicken-pizza", "Chicken Pizza", 180),
        ("chicken-nuggets-pizza", "Chicken Nuggets Pizza", 220),
        ("chicken-popcorn-pizza", "Chicken Popcorn Pizza", 220),
    )),
    *_c("sandwich", (
        ("chicken-sandwich", "Chicken Sandwich", 80),
        ("chicken-nugget-sandwich", "Chicken Nugget Sandwich", 100),
        ("veg-sandwich", "Veg Sandwich", 60),
    )),
    *_c("fries", (
        ("french-fries", "French Fries", 80),
        ("peri-peri-fries", "Peri Peri Fries", 100),
        ("cheesy-fries", "Cheesy Fries", 120),
    )),
    *_c("brosted", (
        ("brosted-2", "Brosted Chicken 2 pcs", 140),
        ("brosted-4", "Brosted Chicken 4 pcs", 260),
        ("brosted-8", "Brosted Chicken 8 pcs", 520),
    )),
    *_c("waffles", (
        ("biscuit-choc", "Biscuit Waffle Choc", 25),
        ("biscuit-dark", "Biscuit Waffle Dark", 50),
        ("biscuit-milky", "Biscuit Waffle Milky", 80),
        ("sandwich-dark", "Sandwich Waffle Dark", 130),
        ("sandwich-milky", "Sandwich Waffle Milky", 150),
        ("sandwich-white", "Sandwich Waffle White", 159),
        ("round-dark", "Round Waffle Dark", 260),
        ("round-milky", "Round Waffle Milky", 300),
        ("round-white", "Round Waffle White", 300),
    )),
    *_c("combos", (
        ("combo-burger", "Burger + Fries + Cold Drink", 149),
        ("combo-wrap", "Wrap + Fries + Cold Drink", 149),
        ("combo-pizza", "Pizza + 2 Cold Drinks", 259),
        ("combo-brosted", "Brosted 4pcs + Fries + 2 Cold Drinks", 359),
    )),
)

ITEMS: dict[str, Item] = {i.id: i for i in _ITEMS}

# Items the kitchen has switched off. Keyed by id so the admin toggle and the
# price lookup share one keyspace. Empty in production; the admin screen writes
# it to the database, not here.
UNAVAILABLE: frozenset[str] = frozenset()

CATEGORY_ORDER: tuple[str, ...] = tuple(_CATEGORIES)

MAX_QTY_PER_ITEM = 20
MAX_LINES = 50
# Sanity ceiling on an order. A single order above this is a mistake or abuse.
MAX_ORDER_VALUE = 50_000
