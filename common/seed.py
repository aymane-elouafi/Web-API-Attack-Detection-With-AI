"""Seed data shared by the demo API and the traffic generator.

Both sides import this file so the generator always knows which users,
products and orders exist in the API's database.
"""

N_USERS = 30                  # regular users (user1..user30), plus one admin
ORDERS_PER_USER = 3
COLORS = ["black", "white", "silver"]
PRODUCT_WORDS = [
    "laptop", "phone", "keyboard", "mouse", "monitor", "headset", "camera",
    "tablet", "printer", "router", "speaker", "charger", "backpack", "webcam",
    "microphone", "drone", "watch", "cable", "dock", "ssd",
]

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Adm1n!Secret"


def username(i: int) -> str:
    return f"user{i}"


def password(i: int) -> str:
    return f"Passw0rd{i}!"


def user_id(i: int) -> int:
    """Database id of regular user i (the admin has id 1)."""
    return i + 1


def n_products() -> int:
    return len(PRODUCT_WORDS) * len(COLORS)


def n_orders() -> int:
    return (N_USERS + 1) * ORDERS_PER_USER


def order_ids_for(uid: int) -> list[int]:
    """Ids of the orders that belong to the user with database id `uid`."""
    return list(range((uid - 1) * ORDERS_PER_USER + 1, uid * ORDERS_PER_USER + 1))
