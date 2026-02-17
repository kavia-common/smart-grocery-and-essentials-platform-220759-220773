from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from src.api import db
from src.api.auth_utils import create_user_access_token, get_current_user, hash_password, require_admin, verify_password
from src.api.schemas import (
    APIMessage,
    Address,
    AddressCreate,
    AddressUpdate,
    AdminOrderUpdate,
    Cart,
    CartItemUpsert,
    Category,
    CategoryCreate,
    CategoryUpdate,
    CheckoutRequest,
    LoginRequest,
    Order,
    Product,
    ProductCreate,
    ProductUpdate,
    SignupRequest,
    TokenResponse,
)

openapi_tags = [
    {"name": "Health", "description": "Service health checks."},
    {"name": "Auth", "description": "Signup/login and current user."},
    {"name": "Catalog", "description": "Categories, products, and search."},
    {"name": "Cart", "description": "Cart management for authenticated users."},
    {"name": "Addresses", "description": "User address book."},
    {"name": "Orders", "description": "Checkout, order placement, and order history."},
    {"name": "Admin", "description": "Admin CRUD for categories/products/orders."},
]

app = FastAPI(
    title="Smart Grocery & Essentials API",
    description=(
        "Backend API for the Smart Grocery & Essentials platform. "
        "Includes auth, catalog, cart, checkout/orders, address book, and admin endpoints.\n\n"
        "Auth: Use the `Authorization: Bearer <token>` header for protected routes."
    ),
    version="1.0.0",
    openapi_tags=openapi_tags,
)

# CORS: allow all by default for template/dev. You can restrict via CORS_ALLOW_ORIGINS env (comma separated).
origins_env = Optional[str].__call__(None)  # type: ignore
origins_env = None  # appease linters
allow_origins = ["*"]
try:
    env_val = __import__("os").getenv("CORS_ALLOW_ORIGINS")
    if env_val:
        allow_origins = [o.strip() for o in env_val.split(",") if o.strip()]
except Exception:
    pass

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _not_found(entity: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{entity} not found")


def _bad_request(msg: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


def _get_or_create_cart(user_id: UUID) -> Dict[str, Any]:
    cart = db.fetch_one("SELECT * FROM carts WHERE user_id=%s", [str(user_id)])
    if cart:
        return cart
    return db.execute_returning_one(
        "INSERT INTO carts (user_id) VALUES (%s) RETURNING *",
        [str(user_id)],
    )


def _load_cart_with_items(cart_id: UUID) -> Dict[str, Any]:
    cart = db.fetch_one("SELECT * FROM carts WHERE id=%s", [str(cart_id)])
    if not cart:
        raise _not_found("Cart")
    items = db.fetch_all(
        """
        SELECT ci.*, p.category_id, p.sku, p.name, p.description, p.image_url, p.price_cents, p.currency, p.is_active,
               p.created_at as product_created_at, p.updated_at as product_updated_at,
               i.quantity as inventory_quantity, i.reserved as inventory_reserved
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        LEFT JOIN inventory i ON i.product_id = p.id
        WHERE ci.cart_id=%s
        ORDER BY ci.created_at ASC
        """,
        [str(cart_id)],
    )
    cart["items"] = []
    for r in items:
        product = {
            "id": r["product_id"],
            "category_id": r["category_id"],
            "sku": r["sku"],
            "name": r["name"],
            "description": r["description"],
            "image_url": r["image_url"],
            "price_cents": r["price_cents"],
            "currency": r["currency"],
            "is_active": r["is_active"],
            "created_at": r["product_created_at"],
            "updated_at": r["product_updated_at"],
            "inventory_quantity": r.get("inventory_quantity"),
            "inventory_reserved": r.get("inventory_reserved"),
        }
        cart["items"].append(
            {
                "id": r["id"],
                "product_id": r["product_id"],
                "quantity": r["quantity"],
                "price_cents_snapshot": r["price_cents_snapshot"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "product": product,
            }
        )
    return cart


@app.on_event("startup")
def _startup() -> None:
    db.init_db_pool()


@app.get("/", tags=["Health"], summary="Health check")
def health_check() -> Dict[str, str]:
    """Health check endpoint used by the frontend to verify backend availability."""
    return {"message": "Healthy"}


# =========================
# Auth
# =========================

@app.post("/auth/signup", response_model=TokenResponse, tags=["Auth"], summary="Sign up")
def signup(payload: SignupRequest) -> TokenResponse:
    """Create a new user (customer) and return an access token."""
    existing = db.fetch_one("SELECT id FROM users WHERE email=%s", [payload.email.lower()])
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = db.execute_returning_one(
        """
        INSERT INTO users (email, password_hash, full_name, phone, role, is_active, email_verified)
        VALUES (%s, %s, %s, %s, 'customer', TRUE, FALSE)
        RETURNING id, email, full_name, role
        """,
        [payload.email.lower(), hash_password(payload.password), payload.full_name, payload.phone],
    )
    token = create_user_access_token(UUID(str(user["id"])), user["role"], user["email"])
    return TokenResponse(
        access_token=token,
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        full_name=user["full_name"],
    )


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"], summary="Login")
def login(payload: LoginRequest) -> TokenResponse:
    """Authenticate user and return an access token."""
    user = db.fetch_one(
        "SELECT id, email, full_name, role, is_active, password_hash FROM users WHERE email=%s",
        [payload.email.lower()],
    )
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_user_access_token(UUID(str(user["id"])), user["role"], user["email"])
    return TokenResponse(
        access_token=token,
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        full_name=user["full_name"],
    )


@app.get("/auth/me", tags=["Auth"], summary="Get current user")
def me(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Return the current authenticated user."""
    return user


# =========================
# Catalog
# =========================

@app.get("/catalog/categories", response_model=List[Category], tags=["Catalog"], summary="List categories")
def list_categories(active_only: bool = Query(True, description="If true, return only active categories")) -> List[Dict[str, Any]]:
    """List product categories."""
    if active_only:
        return db.fetch_all("SELECT * FROM categories WHERE is_active=TRUE ORDER BY sort_order ASC, name ASC")
    return db.fetch_all("SELECT * FROM categories ORDER BY sort_order ASC, name ASC")


@app.get("/catalog/products", response_model=List[Product], tags=["Catalog"], summary="List products")
def list_products(
    q: Optional[str] = Query(None, description="Search query (name/sku)"),
    category_id: Optional[UUID] = Query(None, description="Filter by category id"),
    active_only: bool = Query(True, description="If true, return only active products"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, Any]]:
    """List products with optional search/filter."""
    where = []
    params: List[Any] = []
    if active_only:
        where.append("p.is_active=TRUE")
    if category_id:
        where.append("p.category_id=%s")
        params.append(str(category_id))
    if q:
        where.append("(p.name ILIKE %s OR p.sku ILIKE %s)")
        params.extend([f"%{q}%", f"%{q}%"])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    return db.fetch_all(
        f"""
        SELECT p.*, i.quantity as inventory_quantity, i.reserved as inventory_reserved
        FROM products p
        LEFT JOIN inventory i ON i.product_id = p.id
        {where_sql}
        ORDER BY p.created_at DESC
        LIMIT %s OFFSET %s
        """,
        params + [limit, offset],
    )


@app.get("/catalog/products/{product_id}", response_model=Product, tags=["Catalog"], summary="Get product")
def get_product(product_id: UUID) -> Dict[str, Any]:
    """Get product by id."""
    product = db.fetch_one(
        """
        SELECT p.*, i.quantity as inventory_quantity, i.reserved as inventory_reserved
        FROM products p
        LEFT JOIN inventory i ON i.product_id = p.id
        WHERE p.id=%s
        """,
        [str(product_id)],
    )
    if not product:
        raise _not_found("Product")
    return product


# =========================
# Cart
# =========================

@app.get("/cart", response_model=Cart, tags=["Cart"], summary="Get current user's cart")
def get_cart(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get or create the current user's cart and return it with items."""
    cart = _get_or_create_cart(UUID(str(user["id"])))
    return _load_cart_with_items(UUID(str(cart["id"])))


@app.post("/cart/items", response_model=Cart, tags=["Cart"], summary="Add or update cart item")
def upsert_cart_item(payload: CartItemUpsert, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Add a product to cart or set its quantity."""
    product = db.fetch_one("SELECT id, price_cents, is_active FROM products WHERE id=%s", [str(payload.product_id)])
    if not product or not product.get("is_active"):
        raise _not_found("Product")

    cart = _get_or_create_cart(UUID(str(user["id"])))

    existing = db.fetch_one(
        "SELECT id FROM cart_items WHERE cart_id=%s AND product_id=%s",
        [str(cart["id"]), str(payload.product_id)],
    )
    if existing:
        db.execute(
            "UPDATE cart_items SET quantity=%s, updated_at=NOW() WHERE id=%s",
            [payload.quantity, str(existing["id"])],
        )
    else:
        db.execute(
            """
            INSERT INTO cart_items (cart_id, product_id, quantity, price_cents_snapshot)
            VALUES (%s, %s, %s, %s)
            """,
            [str(cart["id"]), str(payload.product_id), payload.quantity, int(product["price_cents"])],
        )

    return _load_cart_with_items(UUID(str(cart["id"])))


@app.delete("/cart/items/{item_id}", response_model=Cart, tags=["Cart"], summary="Remove cart item")
def remove_cart_item(item_id: UUID, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Remove an item from the current user's cart."""
    cart = _get_or_create_cart(UUID(str(user["id"])))
    affected = db.execute("DELETE FROM cart_items WHERE id=%s AND cart_id=%s", [str(item_id), str(cart["id"])])
    if affected == 0:
        raise _not_found("Cart item")
    return _load_cart_with_items(UUID(str(cart["id"])))


@app.delete("/cart/clear", response_model=Cart, tags=["Cart"], summary="Clear cart")
def clear_cart(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Remove all items from the current user's cart."""
    cart = _get_or_create_cart(UUID(str(user["id"])))
    db.execute("DELETE FROM cart_items WHERE cart_id=%s", [str(cart["id"])])
    return _load_cart_with_items(UUID(str(cart["id"])))


# =========================
# Addresses
# =========================

@app.get("/addresses", response_model=List[Address], tags=["Addresses"], summary="List addresses")
def list_addresses(user: Dict[str, Any] = Depends(get_current_user)) -> List[Dict[str, Any]]:
    """List current user's saved addresses."""
    return db.fetch_all("SELECT * FROM addresses WHERE user_id=%s ORDER BY created_at DESC", [str(user["id"])])


@app.post("/addresses", response_model=Address, tags=["Addresses"], summary="Create address")
def create_address(payload: AddressCreate, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Create an address for the current user."""
    if payload.is_default:
        db.execute(
            "UPDATE addresses SET is_default=FALSE, updated_at=NOW() WHERE user_id=%s AND type=%s",
            [str(user["id"]), payload.type.value],
        )

    return db.execute_returning_one(
        """
        INSERT INTO addresses (user_id, type, full_name, phone, line1, line2, city, state, postal_code, country, is_default)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        [
            str(user["id"]),
            payload.type.value,
            payload.full_name,
            payload.phone,
            payload.line1,
            payload.line2,
            payload.city,
            payload.state,
            payload.postal_code,
            payload.country,
            payload.is_default,
        ],
    )


@app.patch("/addresses/{address_id}", response_model=Address, tags=["Addresses"], summary="Update address")
def update_address(address_id: UUID, payload: AddressUpdate, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Update a saved address belonging to the current user."""
    existing = db.fetch_one("SELECT * FROM addresses WHERE id=%s AND user_id=%s", [str(address_id), str(user["id"])])
    if not existing:
        raise _not_found("Address")

    if payload.is_default:
        addr_type = payload.type.value if payload.type else existing["type"]
        db.execute(
            "UPDATE addresses SET is_default=FALSE, updated_at=NOW() WHERE user_id=%s AND type=%s",
            [str(user["id"]), addr_type],
        )

    fields = []
    params: List[Any] = []
    for col, val in [
        ("type", payload.type.value if payload.type else None),
        ("full_name", payload.full_name),
        ("phone", payload.phone),
        ("line1", payload.line1),
        ("line2", payload.line2),
        ("city", payload.city),
        ("state", payload.state),
        ("postal_code", payload.postal_code),
        ("country", payload.country),
        ("is_default", payload.is_default),
    ]:
        if val is not None:
            fields.append(f"{col}=%s")
            params.append(val)

    if not fields:
        return existing

    params.extend([str(address_id), str(user["id"])])
    return db.execute_returning_one(
        f"UPDATE addresses SET {', '.join(fields)}, updated_at=NOW() WHERE id=%s AND user_id=%s RETURNING *",
        params,
    )


@app.delete("/addresses/{address_id}", response_model=APIMessage, tags=["Addresses"], summary="Delete address")
def delete_address(address_id: UUID, user: Dict[str, Any] = Depends(get_current_user)) -> APIMessage:
    """Delete a saved address."""
    affected = db.execute("DELETE FROM addresses WHERE id=%s AND user_id=%s", [str(address_id), str(user["id"])])
    if affected == 0:
        raise _not_found("Address")
    return APIMessage(message="Deleted")


# =========================
# Orders / Checkout
# =========================

@app.post("/checkout", response_model=Order, tags=["Orders"], summary="Checkout (place order from cart)")
def checkout(payload: CheckoutRequest, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Create an order from the current user's cart.

    Notes:
    - This implementation computes subtotal from cart snapshots.
    - Inventory reservation/locking is intentionally minimal for template use.
    """
    cart = _get_or_create_cart(UUID(str(user["id"])))
    items = db.fetch_all("SELECT * FROM cart_items WHERE cart_id=%s ORDER BY created_at ASC", [str(cart["id"])])
    if not items:
        raise _bad_request("Cart is empty")

    # Validate addresses (if provided) belong to user.
    shipping_address_id = str(payload.shipping_address_id) if payload.shipping_address_id else None
    billing_address_id = str(payload.billing_address_id) if payload.billing_address_id else None

    for addr_id, label in [(shipping_address_id, "shipping_address_id"), (billing_address_id, "billing_address_id")]:
        if addr_id:
            addr = db.fetch_one("SELECT id FROM addresses WHERE id=%s AND user_id=%s", [addr_id, str(user["id"])])
            if not addr:
                raise _bad_request(f"{label} does not belong to current user")

    subtotal = 0
    currency = "USD"
    for it in items:
        subtotal += int(it["price_cents_snapshot"]) * int(it["quantity"])

    total = subtotal + int(payload.tax_cents) + int(payload.shipping_cents)

    order = db.execute_returning_one(
        """
        INSERT INTO orders (user_id, status, currency, subtotal_cents, tax_cents, shipping_cents, total_cents,
                            shipping_address_id, billing_address_id, placed_at)
        VALUES (%s, 'pending', %s, %s, %s, %s, %s, %s, %s, NOW())
        RETURNING *
        """,
        [
            str(user["id"]),
            currency,
            subtotal,
            int(payload.tax_cents),
            int(payload.shipping_cents),
            total,
            shipping_address_id,
            billing_address_id,
        ],
    )

    # Create order items with product snapshots.
    for it in items:
        prod = db.fetch_one("SELECT id, sku, name FROM products WHERE id=%s", [str(it["product_id"])])
        if not prod:
            # product_id is nullable in schema for order_items; allow placing historical item even if product removed
            sku = "unknown"
            name = "Unknown product"
            prod_id = None
        else:
            sku = prod["sku"]
            name = prod["name"]
            prod_id = str(prod["id"])

        price = int(it["price_cents_snapshot"])
        qty = int(it["quantity"])
        line_total = price * qty

        db.execute(
            """
            INSERT INTO order_items (order_id, product_id, sku_snapshot, name_snapshot, price_cents_snapshot, quantity, line_total_cents)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            [str(order["id"]), prod_id, sku, name, price, qty, line_total],
        )

    # Clear cart after successful order placement.
    db.execute("DELETE FROM cart_items WHERE cart_id=%s", [str(cart["id"])])

    order_items = db.fetch_all("SELECT * FROM order_items WHERE order_id=%s ORDER BY created_at ASC", [str(order["id"])])
    order["items"] = order_items
    return order


@app.get("/orders", response_model=List[Order], tags=["Orders"], summary="Order history")
def order_history(user: Dict[str, Any] = Depends(get_current_user)) -> List[Dict[str, Any]]:
    """List orders for the current user (most recent first)."""
    orders = db.fetch_all("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", [str(user["id"])])
    for o in orders:
        items = db.fetch_all("SELECT * FROM order_items WHERE order_id=%s ORDER BY created_at ASC", [str(o["id"])])
        o["items"] = items
    return orders


@app.get("/orders/{order_id}", response_model=Order, tags=["Orders"], summary="Get order")
def get_order(order_id: UUID, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get an order (must belong to current user, unless admin)."""
    order = db.fetch_one("SELECT * FROM orders WHERE id=%s", [str(order_id)])
    if not order:
        raise _not_found("Order")

    if order["user_id"] != user["id"] and user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    items = db.fetch_all("SELECT * FROM order_items WHERE order_id=%s ORDER BY created_at ASC", [str(order_id)])
    order["items"] = items
    return order


# =========================
# Admin
# =========================

@app.post("/admin/categories", response_model=Category, tags=["Admin"], summary="Create category")
def admin_create_category(payload: CategoryCreate, _: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Admin: create a category."""
    return db.execute_returning_one(
        """
        INSERT INTO categories (name, slug, description, parent_id, sort_order, is_active)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        [payload.name, payload.slug, payload.description, str(payload.parent_id) if payload.parent_id else None, payload.sort_order, payload.is_active],
    )


@app.patch("/admin/categories/{category_id}", response_model=Category, tags=["Admin"], summary="Update category")
def admin_update_category(category_id: UUID, payload: CategoryUpdate, _: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Admin: update a category."""
    existing = db.fetch_one("SELECT * FROM categories WHERE id=%s", [str(category_id)])
    if not existing:
        raise _not_found("Category")

    fields = []
    params: List[Any] = []
    for col, val in [
        ("name", payload.name),
        ("slug", payload.slug),
        ("description", payload.description),
        ("parent_id", str(payload.parent_id) if payload.parent_id else None if payload.parent_id is not None else None),
        ("sort_order", payload.sort_order),
        ("is_active", payload.is_active),
    ]:
        if val is not None:
            fields.append(f"{col}=%s")
            params.append(val)

    if not fields:
        return existing

    params.append(str(category_id))
    return db.execute_returning_one(
        f"UPDATE categories SET {', '.join(fields)}, updated_at=NOW() WHERE id=%s RETURNING *",
        params,
    )


@app.delete("/admin/categories/{category_id}", response_model=APIMessage, tags=["Admin"], summary="Delete category")
def admin_delete_category(category_id: UUID, _: Dict[str, Any] = Depends(require_admin)) -> APIMessage:
    """Admin: delete a category."""
    affected = db.execute("DELETE FROM categories WHERE id=%s", [str(category_id)])
    if affected == 0:
        raise _not_found("Category")
    return APIMessage(message="Deleted")


@app.post("/admin/products", response_model=Product, tags=["Admin"], summary="Create product")
def admin_create_product(payload: ProductCreate, _: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Admin: create a product and its inventory record."""
    product = db.execute_returning_one(
        """
        INSERT INTO products (category_id, sku, name, description, image_url, price_cents, currency, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        [
            str(payload.category_id) if payload.category_id else None,
            payload.sku,
            payload.name,
            payload.description,
            payload.image_url,
            int(payload.price_cents),
            payload.currency,
            payload.is_active,
        ],
    )
    db.execute(
        "INSERT INTO inventory (product_id, quantity, reserved) VALUES (%s, %s, 0) ON CONFLICT (product_id) DO NOTHING",
        [str(product["id"]), int(payload.inventory_quantity)],
    )
    # Return joined view
    return db.fetch_one(
        """
        SELECT p.*, i.quantity as inventory_quantity, i.reserved as inventory_reserved
        FROM products p
        LEFT JOIN inventory i ON i.product_id=p.id
        WHERE p.id=%s
        """,
        [str(product["id"])],
    ) or product


@app.patch("/admin/products/{product_id}", response_model=Product, tags=["Admin"], summary="Update product")
def admin_update_product(product_id: UUID, payload: ProductUpdate, _: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Admin: update product and/or inventory quantity."""
    existing = db.fetch_one("SELECT * FROM products WHERE id=%s", [str(product_id)])
    if not existing:
        raise _not_found("Product")

    # Update product fields
    fields = []
    params: List[Any] = []
    if payload.category_id is not None:
        fields.append("category_id=%s")
        params.append(str(payload.category_id) if payload.category_id else None)
    for col, val in [
        ("sku", payload.sku),
        ("name", payload.name),
        ("description", payload.description),
        ("image_url", payload.image_url),
        ("price_cents", int(payload.price_cents) if payload.price_cents is not None else None),
        ("currency", payload.currency),
        ("is_active", payload.is_active),
    ]:
        if val is not None:
            fields.append(f"{col}=%s")
            params.append(val)

    if fields:
        params.append(str(product_id))
        db.execute_returning_one(
            f"UPDATE products SET {', '.join(fields)}, updated_at=NOW() WHERE id=%s RETURNING id",
            params,
        )

    # Inventory update
    if payload.inventory_quantity is not None:
        db.execute(
            """
            INSERT INTO inventory (product_id, quantity, reserved)
            VALUES (%s, %s, 0)
            ON CONFLICT (product_id) DO UPDATE SET quantity=EXCLUDED.quantity, updated_at=NOW()
            """,
            [str(product_id), int(payload.inventory_quantity)],
        )

    product = db.fetch_one(
        """
        SELECT p.*, i.quantity as inventory_quantity, i.reserved as inventory_reserved
        FROM products p
        LEFT JOIN inventory i ON i.product_id=p.id
        WHERE p.id=%s
        """,
        [str(product_id)],
    )
    if not product:
        raise _not_found("Product")
    return product


@app.delete("/admin/products/{product_id}", response_model=APIMessage, tags=["Admin"], summary="Delete product")
def admin_delete_product(product_id: UUID, _: Dict[str, Any] = Depends(require_admin)) -> APIMessage:
    """Admin: delete a product (inventory row will be removed via FK/constraints if configured)."""
    affected = db.execute("DELETE FROM products WHERE id=%s", [str(product_id)])
    if affected == 0:
        raise _not_found("Product")
    return APIMessage(message="Deleted")


@app.get("/admin/orders", response_model=List[Order], tags=["Admin"], summary="List all orders")
def admin_list_orders(
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: Dict[str, Any] = Depends(require_admin),
) -> List[Dict[str, Any]]:
    """Admin: list all orders."""
    params: List[Any] = []
    where = ""
    if status_filter:
        where = "WHERE status=%s"
        params.append(status_filter)

    orders = db.fetch_all(
        f"SELECT * FROM orders {where} ORDER BY created_at DESC LIMIT %s OFFSET %s",
        params + [limit, offset],
    )
    for o in orders:
        items = db.fetch_all("SELECT * FROM order_items WHERE order_id=%s ORDER BY created_at ASC", [str(o["id"])])
        o["items"] = items
    return orders


@app.patch("/admin/orders/{order_id}", response_model=Order, tags=["Admin"], summary="Update order status")
def admin_update_order(order_id: UUID, payload: AdminOrderUpdate, _: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    """Admin: update order status."""
    order = db.fetch_one("SELECT * FROM orders WHERE id=%s", [str(order_id)])
    if not order:
        raise _not_found("Order")

    updated = db.execute_returning_one(
        "UPDATE orders SET status=%s, updated_at=NOW() WHERE id=%s RETURNING *",
        [payload.status.value, str(order_id)],
    )
    items = db.fetch_all("SELECT * FROM order_items WHERE order_id=%s ORDER BY created_at ASC", [str(order_id)])
    updated["items"] = items
    return updated
