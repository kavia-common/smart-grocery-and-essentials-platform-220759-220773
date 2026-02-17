from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, PositiveInt, conint


class UserRole(str, Enum):
    customer = "customer"
    admin = "admin"


class OrderStatus(str, Enum):
    pending = "pending"
    paid = "paid"
    processing = "processing"
    shipped = "shipped"
    delivered = "delivered"
    cancelled = "cancelled"
    refunded = "refunded"


class AddressType(str, Enum):
    shipping = "shipping"
    billing = "billing"


class APIMessage(BaseModel):
    message: str = Field(..., description="Human readable message")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type (bearer)")
    user_id: UUID
    email: EmailStr
    role: UserRole
    full_name: str


class SignupRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 chars)")
    full_name: str = Field(..., min_length=1, description="Full name")
    phone: Optional[str] = Field(None, description="Phone number")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="Password")


class Category(BaseModel):
    id: UUID
    name: str
    slug: str
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    sort_order: int
    is_active: bool
    created_at: datetime
    updated_at: datetime


class CategoryCreate(BaseModel):
    name: str = Field(..., min_length=1)
    slug: str = Field(..., min_length=1)
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    sort_order: int = 0
    is_active: bool = True


class CategoryUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    sort_order: Optional[int] = None
    is_active: Optional[bool] = None


class Product(BaseModel):
    id: UUID
    category_id: Optional[UUID] = None
    sku: str
    name: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    price_cents: int
    currency: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    inventory_quantity: Optional[int] = None
    inventory_reserved: Optional[int] = None


class ProductCreate(BaseModel):
    category_id: Optional[UUID] = None
    sku: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    image_url: Optional[str] = None
    price_cents: conint(ge=0) = Field(..., description="Price in cents")
    currency: str = Field("USD", min_length=1)
    is_active: bool = True
    inventory_quantity: conint(ge=0) = 0


class ProductUpdate(BaseModel):
    category_id: Optional[UUID] = None
    sku: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    price_cents: Optional[conint(ge=0)] = None
    currency: Optional[str] = None
    is_active: Optional[bool] = None
    inventory_quantity: Optional[conint(ge=0)] = None


class CartItem(BaseModel):
    id: UUID
    product_id: UUID
    quantity: int
    price_cents_snapshot: int
    created_at: datetime
    updated_at: datetime
    product: Optional[Product] = None


class Cart(BaseModel):
    id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime
    items: List[CartItem] = []


class CartItemUpsert(BaseModel):
    product_id: UUID
    quantity: PositiveInt = Field(..., description="Quantity (>0)")


class Address(BaseModel):
    id: UUID
    user_id: UUID
    type: AddressType
    full_name: str
    phone: Optional[str] = None
    line1: str
    line2: Optional[str] = None
    city: str
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: str
    is_default: bool
    created_at: datetime
    updated_at: datetime


class AddressCreate(BaseModel):
    type: AddressType
    full_name: str = Field(..., min_length=1)
    phone: Optional[str] = None
    line1: str = Field(..., min_length=1)
    line2: Optional[str] = None
    city: str = Field(..., min_length=1)
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: str = Field(..., min_length=1)
    is_default: bool = False


class AddressUpdate(BaseModel):
    type: Optional[AddressType] = None
    full_name: Optional[str] = None
    phone: Optional[str] = None
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    is_default: Optional[bool] = None


class OrderItem(BaseModel):
    id: UUID
    order_id: UUID
    product_id: Optional[UUID] = None
    sku_snapshot: str
    name_snapshot: str
    price_cents_snapshot: int
    quantity: int
    line_total_cents: int


class Order(BaseModel):
    id: UUID
    user_id: UUID
    status: OrderStatus
    currency: str
    subtotal_cents: int
    tax_cents: int
    shipping_cents: int
    total_cents: int
    shipping_address_id: Optional[UUID] = None
    billing_address_id: Optional[UUID] = None
    placed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    items: List[OrderItem] = []


class CheckoutRequest(BaseModel):
    shipping_address_id: Optional[UUID] = Field(None, description="Existing address id to ship to")
    billing_address_id: Optional[UUID] = Field(None, description="Existing address id to bill to")
    place_order: bool = Field(True, description="If true, creates an order from cart")
    tax_cents: conint(ge=0) = 0
    shipping_cents: conint(ge=0) = 0


class AdminOrderUpdate(BaseModel):
    status: OrderStatus = Field(..., description="New order status")
