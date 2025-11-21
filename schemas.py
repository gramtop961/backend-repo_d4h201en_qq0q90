"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Staff -> "staff" collection
- Appointment -> "appointment" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List
from datetime import datetime

# Core auth/user schema
class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    Roles: admin, doctor, receptionist, patient
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    role: Literal["admin", "doctor", "receptionist", "patient"] = Field(
        "patient", description="User role for authorization"
    )
    # Note: For security, password is not part of the exposed schema.
    is_active: bool = Field(True, description="Whether user is active")


class Staff(BaseModel):
    """
    Staff collection schema (for admins to manage)
    Collection name: "staff"
    """
    name: str = Field(...)
    email: EmailStr
    role: Literal["doctor", "nurse", "admin", "receptionist"]
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True


class Patient(BaseModel):
    """
    Patients collection schema
    Collection name: "patient"
    """
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    date_of_birth: Optional[str] = Field(None, description="YYYY-MM-DD")


class Appointment(BaseModel):
    """
    Appointments collection schema
    Collection name: "appointment"
    """
    patient_id: str
    doctor_id: str
    datetime: datetime
    reason: Optional[str] = None
    status: Literal["scheduled", "completed", "cancelled"] = "scheduled"

# The Flames database viewer can use these schemas for validation.
