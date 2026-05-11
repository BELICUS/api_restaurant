from typing import Union

from apis.auth.utils import get_current_user, get_user_by_username
from db.models import User
from db.session import get_db
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Extra
from sqlalchemy.orm import Session
from typing_extensions import Annotated

router = APIRouter()


class UserRead(BaseModel):
    username: str
    phone_number: str
    first_name: Union[str, None] = None
    last_name: Union[str, None] = None
    role: str


class UserUpdate(BaseModel, extra=Extra.forbid):
    # we forbid extra fields to prevent privilege escalation
    # users should NOT be able to modify sensitive fields like 'role'
    first_name: Union[str, None] = None
    last_name: Union[str, None] = None
    phone_number: Union[str, None] = None


@router.patch("/profile", response_model=UserRead, status_code=status.HTTP_200_OK)
def patch_profile(
    user: UserUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    db_user = get_user_by_username(db, current_user.username)

    # Whitelist of allowed fields to prevent privilege escalation
    allowed_fields = {"first_name", "last_name", "phone_number"}
    
    for var, value in user.dict().items():
        if value and var in allowed_fields:
            setattr(db_user, var, value)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user
