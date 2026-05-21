from apis.auth.utils import RolesBasedAuthChecker, get_current_user
from apis.orders import schemas
from db.models import Order, User, UserRole
from db.session import get_db
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing_extensions import Annotated

router = APIRouter()

@router.get("/orders/{order_id}", response_model=schemas.Order)
def get_order(
    order_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    auth=Depends(RolesBasedAuthChecker([UserRole.CUSTOMER])),
):
    # ✅ SOLUCIÓN IDOR: Validar que el usuario autenticado es el dueño del pedido
    db_order = db.query(Order).filter(
        Order.id == order_id,
        Order.user_id == current_user.id  # 🔒 Validación de propiedad
    ).first()
    
    if db_order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    return db_order