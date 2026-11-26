from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.services.dashboard_service import get_dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
def dashboard_summary(_current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return get_dashboard_summary(db)
