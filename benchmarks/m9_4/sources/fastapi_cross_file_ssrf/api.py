from fastapi import APIRouter
from .service import fetch_preview

router = APIRouter()


@router.get("/preview/{url}")
def preview(url):
    return fetch_preview(url)
