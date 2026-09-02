from fastapi import APIRouter, Depends

router = APIRouter()


def get_current_user():
    pass


def get_database():
    pass


@router.get("/item/{item_id}")
def item(item_id, user=Depends(get_current_user), database=Depends(get_database)):
    return database.query.get(item_id)
