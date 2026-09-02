from django.shortcuts import get_object_or_404


def detail(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    if document.owner_id != request.user.id:
        raise PermissionError()
    return document
