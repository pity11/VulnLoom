from django.shortcuts import get_object_or_404


def detail(request, document_id):
    return get_object_or_404(Document, id=document_id)
