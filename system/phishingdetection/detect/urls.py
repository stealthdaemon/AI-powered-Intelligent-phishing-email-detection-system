from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("scan", views.scan, name="scan"),
    path("feedback", views.feedback, name="feedback"),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
