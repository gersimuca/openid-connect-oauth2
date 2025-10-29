from django.urls import path
from .views import WellKnownView

urlpatterns = [
    path('openid-configuration', WellKnownView.as_view()),
]
