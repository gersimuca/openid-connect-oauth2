from django.urls import path, include
from django.http import JsonResponse


def health(request):
    return JsonResponse({"status": "OK"})


urlpatterns = [
    path('.well-known/openid-configuration', include('apps.security.urls_wellknown')),
    path('protocol/openid-connect/', include('apps.security.urls')),
    path('health/', health),
]
