from django.urls import path
from .views import TokenView, UserInfoView, JwksView, IntrospectView, RevokeView

urlpatterns = [
    path('token', TokenView.as_view(), name='token'),
    path('userinfo', UserInfoView.as_view(), name='userinfo'),
    path('certs', JwksView.as_view(), name='jwks'),
    path('introspect', IntrospectView.as_view(), name='introspect'),
    path('revoke', RevokeView.as_view(), name='revoke'),
]
