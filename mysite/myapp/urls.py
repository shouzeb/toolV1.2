from django.urls.resolvers import URLPattern
from django.urls import path

from . import views

from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path('',views.webpage1, name='webpage1'),
    path('page2',views.webpage2,name='webpage2'),
    path('upload',views.upload,name="upload"),
    path('remotePcTesting',views.remotePcTesting,name="remotePcTesting")
   
    
] +static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)