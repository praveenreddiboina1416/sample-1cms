from django.urls import path
from .views import *
urlpatterns = [
    path('registration/', userregistration.as_view(), name="registration"), #only for admin
    path('login/', userlogin.as_view(), name="login"),    
    path('logout/', userlogout.as_view(), name="logout"), 
    path('viewprofile/', profileview.as_view(), name="viewprofile"),    # for both supervisor and site engineer 

    path('send_otp/',send_otp,name="sendOtp"),  
    path('confirm_otp/',confirm_otp,name="confirmotp"),
    path('reset_password/',reset_password_view,name="reset_password"),

    path('crew/', crew_list_create, name='crew-list-create'),   #for supervisor
    path('crew/<str:crew_id>/', crew_detail_update_delete, name='crew-detail-update-delete'), #for site engineer

    path('jobs/', job_list_create, name='job-list-create'),
    path('job/<int:id>/', job_detail_update_delete, name='job-detail-update-delete'),

]