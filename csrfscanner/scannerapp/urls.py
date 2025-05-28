from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    # Django Admin Panel (default)
    path('admin/', admin.site.urls),

    # Public and Auth Routes
    path('', views.index, name='index'),
    path('register/', views.register_view, name='register'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('login/', views.login_view, name='login'),
    path('verify-login-otp/', views.verify_login_otp, name='verify_login_otp'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Forgot Password Flow
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('verify-reset-code/', views.verify_reset_code, name='verify_reset_code'),  # ✅ updated name
    path('reset-password/', views.set_new_password, name='reset_password'),
    
    # Code Scanning
    path('scan/', views.scan_code, name='scan'),
    path('view-results/', views.view_results, name='view_results'),
    path('download-report/', views.download_report, name='download_report'),

    # Admin Panel Routes (not Django admin site)
    path('admin-panel/manage-users/', views.approve_user_view, name='approve_users'),
    path('admin-panel/reject-user/<int:user_id>/', views.reject_user, name='reject_user'),

    # Admin Panel: FAQ, Help, Feedback, Search
    path('admin-panel/faq/', views.faq_view, name='faq'),
    path('admin-panel/help/', views.help_view, name='help'),
    path('admin-panel/feedback/', views.feedback_view, name='feedback'),
    path('admin-panel/search/', views.search_view, name='search'),

    # Feedback Submission Route
    path('submit-feedback/', views.submit_feedback, name='submit_feedback'),

     path('reset-password/', views.set_new_password, name='set_new_password'),

     path('feedback_page', views.feedback_page, name='feedback_page'),
    path('messages/', views.get_messages, name='get_messages'),
]
