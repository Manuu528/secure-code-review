import re
import random
from io import BytesIO
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.core.mail import send_mail, mail_admins
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.http import HttpResponse
from django.conf import settings
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from .forms import FeedbackForm

login_otp_storage = {}
reset_code_storage = {}

def index(request):
    return render(request, "home.html")

def register_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password1 = request.POST["password1"]
        password2 = request.POST["password2"]

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Invalid email format!")
            return redirect("register")

        if not email.lower().endswith("@gmail.com"):
            messages.error(request, "Only Gmail addresses are allowed.")
            return redirect("register")

        if password1 != password2:
            messages.error(request, "Passwords do not match!")
            return redirect("register")

        try:
            validate_password(password1)
        except ValidationError as e:
            messages.error(request, " ".join(e.messages))
            return redirect("register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered! Try logging in.")
            return redirect("register")

        otp = random.randint(100000, 999999)
        login_otp_storage[email] = otp

        send_mail(
            "Your OTP Verification Code",
            f"Your OTP is {otp}.",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        mail_admins(
            "New User Registration Pending Approval",
            f"A new user '{username}' has registered and is awaiting approval.",
            fail_silently=False
        )

        request.session["temp_user"] = {
            "username": username,
            "email": email,
            "password": password1,
        }

        messages.info(request, "OTP sent to your email. Please verify.")
        return redirect("verify_otp")

    return render(request, "register.html")

def verify_otp_view(request):
    if request.method == "POST":
        otp = request.POST.get("otp")
        temp_user = request.session.get("temp_user")

        if not otp or not temp_user:
            messages.error(request, "Session expired or OTP missing!")
            return redirect("register")

        try:
            otp = int(otp)
        except ValueError:
            messages.error(request, "Invalid OTP format!")
            return redirect("verify_otp")

        email = temp_user["email"]
        if login_otp_storage.get(email) == otp:
            User.objects.create_user(
                username=temp_user["username"],
                email=email,
                password=temp_user["password"],
                is_active=False
            )
            login_otp_storage.pop(email, None)
            del request.session["temp_user"]

            messages.success(request, "Account created! Await admin approval.")
            return redirect("login")
        else:
            messages.error(request, "Invalid OTP!")
            return redirect("verify_otp")

    return render(request, "verify_otp.html")

def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)
        if user:
            if not user.is_active:
                messages.error(request, "Account not yet approved by admin.")
                return redirect("login")

            otp = random.randint(100000, 999999)
            login_otp_storage[user.email] = otp

            send_mail(
                "Your 2FA Login OTP",
                f"Your OTP is {otp}.",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            request.session["2fa_user"] = username
            messages.info(request, "OTP sent to your email.")
            return redirect("verify_login_otp")
        else:
            messages.error(request, "Incorrect username or password.")
            return redirect("login")

    return render(request, "login.html")

def verify_login_otp(request):
    if request.method == "POST":
        otp = request.POST.get("otp")
        username = request.session.get("2fa_user")

        if not otp or not username:
            messages.error(request, "Session expired or OTP missing!")
            return redirect("login")

        try:
            otp = int(otp)
        except ValueError:
            messages.error(request, "Invalid OTP format!")
            return redirect("verify_login_otp")

        user = User.objects.get(username=username)
        if login_otp_storage.get(user.email) == otp:
            login(request, user)
            login_otp_storage.pop(user.email, None)
            request.session.pop("2fa_user", None)

            messages.success(request, f"Welcome, {user.username}!")
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect("verify_login_otp")

    return render(request, "verify_login_otp.html")

def logout_view(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("index")

@login_required
def dashboard_view(request):
    return render(request, "dashboard.html")

# File scan
ALLOWED_EXTENSIONS = {"py", "js", "html", "php", "java", "c", "cpp"}

def is_valid_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_sql_injection(code):
    sql_patterns = {
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*'.*'": "Use parameterized queries or prepared statements.",
        r"INSERT\s+INTO\s+.*\s+VALUES\s*\(.*'.*'\)": "Use parameterized queries instead of inserting raw values.",
        r"UPDATE\s+.*\s+SET\s+.*=.*'.*'": "Avoid direct value assignment; use placeholders.",
        r"DELETE\s+FROM\s+.*\s+WHERE\s+.*=.*'.*'": "Use prepared statements to avoid deleting unintended data."
    }

    results = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        for pattern, advice in sql_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                results.append(
                    f"Line {i}: {line.strip()}\n  🔴 Vulnerability: Potential SQL Injection.\n  💡 Fix: {advice}"
                )

    return "\n\n".join(results) if results else "✅ No vulnerabilities found."

@login_required
def scan_code(request):
    result = ""
    if request.method == "POST":
        if 'file' in request.FILES:
            uploaded_file = request.FILES['file']
            filename = uploaded_file.name

            request.session.pop('last_scan_result', None)
            request.session.pop('last_scanned_filename', None)

            if not is_valid_file(filename):
                result = "Unsupported file type. Please upload a valid code file."
                return render(request, 'scan.html', {'result': result})

            file_content = uploaded_file.read().decode('utf-8', errors='ignore')
            if not re.search(r'[a-zA-Z0-9]', file_content):
                result = "Invalid content detected. Please upload only code files."
                return render(request, 'scan.html', {'result': result})

            result = detect_sql_injection(file_content)
            request.session['last_scan_result'] = result
            request.session['last_scanned_filename'] = filename
            return redirect('view_results')

    return render(request, 'scan.html', {'result': result})

@login_required
def view_results(request):
    result = request.session.get('last_scan_result')
    filename = request.session.get('last_scanned_filename', 'scanned_file')

    if not result:
        messages.error(request, "No scan results found. Please scan a file first.")
        return redirect("scan")

    return render(request, 'view_results.html', {
        'result': result,
        'filename': filename
    })

@login_required
def download_report(request):
    result = request.session.get('last_scan_result')
    filename = request.session.get('last_scanned_filename', 'scanned_file')

    if not result:
        messages.error(request, "No scan result found. Please scan a file first.")
        return redirect("scan")

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, height - 80, "Secure Code Review Report")
    p.setFont("Helvetica", 12)
    p.drawString(100, height - 100, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.drawString(100, height - 120, f"Scanned File: {filename}")
    p.drawString(100, height - 150, "Scan Result:")
    p.setFont("Helvetica-Oblique", 11)

    lines = result.split('\n')
    y = height - 180
    for line in lines:
        if y < 50:
            p.showPage()
            y = height - 80
        p.drawString(100, y, line)
        y -= 20

    p.showPage()
    p.save()
    buffer.seek(0)

    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="scan_report.pdf"'
    return response

@staff_member_required
def approve_user_view(request):
    inactive_users = User.objects.filter(is_active=False)
    if request.method == "POST":
        selected_ids = request.POST.getlist("approve_users")
        for user_id in selected_ids:
            try:
                user = User.objects.get(id=user_id, is_active=False)
                user.is_active = True
                user.save()
            except User.DoesNotExist:
                continue
        messages.success(request, "Selected users have been approved.")
        return redirect("approve_users")

    return render(request, "approve_user.html", {"users": inactive_users})

@staff_member_required
def reject_user(request, user_id):
    user = get_object_or_404(User, id=user_id, is_active=False)
    if request.method == "POST":
        comment = request.POST.get("comment")
        if not comment:
            messages.error(request, "A rejection comment is required.")
            return redirect("approve_users")

        user.delete()
        messages.success(request, f"User '{user.username}' has been rejected and removed.")
        return redirect("approve_users")
    
    return render(request, "reject_user.html", {"user": user})

@login_required
def faq_view(request):
    return render(request, "faq.html")

@login_required
def search_view(request):
    return render(request, "search.html")

@login_required
def feedback_view(request):
    return render(request, "feedback.html")

@login_required
def help_view(request):
    return render(request, "help.html")

def submit_feedback(request):
    if request.method == 'POST':
        form = FeedbackForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Feedback submitted successfully.")
            return redirect('feedback')
    else:
        form = FeedbackForm()
    return render(request, 'feedback_form.html', {'form': form})

# Forgot Password: Request Code
def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        if not User.objects.filter(email=email).exists():
            messages.error(request, "Email not found.")
            return redirect("forgot_password")

        code = random.randint(100000, 999999)
        reset_code_storage[email] = code

        send_mail(
            "Password Reset Code",
            f"Your password reset code is: {code}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        request.session["reset_email"] = email
        messages.info(request, "Reset code sent to your email.")
        return redirect("verify_reset_code")
    return render(request, "forgot_password.html")

# Forgot Password: Verify Code
def verify_reset_code(request):
    if request.method == "POST":
        email = request.session.get("reset_email")
        code = request.POST.get("code")

        if not email or not code:
            messages.error(request, "Invalid session or code.")
            return redirect("forgot_password")

        try:
            code = int(code)
        except ValueError:
            messages.error(request, "Invalid code format.")
            return redirect("verify_reset_code")

        if reset_code_storage.get(email) == code:
            messages.info(request, "Code verified. Please set a new password.")
            return redirect("reset_password")  # Match the URL name defined in your urls.py

        else:
            messages.error(request, "Invalid code.")
            return redirect("verify_reset_code")
    return render(request, "verify_reset_code.html")

# Forgot Password: Set New Password
def set_new_password(request):
    email = request.session.get("reset_email")
    if not email:
        messages.error(request, "Session expired.")
        return redirect("forgot_password")

    if request.method == "POST":
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect("set_new_password")

        try:
            validate_password(password1)
        except ValidationError as e:
            messages.error(request, " ".join(e.messages))
            return redirect("set_new_password")

        user = User.objects.get(email=email)
        if user.check_password(password1):
            messages.error(request, "New password cannot be same as old password.")
            return redirect("set_new_password")

        user.set_password(password1)
        user.save()
        reset_code_storage.pop(email, None)
        del request.session["reset_email"]

        send_mail(
            "Password Changed",
            "Your password has been changed successfully.",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        messages.success(request, "Password updated successfully. You can now log in.")
        return redirect("login")

    return render(request, "set_new_password.html")


# feedback/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import FeedbackMessage
from django.http import JsonResponse
from django.utils import timezone

@login_required
def feedback_page(request):
    if request.method == "POST":
        msg = request.POST.get("message")
        if msg:
            FeedbackMessage.objects.create(user=request.user, message=msg, is_admin=False)
    return render(request, "feedback_page.html")

@login_required
def get_messages(request):
    messages = FeedbackMessage.objects.filter(user=request.user).order_by("timestamp")
    data = [
        {
            "sender": "Admin" if m.is_admin else request.user.username,
            "message": m.message,
            "is_admin": m.is_admin,
            "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }
        for m in messages
    ]
    return JsonResponse({"messages": data})



def reply_view(self, request, feedback_id):
       
    feedback = FeedbackMessage.objects.get(id=feedback_id)

    if request.method == 'POST':
        form = FeedbackReplyForm(request.POST)
        if form.is_valid():
            reply = form.cleaned_data['reply']
            if reply:
                # Save the admin's reply as a new FeedbackMessage
                FeedbackMessage.objects.create(
                    user=feedback.user,  # Send to the same user
                    is_admin=True,  # Mark as admin's message
                    message=reply,
                    timestamp=timezone.now()
                )
                self.message_user(request, "Your reply has been sent to the user.")
                return redirect(reverse('admin:scannerapp_feedbackmessage_changelist'))  # Correct URL name
    else:
        form = FeedbackReplyForm()

    return render(request, 'admin/feedback_reply_form.html', {'form': form, 'feedback': feedback})
