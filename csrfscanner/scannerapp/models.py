from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User

class Feedback(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.email})"
    
class FeedbackMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True, related_name='feedback_messages')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return f"{'Admin' if self.is_admin else self.user.username}: {self.message[:30]}"
