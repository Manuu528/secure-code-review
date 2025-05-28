# forms.py
from django import forms
from .models import Feedback

# General feedback form (e.g. for Help/FAQ pages)
class SimpleFeedbackForm(forms.Form):
    feedback = forms.CharField(widget=forms.Textarea(attrs={'rows': 5, 'cols': 40}))

# Email-enabled feedback form connected to the Feedback model
class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['name', 'email', 'message']  # Your Feedback model's fields

# Rejection comment form (for admin to reject users)
class RejectionCommentForm(forms.Form):
    comment = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 5, 'cols': 40}),
        required=True,
        label="Reason for Rejection",
        max_length=500  # Optional: limit the length of the comment
    )
