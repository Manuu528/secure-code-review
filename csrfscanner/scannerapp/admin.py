from django.contrib import admin
from django import forms
from .models import FeedbackMessage
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import path
from django.utils import timezone
from django.urls import reverse


class FeedbackReplyForm(forms.Form):
    reply = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Type your reply here...'}),
        required=False,
        help_text="Type a reply to this user."
    )

class FeedbackMessageAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'is_admin', 'timestamp', 'reply_button')
    readonly_fields = ('user', 'message', 'timestamp', 'conversation_thread', 'is_admin')
    ordering = ('-timestamp',)
    actions = ['mark_as_read']

    def conversation_thread(self, obj):
        """Displays the full conversation thread between user and admin."""
        thread = FeedbackMessage.objects.filter(
            user__in=[obj.user],
            is_admin__in=[True, False]
        ).order_by('timestamp')

        html = "<div style='max-height:300px;overflow-y:auto;border:1px solid #ccc;padding:10px;'>"
        for msg in thread:
            html += f"<p><strong>{msg.user.username if not msg.is_admin else 'Admin'}</strong>: {msg.message}<br><small>{msg.timestamp.strftime('%Y-%m-%d %H:%M')}</small></p><hr>"
        html += "</div>"
        return mark_safe(html)

    def reply_button(self, obj):
        """Adds a button to reply directly to this message."""
        return format_html(
            '<a href="{0}" class="button" style="background-color:#4CAF50;color:white;padding:5px 10px;">Reply</a>',
            reverse('admin:feedback_reply', args=[obj.pk])
        )

    def mark_as_read(self, request, queryset):
        """Marks feedback messages as read (or handled)."""
        count = queryset.update(is_admin=True)
        self.message_user(request, f"{count} feedback messages marked as read.")
    mark_as_read.short_description = "Mark selected feedback as read"

    def get_urls(self):
        """Add a custom URL for replying to feedback."""
        urls = super().get_urls()
        custom_urls = [
            path('reply/<int:feedback_id>/', self.admin_site.admin_view(self.reply_view), name='feedback_reply'),
        ]
        return custom_urls + urls

    def reply_view(self, request, feedback_id):
        """Handle the admin's reply to feedback."""
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
                    return redirect(reverse('admin:scannerapp_feedbackmessage_changelist'))
  # Redirect back to the list view
        else:
            form = FeedbackReplyForm()

        return render(request, 'admin/feedback_reply_form.html', {'form': form, 'feedback': feedback})

# Registering the model in admin
admin.site.register(FeedbackMessage, FeedbackMessageAdmin)
