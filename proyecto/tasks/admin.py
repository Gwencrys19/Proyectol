from django.contrib import admin
from .models import task

class taskAdmin(admin.ModelAdmin):
    readonly_fields = ("created",)
    
# Register your models here.
admin.site.register(task, taskAdmin)