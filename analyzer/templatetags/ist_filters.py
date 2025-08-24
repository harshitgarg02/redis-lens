from django import template
from django.utils import timezone
import datetime

register = template.Library()

@register.filter
def to_ist(value):
    """Convert UTC datetime to IST (Indian Standard Time)"""
    if not value:
        return ""
    
    if isinstance(value, datetime.datetime):
        # Convert to IST (UTC + 5:30)
        ist_time = value + datetime.timedelta(hours=5, minutes=30)
        return ist_time
    return value

@register.filter
def ist_datetime(value):
    """Format datetime in IST with readable format including seconds"""
    if not value:
        return "N/A"
    
    if isinstance(value, datetime.datetime):
        # Convert to IST (UTC + 5:30)
        ist_time = value + datetime.timedelta(hours=5, minutes=30)
        return ist_time.strftime('%d %b %Y, %I:%M:%S %p IST')
    return str(value)

@register.filter
def ist_date(value):
    """Format date in IST"""
    if not value:
        return "N/A"
    
    if isinstance(value, datetime.datetime):
        # Convert to IST (UTC + 5:30)
        ist_time = value + datetime.timedelta(hours=5, minutes=30)
        return ist_time.strftime('%d %b %Y')
    return str(value)

@register.filter
def ist_time(value):
    """Format time in IST with seconds"""
    if not value:
        return "N/A"
    
    if isinstance(value, datetime.datetime):
        # Convert to IST (UTC + 5:30)
        ist_time = value + datetime.timedelta(hours=5, minutes=30)
        return ist_time.strftime('%I:%M:%S %p IST')
    return str(value)

@register.filter
def ist_short(value):
    """Format datetime in short IST format with seconds"""
    if not value:
        return "N/A"
    
    if isinstance(value, datetime.datetime):
        # Convert to IST (UTC + 5:30)
        ist_time = value + datetime.timedelta(hours=5, minutes=30)
        return ist_time.strftime('%d/%m/%Y %I:%M:%S %p')
    return str(value)