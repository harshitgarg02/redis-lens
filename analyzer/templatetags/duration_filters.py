from django import template
from datetime import timedelta
import math

register = template.Library()


@register.filter
def format_duration(value):
    """
    Format a timedelta object into a human-readable string.
    
    Args:
        value: datetime.timedelta object
        
    Returns:
        Human-readable duration string
    """
    if not value:
        return "N/A"
    
    if isinstance(value, timedelta):
        total_seconds = int(value.total_seconds())
    else:
        return str(value)
    
    if total_seconds < 60:
        return f"{total_seconds} seconds"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        if seconds > 0:
            return f"{minutes}m {seconds}s"
        return f"{minutes} minutes"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        if minutes > 0:
            return f"{hours}h {minutes}m"
        return f"{hours} hours"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        if hours > 0:
            return f"{days}d {hours}h"
        return f"{days} days"


@register.filter
def format_uptime(seconds):
    """
    Format uptime seconds into a human-readable string.
    
    Args:
        seconds: integer representing uptime in seconds
        
    Returns:
        Human-readable uptime string
    """
    if not seconds or not isinstance(seconds, (int, float)):
        return "N/A"
    
    total_seconds = int(seconds)
    
    if total_seconds < 60:
        return f"{total_seconds} seconds"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        return f"{minutes} minutes"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        if minutes > 0:
            return f"{hours}h {minutes}m"
        return f"{hours} hours"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        if hours > 0:
            return f"{days}d {hours}h"
        return f"{days} days"


@register.filter
def format_bytes(bytes_value):
    """
    Format bytes into human-readable units.
    
    Args:
        bytes_value: integer representing bytes
        
    Returns:
        Human-readable byte string (e.g., "1.5 GB")
    """
    if not bytes_value or not isinstance(bytes_value, (int, float)):
        return "N/A"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            if unit == 'B':
                return f"{int(bytes_value)} {unit}"
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


@register.filter
def percentage(value, total):
    """
    Calculate percentage of value over total.
    
    Args:
        value: numerator
        total: denominator
        
    Returns:
        Percentage as string
    """
    if not total or total == 0:
        return "0%"
    
    try:
        percentage = (float(value) / float(total)) * 100
        return f"{percentage:.1f}%"
    except (ValueError, TypeError):
        return "0%"