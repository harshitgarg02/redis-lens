# RedisLens Version Information
"""
RedisLens version information
"""
import os
from datetime import datetime

__version__ = "1.0.1"
__version_info__ = tuple(map(int, __version__.split('.')))

# Version metadata
VERSION_MAJOR = __version_info__[0]
VERSION_MINOR = __version_info__[1]
VERSION_PATCH = __version_info__[2]

# Build information (can be overridden by CI/CD via environment variables)
BUILD_DATE = os.getenv('BUILD_DATE')
BUILD_COMMIT = os.getenv('BUILD_COMMIT')
BUILD_BRANCH = os.getenv('BUILD_BRANCH')

# If no build date is provided, use current timestamp for development builds
if not BUILD_DATE:
    BUILD_DATE = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

def get_version():
    """Get the current version string"""
    return __version__

def get_version_info():
    """Get version as tuple (major, minor, patch)"""
    return __version_info__

def get_full_version():
    """Get full version with build info if available"""
    version = __version__
    
    if BUILD_COMMIT:
        version += f"+{BUILD_COMMIT[:8]}"
    
    return version

def get_version_display():
    """Get version for display in UI"""
    return f"v{get_full_version()}"
