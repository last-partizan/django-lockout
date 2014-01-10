"""
Lockout Decorators
"""

from django.utils.functional import wraps
from django.core.cache import cache
from exceptions import LockedOut
from utils import generate_base_key
import settings

def enforce_lockout(function):
    """Wraps the login function to enforce lockout if the max attempts is exceeded.
    """
    @wraps(function)
    def wrapper(request, *args, **kwargs):
        params = []
        ip = request.META.get('HTTP_X_FORWARDED_FOR', None)
        if ip:
            # X_FORWARDED_FOR returns client1, proxy1, proxy2,...
            ip = ip.split(', ')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        params.append(ip)
        if settings.USE_USER_AGENT:
            useragent = request.META.get('HTTP_USER_AGENT', '')
            params.append(useragent)
        
        key = generate_base_key(*params)
        attempts = cache.get(key) or 0
        
        if attempts >= settings.MAX_ATTEMPTS:
            raise LockedOut()
        
        response = function(request, *args, **kwargs)

        if request.method == 'POST':
            login_failed = (
                response and
                not response.has_header('location') and
                response.status_code != 302
            )
            if login_failed:
                try:
                    attempts = cache.incr(key)
                except ValueError:
                    # No such key, so set it
                    cache.set(key, 1, settings.ENFORCEMENT_WINDOW)
                
                # If attempts is max allowed, set a new key with that
                # value so that the lockout time will be based on the most
                # recent login attempt.
                if attempts >= settings.MAX_ATTEMPTS:
                    cache.set(key, attempts, settings.LOCKOUT_TIME)
            
        return response
    return wrapper
