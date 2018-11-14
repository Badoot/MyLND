# Handle errors in more entertaining ways

from functools import wraps
import grpc


def error_handler(fnc):
    # Cleaner error output
    @wraps(fnc)
    def wrapper(*args, **kwargs):
        try:
            return fnc(*args, **kwargs)
        except grpc.RpcError as er:
            print('\ngRPC error: {0}: {1}'.format(er.code(), er.details()))
            print('\r')
        except (IndexError, ValueError, AttributeError, NameError, TypeError, SyntaxError):
            print('\nWhat the hell are you doing? \n\nDo you even mylnd, bro? \n\nTry: mylnd.py -h\n')
    return wrapper
