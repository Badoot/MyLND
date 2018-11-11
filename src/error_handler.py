from functools import wraps
import grpc


def error_handler(fnc):
    # Cleaner RPC errors
    @wraps(fnc)
    def wrapper(*args, **kwargs):
        try:
            return fnc(*args, **kwargs)
        except grpc.RpcError as er:
            print('RPC call failed with {0}: {1}'.format(er.code(), er.details()))
            print('\r')
        except (IndexError, ValueError, AttributeError):
            print('What the hell are you doing? \n\nDo you even mylnd, bro? \n\nTry "mylnd.py -h" \n')
    return wrapper
