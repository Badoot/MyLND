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
            if er.code() == grpc.StatusCode.UNIMPLEMENTED:
                print('\nError: The RPC service required for this LND function is not running.')
                print('\nPlease restart the lnd service, then try again.\n')
                exit(1)
            else:
                print('\ngRPC error: {0}: {1}'.format(er.code(), er.details()))
                print('\r')
                exit(1)
    return wrapper
