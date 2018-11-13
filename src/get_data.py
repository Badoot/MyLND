# Grab the data

import gRPCfiles.rpc_pb2 as ln
import gRPCfiles.rpc_pb2_grpc as lnrpc
import grpc
import os
import src.arg_parser as arg_parser
import codecs

args = arg_parser.arg_parser_func()


''' Default ip:port is localhost:10009'''

if args.ip_port:
    ip_port = args.ip_port
else:
    ip_port = 'localhost:10009'

''' Default data_dir is '.' '''

if args.lnddir:
    lnddir = args.lnddir
else:
    lnddir = '.'


class APICall:

    os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA'
    cert = open(lnddir + '/tls.cert', 'rb').read()

    def metadata_callback(self, callback):
        macaroon = codecs.encode(open(lnddir + '/admin.macaroon', 'rb').read(), 'hex')
        callback([('macaroon', macaroon)], None)

    ssl_creds = grpc.ssl_channel_credentials(cert)
    auth_creds = grpc.metadata_call_credentials(metadata_callback)
    combined_cred = grpc.composite_channel_credentials(ssl_creds, auth_creds)
    channel = grpc.secure_channel(ip_port, combined_cred)
    stub = lnrpc.LightningStub(channel)
    wallet_stub = lnrpc.WalletUnlockerStub(channel)


def get_info():
    response = APICall.stub.GetInfo(ln.GetInfoRequest())
    return response


def get_peers():
    response = APICall.stub.ListPeers(ln.ListPeersRequest())
    return response


def get_channels():
    response = APICall.stub.ListChannels(ln.ListChannelsRequest())
    return response


def get_pending_channels():
    response = APICall.stub.PendingChannels(ln.PendingChannelsRequest())
    return response


def get_wallet_balance():
    response = APICall.stub.WalletBalance(ln.WalletBalanceRequest())
    return response


def get_channel_balance():
    response = APICall.stub.ChannelBalance(ln.ChannelBalanceRequest())
    return response


def get_network_info():
    response = APICall.stub.GetNetworkInfo(ln.NetworkInfoRequest())
    return response


def get_describe_graph():
    request = ln.ChannelGraphRequest()
    response = APICall.stub.DescribeGraph(request)
    return response


def get_closed_channels():
    response = APICall.stub.ClosedChannels(ln.ClosedChannelsRequest())
    return response


def get_transactions():
    response = APICall.stub.GetTransactions(ln.GetTransactionsRequest())
    return response


def get_list_payments():
    response = APICall.stub.ListPayments(ln.ListPaymentsRequest())
    return response


def get_delete_payments():
    response = APICall.stub.DeleteAllPayments(ln.DeleteAllPaymentsRequest())
    return response


def get_channel_info(chan_id):
    response = APICall.stub.GetChanInfo(ln.ChanInfoRequest(chan_id=chan_id))
    return response


def get_node_info(pub_key):
    response = APICall.stub.GetNodeInfo(ln.NodeInfoRequest(pub_key=pub_key))
    return response


def get_new_address():
    response = APICall.stub.NewAddress(ln.NewAddressRequest())
    return response


def get_fee_report():
    response = APICall.stub.FeeReport(ln.FeeReportRequest())
    return response


def get_connect_peer(peer_data):
    data = peer_data.split('@')
    pubkey = str(data[0])
    host = str(data[1])
    ln_address = ln.LightningAddress(pubkey=pubkey, host=host)
    request = ln.ConnectPeerRequest(addr=ln_address, perm=False)
    response = APICall.stub.ConnectPeer(request)
    return response


def get_disconnect_peer(pub_key):
    request = ln.DisconnectPeerRequest(pub_key=pub_key)
    response = APICall.stub.DisconnectPeer(request)
    return response


def get_open_channel(node_pubkey, local_funding_amount=None, push_sat=None):
    pubkey_bytes = codecs.decode(node_pubkey, 'hex')
    request = ln.OpenChannelRequest(
        node_pubkey=pubkey_bytes,
        node_pubkey_string=node_pubkey,
        local_funding_amount=int(local_funding_amount),
        push_sat=int(push_sat)
        # TODO
        # Need to add option to create a private channel
        # If I tried to include the option, every channel was private,
        # even with multiple "private=False" in the different modules. The
        # default is "private=False", so accepting that my code is shit and just
        # forcing that for now.
        #
        # private=bool(private)
    )
    response = APICall.stub.OpenChannelSync(request)
    return response


def get_open_channel_wait(node_pubkey=None, local_funding_amount=0, push_sat=0):
    pubkey_bytes = codecs.decode(node_pubkey, 'hex')
    request = ln.OpenChannelRequest(
        node_pubkey=pubkey_bytes,
        node_pubkey_string=node_pubkey,
        local_funding_amount=int(local_funding_amount),
        push_sat=int(push_sat)
    )
    response = APICall.stub.OpenChannel(request)
    return response


def get_close_channel(funding_tx, output_index, force):
    channel_point = ln.ChannelPoint(
        funding_txid_str=str(funding_tx),
        output_index=int(output_index),
    )
    request = ln.CloseChannelRequest(
        channel_point=channel_point,
        force=force,
        target_conf=None,
        sat_per_byte=None)
    response = APICall.stub.CloseChannel(request)
    return response


def wallet_unlock(password):
    request = ln.UnlockWalletRequest(wallet_password=password.encode())
    response = APICall.wallet_stub.UnlockWallet(request)
    return response


def change_password(current_password, new_password):
    request = ln.ChangePasswordRequest(
            current_password=current_password.encode(),
            new_password=new_password.encode()
            )
    response = APICall.wallet_stub.ChangePassword(request)
    return response


def get_gen_seed():
    request = ln.GenSeedRequest()
    response = APICall.wallet_stub.GenSeed(request)
    return response


def get_create(wallet_password, cipher_seed_mnemonic):
    request = ln.InitWalletRequest(
        wallet_password=wallet_password,
        cipher_seed_mnemonic=cipher_seed_mnemonic)
    response = APICall.wallet_stub.InitWallet(request)
    return response


def get_send_coins(addr, amount):
    request = ln.SendCoinsRequest(
        addr=str(addr),
        amount=int(amount),
    )
    response = APICall.stub.SendCoins(request)
    return response


def get_list_invoices():
    response = APICall.stub.ListInvoices(ln.ListInvoiceRequest())
    return response


def get_add_invoice(amount, memo):
    request = ln.Invoice(
        memo=memo,
        value=amount,
    )
    response = APICall.stub.AddInvoice(request)
    return response


def get_lookup_invoice(r_hash):
    request = ln.PaymentHash(r_hash_str=r_hash)
    response = APICall.stub.LookupInvoice(request)
    return response


def get_send_payment(payment_request, dest, amt, payment_hash_str, final_cltv_delta):
    request = ln.SendRequest(
        payment_request=payment_request,
        dest_string=dest,
        amt=int(amt),
        payment_hash_string=payment_hash_str,
        final_cltv_delta=int(final_cltv_delta)
    )
    response = APICall.stub.SendPaymentSync(request)
    return response


def get_payinvoice(payment_request):
    request = ln.SendRequest(payment_request=payment_request)
    response = APICall.stub.SendPaymentSync(request)
    return response


def get_decode_payreq(payment_request):
    request = ln.PayReqString(pay_req=payment_request)
    response = APICall.stub.DecodePayReq(request)
    return response


def get_query_route(pub_key, amount, num_routes):
    request = ln.QueryRoutesRequest(
        pub_key=pub_key,
        amt=amount,
        num_routes=num_routes,
    )
    response = APICall.stub.QueryRoutes(request)
    return response

