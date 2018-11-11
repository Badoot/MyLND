#!/usr/local/bin/python3.7

# MyLND main

import src.out_data as output
import src.arg_parser as arg_parser
import getpass
import os
from src.error_handler import error_handler

# First, parse those arguments
args = arg_parser.arg_parser_func()

@error_handler
# Run the option provided
def run_it():

    # LND software info
    if args.lnd_version:
        output.out_version()

    # My LND node info
    if args.getinfo:
        output.out_get_info()

    if args.networkinfo:
        output.out_network_info()

    if args.describegraph:
        output.out_describe_graph()

    if args.listpeers:
        output.out_list_peers()

    if args.listpeers_detail:
        output.out_list_peers_detail()

    if args.listchannels:
        output.out_list_channels()

    if args.listchannels_detail:
        output.out_list_channels_detail()

    if args.closedchannels:
        output.out_closed_channels()

    if args.transactions:
        output.out_txns()

    if args.walletbalance:
        output.out_wallet_balance()

    if args.channelbalance:
        output.out_channel_balance()

    if args.pendingchannels:
        output.out_pending_channels()

    if args.channel_info:
        chan_id = args.channel_info[0]
        output.out_channel_info(chan_id)

    if args.node_info:
        pub_key = args.node_info[0]
        output.out_node_info(pub_key)

    if args.newaddress:
        # Python does not like the type= argument that LND requires for this, so accepting default from LND
        output.out_new_address()

    if args.listpayments:
        output.out_list_payments()

    if args.deletepayments:
        output.out_delete_payments()

    if args.add_invoice:
        amount = int(args.add_invoice[0])
        memo = str(args.add_invoice[1])
        output.out_add_invoice(amount, memo)

    if args.lookup_invoice:
        r_hash = args.lookup_invoice[0]
        output.out_lookup_invoice(r_hash)

    if args.listinvoices:
        output.out_list_invoices()

    if args.fee_report:
        output.out_fee_report()

    if args.connect:
        peer_data = args.connect
        output.out_connect_peer(peer_data)

    if args.disconnect:
        pub_key = args.disconnect
        output.out_disconnect_peer(pub_key)

    if args.openchannel:
        node_pubkey = args.openchannel[0]
        local_funding_amount = int(args.openchannel[1])
        push_sat = args.openchannel[2]
        output.out_open_channel(node_pubkey, local_funding_amount, push_sat)

    if args.openchannel_wait:
        node_pubkey = args.openchannel_wait[0]
        local_funding_amount = int(args.openchannel_wait[1])
        push_sat = args.openchannel_wait[2]
        output.out_open_channel_wait(node_pubkey, local_funding_amount, push_sat)

    if args.closechannel:
        channel_point = str(args.closechannel)
        data = channel_point.split(':')
        funding_tx = str(data[0][2:])
        output_index = (data[1][0])
        force = bool(False)
        if len(args.closechannel) > 1:
            if 'force' in args.closechannel[1]:
                force = bool(args.closechannel[1])
        else:
            force = bool(False)
        output.out_close_channel(funding_tx, output_index, force)

    if args.closeallchannels:
        output.out_close_all_channels()

    if args.sendcoins:
        addr = args.sendcoins[0]
        amount = args.sendcoins[1]
        output.out_sendcoins(addr, amount)

    if args.sendpayment:
        dest = args.sendpayment[0]
        amt = int(args.sendpayment[1])
        r_hash = args.sendpayment[2]
        output.out_send_payment(dest, amt, r_hash)

    if args.payinvoice:
        payment_request = args.payinvoice[0]
        output.out_payinvoice(payment_request)

    if args.decodepayreq:
        payment_request = args.decodepayreq[0]
        output.out_decode_payreq(payment_request)

    if args.queryroutes:
        route_data = args.queryroutes
        pub_key = str(route_data[0])
        amount = int(route_data[1])
        num_routes = int(route_data[2])
        output.out_query_route(pub_key, amount, num_routes)

    if args.status:
        output.out_get_info()
        output.out_wallet_balance()
        output.out_channel_balance()


    # Wallet stub stuff
    def wallet_file_check():
        walletfile = os.path.isfile(args.data_dir + '/wallet.db')
        if walletfile:
            print('\nWallet exists... exiting\n')
            exit(1)


    if args.genseed:
        wallet_file_check()
        output.out_gen_seed()

    if args.change_password:
        current_password = getpass.getpass('Current Password:')
        new_password = getpass.getpass('\nEnter New Password:')
        conf_new_password = getpass.getpass('Confirm New Password:')
        if new_password == conf_new_password:
            output.out_change_password(current_password, new_password)
        else:
            print("\nNew passwords do not match... try again")
            exit(1)

    if args.unlock:
        password = getpass.getpass('Password:')
        output.out_unlock(password)

    if args.create:
        wallet_file_check()
        #  in-progress....
        print('\nPlease use "lncli create"\n')
        exit(0)

run_it()
