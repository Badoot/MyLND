#!/usr/bin/env python3

# MyLND main

import out_data as output
import arg_parser as arg_parser
import getpass
import os
from error_handler import error_handler 


@error_handler
def run_it():
    
    # First, parse those arguments
    args = arg_parser.arg_parser_func()
   

    # # # # # # # # # #
    #   My LND node
    # # # # # # # # # #

    if args.version:
        output.out_version()

    if args.status:
        output.out_get_info()
        output.out_wallet_balance()
        output.out_channel_balance()
        output.out_btcusd()

    if args.getinfo:
        output.out_get_info()

    if args.fee_report:
        output.out_fee_report()

    # # # # # # # # # # # # # # # # #
    #     Lightning Network Info
    # # # # # # # # # # # # # # # # #

    if args.networkinfo:
        output.out_network_info()

    if args.describegraph:
        output.out_describe_graph()

    # TODO
    # This returns like it works, but tailing the
    # logs shows no change whatsoever
    if args.debug_level:
        show = bool(args.debug_level[0])
        level_spec = args.debug_level[1]
        output.out_debug_level(show, level_spec)

    # # # # # # # # # # # # # # #
    #   On-chain transactions
    # # # # # # # # # # # # # # #

    if args.sendcoins:
        addr = args.sendcoins[0]
        amount = args.sendcoins[1]
        output.out_sendcoins(addr, amount)

    if args.transactions:
        output.out_txns()

    if args.walletbalance:
        output.out_wallet_balance()

    if args.newaddress:
        output.out_new_address()

    # # # # # # # # # #
    #       Peers
    # # # # # # # # # #

    if args.listpeers:
        output.out_list_peers()

    if args.node_info:
        pub_key = args.node_info
        output.out_node_info(pub_key)

    if args.connect:
        peer_data = args.connect
        output.out_connect_peer(peer_data)

    if args.disconnect:
        pub_key = args.disconnect
        output.out_disconnect_peer(pub_key)

    # # # # # # # # # #
    #     Channels
    # # # # # # # # # #

    if args.listchannels:
        output.out_list_channels()

    if args.closedchannels:
        output.out_closed_channels()

    if args.channelbalance:
        output.out_channel_balance()

    if args.pendingchannels:
        output.out_pending_channels()

    if args.channel_info:
        chan_id = args.channel_info[0]
        output.out_channel_info(chan_id)

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

    if args.update_channel_policy:
        # Build channel point
        chan_point = args.update_channel_policy[0]
        funding_tx,output_index = chan_point.split(':')
        # Other options
        base_fee_msat = int(args.update_channel_policy[1])
        fee_rate = float(args.update_channel_policy[2])
        time_lock_delta = int(args.update_channel_policy[3])
        output.out_update_channel_policy(
            funding_tx = funding_tx,
            output_index = output_index,
            base_fee_msat = base_fee_msat,
            fee_rate = fee_rate,
            time_lock_delta = time_lock_delta
        )

    # # # # # # # # # # # # # # # #
    #      Lightning Payments
    # # # # # # # # # # # # # # # #

    if args.listpayments:
        output.out_list_payments()

    if args.deletepayments:
        output.out_delete_payments()

    # Add an empty invoice for 0 sats with '--addinvoice 0'
    if args.add_invoice:
        if len(args.add_invoice) == 1:
            amount = int(args.add_invoice[0])
            memo = ""
            output.out_add_invoice(amount, memo)
        elif len(args.add_invoice) == 2:
            amount = int(args.add_invoice[0])
            memo = str(args.add_invoice[1])
            output.out_add_invoice(amount, memo)
        else:
            output.out_add_invoice(amount=0, memo="")

    if args.lookup_invoice:
        r_hash = args.lookup_invoice[0]
        output.out_lookup_invoice(r_hash)

    if args.listinvoices:
        output.out_list_invoices()

    if args.sendpayment:
        if len(args.sendpayment) == 1:
            payment_request = args.sendpayment[0]
            output.out_send_payment(payment_request, dest=None, amt=None, payment_hash_str=None, final_cltv_delta=None)
        else:
            payment_request = None
            dest = args.sendpayment[0].encode()
            amt = int(args.sendpayment[1])
            payment_hash_str = args.sendpayment[2]
            final_cltv_delta = int(args.sendpayment[3])
            output.out_send_payment(payment_request, dest, amt, payment_hash_str, final_cltv_delta)

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

    # # # # # # # # # # # # # # #
    #      Wallet stub stuff
    # # # # # # # # # # # # # # #

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
        # Check for an existing wallet
        walletfile = os.path.isfile(args.lnddir + '/wallet.db')
        if walletfile:
            print('\nWallet already exists... exiting\n')
            exit(1)
        else:
            output.out_create()

    # # # # # # # # # # # # # # # # # # # # 
    #  Conmarketcap.com BTC/USD Converter
    # # # # # # # # # # # # # # # # # # # #

    if args.btcusd:
        output.out_btcusd()

    if args.satstousd:
        satoshis = args.satstousd
        output.out_satstousd(satoshis)


    # # # # # #
    #  Loop 
    # # # # # #

    # Just playing with the new loopd api here... Do not use this on mainnet...
    if args.loop:
        amount = int(args.loop[0])
        # dest = args.loop[1]
        # loop_out_channel = args.loop[1]
        # output.out_loop(amount=amount, dest=dest, loop_out_channel=loop_out_channel)
        output.out_loop(amount=amount)

    return args


# Run it!
run_it()
