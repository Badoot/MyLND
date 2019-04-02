# Argument parser

import argparse


def arg_parser_func():

    # Argparser with help description
    parser = argparse.ArgumentParser(
        prog='mylnd.py', usage='mylnd.py --command [command_option1] [command_option2]',
        description='MyLND - A gRPC Client for the Lightning Network Daemon (LND) in Python.')

    # # # # # # # # # # # # # #
    #  LND Connection Options
    # # # # # # # # # # # # # # 

    rpc_connect = parser.add_argument_group('LND Connection Options')
    rpc_connect.add_argument("--lnddir", help="Path to LND's base dir", type=str, action='store',
                                dest='lnddir', metavar='</path/to/.lnd>')
    rpc_connect.add_argument("--ip_port", help="IP address and port of the LND node", type=str, action='store',
                                dest='ip_port', metavar='<ip_address>:<port>')
    rpc_connect.add_argument("--macaroonpath", help="Path to admin.macaroon", type=str, action='store',
                                dest='macaroonpath', metavar='</path/to/admin.macaroon>')
    rpc_connect.add_argument("--tlspath", help="Path to tls.cert", type=str, action='store',
                                dest='tlspath', metavar='</path/to/tls.cert>')

    # # # # # # # # # #
    #   My LND node
    # # # # # # # # # #
    mynode = parser.add_argument_group('My LND Node')
    mynode.add_argument("--version", help="LND version", action='store_true', dest='version')
 
    mynode.add_argument("--status", help="Same as '--getinfo --walletbalance --channelbalance --btcusd'",
                               action='store_true')
    mynode.add_argument("--debug_level", nargs=2, help="Logging verbosity of LND", type=str, action='store',
                                dest='debug_level', metavar=('<level>', '<subsystem>'))
    mynode.add_argument("--getinfo", help="Lightning node info", action='store_true')
    mynode.add_argument("--feereport", help="current fee schedule enforced by the node", action='store_true',
                               dest='fee_report')

    # # # # # # # # # # # # #
    #   Lightning Network
    # # # # # # # # # # # # #
    lightning_net = parser.add_argument_group('Lightning Network Info')
    lightning_net.add_argument("--networkinfo", help="Lightning network info", action='store_true')
    lightning_net.add_argument("--describegraph", help="All nodes and edges that this node knows about", 
                        action='store_true')

    # # # # # # # # # # #
    #       Peers
    # # # # # # # # # # #
    peers = parser.add_argument_group('Peers')
    peers.add_argument("--listpeers", help="List peers connected to this node", action='store_true')
    peers.add_argument("--nodeinfo", help="Node details by pub_key", action='store', dest='node_info',
                               metavar='<public_key>')
    peers.add_argument("--connect", help="Attempt to establish network connection to a remote peer",
                               action='store', dest='connect', metavar='<public_key>@<ip_address>:<port>')
    peers.add_argument("--disconnect", help="Attempt to disconnect from a remote peer",
                               action='store', dest='disconnect', metavar='<public_key>')

    # # # # # # # # # # # #
    #       Channels
    # # # # # # # # # # # #
    channels = parser.add_argument_group('Channels')
    channels.add_argument("--openchannel", nargs=3, help="Attempt to open a channel with a remote peer",
                               action='store', dest='openchannel', metavar=('<public_key>', '<local_amount>',
                                                                            '<push_amount>'))
    channels.add_argument("--openchannel-wait", nargs=3,
                               help="Attempt to open a channel with a remote peer and wait for confirmation",
                               action='store', dest='openchannel_wait', metavar=('<public_key>', '<local_amount>',
                                                                            '<push_amount>'))
    channels.add_argument("--closechannel", nargs="*", help="Attempt to close a channel with a remote peer",
                               action='store', metavar=('<channel_point>', 'force'))
    channels.add_argument("--closeallchannels", help="Attempt to close all open channels", action='store_true')
    channels.add_argument("--listchannels", help="List channels", action='store_true')
    channels.add_argument("--channelinfo", nargs=1, help="Channel details by channel ID", type=int, action='store',
                               dest='channel_info', metavar='<channel_id>')
    channels.add_argument("--pendingchannels", help="Pending channels", action='store_true')
    channels.add_argument("--closedchannels", help="Closed channels", action='store_true')
    channels.add_argument("--channelbalance", help="Channel balance", action='store_true')
    channels.add_argument("--updatechannel", nargs=4, help="Update fee schedule and channel policies "
                        "for a particular channel", action='store', dest="update_channel_policy", 
                        metavar=('<channel_point>', '<base_fee_msat', '<fee_rate>', '<time_lock_delta>'))

    # # # # # # # # # # # # # # # # # # # #
    #     Lightning Network Payments
    # # # # # # # # # # # # # # # # # # # #
    payments = parser.add_argument_group('Payments')
    payments.add_argument("--sendpayment", nargs="*",
                            help="Send satoshis with either a payment_request, OR public key, payment hash, "
                                "amount, and final_cltv_delta\n", action='store',
                               dest='sendpayment')
    payments.add_argument("--listpayments", help="List lightning network payments", action='store_true')
    payments.add_argument("--deletepayments", help="Delete all outgoing payments from DB", action='store_true')
    payments.add_argument("--listinvoices", help="List of all invoices in the db", action='store_true')
    payments.add_argument("--addinvoice", nargs="*", help="Add a new invoice", action='store', dest='add_invoice',
                        metavar=('<amount>', '<memo>'))
    payments.add_argument("--lookupinvoice", nargs=1, help="Lookup an invoice by payment hash", action='store',
                               dest='lookup_invoice', metavar='<payment_hash>')
    payments.add_argument("--decodepayreq", nargs=1, help="Decode an invoice's payment_request", action='store',
                               metavar='<payment_request>')
    payments.add_argument("--queryroutes", nargs=3,
                               help="Look for x number of routes to a node's public key for y amount of satoshis",
                               action='store', metavar=('<destination_pub_key>', '<amount>', '<number_of_routes>'))

    # # # # # # # # # # # # # # # #
    #   On-chain Transactions
    # # # # # # # # # # # # # # # #
    on_chain = parser.add_argument_group('On-chain')
    on_chain.add_argument("--walletbalance", help="Wallet balance", action='store_true')
    on_chain.add_argument("--newaddress", help="Create a new np2ksh address", action='store_true')
    on_chain.add_argument("--sendcoins", nargs=2, help="Send an on-chain bitcoin transaction", action='store',
                               dest='sendcoins', metavar=('<bitcoin_address>', '<amount_in_satoshis>'))
    on_chain.add_argument("--transactions", help="Transaction list and counts", action='store_true')

    # # # # # # # # # # # # #
    #   Wallet stub stuff
    # # # # # # # # # # # # #
    wallet = parser.add_argument_group('Wallet')
    wallet.add_argument("--create", help="Initialize a new wallet", action='store_true')
    wallet.add_argument("--unlock", help="Unlock wallet", action='store_true')
    wallet.add_argument("--change_password", help="Change wallet password", action='store_true')

    # # # # # # # # # # # # # # # # # # # # 
    #  Conmarketcap.com BTC/USD Converter
    # # # # # # # # # # # # # # # # # # # #
    btcusd = parser.add_argument_group('BTC to USD')
    btcusd.add_argument("--btcusd", help="Current BTC/USD Conversion Rate", action='store_true')
    btcusd.add_argument("--satstousd", help="Convert # of sats to USD", action='store',
                        metavar='<satoshis>')

    # # # # # 
    # Loop
    # # # # #
    loop = parser.add_argument_group('Loop')
    loop.add_argument("--loop", nargs=1, help="Loop Out", action='store', metavar='<amount>')

    args = parser.parse_args()
    return args
