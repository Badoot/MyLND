# Argument parser

import argparse


def arg_parser_func():

    # Argparser with help description
    parser = argparse.ArgumentParser(prog='mylnd.py', description="""
    MyLND - A gRPC Client for the Lightning Network Daemon (LND) in Python.""", usage='%(prog)s [options]')
   
    

    # # # # # # # # # #
    #   My LND node
    # # # # # # # # # #
    parser.add_argument("--version", help="LND version", action='store_true', dest='version')
    parser.add_argument("--lnddir", help="Path to LND's base dir", type=str, action='store',
                                dest='lnddir', metavar='</path/to/.lnd>')
    parser.add_argument("--ip_port", help="IP address and port of the LND node", type=str, action='store',
                                dest='ip_port', metavar='<ip_address>:<port>')
    parser.add_argument("--status", help="Same as '--getinfo --walletbalance --channelbalance'",
                               action='store_true')
    parser.add_argument("--macaroonpath", help="Path to admin.macaroon", type=str, action='store',
                                dest='macaroonpath', metavar='</path/to/admin.macaroon>')
    parser.add_argument("--tlspath", help="Path to tls.cert", type=str, action='store',
                                dest='tlspath', metavar='</path/to/tls.cert>')
    parser.add_argument("--debug_level", nargs=2, help="Logging verbosity of LND", type=str, action='store',
                                dest='debug_level', metavar=('<level>', '<subsystem>'))
    parser.add_argument("--getinfo", help="Lightning node info", action='store_true')
    parser.add_argument("--feereport", help="current fee schedule enforced by the node", action='store_true',
                               dest='fee_report')

    # # # # # # # # # # # # #
    #   Lightning Network
    # # # # # # # # # # # # #

    parser.add_argument("--networkinfo", help="Lightning network info", action='store_true')
    parser.add_argument("--describegraph", help="All nodes and edges that this node knows about", 
                        action='store_true')

    # # # # # # # # # # #
    #       Peers
    # # # # # # # # # # #

    parser.add_argument("--listpeers", help="List peers connected to this node", action='store_true')
    parser.add_argument("--listpeers-detail", help="Details about peers connected to this node",
                               action='store_true', dest='listpeers_detail')
    parser.add_argument("--nodeinfo", nargs="?", help="Node details by pub_key", action='store', dest='node_info',
                               metavar='<public_key>')
    parser.add_argument("--connect", help="Attempt to establish network connection to a remote peer",
                               action='store', dest='connect', metavar='<public_key>@<ip_address>:<port>')
    parser.add_argument("--disconnect", help="Attempt to disconnect from a remote peer",
                               action='store', dest='disconnect', metavar='<public_key>')

    # # # # # # # # # # # #
    #       Channels
    # # # # # # # # # # # #

    parser.add_argument("--openchannel", nargs=3, help="Attempt to open a channel with a remote peer",
                               action='store', dest='openchannel', metavar=('<public_key>', '<local_amount>',
                                                                            '<push_amount>'))
    parser.add_argument("--openchannel-wait", nargs=3,
                               help="Attempt to open a channel with a remote peer and wait for confirmation",
                               action='store', dest='openchannel_wait', metavar=('<public_key>', '<local_amount>',
                                                                            '<push_amount>'))
    parser.add_argument("--closechannel", nargs="*", help="Attempt to close a channel with a remote peer",
                               action='store', metavar=('<channel_point>', '<force>'))
    parser.add_argument("--closeallchannels", help="Attempt to close all open channels", action='store_true')
    parser.add_argument("--listchannels", help="List channels", action='store_true')
    parser.add_argument("--channelinfo", nargs=1, help="Channel details by channel ID", type=int, action='store',
                               dest='channel_info', metavar='<channel_id>')
    parser.add_argument("--pendingchannels", help="Pending channels", action='store_true')
    parser.add_argument("--closedchannels", help="Closed channels", action='store_true')
    parser.add_argument("--channelbalance", help="Channel balance", action='store_true')
    parser.add_argument("--updatechannel", nargs=4, help="Update fee schedule and channel policies "
                        "for a particular channel", action='store', dest="update_channel_policy", 
                        metavar=('<channel_point>', '<base_fee_msat', '<fee_rate>', '<time_lock_delta>'))

    # # # # # # # # # # # # # # # # # # # #
    #     Lightning Network Payments
    # # # # # # # # # # # # # # # # # # # #

    parser.add_argument("--sendpayment", nargs="*",
                               help="Send satoshis with either a) just a payment_request, or b) a public key, "
                                    "amount, payment hash, and final_cltv_delta from --addinvoice", action='store',
                               dest='sendpayment')
    parser.add_argument("--listpayments", help="List lightning network payments", action='store_true')
    parser.add_argument("--deletepayments", help="Delete all outgoing payments from DB", action='store_true')
    parser.add_argument("--listinvoices", help="List of all invoices in the db", action='store_true')
    parser.add_argument("--addinvoice", nargs="*", help="Add a new invoice", default=0, action='store', dest='add_invoice',
                        metavar=('<amount>', '<memo>'))
    parser.add_argument("--lookupinvoice", nargs=1, help="Lookup an invoice by r_hash", action='store',
                               dest='lookup_invoice', metavar='<r_hash>')
    parser.add_argument("--payinvoice", nargs=1, help="Pay an invoice", action='store',
                               metavar='<payment_request>')
    parser.add_argument("--decodepayreq", nargs=1, help="Decode an invoice's payment_request", action='store',
                               metavar='<payment_request>')
    parser.add_argument("--queryroutes", nargs=3,
                               help="Look for x number of routes to a node's public key for y amount of satoshis",
                               action='store', metavar=('<destination_pub_key>', '<amount>', '<number_of_routes>'))

    # # # # # # # # # # # # # # # #
    #   On-chain Transactions
    # # # # # # # # # # # # # # # #

    parser.add_argument("--walletbalance", help="Wallet balance", action='store_true')
    parser.add_argument("--newaddress", help="Create a new np2ksh address", action='store_true')
    parser.add_argument("--sendcoins", nargs=2, help="Send an on-chain bitcoin transaction", action='store',
                               dest='sendcoins', metavar=('<bitcoin_address>', '<amount_in_satoshis>'))
    parser.add_argument("--transactions", help="Transaction list and counts", action='store_true')

    # # # # # # # # # # # # #
    #   Wallet stub stuff
    # # # # # # # # # # # # #

    parser.add_argument("--create", help="Initialize a new wallet", action='store_true')
    parser.add_argument("--unlock", help="Unlock wallet", action='store_true')
    parser.add_argument("--change_password", help="Change wallet password", action='store_true')

    # # # # # # # # # # # # # # # # # # # # 
    #  Conmarketcap.com BTC/USD Converter
    # # # # # # # # # # # # # # # # # # # #

    parser.add_argument("--btcusd", help="Current BTC/USD Conversion Rate", action='store_true')
    parser.add_argument("--satstousd", help="Convert # of sats to USD", action='store')

    # # # # # 
    # Loop
    # # # # #

    parser.add_argument("--loop", nargs="*", help="Loop Out", action='store')

    args = parser.parse_args()
    return args
