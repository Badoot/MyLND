# Argument parser

import argparse


def arg_parser_func():

    # Argparser with help description
    parent_parser = argparse.ArgumentParser(prog='mylnd.py', description="""
    MyLND - A gRPC Client for the Lightning Network Daemon (LND) in Python.""",
                                usage='mylnd.py --argument <value1> <value2> \n'
                                      '\nexample: mylnd.py --addinvoice 100 "for hugs"',
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # Define arguments and actions
    parent_parser.add_argument("--version", help="LND version", action='store_true',
                               dest='lnd_version')
    parent_parser.add_argument("--lnddir", help="Path to LND's base dir", type=str, action='store',
                                dest='lnddir', metavar='</path/to/.lnd>')
    parent_parser.add_argument("--ip_port", help="IP address and port of the LND node", type=str, action='store',
                                dest='ip_port', metavar='<ip_address>:<port>')
    parent_parser.add_argument("--status", help="Same as '--getinfo --walletbalance --channelbalance'",
                               action='store_true')
    parent_parser.add_argument("--macaroonpath", help="Path to admin.macaroon", type=str, action='store',
                                dest='macaroon_path', metavar='</path/to/admin.macaroon>')
    parent_parser.add_argument("--tlspath", help="Path to tls.cert", type=str, action='store',
                                dest='tls_path', metavar='</path/to/tls.cert>')
    parent_parser.add_argument("--genseed", help="Generate mnemonic seed", action='store_true')
    parent_parser.add_argument("--create", help="Initialize a new wallet", action='store_true')
    parent_parser.add_argument("--unlock", help="Unlock wallet", action='store_true')
    parent_parser.add_argument("--change_password", help="Change wallet password", action='store_true')
    parent_parser.add_argument("--walletbalance", help="Wallet balance", action='store_true')

    parent_parser.add_argument("--getinfo", help="Lightning node info", action='store_true')
    parent_parser.add_argument("--networkinfo", help="Lightning network info", action='store_true')
    parent_parser.add_argument("--describegraph", help="All nodes and edges that this node knows about",
                               action='store_true')
    parent_parser.add_argument("--feereport", help="current fee schedule enforced by the node", action='store_true',
                               dest='fee_report')
    parent_parser.add_argument("--openchannel", nargs=3, help="Attempt to open a channel with a remote peer",
                               action='store', dest='openchannel', metavar=('<public_key>', '<local_amount>',
                                                                            '<push_amount>'))
    parent_parser.add_argument("--openchannel-wait", nargs=3,
                               help="Attempt to open a channel with a remote peer and wait for confirmation",
                               action='store', dest='openchannel_wait', metavar=('<public_key>', '<local_amount>',
                                                                            '<push_amount>'))
    parent_parser.add_argument("--closechannel", nargs="*", help="Attempt to close a channel with a remote peer",
                               action='store', metavar=('<channel_point>', '<force>'))
    parent_parser.add_argument("--closeallchannels", help="Attempt to close all open channels", action='store_true')
    parent_parser.add_argument("--listchannels", help="List channels", action='store_true')
    parent_parser.add_argument("--listchannels-detail", help="Details about open channels",
                               action='store_true', dest='listchannels_detail')
    parent_parser.add_argument("--channelinfo", nargs=1, help="Channel details by channel ID", type=int, action='store',
                               dest='channel_info', metavar='<channel_id>')
    parent_parser.add_argument("--pendingchannels", help="Pending channels", action='store_true')
    parent_parser.add_argument("--closedchannels", help="Closed channels", action='store_true')
    parent_parser.add_argument("--channelbalance", help="Channel balance", action='store_true')
    parent_parser.add_argument("--listpeers", help="List peers connected to this node", action='store_true')
    parent_parser.add_argument("--listpeers-detail", help="Details about peers connected to this node",
                               action='store_true', dest='listpeers_detail')
    parent_parser.add_argument("--nodeinfo", nargs=1, help="Node details by pub_key", action='store', dest='node_info',
                               metavar='<public_key>')
    parent_parser.add_argument("--connect", help="Attempt to establish network connection to a remote peer",
                               action='store', dest='connect', metavar='<public_key>@<ip_address>:<port>')
    parent_parser.add_argument("--disconnect", help="Attempt to disconnect from a remote peer",
                               action='store', dest='disconnect', metavar='<public_key>')
    parent_parser.add_argument("--newaddress", help="Create a new np2ksh address", action='store_true')
    parent_parser.add_argument("--sendcoins", nargs=2, help="Send an on-chain bitcoin transaction", action='store',
                               dest='sendcoins', metavar=('<bitcoin_address>', '<amount_in_satoshis>'))
    parent_parser.add_argument("--sendpayment", nargs="*",
                               help="Send satoshis with either a) just a payment_request, or b) a public key, "
                                    "amount, payment hash, and final_cltv_delta from --addinvoice", action='store',
                               dest='sendpayment'
                                )
    parent_parser.add_argument("--transactions", help="Transaction list and counts", action='store_true')
    parent_parser.add_argument("--listpayments", help="List lightning network payments", action='store_true')
    parent_parser.add_argument("--deletepayments", help="Delete all outgoing payments from DB", action='store_true')
    parent_parser.add_argument("--listinvoices", help="List of all invoices in the db", action='store_true')
    parent_parser.add_argument("--addinvoice", nargs="*", help="Add a new invoice", action='store', dest='add_invoice',
                               metavar=('<amount>', '<memo>'))
    parent_parser.add_argument("--lookupinvoice", nargs=1, help="Lookup an invoice by r_hash", action='store',
                               dest='lookup_invoice', metavar='<r_hash>')
    parent_parser.add_argument("--payinvoice", nargs=1, help="Pay an invoice", action='store',
                               metavar='<payment_request>')
    parent_parser.add_argument("--decodepayreq", nargs=1, help="Decode an invoice's payment_request", action='store',
                               metavar='<payment_request>')
    parent_parser.add_argument("--queryroutes", nargs=3,
                               help="Look for x number of routes to a node's public key for y amount of satoshis",
                               action='store', metavar=('<destination_pub_key>', '<amount>', '<number_of_routes>'))

    args = parent_parser.parse_args()
    return args
