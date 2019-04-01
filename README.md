# MyLND

    A gRPC Client for Lightning Network Daemon (LND) in Python

# Setup

    1. Install Python 3 and pip
    2. pip install -r requirements.txt

# Usage

    usage: mylnd.py --command [command_option1] [command_option2]
    
    example: mylnd.py --addinvoice 100 "for hugs"
    
        MyLND - A gRPC Client for the Lightning Network Daemon (LND) in Python.
    
    optional arguments:
    -h, --help            show this help message and exit

    LND Connection Options:
    --lnddir </path/to/.lnd>
                            Path to LND's base dir
    --ip_port <ip_address>:<port>
                            IP address and port of the LND node
    --macaroonpath </path/to/admin.macaroon>
                            Path to admin.macaroon
    --tlspath </path/to/tls.cert>
                            Path to tls.cert

    My LND Node:
    --version             LND version
    --status              Same as '--getinfo --walletbalance --channelbalance
                            --btcusd'
    --debug_level <level> <subsystem>
                            Logging verbosity of LND
    --getinfo             Lightning node info
    --feereport           current fee schedule enforced by the node

    Lightning Network Info:
    --networkinfo         Lightning network info
    --describegraph       All nodes and edges that this node knows about

    Peers:
    --listpeers           List peers connected to this node
    --nodeinfo <public_key>
                            Node details by pub_key
    --connect <public_key>@<ip_address>:<port>
                            Attempt to establish network connection to a remote
                            peer
    --disconnect <public_key>
                            Attempt to disconnect from a remote peer

    Channels:
    --openchannel <public_key> <local_amount> <push_amount>
                            Attempt to open a channel with a remote peer
    --openchannel-wait <public_key> <local_amount> <push_amount>
                            Attempt to open a channel with a remote peer and wait
                            for confirmation
    --closechannel [<channel_point> [force ...]]
                            Attempt to close a channel with a remote peer
    --closeallchannels    Attempt to close all open channels
    --listchannels        List channels
    --channelinfo <channel_id>
                            Channel details by channel ID
    --pendingchannels     Pending channels
    --closedchannels      Closed channels
    --channelbalance      Channel balance
    --updatechannel <channel_point> <base_fee_msat <fee_rate> <time_lock_delta>
                            Update fee schedule and channel policies for a
                            particular channel

    Payments:
    --sendpayment [SENDPAYMENT [SENDPAYMENT ...]]
                            Send satoshis with either a payment_request, OR public
                            key, payment hash, amount, and final_cltv_delta
    --listpayments        List lightning network payments
    --deletepayments      Delete all outgoing payments from DB
    --listinvoices        List of all invoices in the db
    --addinvoice [<amount> [<memo> ...]]
                            Add a new invoice
    --lookupinvoice <payment_hash>
                            Lookup an invoice by payment hash
    --decodepayreq <payment_request>
                            Decode an invoice's payment_request
    --queryroutes <destination_pub_key> <amount> <number_of_routes>
                            Look for x number of routes to a node's public key for
                            y amount of satoshis

    On-chain:
    --walletbalance       Wallet balance
    --newaddress          Create a new np2ksh address
    --sendcoins <bitcoin_address> <amount_in_satoshis>
                            Send an on-chain bitcoin transaction
    --transactions        Transaction list and counts

    Wallet:
    --create              Initialize a new wallet
    --unlock              Unlock wallet
    --change_password     Change wallet password

    BTC to USD:
    --btcusd              Current BTC/USD Conversion Rate
    --satstousd <satoshis>
                            Convert # of sats to USD

    Loop:
    --loop <amount>       Loop Out
