# MyLND

    A gRPC Client for Lightning Network Daemon (LND) in Python

# Setup

    1. Install Python 3 (apt-get install python3)
    2. Install pip3 (apt-get install python3-pip)
    3. git clone https://github.com/Badoot/MyLND.git
    4. pip3 install grpcio grpcio-tools googleapis-common-protos pandas
    5. If you don't already have a wallet, please use 'lncli create' to create a new wallet (for now).
    6. Copy *.macaroon and tls.cert from your LND node to --lnddir ('.' by default)
       or --macaroonpath and --tlspath on your local machine.

# Usage

    usage: mylnd.py --argument <value1> <value2>
    
    example: mylnd.py --addinvoice 100 "for hugs"
    
        MyLND - A gRPC Client for the Lightning Network Daemon (LND) in Python.
    
    optional arguments:
      -h, --help            show this help message and exit
      --version             LND version
      --lnddir </path/to/.lnd>
                            Path to LND's base dir
      --ip_port <ip_address>:<port>
                            IP address and port of the LND node
      --status              Same as '--getinfo --walletbalance --channelbalance'
      --macaroonpath </path/to/admin.macaroon>
                            Path to admin.macaroon
      --tlspath </path/to/tls.cert>
                            Path to tls.cert
      --genseed             Generate mnemonic seed
      --create              Initialize a new wallet
      --unlock              Unlock wallet
      --change_password     Change wallet password
      --walletbalance       Wallet balance
      --getinfo             Lightning node info
      --networkinfo         Lightning network info
      --describegraph       All nodes and edges that this node knows about
      --feereport           current fee schedule enforced by the node
      --openchannel <public_key> <local_amount> <push_amount>
                            Attempt to open a channel with a remote peer
      --openchannel-wait <public_key> <local_amount> <push_amount>
                            Attempt to open a channel with a remote peer and wait
                            for confirmation
      --closechannel [<channel_point> [<force> ...]]
                            Attempt to close a channel with a remote peer
      --closeallchannels    Attempt to close all open channels
      --listchannels        List channels
      --listchannels-detail
                            Details about open channels
      --channelinfo <channel_id>
                            Channel details by channel ID
      --pendingchannels     Pending channels
      --closedchannels      Closed channels
      --channelbalance      Channel balance
      --update_channel_policy <channel_point> <base_fee_msat> <fee_rate> <time_lock_delta>
                            Update the fee schedule and channel policies for a channel
      --listpeers           List peers connected to this node
      --listpeers-detail    Details about peers connected to this node
      --nodeinfo <public_key>
                            Node details by pub_key
      --connect <public_key>@<ip_address>:<port>
                            Attempt to establish network connection to a remote
                            peer
      --disconnect <public_key>
                            Attempt to disconnect from a remote peer
      --newaddress          Create a new np2ksh address
      --sendcoins <bitcoin_address> <amount_in_satoshis>
                            Send an on-chain bitcoin transaction
      --sendpayment <payment_hash> 
      OR
      --sendpayment <public_key> <amount> <payment_hash> <final cltv>
                            Send satoshis with either a payment_request,
                            or a public key, amount, payment hash, and
                            final_cltv_delta from --addinvoice
      --transactions        Transaction list and counts
      --listpayments        List lightning network payments
      --deletepayments      Delete all outgoing payments from DB
      --listinvoices        List of all invoices in the db
      --addinvoice [<amount> [<memo> ...]]
                            Add a new invoice
      --lookupinvoice <r_hash>
                            Lookup an invoice by r_hash
      --payinvoice <payment_request>
                            Pay an invoice
      --decodepayreq <payment_request>
                            Decode an invoice's payment_request
      --queryroutes <destination_pub_key> <amount> <number_of_routes>
                            Look for x number of routes to a node's public key for
                            y amount of satoshis

# Examples
    
    root@bobuntu:~# mylnd-danny --status
    
    My Lightning Node:
    ------------------
    identity_pubkey: "036b7debe9fc4e79fb7349c9d3e3d8f53abcc2ec9e5be3d8835c17c8a4954708e8"
    alias: "Danny"
    num_active_channels: 2
    num_peers: 2
    block_height: 4308
    block_hash: "197769a8d4c900b5b56edacdcf1a4554656755c4c372c64576dfae3c68be4dd2"
    synced_to_chain: true
    chains: "bitcoin"
    best_header_timestamp: 1541190855
    version: "0.5.0-beta commit=v0.5-beta-153-g1b0d8e8f13359d361cd957d2a18bf8d2801c6c86"
       
    
    Wallet Balance:
    ---------------
    total_balance: 5104055303
    confirmed_balance: 5104055303
    
    
    Channel Balance:
    ----------------
    balance: 125900

    
    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    root@bobuntu:/python/MyLND# mylnd-danny --pendingchannels
    
    Pending Channels:
    -----------------
    total_limbo_balance  :  237983
    
    
    Pending open:
    --------------
    remote_node_pub :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    channel_point :  492e600ce9617f7e817fae23cf7d3cd0f7849a671d7a942e8ba12118c7cd9a56:0
    capacity :  50000
    local_balance :  30950
    remote_balance :  10000
    
    remote_node_pub :  03d25ac3598492ba8a82d224d69aef635b5838890cb6dad9cd9391a141b823d918
    channel_point :  adf15924bb035aca77a2145bfe45eb054bbe3091409a8cae921c7ae67a0a5ef9:1
    capacity :  12341241
    local_balance :  12330960
    remote_balance :  1231
    
    
    Pending forced closing:
    ----------------------
    closing_txid  :  bda213d4318aa1682b54e2af6a0f3d4d44ae6f8bfe9981c3c4ce93c60525d8c7
    limbo_balance  :  113184
    maturity_height  :  9345
    blocks_til_maturity  :  45
    remote_node_pub  :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    channel_point  :  e89283eb5e4eae8e536353b7e109e53f4e9f876051f4b8bedba0d4c3dde1c7a2:0
    capacity  :  122234
    local_balance  :  113184
    
    closing_txid  :  7161e390ed23a62f634ebdcc840ea269870e4bd5b2196c27ba10e87834383f7a
    limbo_balance  :  10850
    maturity_height  :  9345
    blocks_til_maturity  :  45
    remote_node_pub  :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    channel_point  :  c16e688d4666a6c10f08075527b091a62dda0b162b0ab0832de436fa71a5d4d9:0
    capacity  :  20000
    local_balance  :  10850
    
    
    Pending close:
    --------------
    remote_node_pub  :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    channel_point  :  32c69d80b714af8aadd7c917caba4e1d680813f123d59c7d783790e5283587a2:0
    capacity  :  123123
    local_balance  :  113949
    limbo_balance  :  113949


     +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   
    root@bobuntu:~# mylnd --listpeers

    Peers: 3 total
    ---------------
    
    address          alias    pub_key                                                             bytes_recv bytes_sent ping_time
    127.0.0.1:10011  Alice    03d25ac3598492ba8a82d224d69aef635b5838890cb6dad9cd9391a141b823d918  49192      95788      255
    127.0.0.1:10013  Charlie  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f  168406     164733     4154
    127.0.0.1:10012  Bob      02ac3a63b851a0171524015bfd496f81ea6786c77af401a2c778586733b59fd554  96468      117087     230
    
    root@bobuntu:~# mylnd --listpeers-detail
    
    Peers: 3 total
    ---------------
    
    alias :  Alice
    color :  #3399ff
    last_update :  1541488788
    address :  127.0.0.1:10011
    bytes_recv :  49218
    bytes_sent :  95814
    ping_time :  152
    pub_key :  03d25ac3598492ba8a82d224d69aef635b5838890cb6dad9cd9391a141b823d918
    num_channels : 0
    total_capacity : 0
    
    alias :  Charlie
    color :  #3399ff
    last_update :  1541567703
    address :  127.0.0.1:10013
    bytes_recv :  168406
    bytes_sent :  164733
    ping_time :  4154
    pub_key :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    num_channels : 0
    total_capacity : 0
    
    alias :  Bob
    color :  #3399ff
    last_update :  1541567781
    address :  127.0.0.1:10012
    bytes_recv :  96468
    bytes_sent :  117087
    ping_time :  230
    pub_key :  02ac3a63b851a0171524015bfd496f81ea6786c77af401a2c778586733b59fd554
    num_channels : 0
    total_capacity : 0

    
     +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    
    root@bobuntu:~# mylnd --listchannels
    
    Channels: 2 total
    ------------------
    
    active capacity chan_id           channel_point                                                       commit_fee commit_weight  csv_delay fee_per_kw local_balance remote_balance remote_pubkey
    True    200000   4863139929718785  1f3b5f89897f21a6a265537ed43c3477f777db4168eaacfa1d9fce4c4c7f18fc:1  9050       724           144        12500      100000        90950          03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    True    200000   4863139929784321  cd74aed20423a889827b9ec3e5d8195164b9d295c4c6e2dd39544c3aaee63429:1  9050       724           144        12500      100000        90950          03d25ac3598492ba8a82d224d69aef635b5838890cb6dad9cd9391a141b823d918
    
    root@bobuntu:~# mylnd --listchannels-detail
    
    Channels: 2 total
    ------------------
    
    Remote Node : Charlie
    active :  True
    capacity :  200000
    chan_id :  4863139929718785
    channel_point :  1f3b5f89897f21a6a265537ed43c3477f777db4168eaacfa1d9fce4c4c7f18fc:1
    commit_fee :  9050
    commit_weight :  724
    csv_delay :  144
    fee_per_kw :  12500
    local_balance :  100000
    remote_balance :  90950
    last_update :  1541454641
    node1_pub :  02ac3a63b851a0171524015bfd496f81ea6786c77af401a2c778586733b59fd554
    node2_pub :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
    node1_policy :  {'time_lock_delta': 144, 'min_htlc': '1000', 'fee_base_msat': '1000', 'fee_rate_milli_msat': '1'}
    node2_policy :  {'time_lock_delta': 144, 'min_htlc': '1000', 'fee_base_msat': '1000', 'fee_rate_milli_msat': '1'}
    
    Remote Node : Alice
    active :  True
    capacity :  200000
    chan_id :  4863139929784321
    channel_point :  cd74aed20423a889827b9ec3e5d8195164b9d295c4c6e2dd39544c3aaee63429:1
    commit_fee :  9050
    commit_weight :  724
    csv_delay :  144
    fee_per_kw :  12500
    local_balance :  100000
    remote_balance :  90950
    last_update :  1541454641
    node1_pub :  02ac3a63b851a0171524015bfd496f81ea6786c77af401a2c778586733b59fd554
    node2_pub :  03d25ac3598492ba8a82d224d69aef635b5838890cb6dad9cd9391a141b823d918
    node1_policy :  {'time_lock_delta': 144, 'min_htlc': '1000', 'fee_base_msat': '1000', 'fee_rate_milli_msat': '1'}
    node2_policy :  {'time_lock_delta': 144, 'min_htlc': '1000', 'fee_base_msat': '1000', 'fee_rate_milli_msat': '1'}


    root@bobuntu:/python/MyLND# mylnd --channelinfo 4868637487857664
    
    Channel Details:
    ----------------
    channel_id :  4868637487857664
    chan_point :  0cbfed6f585261aff04f28b1bfdd5040c79b1d3824e5e31488f205be7322a873:0
    last_update :  1541456059
    Node 1 :
      last_update  :  1541454686
      pub_key  :  036b7debe9fc4e79fb7349c9d3e3d8f53abcc2ec9e5be3d8835c17c8a4954708e8
      alias  :  Danny
      color  :  #3399ff
    Node 2 :
      last_update  :  1541454686
      pub_key  :  03a98291d7938e7d4df15bdf7e77acd24c0bdefe685a9d419446df58cb13a86c2f
      alias  :  Charlie
      color  :  #3399ff
    capacity :  200000
    Node 1 Policy :
      time_lock_delta  :  144
      min_htlc  :  1000
      fee_base_msat  :  1000
      fee_rate_milli_msat  :  1
    Node 2 Policy :
      time_lock_delta  :  144
      min_htlc  :  1000
      fee_base_msat  :  1000
      fee_rate_milli_msat  :  1


     +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


    root@bobuntu:/python/MyLND# mylnd-danny --addinvoice 500 'for hugs'
    
    Adding Invoice:
    ----------------
    Amount in sats : 500
    Memo : for hugs
    
    r_hash : b32488d3aad8cdb310082b28ffb590dfd8bd97a1892624d523f86c806c024afb
    payment_request : lnsb5u1pd73mhepp5kvjg35a2mrxmxyqg9v50ldvsmlvtm9ap3ynzf4frlpkgqmqzftasdqdvehhygrgw4nhxcqzys5v5ay6
    4wrvjx5sdrjyt9qnt3sq684tnm3w8jjdglvqzz53p2kr9qpxeyfvdzf3z8flfvx6tgydg9nwvlsqm9cpdv7ftezmv3smd5sscq5hfvzg
    
    
    
    root@bobuntu:/python/MyLND# mylnd-danny --lookupinvoice b32488d3aad8cdb310082b28ffb590dfd8bd97a1892624d523f86c806c024afb
    
    Invoice Details:
    ----------------
    memo  :  for hugs
    r_preimage :  5c73fa315418c04f507bcc2649d7c3bd6fbf9da44c14ae381f3ca9834e25b261
    r_hash_hex : b32488d3aad8cdb310082b28ffb590dfd8bd97a1892624d523f86c806c024afb
    value  :  500
    creation_date  :  1541992185
    payment_request  :  lnsb5u1pd73mhepp5kvjg35a2mrxmxyqg9v50ldvsmlvtm9ap3ynzf4frlpkgqmqzftasdqdvehhygrgw4nhxcqzys5v5ay6
    4wrvjx5sdrjyt9qnt3sq684tnm3w8jjdglvqzz53p2kr9qpxeyfvdzf3z8flfvx6tgydg9nwvlsqm9cpdv7ftezmv3smd5sscq5hfvzg
    expiry  :  3600
    cltv_expiry  :  144
    
    
    
    root@bobuntu:/python/MyLND# mylnd-alice --decodepayreq lnsb5u1pd73mhepp5kvjg35a2mrxmxyqg9v50ldvsmlvtm9ap3ynzf4frlpk
    gqmqzftasdqdvehhygrgw4nhxcqzys5v5ay64wrvjx5sdrjyt9qnt3sq684tnm3w8jjdglvqzz53p2kr9qpxeyfvdzf3z8flfvx6tgydg9nwvlsqm9
    cpdv7ftezmv3smd5sscq5hfvzg
    
    Payment request details:
    ------------------------
    destination: "036b7debe9fc4e79fb7349c9d3e3d8f53abcc2ec9e5be3d8835c17c8a4954708e8"
    payment_hash: "b32488d3aad8cdb310082b28ffb590dfd8bd97a1892624d523f86c806c024afb"
    num_satoshis: 500
    timestamp: 1541992185
    expiry: 3600
    description: "for hugs"
    cltv_expiry: 144
    
    
    
    root@bobuntu:/python/MyLND# mylnd-alice --payinvoice lnsb5u1pd73mhepp5kvjg35a2mrxmxyqg9v50ldvsmlvtm9ap3ynzf4frlpkgqm
    qzftasdqdvehhygrgw4nhxcqzys5v5ay64wrvjx5sdrjyt9qnt3sq684tnm3w8jjdglvqzz53p2kr9qpxeyfvdzf3z8flfvx6tgydg9nwvlsqm9cpdv
    7ftezmv3smd5sscq5hfvzg
    
    Invoice Payment Request :
    -------------------------
    destination: "036b7debe9fc4e79fb7349c9d3e3d8f53abcc2ec9e5be3d8835c17c8a4954708e8"
    payment_hash: "b32488d3aad8cdb310082b28ffb590dfd8bd97a1892624d523f86c806c024afb"
    num_satoshis: 500
    timestamp: 1541992185
    expiry: 3600
    description: "for hugs"
    cltv_expiry: 144
    
    Do you agree to send this payment?
    y
    
    Invoice Payment Receipt :
    -------------------------
    payment_preimage  :  5c73fa315418c04f507bcc2649d7c3bd6fbf9da44c14ae381f3ca9834e25b261
    total_time_lock  :  9717
    total_fees  :  2
    total_amt  :  502
    hops :
      chan_id  :  6770792603910144
      chan_capacity  :  500000
      amt_to_forward  :  501
      fee  :  1
      expiry  :  9573
      amt_to_forward_msat  :  501000
      fee_msat  :  1000
    total_fees_msat  :  2000
    total_amt_msat  :  502000
    
