# Reformat return data and print to stdout

import pandas as pd
import get_data as get_data
import codecs
from error_handler import error_handler
import converters as converters
import getpass
import requests


# Pandas dataframe display options
pd.set_option('colheader_justify', 'left')
pd.set_option('display.max_colwidth', -1)

# # # # # # # # # # # # # # # # # # #
#           My LND Node
# # # # # # # # # # # # # # # # # # #


@error_handler
def out_version():
    lnd_ver = get_data.get_info()
    lnd_ver = lnd_ver.version
    print('\nLND Version: ', lnd_ver)
    print('\r')


@error_handler
def out_get_info():
    get_info = get_data.get_info()
    print("\nMy Lightning Node:\n" + "-" * 18)
    print(get_info)


@error_handler
def out_debug_level(show, level_spec):
    debug_level = get_data.get_set_debug_level(show, level_spec)
    print("\nDebug Level:\n" + "-" * 12)
    print(debug_level)


@error_handler
def out_fee_report():
    fee_report = get_data.get_fee_report()
    # Create a list of channel fee responses
    channel_fee_list = []
    for channel_fees in fee_report.channel_fees:
        chan_point = channel_fees.chan_point
        base_fee_msat = channel_fees.base_fee_msat
        fee_per_mil = channel_fees.fee_per_mil
        fee_rate = channel_fees.fee_rate
        channel_fees = [chan_point, base_fee_msat, fee_per_mil, fee_rate]
        channel_fee_list.append(channel_fees)
    if len(channel_fee_list) > 0 :
        # Build dataframe
        channel_fee_columns = [' Channel Point', 'Base Fee mSat', 'Fee Per Mil', 'Fee Rate']
        channel_df = pd.DataFrame(channel_fee_list, 
                    columns=channel_fee_columns).to_string(index=False)
        # day/week/month fee sums at the end
        day_fee_sum = fee_report.day_fee_sum
        week_fee_sum = fee_report.week_fee_sum
        month_fee_sum = fee_report.month_fee_sum
        # Print it
        print("\nFee Report:", '\n' + "-" * 11)
        print(channel_df)
        print('\nDaily Fee Sum :', day_fee_sum)
        print('Weekly Fee Sum :', week_fee_sum)
        print('Monthly Fee Sum :', month_fee_sum)
        print('\r')
    else:
        # If there's no fee dat to report...
        print("No fee data to report")

        
# # # # # # # # # # # # # # # # # # #
#       Lightning Network info
# # # # # # # # # # # # # # # # # # #


@error_handler
def out_network_info():
    net_info = get_data.get_network_info()
    print("\nLightning Network Stats:\n" + "-" * 24)
    print(net_info)


@error_handler
def out_describe_graph():
    describe_graph = get_data.get_describe_graph()
    print(describe_graph)


# # # # # # # # # # # # # # # # # # #
#               Peers
# # # # # # # # # # # # # # # # # # #


@error_handler
def out_connect_peer(peer_data):
    connect_peers = get_data.get_connect_peer(peer_data)
    get_data.get_peers()
    print(connect_peers, '\nPeer connected\n')


@error_handler
def out_disconnect_peer(pub_key):
    disconnect_peer = get_data.get_disconnect_peer(pub_key)
    print(disconnect_peer, '\nPeer disconnected\n')


@error_handler
def out_list_peers():
    peers = get_data.get_peers()
    peers = peers.peers
    # Gather list of peers
    peer_list = []
    for peer in peers:
        pub_key = peer.pub_key
        address = peer.address
        bytes_sent = peer.bytes_sent
        bytes_recv = peer.bytes_recv
        sat_sent = peer.sat_sent
        sat_recv = peer.sat_recv
        inbound = peer.inbound
        ping_time = peer.ping_time
        # Get alias of the remote node
        node_info = get_data.get_node_info(pub_key)
        node_info = converters.response_to_dict(node_info)
        alias = node_info['node']['alias']
        # append this peer to peer_list
        peer = [alias, pub_key, address, bytes_sent, bytes_recv, sat_sent, sat_recv, inbound, ping_time]
        peer_list.append(peer)
    if len(peer_list) > 0:
        # Build DataFrame
        peer_df_columns = [' Alias', ' Public Key', ' Address', 'Bytes Sent', 'Bytes Recv', 'Sats Sent', 'Sats Recv', 'Inbound', 'Ping Time']
        peer_df = pd.DataFrame.from_records(peer_list, columns=peer_df_columns).to_string(index=False)
        # Print it
        print("\nPeers: " + str(len(peer_list)) + " total \n" + "-" * 15)
        print(peer_df, '\n')
    else:
        print('\nNo peers connected\n')

@error_handler
def out_node_info(pub_key):
    node_info = get_data.get_node_info(pub_key)
    node_details = node_info.node
    last_update = converters.convert_date(node_details.last_update)
    pub_key = node_details.pub_key
    alias = node_details.alias
    color = node_details.color
    num_channels = node_info.num_channels
    total_capacity = node_info.total_capacity
    print('\nNode Info')
    print('-' * 9)
    print('Alias :', alias)
    print('Public Key :', pub_key)
    print('Color :', color)
    print('Last Update :', last_update)
    print('Nubmer of Channels :', num_channels)
    print('Total Capacity :', total_capacity)
    print('\r')


# # # # # # # # # # # # # # # # # # #
#           Channels
# # # # # # # # # # # # # # # # # # #


@error_handler
def out_channel_info(chan_id):
    # Query for channel ID
    chan_info = get_data.get_channel_info(chan_id)
    channel_id = chan_info.channel_id
    chan_point = chan_info.chan_point
    last_update = chan_info.last_update
    node1_pub = chan_info.node1_pub
    node2_pub = chan_info.node2_pub
    capacity = chan_info.capacity
    # Node1 Policy
    node1_policy = chan_info.node1_policy
    node1_time_lock_delta = node1_policy.time_lock_delta
    node1_min_htlc = node1_policy.min_htlc
    node1_fee_base_msat = node1_policy.fee_base_msat
    node1_fee_rate_milli_msat = node1_policy.fee_rate_milli_msat
    # Node2 Policy
    node2_policy = chan_info.node2_policy
    node2_time_lock_delta = node2_policy.time_lock_delta
    node2_min_htlc = node2_policy.min_htlc
    node2_fee_base_msat = node2_policy.fee_base_msat
    node2_fee_rate_milli_msat = node2_policy.fee_rate_milli_msat
    # Get aliases for node_1 and node_2
    node1_info = get_data.get_node_info(node1_pub)
    node2_info = get_data.get_node_info(node2_pub)
    node1_info = converters.response_to_dict(node1_info)
    node2_info = converters.response_to_dict(node2_info)
    node1_alias = node1_info['node']['alias']
    node2_alias = node2_info['node']['alias']
    # Channel details
    print("\nChannel Details:", '\n' + "-" * 16)
    print("Channel ID :", channel_id)
    print("Channel Point :", chan_point)
    print("Capacity :", capacity)
    print("Last Update :", converters.convert_date(last_update))
    print('\r')
    # Node1 details
    print("Node1 Alias :", node1_alias)
    print("Node1 Public Key :", node1_pub)
    print("Node1 Policy :")
    print(" Time Lock Delta : ", node1_time_lock_delta)
    print(" Min HTLC :", node1_min_htlc)
    print(" Fee Base mSat :", node1_fee_base_msat)
    print(" Fee Rate Milli mSat :", node1_fee_rate_milli_msat)
    print('\r')
    # Node2 details
    print("Node2 Alias :", node2_alias)
    print("Node2 Public Key :", node2_pub)
    print("Node2 Policy :")
    print(" Time Lock Delta : ", node2_time_lock_delta)
    print(" Min HTLC :", node2_min_htlc)
    print(" Fee Base mSat :", node2_fee_base_msat)
    print(" Fee Rate Milli mSat :", node2_fee_rate_milli_msat)
    print('\r')



@error_handler
def out_list_channels():
    channels = get_data.get_channels()
    channels = channels.channels
    # Build list of channels from RPC response
    channel_list = []
    for channel in channels:
        active = channel.active
        remote_pubkey = channel.remote_pubkey
        channel_point = channel.channel_point
        chan_id = channel.chan_id
        capacity = channel.capacity
        local_balance = channel.local_balance
        remote_balance = channel.remote_balance
        commit_fee = channel.commit_fee
        commit_weight = channel.commit_weight
        fee_per_kw = channel.fee_per_kw
        unsettled_balance = channel.unsettled_balance
        total_satoshis_sent = channel.total_satoshis_sent
        total_satoshis_received = channel.total_satoshis_received
        num_updates = channel.num_updates
        csv_delay = channel.csv_delay
        private = channel.private
        # Get alias of the remote node
        node_info = get_data.get_node_info(remote_pubkey)
        node_info = converters.response_to_dict(node_info)
        alias = node_info['node']['alias']
        # List of fields to include in the output
        channel = [active, private, chan_id, alias, num_updates, capacity, local_balance, remote_balance, unsettled_balance, total_satoshis_received, total_satoshis_sent]
        channel_list.append(channel)
    if len(channel_list) > 0:
        # Build the DataFrame from list of channels
        channels_df_columns = ['Active', 'Private', 'Channel ID', 'Remote Alias', 'Updates', 'Capacity', 'Local Balance', 'Remote Balance', 'Unsettled', 'Sats Received', 'Sats Sent']
        channels_df = pd.DataFrame.from_records(channel_list, columns=channels_df_columns).to_string(index=False)
        # Print it
        print("\nChannels: " + str(len(channel_list)) + " total \n" + "-" * 18)
        print(channels_df, '\n')
    else:
        "\nNo channels open\n"


@error_handler
def out_pending_channels():
    pending = get_data.get_pending_channels()
    pending = converters.response_to_dict(pending)
    if len(pending) == 0:
        print('\nNo pending channels\n')
    else:
        print("\nPending Channels: " + "\n" + "-" * 17)
        for index, pen_type in pending.items():

            # Total limbo balance of all closing channels
            if 'limbo' in index:
                print(index, ' : ', pen_type, '\n')

            # If the pending channel is opening...
            elif 'open' in index:
                # opening = pending['pending_open_channels'][0]['channel']
                print('\nPending open: \n' + "-" * 14)
                for channel in pending['pending_open_channels']:
                    if channel['channel']:
                        channel = channel['channel']
                        for key, value in channel.items():
                            if 'limbo' not in key:
                                print(key + " : ", value)
                    print('\r')

            # If the pending channel is force-closing
            elif 'closing' in index:
                print('\nPending forced closing: \n' + "-" * 22)
                closing = pending['pending_force_closing_channels']
                for channel in closing:
                    for key, value in channel.items():
                        if key != 'channel':
                            print(key, ' : ', value)
                    channel_info = channel['channel']
                    for key, value in channel_info.items():
                        print(key, ' : ', value)
                    print('\r')

            # If the pending channel is closing...
            elif 'close' in index:
                print('\nPending close: \n' + "-" * 14)
                closing = pending['waiting_close_channels'][0]
                for key, value in closing.items():
                    if 'channel' in key:
                        for k, v in value.items():
                            print(k, ' : ', v)
                    else:
                        print(key, ' : ', value)
                print('\r')


@error_handler
def out_channel_balance():
    channel_balance = get_data.get_channel_balance()
    channel_balance_dict = converters.response_to_dict(channel_balance)
    balance = channel_balance.balance
    pending = channel_balance.pending_open_balance
    print("\nChannel Balance:\n" + "-" * 16)
    print("Channel Balance: " + str(balance))
    if balance > 0:
        balance_usd = converters.btc_to_usd(balance)
        print('Total Channel USD Value: $' + str(balance_usd))
    if pending:
        balance_pending = converters.btc_to_usd(pending)
        print("Pending Channel Balance: " + str(pending))
        print('Pending Channel USD Value: $' + str(balance_pending))
    print("\r")


@error_handler
def out_closed_channels():
    closed = get_data.get_closed_channels()
    closed = converters.response_to_dict(closed)
    if len(closed) > 0:
        closed = closed['channels']
        total_closed = str(len(closed))
        print("\nClosed Channels: " + "\n" + "-" * 16)
        for channel in closed:
            for key, value in channel.items():
                print(key, ' : ', value)
            print('\r')
        print(total_closed + " total closed channels\n")
    else:
        print('\nNo closed channels\n')


@error_handler
def out_open_channel(node_pubkey=None, local_funding_amount=0, push_sat=0):
    open_channel = get_data.get_open_channel(node_pubkey, local_funding_amount, push_sat)
    print('\nNew Channel Details:' + '\n' + '-' * 20)
    print('Public Key : ' + node_pubkey)
    print('Local Amount :', local_funding_amount)
    print('Push Amount : ', push_sat)
    print('\r')
    # Convert tx_id to 32-bit hex
    tx_id = codecs.encode(open_channel.funding_txid_bytes, 'hex')
    # Convert tx_id to a string
    tx_id = codecs.decode(tx_id, 'utf-8')
    print('Funding transaction ID :', tx_id, '\n')


@error_handler
def out_open_channel_wait(node_pubkey=None, local_funding_amount=0, push_sat=0):
    request = get_data.get_open_channel_wait(node_pubkey, local_funding_amount, push_sat)
    print('\nNew Channel Details:' + '\n' + '-' * 20)
    print('pubkey : ' + node_pubkey)
    print('localamt : ' + str(local_funding_amount))
    print('pushsat : ' + str(push_sat))
    print('\r')
    for response in request:
        # Pull txid from response
        txid = response.chan_pending.txid
        # Convert txid bytes to hex
        txid_hex = codecs.encode(txid, 'hex')
        # Convert hex to string
        txid_str = codecs.decode(txid_hex, 'utf-8')
        if len(txid) > 5:
            print('Transaction :', txid_str, '\n')
            print('Waiting for 3 confirmations...')
        else:
            print('\nChannel open.\r')
    print('\r')


@error_handler
def out_close_channel(funding_tx, output_index, force):
    request = get_data.get_close_channel(funding_tx, output_index, force)
    print('\nClosing channel : ' + funding_tx + ':' + str(output_index) + '\r')
    for response in request:
        if response.close_pending:
            txid_response = response.close_pending
            txid = txid_response.txid
            txid_hex = codecs.encode(txid, 'hex')
            txid_str = codecs.decode(txid_hex, 'utf-8')
            if len(txid) > 0:
                print('\nTransaction :', txid_str)
                if force:
                    print('\r')
                    exit(0)
                else:
                    continue
            else:
                print('\nChannel closed.\r')
    print('\r')


@error_handler
def out_close_all_channels():
    channel_list = get_data.get_channels()
    channel_list = converters.response_to_dict(channel_list)
    channel_df = pd.DataFrame.from_dict(channel_list)
    if len(channel_df) > 0:
        print('\nClosing ALL channels...' + '\r')
        for channel in channel_df['channels']:

            # Force close each channel
            def force_close_all_channels():
                for key, value in channel.items():
                    if 'point' in key:
                        channel_point = str(value[0:])
                        channel_point = channel_point.split(':')
                        funding_tx = str(channel_point[0])
                        output_index = int(channel_point[1])
                        force = bool(True)
                        request = get_data.get_close_channel(funding_tx, output_index, force)
                        for response in request:
                            if response.close_pending:
                                txid_response = response.close_pending
                                txid = txid_response.txid
                                # print(txid)
                                txid_hex = codecs.encode(txid, 'hex')
                                # print(txid_hex)
                                txid_str = codecs.decode(txid_hex, 'utf-8')
                                if len(txid) > 0:
                                    print('\nTransaction :', txid_str)
                                    if force:
                                        return
                                else:
                                    print('\nChannel closed.\r')
            force_close_all_channels()
        print('\r')
    else:
        print('\nNo channels to close\n')


@error_handler
def out_update_channel_policy(funding_tx, output_index, base_fee_msat, fee_rate, time_lock_delta):
    response = get_data.get_update_channel_policy(funding_tx, output_index, base_fee_msat, fee_rate, time_lock_delta)
    if response:
        print("\nChannel Policy Updated:", '\n' + "-" * 23)
        channel_point = (str(funding_tx) + ':' + str(output_index))
        print('Channel Point : ', channel_point)
        print('Base Fee mSat : ', base_fee_msat)
        print('Fee Rate : ', fee_rate)
        print('Time Lock Delta : ', time_lock_delta)
    print('\r')


# # # # # # # # # # # # # # # # # # #
#       On-chain Transactions
# # # # # # # # # # # # # # # # # # #


@error_handler
def out_new_address():
    new_address = get_data.get_new_address()
    new_address = converters.response_to_dict(new_address)
    print("\nNew Address:", '\n' + "-" * 12)
    print(new_address['address'], '\n')


@error_handler
def out_wallet_balance():
    wallet_balance = get_data.get_wallet_balance()
    total_balance = wallet_balance.total_balance
    confirmed_balance = wallet_balance.confirmed_balance
    print("\nWallet Balance:\n" + "-" * 16)
    print("Total Balance: " + str(total_balance))
    total_usd_value = converters.btc_to_usd(total_balance)
    print('Total USD value: $' + str(total_usd_value))
    print("Confirmed Balance: " + str(confirmed_balance))
    conf_usd_value = converters.btc_to_usd(confirmed_balance)
    print('Confirmed USD value: $' + str(conf_usd_value))
    print("\r")


@error_handler
def out_txns():
    txns = get_data.get_transactions()
    txns = converters.response_to_dict(txns)
    df = pd.DataFrame.from_dict(txns['transactions']).fillna(0)
    # num_confirmations is too long - shorten to 'confs'
    df = df.rename(index=str, columns={'num_confirmations': 'confs'})
    dropcols = ['block_hash']
    df = df.drop(columns=dropcols)
    print("\nTransactions: " + str(len(txns['transactions'])) + " total \n" + "-" * 22)
    # Convert Unix timestamps to readable date/time format
    timestamp_list = []
    for time_stamp in df['time_stamp']:
        time_stamp = converters.convert_date(time_stamp)
        timestamp_list.append(time_stamp)
    df['time_stamp'] = timestamp_list
    df = df[['time_stamp', 'amount', 'tx_hash', 'confs', 'total_fees', 'dest_addresses']]
    txns_df = df.to_string(index=False)
    # Print transactions
    print(txns_df + '\n')
    # Print total tx amounts and fees
    print("Transaction Totals\n" + "-" * 18)

    def sum_totals():
        tx_amt = list(pd.to_numeric(df['amount']))
        amt_sum = 0
        for x in tx_amt:
            amt_sum += x
        return amt_sum

    def fees_totals():
        tx_fee = list(pd.to_numeric(df['total_fees']))
        fee_sum = 0
        for x in tx_fee:
            fee_sum += x
        return fee_sum

    # Print TX totals
    print("Total TX Count : " + str(len(txns['transactions'])))
    print("Total TX Amount : " + str(sum_totals()))
    print("Total TX Fees : " + str(fees_totals()))
    print('\r')


@error_handler
def out_sendcoins(addr, amount):
    response = get_data.get_send_coins(addr, amount)
    print('\n', response)


# # # # # # # # # # # # # # # # # # #
#         Lightning Payments
# # # # # # # # # # # # # # # # # # #


@error_handler
def out_list_payments():
    payments = get_data.get_list_payments()
    payments = converters.response_to_dict(payments)
    if len(payments) > 0:
        print("\nPayments: " + str(len(payments['payments'])), '\n' + "-" * 12)
        payments_df = pd.DataFrame.from_dict(payments['payments']).fillna(0)
        payments_df = payments_df.drop(columns='path')
        # Convert Unix timestamps to readable date/time format
        timestamp_list = []
        for time_stamp in payments_df['creation_date']:
            time_stamp = converters.convert_date(time_stamp)
            timestamp_list.append(time_stamp)
        payments_df['creation_date'] = timestamp_list
        # Convert dataframe to string
        payments_str = pd.DataFrame.to_string(payments_df, index=False)
        print(payments_str)
    else:
        print("\nNo payments to list")
    print("\r")


@error_handler
def out_delete_payments():
    delete_payments = get_data.get_delete_payments()
    print(delete_payments, '\nPayments deleted\n')


@error_handler
def out_list_invoices():
    invoices = get_data.get_list_invoices()
    invoices = converters.response_to_dict(invoices)
    if len(invoices) > 0:
        print("\nInvoices: " + str(len(invoices['invoices'])), '\n' + "-" * 12)
        invoice_list = invoices["invoices"]
        columns = ['creation_date', 'value', 'payment_request']
        invoice_df = pd.DataFrame(invoice_list, columns=columns).fillna(0)
        # Convert Unix timestamps to readable date/time format
        timestamp_list = []
        for time_stamp in invoice_df['creation_date']:
            time_stamp = converters.convert_date(time_stamp)
            timestamp_list.append(time_stamp)
        invoice_df['creation_date'] = timestamp_list
        print(invoice_df.to_string(index=False))
    else:
        print('\nNo invoices to list')
    print("\r")


@error_handler
def out_send_payment(payment_request, dest, amt, payment_hash_str, final_cltv_delta):
    response = get_data.get_send_payment(payment_request, dest, amt, payment_hash_str, final_cltv_delta)
    response_dict = converters.response_to_dict(response)
    print('\nPayment Receipt:' + '\n' + '-' * 16)
    for key, value in response_dict.items():
        if 'payment_preimage' in key:
            preimage_str = value
            # Convert str to bytes
            primage_bytes = codecs.encode(preimage_str, 'utf-8')
            # Decode base64
            preimage_64 = codecs.decode(primage_bytes, 'base64')
            # Encode hex
            preimage_hex = codecs.encode(preimage_64, 'hex')
            # Decode utf-8
            preimage_print = codecs.decode(preimage_hex, 'utf-8')
            print('payment_preimage : ', preimage_print)
        elif 'payment_route' in key:
            print('payment_route :\r')
            for k, v in value.items():
                if 'hops' in k:
                    print(' hops : \r')
                    for k2, v2 in v[0].items():
                        print('  ', k2, ' : ', v2)
                elif 'hops' not in key:
                    print(' ', k, ' : ', v)
            # print(key, ' : ', value)
        else:
            print(key, ' : ', value)
    print('\r')


@error_handler
def out_decode_payreq(payment_request):
    response = get_data.get_decode_payreq(payment_request)
    destination = response.destination
    payment_hash = response.payment_hash
    num_satoshis = response.num_satoshis
    description = response.description
    timestamp = converters.convert_date(response.timestamp)
    expiry = response.expiry
    cltv_expiry = response.cltv_expiry
    print('\nPayment request details:' + '\n' + '-' * 24)
    print("Destination :", destination)
    print("Payment Hash :", payment_hash)
    print("Amount in Satoshis :", num_satoshis)
    print("Timestamp :", timestamp)
    print("Expiry :", expiry)
    print("CLTV Expiry :", cltv_expiry, '\n')


@error_handler
def out_add_invoice(amount, memo):
    response = get_data.get_add_invoice(amount, memo)
    print('\nAdding Invoice:' + '\n' + '-' * 16)
    print('Amount in sats : ' + str(amount))
    print('Memo : ' + str(memo), '\n')
    r_hash = response.r_hash
    payment_request = response.payment_request
    # Convert r_hash to 32-bit hex
    r_hash_hex = codecs.encode(r_hash, 'hex')
    # Convert r_hash to a string
    r_hash_str = codecs.decode(r_hash_hex, 'utf-8')
    print('r_hash (aka payment_hash) :', r_hash_str)
    print('payment_request (aka invoice) :', payment_request)
    print('\r')


@error_handler
def out_lookup_invoice(r_hash):
    response = get_data.get_lookup_invoice(r_hash)
    response_dict = converters.response_to_dict(response)
    r_hash = response.r_hash
    r_preimage = response.r_preimage
    # Convert r_hash to 32-bit hex
    r_hash_hex = codecs.encode(r_hash, 'hex')
    # Convert r_hash to a string
    r_hash_str = codecs.decode(r_hash_hex, 'utf-8')
    # Convert r_preimage to 32-bit hex
    r_preimage_hex = codecs.encode(r_preimage, 'hex')
    # Convert r_preimage to a string
    r_preimage_str = codecs.decode(r_preimage_hex, 'utf-8')
    print('\nInvoice Details:' + '\n' + '-' * 16)
    for key, value in response_dict.items():
        if 'r_hash' in key:
            print('payment_hash :', r_hash_str)
        elif 'r_preimage' in key:
            print('payment_preimage : ', r_preimage_str)
        else:
            print(key, ' : ', value)
    print('\r')


@error_handler
def out_payinvoice(payment_request):
    response = get_data.get_decode_payreq(payment_request)
    print('\nInvoice Payment Request :\n' + '-' * 25)
    print(response)
    print('Do you agree to send this payment? (y/n)')
    answer = input()
    if answer == 'y':
        pay_response = get_data.get_payinvoice(payment_request)
        payment_receipt = converters.response_to_dict(pay_response)
        print('\nInvoice Payment Receipt :\n' + '-' * 25)
        for key, value in payment_receipt.items():
            # Decode base64, encode hex the preimage
            if 'payment_preimage' in key:
                preimage_encoded = str(value).encode()
                preimage_base64_decoded = codecs.decode(preimage_encoded, 'base64')
                preimage_hex = codecs.encode(preimage_base64_decoded, 'hex')
                preimage_str = codecs.decode(preimage_hex, 'utf-8')
                print(key, ' : ', preimage_str)
            elif 'payment_route' in key:
                for k, v in value.items():
                    if 'hops' in k:
                        print('hops : \r')
                        for k2, v2 in v[0].items():
                            print(' ', k2, ' : ', v2)
                    else:
                        print(k, ' : ', v)
            else:
                print(key, ' : ', value)
        print('\r')

    else:
        print('\nOk, cancelling...\n')
        exit(1)


@error_handler
def out_query_route(pub_key, amount, num_routes):
    route_data = get_data.get_query_route(pub_key, amount, num_routes)
    route_data = converters.response_to_dict(route_data)
    print('\n' + str(len(route_data['routes'])) + ' possible routes\n' + '-' * 18 + '\n')
    route_count = 1
    for route in route_data['routes']:
        print('Route ' + str(route_count) + '\n' + '-' * 8)
        route_count += 1
        for key, value in route.items():
            if 'hops' in key:
                print('hops : ')
                for hop_value in value:
                    for k, v in hop_value.items():
                        print(' ', k, ':', v)
            else:
                print(key, ':', value)
        print('\r')


# # # # # # # # # # # # # # # # # # #
#        Wallet Stub Stuff
# # # # # # # # # # # # # # # # # # #

@error_handler
def out_unlock(password):
    get_data.wallet_unlock(password)
    print('\nWallet unlocked!\n')


@error_handler
def out_genseed():
    get_data.get_gen_seed()

@error_handler
def out_change_password(current_password, new_password):
    get_data.change_password(current_password, new_password)
    print('\nPassword changed\n')


@error_handler
def out_create():
    # Establish a password for the new wallet
    def set_wallet_password():
        print('\nPlease enter a new password for this new wallet:\r')
        new_password = getpass.getpass('\nEnter New Password:')
        if len(new_password) < 8:
            print('\n Please use a passwords that is at least 8 characters\n')
            exit(1)
        conf_new_password = getpass.getpass('Confirm New Password:')
        if new_password == conf_new_password:
            password = conf_new_password.encode('utf-8')
            return password
        else:
            print("\nNew passwords do not match... try again\n")
            exit(1)

    # Set 24 word mnemonic recover passphrase
    def set_mnemonic():
        print('\nWould you like to specify your own mnemonic recovery passphrase? (y/n) : ')
        answer = input()
        if answer == 'n':
            # Generate cipher seed
            import get_data
            genseed = get_data.get_gen_seed()
            mnemonic = genseed.cipher_seed_mnemonic
            return mnemonic
        else:
            print('\nPlease enter 24 words with spaces between them :')
            mnemonic = input()
            return mnemonic

    # Set aezeed passphrase
    def set_aezeed_passphrase():
        print('\nWould you like to enter a passphrase to encrypt the cipher seed? (y/n)')
        answer = input()
        if answer == 'y':
            passphrase = getpass.getpass('\nPlease enter a passphrase:')
            passphrase_conf = getpass.getpass('\nPlease confirm passphrase:')
            if passphrase == passphrase_conf:
                passphrase = passphrase.encode('utf-8')
                return passphrase
            else:
                print('\nPassphrases do not match... Please try again:')
                exit(1)

    wallet_password = set_wallet_password()
    cipher_seed_mnemonic = set_mnemonic()
    aezeed_passphrase = set_aezeed_passphrase()

    response = get_data.get_create(wallet_password, cipher_seed_mnemonic, aezeed_passphrase)
    datadf = pd.DataFrame({'listcol': [cipher_seed_mnemonic][0]})
    col1 = datadf[0:6].values[0:, 0]
    col2 = datadf[6:12].values[0:, 0]
    col3 = datadf[12:18].values[0:, 0]
    col4 = datadf[18:24].values[0:, 0]
    print(response)
    print('\rWallet created!\n')
    print('Here is your 24 word mnemonic recovery phrase:\n')
    print('-' * 72)
    print('!!!  You can use this passphrase to recover your wallet, so    !!!')
    print('!!!  make sure to write this down and keep it som eplace safe. !!!')
    print('-' * 72)
    print('\n')
    newdf = pd.DataFrame.from_records([col1, col2, col3, col4])
    newdf = pd.DataFrame.to_string(newdf, index=False, header=False)
    print(newdf)
    print('\n')

# # # # # # # # # # # # # # # # # # # # # 
#  Coinmarketcap.com BTC/USD converter
# # # # # # # # # # # # # # # # # # # # # 

def out_btcusd():
    price = converters.btc_to_usd(100000000)
    print("\nConbase BTC/USD Conversion Rate:\n" + "-" * 31)
    print('1 BTC = ' + '$' + str(price), '\n')


def out_satstousd(satoshis):
    dollar_value = converters.btc_to_usd(satoshis)
    print("\n" + str(satoshis), "sats are currently worth $" + str(dollar_value), "\n")
      

# # # # # # 
#   Loop
# # # # # # 

def out_loop(amount):
    response = get_data.get_loop(amount)
    return response
