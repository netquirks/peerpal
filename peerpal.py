#!/usr/bin/env python3

import json
import urllib.request
import configparser
import sys
import os.path
import argparse


def main():
    try:

        # Obligatory Variables
        ios_neigh_grp_v4 = None
        ios_neigh_grp_v6 = None
        xr_neigh_grp_v4 = None
        xr_neigh_grp_v6 = None
        op_sys = None

        # Optional Variables
        your_asn = None
        peer_asn = None
        password = None
        ttl_sec = False

        config = None
        parser = None
        debugging = False

        def debug(msg):
            if(debugging):
                print('DEBUG: {0:s}'.format(msg))

        parser = argparse.ArgumentParser(description='Peerpal')
        parser_group_main = parser.add_argument_group('Main arguments')
        parser_group_main.add_argument(
            '-d', '--debug-requests',
            action='store_true',
            help='Show debugging output'
                                            )
        parser_group_main.add_argument(
            '-p', '--peer-asn',
            action='store', type=int,
            help='Peer Autonomous System Number'
                                            )
        parser_group_main.add_argument(
            '-l', '--local-asn',
            action='store', type=int,
            help='Local Autononmous System Number'
                                        )
        args = parser.parse_args()
        if(args.peer_asn):
            peer_asn = str(args.peer_asn)
        if(args.local_asn):
            your_asn = str(args.local_asn)
        if(args.debug_requests):
            debugging = True
        debug('Attempting to read config file.')
        if(not os.path.isfile('peerpal.conf')):
            sys.exit('Could not locate config file. Please check '
                     '\'peerpal.conf\' is located in same directory.')
        try:
            config = configparser.ConfigParser()
            config.read('peerpal.conf')

            # Check config file
            for section_name in config.sections():
                for name, value in config.items(section_name):
                    check_config_value(name, value)
            for name, value in config.items('DEFAULT'):
                check_config_value(name, value)

            # Check obligatory fields
            debug('Reading defaults from config.')
            op_sys = config['DEFAULT']['op_sys']
            ios_neigh_grp_v4 = config['DEFAULT']['ios_neigh_grp_v4'].split(',')
            ios_neigh_grp_v6 = config['DEFAULT']['ios_neigh_grp_v6'].split(',')
            xr_neigh_grp_v4 = config['DEFAULT']['xr_neigh_grp_v4']
            xr_neigh_grp_v6 = config['DEFAULT']['xr_neigh_grp_v6']

            # Check optional fields
            if('as' in config['DEFAULT'] and not your_asn):
                your_asn = config['DEFAULT']['as']
            if('ttl_sec' in config['DEFAULT']):
                if(config['DEFAULT']['ttl_sec'].lower() == 'true'):
                    ttl_sec = True
                    debug('ttl-sec being used as a default')
            if('password' in config['DEFAULT']):
                password = config['DEFAULT']['password']
                debug('Default password found')

            # Log the results
            debug('Following defaults detected:')
            debug('Operating Systems: {0:s}'.format(op_sys))
            debug('IOS Neighbor Groups: {0:s}, {1:s}'
                  .format(str(ios_neigh_grp_v4), str(ios_neigh_grp_v6)))
            debug('XR Neighbor Groups: {0:s}, {1:s}'
                  .format(xr_neigh_grp_v4, xr_neigh_grp_v6))
            if(your_asn):
                debug('Autonomous System: {0:s}'.format(your_asn))
            debug('Using TTL Sec: {0:s}'.format(str(ttl_sec)))
        except KeyError as e:
            sys.exit('KeyError reading config file. Check that field '
                     '{0:s} exists in file.'.format(str(e)))
        except configparser.MissingSectionHeaderError:
            sys.exit('Header inaccurate. Check header format and retry.')
        except configparser.ParsingError as e:
            sys.exit('Error Parsing config file: {0:s}'.format(str(e)))
        debug('Config file successful read.')
        if(not your_asn):
            your_asn = ask_for_asn('What is your ASN? ')
        if(not peer_asn):
            peer_asn = ask_for_asn('What is your potential peers ASN? ')

        your_basic_json = get_basic_isp_details(your_asn)
        peer_basic_json = get_basic_isp_details(peer_asn)

        debug('Finding peering information. Standby...')
        debug('Getting Net IDs...')
        your_net_id = str(your_basic_json['data'][0]['id'])
        peer_net_id = str(peer_basic_json['data'][0]['id'])

        debug('Getting full ISP details')
        your_data = get_full_isp_details(your_net_id)['data'][0]
        peer_data = get_full_isp_details(peer_net_id)['data'][0]

        debug('Getting your Companys details.')
        your_name = your_data['name']
        your_irr = your_data['irr_as_set']

        debug('Getting potential Peers details.')
        peer_name = peer_data['name']
        peer_prfx_cnt_v4 = peer_data['info_prefixes4']
        peer_prfx_cnt_v6 = peer_data['info_prefixes6']
        peer_irr = peer_data['irr_as_set']

        your_ix_data = your_data['netixlan_set']
        peer_ix_data = peer_data['netixlan_set']

        # If unable to get IRR information, construct one using AS-name format
        debug('Correcting missing/incorrect information.')
        if(len(your_irr) == 0):
            your_irr = 'AS-' + your_name.replace(" ", "-").upper()

        if(len(peer_irr) == 0):
            peer_irr = 'AS-' + peer_name.replace(" ", "-").upper()

        debug('Getting your Companys IPv4 Exchange Points.')
        your_ix_v4 = get_ix(your_ix_data, 'ipaddr4')

        debug('Getting your Companys IPv6 Exchange Points.')
        your_ix_v6 = get_ix(your_ix_data, 'ipaddr6')

        debug('Getting potential Peers IPv4 Exchange Points.')
        peer_ix_v4 = get_ix(peer_ix_data, 'ipaddr4')

        debug('Getting potential Peers IPv6 Exchange Points.')
        peer_ix_v6 = get_ix(peer_ix_data, 'ipaddr6')

        debug('Determining common exchange points.')
        common_ix_v4 = get_common_ix(your_ix_v4, peer_ix_v4, your_name,
                                     peer_name)
        common_ix_v6 = get_common_ix(your_ix_v6, peer_ix_v6, your_name,
                                     peer_name)

        new_peers_v4 = ask_which_peerings(common_ix_v4, '4', your_name,
                                          peer_name, your_ix_v4,
                                          peer_ix_v4, config, debugging)

        new_peers_v6 = ask_which_peerings(common_ix_v6, '6', your_name,
                                          peer_name, your_ix_v6,
                                          peer_ix_v6, config, debugging)

        if(not len(common_ix_v4) == 0):
            print('\nIPv4 Peerings:\n****************')
            generate_peerings(
                    new_peers_v4, common_ix_v4, '4', your_name,
                    peer_name, your_asn, peer_asn, peer_ix_v4, peer_irr,
                    peer_prfx_cnt_v4, op_sys, ios_neigh_grp_v4,
                    xr_neigh_grp_v4, password, config, ttl_sec, debugging
                            )

        if(not len(common_ix_v6) == 0):
            print('\nIPv6 Peerings:\n****************')
            generate_peerings(
                    new_peers_v6, common_ix_v6, '6', your_name,
                    peer_name, your_asn, peer_asn, peer_ix_v6, peer_irr,
                    peer_prfx_cnt_v6, op_sys, ios_neigh_grp_v6,
                    xr_neigh_grp_v6, password, config, ttl_sec, debugging
                            )

    except ValueError as e:
        raise
        print('ValueError in main method: {0:s}.'.format(e))
    except KeyboardInterrupt:
        sys.exit('\nScript stopped by user.')


def get_basic_isp_details(asn):
    '''
    This function returns a json object from the peering DB based on the
    provided autonomous system number
    '''
    try:
        url = 'https://www.peeringdb.com/api/net?asn={0:s}'.format(asn)
        json_obj = urllib.request.urlopen(url)
        str_json_obj = json_obj.read().decode('utf-8')
        output = json.loads(str_json_obj)
    except urllib.error.HTTPError as e:
        if('404' in str(e)):
            sys.exit('Cannot find ASN number {0:s} on peering DB. '
                     'Please check this and try again'.format(asn))
    except urllib.error.URLError as e:
        sys.exit('Cannot access \'{0:s}\'. Check network connection.'
                 'Detail: {1:s}'.format(url, str(e)))
    return output


def get_full_isp_details(net_id):
    '''
    This function returns a json object from the peering DB based on the
    provided Net ID
    '''
    try:
        url = 'https://www.peeringdb.com/api/net/{0:s}'.format(net_id)
        json_obj = urllib.request.urlopen(url)
        str_json_obj = json_obj.read().decode('utf-8')
        output = json.loads(str_json_obj)
    except urllib.error.HTTPError as e:
        sys.exit('Cannot access \'{0:s}\'. Check network '
                 'connection. Detail: {1:s}'.format(url, str(e)))
    return output


def get_ix_details(net_id):
    '''
    This function returns a json object from the peering DB, detailing the ix
    points, based on the provided net id (which will correspond to an
    organisation)
    '''
    try:
        url = 'https://www.peeringdb.com/api/ix?net_id={0:s}'.format(net_id)
        json_obj = urllib.request.urlopen(url)
        str_json_obj = json_obj.read().decode('utf-8')
        output = json.loads(str_json_obj)
    except urllib.error.HTTPError as e:
        sys.exit('Cannot access \'{0:s}\'. Check network connection.'
                 'Detail: {1:s}'.format(url, str(e)))
    return output


def ask_for_asn(question):
    '''
    Ask for the required ASN and return the result.
    '''
    while(True):
        try:
            # If suggested ASN is 0 then there no default ASN
            result = input(question)
            check_asn_range(int(result))
            return result
        except ValueError:
            print('Must be an integer.')


def get_ix(output, address_type):
    '''
    Query the PeeringDB API and get the Exchange Points. Create a dictionary
    where each Value-Key pair is a string, representing the peeringDB
    designated number of the exchange PLUS a list, comprised of all the IPs at
    that Exchange
    '''
    ix_dict = {}
    for item in output:
        try:
            exchange = str(item['ixlan_id'])
            ip_address = str(item[address_type])
            if(ip_address != 'None'):
                if exchange in ix_dict:
                    ix_dict[exchange].append(ip_address)
                else:
                    ix_dict[exchange] = [ip_address]
        except TypeError as e:
            print('Type Error when getting IX.'
                  'Details {0:s}.'.format(str(e)))
    return ix_dict


def get_ix_name(net, debugging):
    '''
    This function accesses the peering DB API and
    pulls back the 'name' string of a the given IX
    '''
    try:
        url = 'https://www.peeringdb.com/api/ix/{0:s}'.format(net)
        json_obj = urllib.request.urlopen(url)
        str_json_obj = json_obj.read().decode('utf-8')
        output = json.loads(str_json_obj)
        return str(output['data'][0]['name'])
    except urllib.error.HTTPError:
        # If no IX name, construct one with format Exhcange_Nummber_ASN
        if debugging:
            print('DEBUG: Could not find IX name from peeringDB. Setting '
                  'to \'Exchange_Number_{0:s}\''.format(net))
        return ('Exchange_Number_' + net)


def get_common_ix(your_ix, peer_ix, your_name, peer_name):
    '''
    This function compares both your IX list and the potential
    peers IX list and returns a list of the IXs common to both
    '''
    common_ix = []
    for site in your_ix.keys():
        if site in peer_ix.keys():
            common_ix.append(site)
    return common_ix


def ask_which_peerings(common_ix, protocol, your_name, peer_name, your_ix,
                       peer_ix, config, debugging):
    '''
    This function presents the list of common peering points to the user
    (first in IPv4 then in IPv6). The user needs to enter a comma separated
    string indicating the common peering points that they want peerpal to
    generate the config for. This is returned as a list called peer_list
    '''
    if(len(common_ix) == 0):
        print('\n{0:s} and {1:s} have no common IPv{2:s} peering '
              'locations.'.format(your_name, peer_name, protocol))
        return []
    print('\nThe following are the locations where {0:s} and {1:s} have '
          'common IPv{2:s} presence:'.format(your_name, peer_name, protocol))
    print('(IPs for ' + peer_name + ' are displayed)')
    # Interate throught common peering points and display them as numbered list
    for index, location in enumerate(common_ix):
        loc_str = get_ix_name(location, debugging)
        print('{0:1}: {1:s} - {2:s}'.format(index+1, check_ix_correction(
              config, loc_str, debugging), ','.join(peer_ix[location])))
    while(True):
        try:
            peer_list = []
            input_peer_list = str(input(
                'Please enter comma-separated list of desired '
                'peerings (e.g. 1,3,5) or enter \'n\' not to '
                'peer over IPv{0:s}: '.format(protocol)))
            if(input_peer_list == 'n'):
                return peer_list
            indices_of_peers = input_peer_list.split(',')
            for peer in indices_of_peers:
                peer_number = int(peer) - 1
                if(peer_number < 0):
                    raise IndexError
                peer_list.append(str(common_ix[peer_number]))
            if(len(peer_list) != len(set(peer_list))):
                print('Error. Entry includes duplicates.')
            else:
                return peer_list
        except ValueError:
            print('Error. Comma separated values must be integers.')
        except IndexError:
            print('Error. Numbers must be one of the options listed above.')


def check_ix_correction(config, ix_name, debugging):
    '''
    Creates the Exchange name to see if there
    is an override correction in the config file.
    '''
    if(ix_name in config):
        if('correction' in config[ix_name]):
            if(debugging):
                print('DEBUG: {0:s} has been corrected to {1:s} as per config '
                      'file'.format(ix_name, config[ix_name]['correction']))
            return config[ix_name]['correction']
    return ix_name


def generate_peerings(new_peers, common_ix, protocol, your_name, peer_name,
                      your_asn, peer_asn, peer_ix, peer_irr,
                      peer_prefix_count, op_sys, ios_neigh_grp,
                      xr_neigh_grp, password, config, ttl_sec, debugging):
    '''
    This function generates the CLI output
    required to configure the desired peerings.
    '''
    underline = '============================================================='
    try:
        for index, location in enumerate(new_peers):
            loc_str = get_ix_name(location, debugging)
            print('\nThe {0:s} IPv{1:s} peerings are as follows:\n{2:s}'
                  .format(check_ix_correction(config, loc_str, debugging),
                          protocol, underline))
            for address in peer_ix[location]:
                # Check the config file for the matching IX and set variables
                if(loc_str in config):
                    if('as' in config[loc_str]):
                        asn = config[loc_str]['as']
                    else:
                        asn = your_asn
                    if('op_sys' in config[loc_str]):
                        op_sys = config[loc_str]['op_sys']
                    if(op_sys == 'xr' or op_sys == 'both'):
                        xr_neigh_grp = config[loc_str]['xr_neigh_grp_v'
                                                       + protocol]
                    if(op_sys == 'ios' or op_sys == 'both'):
                        ios_neigh_grp = config[loc_str]['ios_neigh_grp_v'
                                                        + protocol].split(',')
                    if('password' in config[loc_str]):
                        password = config[loc_str]['password']
                        if(password == 'default' and 'password' in
                           config['DEFAULT']):
                            password = config['DEFAULT']['password']
                    if('ttl_sec' in config[loc_str]):
                        if(config[loc_str]['ttl_sec'].lower() == 'true'):
                            ttl_sec = True
                        else:
                            ttl_sec = False
                    if('routers' in config[loc_str]):
                        print('\n---\nCopy config to these routers:')
                        router_list = config[loc_str]['routers'].split(',')
                        for hostname in router_list:
                            print(hostname)
                else:
                    print('IX not in config file. Using default values.')
                    asn = your_asn
                if(op_sys == 'xr' or op_sys == 'both'):
                    print('\nXR CONFIG\n----------')
                    print('router bgp {0:s}'.format(asn))
                    print(' neighbor {0:s}'.format(address))
                    print('  remote-as {0:s}'.format(peer_asn))
                    print('  use neighbor-group {0:s}'
                          .format(xr_neigh_grp))
                    if(password):
                        print('  password {0:s}'.format(password))
                    if(ttl_sec):
                        print('  ttl-security')
                    print('  description {0:s}'.format(peer_irr
                          .replace(' ', '_')))
                    print('  address-family ipv{0:s} unicast'
                          .format(protocol))
                    print('   maximum-prefix {0:d} 90 restart 60'
                          .format(max(10, peer_prefix_count)))
                if(op_sys == 'ios' or op_sys == 'both'):
                    print('\nIOS CONFIG\n----------')
                    print('router bgp {0:s}'.format(asn))
                    print(' neighbor {0:s} remote-as {1:s}'
                          .format(address, peer_asn))
                    print(' neighbor {0:s} description {1:s}'
                          .format(address, peer_irr.replace(' ', '_')))
                    if(len(ios_neigh_grp) == 1):
                        print(' neighbor {0:s} peer-group {1:s}'
                              .format(address, ios_neigh_grp[0]))
                    else:
                        print(' neighbor {0:s} inherit peer-session {1:s}'
                              .format(address, ios_neigh_grp[0]))
                    if(password):
                        print(' neighbor {0:s} password {1:s}'
                              .format(address, password))
                    if(ttl_sec):
                        print(' neighbor {0:s} ttl-security hops 1'
                              .format(address))
                    print(' address-family ipv{0:s} unicast'.format(protocol))
                    print('  neighbor {0:s} activate'.format(address))
                    print('  neighbor {0:s} maximum-prefix {1:d} 90 restart 60'
                          .format(address, max(10, peer_prefix_count)))
                    if(len(ios_neigh_grp) == 2):
                        print('  neighbor {0:s} inherit peer-policy {1:s}'
                              .format(address, ios_neigh_grp[1]))

                # Reset to defaults in config file
                if(debugging):
                    print('DEBUG: Reseting to defaults')
                if('as' in config['DEFAULT']):
                    asn = config['DEFAULT']['as']
                xr_neigh_grp = config['DEFAULT']['xr_neigh_grp_v' + protocol]
                ios_neigh_grp = config['DEFAULT']['ios_neigh_grp_v'
                                                  + protocol].split(',')
                op_sys = config['DEFAULT']['op_sys']
                if('password' in config['DEFAULT']):
                    password = config['DEFAULT']['password']
                else:
                    password = None
                if('ttl_sec' in config['DEFAULT']):
                    if(config['DEFAULT']['ttl_sec'].lower() == 'true'):
                        ttl_sec = True
                    else:
                        ttl_sec = False
                if('password' in config['DEFAULT']):
                    password = config['DEFAULT']['password']
                else:
                    password = None

    except KeyError as e:
        print('KeyError when generating peerings: {0:s}'.format(e))


def check_asn_range(as_number):
    '''
    Make sure an ASN given in both a number and in the range of public ASNs
    '''
    try:
        asn = int(as_number)
        if((asn >= 64496 and asn <= 65535) or asn <= 0 or
           asn >= 4200000000 or asn == 23456):
            sys.exit('Error. AS must be valid and public.')
    except ValueError:
        sys.exit('Error. AS must be a number')


def check_config_value(name, value):
    if(' ' in str(value).strip()):
        sys.exit('Values in config cannot contain spaces. '
                 'Check \'{0:s}\''.format(value))
    if(name == 'ttl_sec'):
        value = value.lower()
        if(not(value == 'true' or value == 'false')):
            sys.exit('Error. ttl security must be either '
                     '\'true\' or \'false\'')
    if(name == 'as'):
        check_asn_range(value)
    if(name == 'op_sys'):
        value = value.lower()
        if(not(value == 'xr' or value == 'ios' or value == 'both')):
            sys.exit('Error. op_sys must be \'ios\', \'xr\' or \'both\'')
    if(name == 'ios_neigh_grp_v4' or name == 'ios_neigh_grp_v6'):
        neigh_grp_list = value.split(',')
        if(not(len(neigh_grp_list) == 1 or len(neigh_grp_list) == 2)):
            sys.exit('ios_neigh_grp v4 or v6 must be a list of length'
                     ' 1 or 2')
        for group in neigh_grp_list:
            if(' ' in str(group).strip()):
                sys.exit('Values in config cannot contain spaces.'
                         'Check \'{0:s}\''.format(value))


if __name__ == "__main__":
    main()
