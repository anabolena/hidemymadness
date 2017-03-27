'''
    Hidemymadness.py
    by Matteo Lodi
'''
import re
import csv
import argparse
import time
import socket
import traceback
import requests
from ipaddress import IPv4Address, AddressValueError
from requests.exceptions import ProxyError, Timeout
from pathlib import Path
from bs4 import BeautifulSoup


def main():
    '''
        main function
    '''
    description = ('Extract Hidemyass.com proxy list and export it in a csv file\n'
                   'Test proxies found and select the usable ones\n'
                   'by Matteo Lodi')
    parser = argparse.ArgumentParser(description=description, \
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-e', '--extract', action='store_true', \
                        help='extract proxy list')
    parser.add_argument('-t', '-test', dest='test_site', \
                        help='test proxy list.\nif not used with extraction,'
                        'this needs a csv file in input (default:'
                        '"proxy_list_hidemyass.csv")', default='')
    parser.add_argument('-c', '--ecsv', action='store_true', \
                        help='export extracted proxies in a csv file'
                        ' (default:"proxy_list_hidemyass.csv")')
    parser.add_argument('-C', '--tcsv', action='store_true', \
                        help='export tested proxies in a csv file'
                        ' (default:"usable_proxy_list_hidemyass.csv")')
    parser.add_argument('-o', '--outecsv', dest='export_ecsv', \
                        help='csv file name to export extracted proxies',
                        default='proxy_list_hidemyass.csv')
    parser.add_argument('-O', '--outtcsv', dest='export_tcsv', \
                        help='csv file name to export tested proxies',
                        default='usable_proxy_list_hidemyass.csv')
    parser.add_argument('-i', '--incsv', dest='import_csv', \
                        help='csv file name to import for the test',
                        default='proxy_list_hidemyass.csv')
    parser.add_argument('-T', '--timeout', dest='timeout', \
                        help='set request timeout for the test',
                        default=10, type=int)
    parser.add_argument('-q', '--qty', dest='qty', \
                        help='number of proxies to extract (default:50)',
                        default=50, type=int)
    parser.add_argument('-d', '--debug', action='store_true', \
                        help='add debugging messages')
    args = parser.parse_args()

    list_proxies = []
    if hasattr(args, 'extract') and args.extract:
        list_proxies = extract_proxy_list(args)
        if hasattr(args, 'ecsv') and args.ecsv:
            export_csv_file(args, "extract", list_proxies)
    if hasattr(args, 'test_site') and args.test_site:
        usables_proxies = test_proxies(args, list_proxies)
        if hasattr(args, 'tcsv') and args.tcsv:
            export_csv_file(args, "test", usables_proxies)
    if (not hasattr(args, 'extract') or not args.extract) \
    and (not hasattr(args, 'test_site') or not args.test_site):
        print('You must specify if u want to extract (-e) and/or to test (-t)')
        print(parser.parse_args(['-h']))
        exit(1)


def test_proxies(args, list_proxies):
    '''
        Test proxies with different methods
    '''
    # if i used extract method, i test proxies just found
    if hasattr(args, 'extract') and args.extract:
        proxies_to_test = list_proxies
        info = "Testing proxies just extracted..."
    # else i use a csv file got in input
    else:
        # check if the csv file exists
        csv_file = Path("./{}".format(args.import_csv))
        if not csv_file.is_file():
            print("{} does not exist or it's not\
                  a valid csv file".format(args.import_csv))
            exit(1)
        proxies_to_test = []
        with open(args.import_csv, 'r') as f:
            rdr = csv.reader(f)
            for list_values in rdr:
                ip = list_values[0]
                port = list_values[1]
                nation = list_values[2]
                anonimity = list_values[3]
                el = {'ip': ip, 'port': port, 'nation': nation, 'anonimity': anonimity}
                proxies_to_test.append(el)
        if not proxies_to_test:
            print("No proxies extracted from {}. \
                  Check if the file is corrupted".format(args.import_csv))
            exit(1)
        info = "Using file {} ...".format(args.import_csv)

    # some checks to the site name got in input
    if not args.test_site.startswith('http://'):
        http_site = "http://{}".format(args.test_site)
    else:
        http_site = args.test_site

    print("Start to test proxies: site {}".format(args.test_site))
    print("Timeout is {}s".format(args.timeout))
    print("Checking internet connection....", end='')
    try:
        resp = requests.get(http_site, timeout=10)
    except Exception:
        print("Error! Are u connected to the internet?")
        exit(1)
    print("OK")

    print("BEWARE! TEST RESULTS MAY CHANGE ACCORDING TO THE CHOSEN SITE URL")
    # now test proxies
    usables_proxies = []
    print("{}".format(info))
    for proxy in proxies_to_test:
        print("-"*30)
        print("Testing {ip} {port} {nation} ({anonimity})...".format(**proxy))
        proxy_url = {'http': "http://{ip}:{port}".format(**proxy)}
        is_proxy_usable = True
        can_i_try_trace = False
        methods = ['CLASSIC', 'TUNNEL', 'TRACE']
        for method in methods:
            message = ''
            trace_headers = ''
            trace_message = ''
            status_code = ''
            tic = time.time()
            try:
                # first method: http proxy classic
                if method == 'CLASSIC':
                    resp = requests.get(http_site, proxies=proxy_url,\
                                        timeout=args.timeout)
                    if resp.status_code == 200:
                        message = 'OK'
                        can_i_try_trace = True
                    else:
                        message = 'KO'
                        is_proxy_usable = False
                    status_code = resp.status_code
                # second check: http tunnel via connect method
                elif method == 'TUNNEL':
                    status_code, received = connect_or_trace_attempts(args, proxy, method)
                    if status_code == '200':
                        message = 'OK'
                    else:
                        message = 'KO'
                        is_proxy_usable = False
                # third optional check: http trace method to check header variations
                elif method == 'TRACE' and can_i_try_trace:
                    status_code, received = connect_or_trace_attempts(args, proxy, method)
                    if status_code == '200':
                        message = 'OK'
                        trace_message = 'TRACE RESULT:'
                        #this is to exclude http response useless lines
                        lines = received.split('\n')
                        trace_lines = []
                        for index, line in enumerate(lines):
                            if 'TRACE' in line:
                                trace_lines = lines[index:]
                                cleaned = [line for line in trace_lines\
                                           if line and line not in ('0\r', '\r')]
                        trace_headers = '\n'.join(cleaned)
                    else:
                        message = 'KO'
            except RuntimeError:
                status_code = 'BROKENSOC'
                is_proxy_usable = False
            except ProxyError:
                status_code = 'PROXYERR'
                is_proxy_usable = False
            except Timeout:
                status_code = 'TIMEOUT'
                is_proxy_usable = False
            except socket.timeout:
                status_code = 'TIMEOUT'
                is_proxy_usable = False
            except ConnectionResetError:
                status_code = 'CONRESET'
                is_proxy_usable = False
            except Exception:
                if args.debug: print(traceback.print_exc())
                status_code = 'GENERR'
                is_proxy_usable = False
            toc = time.time()
            timestamp = "{0:.3f}".format(toc-tic)
            dict_format = {
                'status_code': status_code,
                'message': message,
                'timestamp': timestamp,
                'method': method
            }
            final_message = ("{status_code} {message} {timestamp}s"
                             " - HTTP {method}".format(**dict_format))
            if method == 'TRACE':
                if can_i_try_trace and trace_headers:
                    print(final_message, trace_message, trace_headers, sep="\n")
                elif can_i_try_trace and not trace_headers:
                    print(final_message)
            else:
                print(final_message)


        if is_proxy_usable:
            usables_proxies.append(proxy)

    print("Test ended correctly")
    return usables_proxies


def connect_or_trace_attempts(args, proxy, method):
    '''
        This method attempts TRACE or CONNECT HTTP method
    '''
    # open tcp connection
    sock = socket.create_connection((proxy['ip'], proxy['port']),\
                                    timeout=10)
    sock.settimeout(args.timeout)
    if method == 'TUNNEL':
        # try http CONNECT method
        data = ("CONNECT {0} HTTP/1.1\n"
                "Host: {0}\n\n".format(args.test_site))
    elif method == 'TRACE':
        # try http TRACE method
        data = ("TRACE / HTTP/1.1\n"
                "Host: {0}\n\n".format(args.test_site))
    else: raise Exception('impossible')
    if args.debug: print(data)
    sent = sock.send(data.encode())
    if sent == 0: raise RuntimeError
    received = sock.recv(256).decode()
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    if args.debug: print(received)
    #extract http response status_code
    if received.startswith("HTTP/") and len(received) > 12:
        status_code = received[9:12]
    else:
        status_code = '---'
    return status_code, received


def extract_proxy_list(args):
    '''
        Extract proxy list from hidemyass.com
    '''
    print("Extraction running....")
    list_proxies = []
    page = 0
    while len(list_proxies) < args.qty:
        proxies_extracted_this_page = 0
        page += 1
        url = 'http://proxylist.hidemyass.com/{}'.format(page)
        try:
            resp = requests.get(url, timeout=10)
        except Exception:
            print("Error! Are u connected to the internet?")
            exit(1)
        html = resp.content
        soup = BeautifulSoup(html, 'html5lib')
        # extract table rows from the soup
        list_tr = soup.find_all('tr')
        for index, tr in enumerate(list_tr):
            # first row is the header, ignore it
            if index == 0: continue
            # extract columns from rows
            # (this regex WANTS to ignore the first column of the table)
            regex = re.compile('<td(?:\s\w+?\=\".*?\")*>(?:\s*.*?)*<\/td>')
            tr_text = tr.prettify()
            list_td = re.findall(regex, tr_text)
            # cycle every column of the row
            for col, td in enumerate(list_td):
                # first column: ip numbers
                # hardest part of this script: parse ip numbers
                # why? cause they use CSS obfuscation
                if col == 1:
                    # extract hardcoded css
                    regexs = re.compile('<style>(?:\s*.*?)*<\/style>')
                    style = re.findall(regexs, td)
                    # clear the tag
                    regexc = re.compile('<\/*style>')
                    css = re.sub(regexc, '', style[0]).split()
                    list_right_classes = []
                    # extract right classes ("display:inline;")
                    for classe in css:
                        if 'inline' in classe:
                            # random classes name are 4 char long
                            class_name = classe[1:5]
                            list_right_classes.append(class_name)
                    # death regex to bypass CSS obfuscation
                    death = '<(?:span|div)(?:\s\w+?\="(.*?)")*>\s*(\d{1,3}|\.)\s*<\/(?:span|div)>|(\d{1,3})'
                    regexdeath = re.compile(death)
                    style_span = re.findall(regexdeath, td)
                    list_ip_values = []
                    # regex found tuples with 3 groups:
                    # 1-classname or style Attribute
                    # 2-one of the 4 part of the ip number
                    # 3-exceptional case where theres a part of the ip number alone
                    for trythis in style_span:
                        # after a focused check, i found 4 ways to be sure that...
                        # ...a number is a valid one
                        if trythis[0] in list_right_classes \
                        or 'inline' in trythis[0] \
                        or trythis[0].isdigit():
                            list_ip_values.append(trythis[1])
                            continue
                        elif trythis[2]:
                            list_ip_values.append(trythis[2])
                    list_right_ip = []
                    # clean cases where i found a '.' instead of a number
                    for num in list_ip_values:
                        if num != '.': list_right_ip.append(num)
                    # there are exceptional cases where they add some s**t at the....
                    # ...start that makes my engine to find more values than needed
                    # they fall in the 4th right way but in fact they are not right
                    # im clearing them too
                    list_right_ip = list_right_ip[::-1][:4][::-1]
                    # finally i got the ip address... YUP
                    ip = "{0}.{1}.{2}.{3}".format(*list_right_ip)
                    #check if the ip address is a correct one
                    try:
                        IPv4Address(ip)
                    except AddressValueError:
                        print("The program extracted an ip address\
                              not valid: {}. Maybe hidemyass.com changed \
                              the css obfuscation engine...sigh".format(ip))
                        exit(1)

                # second column: port number
                if col == 2:
                    regexp = re.compile('<td(?:\s\w+?\=\".*?\")*>|<\/td>')
                    port = re.sub(regexp, '', td).split()[0]

                # third column: nation name
                if col == 3:
                    regexpnat = re.compile('<img.*?>\s*(.*?)\s*</span>')
                    nation = re.findall(regexpnat, td)[0]

                # seventh column: anonimity level
                if col == 7:
                    anonimity = re.sub(regexp, '', td).split()[0]


            #save the found proxy
            el = {'ip': ip, 'port': port, 'nation': nation, 'anonimity': anonimity}
            list_proxies.append(el)
            proxies_extracted_this_page += 1

            #if i reach the limit...stop
            if len(list_proxies) == args.qty: break

        #if the page is empty, stop the cycle
        if proxies_extracted_this_page == 0: break

    if not list_proxies:
        print("No proxy extracted...???")
        exit(1)
    for proxy in list_proxies:
        print("IP-{ip} PORT-{port} N-{nation} ({anonimity})".format(**proxy))

    print("Extracted {} proxies!".format(len(list_proxies)))
    return list_proxies


def export_csv_file(args, type, list_proxies):
    '''
        export results in a csv file
    '''
    if type == "test":
        filename = args.export_tcsv
        message = "Usable"
    else: # type="extract"
        filename = args.export_ecsv
        message = "Extracted"
    with open(filename, 'w') as f:
        wr = csv.writer(f)
        for proxy in list_proxies:
            wr.writerow([proxy['ip'], proxy['port'], proxy['nation'],\
                         proxy['anonimity']])
    print("{} proxy list exported in file named {}".format(message, filename))


if __name__ == '__main__':
    main()
