import dns.resolver
import requests
from textwrap3 import dedent

def banner():
    banner = dedent(f"""\

    ███████ ███████ ███    ██ ████████ ██ ███    ██ ███████ ██      
    ██      ██      ████   ██    ██    ██ ████   ██ ██      ██      
    ███████ █████   ██ ██  ██    ██    ██ ██ ██  ██ █████   ██      
         ██ ██      ██  ██ ██    ██    ██ ██  ██ ██ ██      ██      
    ███████ ███████ ██   ████    ██    ██ ██   ████ ███████ ███████  Website Analyzer - V 1.0                                                      
    """)
    print(banner)

def Check_request(ip):
    whois_url = "https://stat.ripe.net/data/whois/data.json?data_overload_limit=ignore&resource={}".format(ip)
    r = requests.get(whois_url)
    data = r.json()
    return data

def Get_ip_list(domain):
    answers = dns.resolver.resolve(domain, 'A')
    ip_list = []
    for rdata in answers:
        ip_list.append(rdata.to_text())
    return ip_list    

def main():
    domain = input('[?] What is the domain : ')
    ip_list = Get_ip_list(domain)
    for item in ip_list:
        print("[{}] {}".format(ip_list.index(item) + 1,item))

    user_select = input('[?] Which one do you want to check ? ')
    if int(user_select) > len(ip_list):
        raise Exception("[!] Selected item is not in the results")
    else:
        ip = ip_list[int(user_select) - 1]
        json_res = Check_request(ip)
        # Values that we want to show
        records = json_res['data']['records'][0]
        irr_records = json_res['data']['irr_records'][0]
        ASN_lookup = ip_ASN = modification = creation = country = ip_range = provider = provider_descr = "No data available"
        for item in records:
            if item['key'] == 'inetnum': ip_range = item['value']
            elif item['key'] == 'netname': provider = item['value']
            elif item['key'] == 'descr': provider_descr = item['value']
            elif item['key'] == 'country': country = item['value']
            elif item['key'] == 'created': creation = item['value']
            elif item['key'] == 'last-modified': modification = item['value']
        for item in irr_records:
            if item['key'] == 'origin':
                ip_ASN = "AS" + item['value']
                ASN_lookup = item['details_link']   
        banner()         
        massage = dedent(f"""\
            -------------------- Sentinel Automated Report --------------------
            [~] Show smart analyze for : {ip} which belongs to {domain}
            [*] Provider of Website : {provider}
            [*] Provider Description : {provider_descr}
            [*] Country of the provider : {country}
            [*] Full ip range : {ip_range}
            [*] ASN : {ip_ASN}
            [*] ASN Lookup link : {ASN_lookup}
            [*] Creation date : {creation}
            [*] Last modification date : {modification}
        """)
        print(massage)


if __name__ == "__main__":
    main()
