---
layout: post
title: Week 12 - The Great Firewall of China - Part 1
tags: [year-of-hacking, china, censorship]
---
I had a bit of free time on my hands last summer, so I occupied myself by going through and learning absolutely everything I could about the Great Firewall of China. This ended up being one of the three countries I hastily presented on at the [BYU Cybersecurity Symposium](https://www.youtube.com/watch?v=2V60P2w1C9o) in February, the other two being Egypt and Russia. I have since forgotten all of the information, mostly because I wasn't nearly as good at digesting papers and information as I am now. In an effort to rectify that, I'm codifying my notes instead of using handwritten versions in various OneNotes scattered in my cloud storage.

For part one of this series, I'll be doing a literature re-review of the papers I marked as the most important to the academic community's understanding of the Great Firewall. I hope to continue this work in the future. I've spun up an Elastic Compute instance in Beijing through Ali Baba Cloud that I'll running experiments on. This is part of a larger effort to examine how software has shaped diplomacy, particularly with private hacking tools like Pegasus and the proliferation of dual-use technology like Artificial Intelligence and advanced cryptography.

The Great Firewall is a censorship program managed by the Cyberspace Administration of China meant to prevent Chinese citizens from accessing external services. I study Arabic, not Chinese so I'll not theorize on the reason for going through such tremendous effort to restrict the internet for China's citizens. However, it is often brought up in discussions online that Deng Xiaoping, Mao Zedong's successor, has been quoted with saying "If you open the window for fresh air, you have to expect some flies to blow in." Perhaps there is a larger cultural context that I am missing, so I won't take the words a man who died 27 years ago as load-bearing, even if he was the leader of China more than a decade.

I'll start out by giving a rough timeline of our understanding of the Great Firewall of China through the lens of academic papers, then at the end I'll dump all of my notes, including my thoughts, opinions, and a quick summary on each paper.

## 2006

[Ignoring the Great Firewall of China](https://www.cl.cam.ac.uk/~rnc1/ignoring.pdf) by Richard Clayton, Steven J. Murdoch, and Robert N. M. Watson proposes a technique for circumventing censorship by exploiting the fact that the Great Firewall only ends a connection by signaling to both the client and the server to stop any connection using a TCP segment with the RST flag enabled, and doesn't actually drop packets. If both the server and the client ignore the TCP RST flag, data transfer can still happen. The paper presents a simple command (`iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP`) that makes a Linux machine practically immune to this form of TCP censorship, but does not help with the DNS censorship that is described in later papers. The paper also proves that the firewall reacts the same to inbound as outbound traffic.

## 2014

[Towards a Comprehensive Picture of the Great Firewall's DNS Censorship](https://www.usenix.org/system/files/conference/foci14/foci14-anonymous.pdf) by anonymous authors focuses on exclusively the DNS censorship portion of the firewall. It shows that the DNS portion of the firewall is 99.9% effective, with something only about 80 DNS resolvers of 150 thousand active in China slipping through the of the wall. It proved that the DNS injectors lie at the borders of Chinese internet, and do not execute DNS censorship within China. It also constructed a blocked keyword list, albeit in English.

# 2018

[Automatically Generating a Large, Culture-specific Blocklist for China](https://www.usenix.org/system/files/conference/foci18/foci18-paper-hounsel.pdf) by Austin Hounsel, Prateek Mittal, and Nick Feamster introduces a method for doing just that. They architected a system that takes an existing list of blocked websites, extracts the most important information from those websites, uses that information as a web search query, then adds any of the resulting websites to the block list. The cycle repeats, filling out with more blocked domains with each iteration. This system is also able to parse Chinese-language content, which gives it a leg up on previous domain-based censorship detection systems that could only process English content.

The paper presents a list of the top ten one, two, and three word phrases (technically n-grams, not phrases) that were most frequently present on blocked sites. The one word blocklist contains mostly names like 王岐山 (Wang Qishan) a close political ally of Xi Jinping, and 李洪志 (Li Hongzhi), founder of the Falun Gong. The two and three word blocklist contain much more complex ideas. Common phrases used in political reporting like: 声明的反共产主义 (Declared anti-Communist), 采取暴力镇压 to (violently crackdown), 非法 拘留 (illegal detention), and 中共 威胁 (Chinese Communists threaten). There are also sensitive topics that the CCP has shown a desire to erase from history like 天安 门广 场示威 (Tienanmen Square Demonstrations) and 1989 民主 运动 (1989 democracy movement), as well as more current topics that are likely placed in conjunction with criticism, like 香港 政 治 (Hong Kong Politics) and 北戴 河 会议 (Beidaihe meeting).

## 2021

Xiangyu Gao, Meikang Qiu, and Meiqin Liu publish [Machine Learning Based Network Censorship](https://ieeexplore.ieee.org/document/9492228) to IEEE. This paper proposes a future extension to the capabilities of a non-specific and hypothetical censorship system to leverage the presumed tendency of a user seeking blocked information to, upon finding the website they are trying to access is blocked, attempt to find the "bad" information on a different site. The firewall could analyze user behavior using a Machine Learning model and draw conclusions on whether the website contains likely blocked information. The system would then use the results to update its ruleset. The paper brings up some practical concerns with overblocking using this method. Extrapolating the average growth rate of the last three years of 25%, China should be exchanging something like 36 Terabits of information a second internationally. It would be incredibly wasteful given the high throughput to expect to monitor and train off of each connection. However, it wouldn't be necessary to run this model on every single connection, as the goal would be to use a small subset of traffic to "improve" the block list used by the entire sample. Doing some back of the napkin architecting, a reasonable setup could be collecting data on a very small percentage of connections, then doing some preprocessing to select only connections to websites that are known to have "bad" content that will be blocked, and then building a list of potentially "bad" websites to be examined later by a human censor.

The troubling part of this paper is that this is totally the "problem" I would love to "solve". It's a unique cat-and-mouse game between well funded defenders and scrappy, young, and resourceful attackers. I don't know which side seems more appealing to be a part of.

That same year, [Understanding the Practices of Global Censorship through Accurate, End-to-End Measurements](https://dl.acm.org/doi/10.1145/3491055) by Lin Jin, Shuai Hao, Haining Wang, and Chase Cotton was published to the ACM conference on Measurement and Analysis of Computing Systems in 2021. The researchers used RIPE Atlas, SOCKS proxies, and VPNs to collect measurements of censorship detection in 177 countries during 2 periods in 2020 and 2021, including China. This paper reveals that between the time of the two measurements, about 13 months, China had gone from censoring 23% of all test domains to 35%, a change of almost 52%. The paper also shows the kinds of content that is most often blocked by Country. China is primarily concerned with blocking access to news, external search tools, and proxies, while Middle Eastern countries like Iran, the United Arab Emirates, and Saudi Arabia, and Israel primarily block news and pornography.

# End of the polished bit

I took a LOT of notes reading these five papers. I would rather make them accessible, even if they're not FDA-approved for human consumption. Below I've copied and pasted my notes for each paper, as well as a quick summarization.

## Ignoring the Great Firewall of China

Boundary router injects forged TCP RST into all subsequent data streams.

3 methods for content blocking:

- _Packet Dropping_: All traffic to IP address is discarded. [4] talks about how complex of a problem that is. Also, [6] discovered that 69.8% of all `.com`, `.org`, and `.net` domains shared an IP with 50 other websites, probably from CDNs.
    
- _DNS Poisoning_: DNS poisoning attack takes place, either no answer is returned, or an incorrect answer is given which redirects to a warning page.
    
- _Content Inspection_: Most expensive option. A proxy will refuse to serve forbidden material. More flexible option is to use an IDS.
    

When testing the the reset behavior, it is revealed that the RST segments come arrive with a TTL of 47 when the target arrives with a TTL of 39, meaning they were generated by different sources. This technique can be used to pinpoint exactly where the censorship is happening in a path.

The paper proposes that there is an off-path censor that will evaluate a packet based off of a keyword search. If a packet is evaluated to be "bad", it will generate 3 TCP RST segments to end the connection. However, the censor does not have the ability to remove the packet from the data stream. There are consequently no guarantees that a single TCP RST segment generated by the censor will arrive after the data gets sent to the target, meaning that it will be ineffective. It is likely that this is the reason for multiple TCP RSTs being transmitted.

They attempted to get an idea of how many parallel censorship systems exist in a path, but failed. They did, however, discover that splitting a "bad" query up between multiple packets was enough to dodge censors.

The setup to ignoring the RST segments the censor sent is deceptively simple. All it requires is a single `iptables` configuration, which drops any inbound TCP segments that have the `RST` flag enabled.

`iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP`

Breaking down this command:

- `iptables`: command line tool to configure Linux kernel network rules and firewall.
    
- `-A INPUT`: Only apply rule to inbound packets
    
- `-p tcp`: Only apply rule to TCP packets
    
- `--tcp-flag RST RST`: Only apply to segments that have the `RST` flag enabled.
    
- `-j DROP`: Action to take when the previous rules are matched.
    

The firewall also sometimes injects `SYN/ACK` segments that, if arrive before the legitimate `SYN/ACK`, will cause the connection to close because of an incorrect `ACK` value. This censorship method is not nearly as trivial to circumvent using tools like `iptables`. Some potential circumvention techniques include changing the behavior of the the kernel to not drop a connection when a malformed `SYN/ACK` segment is reached, but instead, discard it and wait for a new one. I could imagine this being fairly simple to achieve if all the traffic on a client is routed through a proxy, so that no kernel modifications could be made. Or perhaps, there is another simple `iptables` rule that can be implemented.

The paper goes on to discuss strategic considerations for building censorship-dodging systems, including the possibility that the firewall could detect encrypted traffic. It also brings up the practical ramifications of dropping every `RST` segment. As a potential fix, it would be possible to distinguish TCP RSTs coming from the legitimate target as they would have different TTLs. A fix for that would require either a kernel update or specialized software. However, making this behavior default in newer (for 2006) kernel updates would be a reasonable step to take for TCP/IP stack vendors. This paper also clarifies that a fix for this would be simple by updating the RST segment to have the same TTL as the censored packets. This is an interesting demonstration of the arms race that the architects of the firewall and the scrappy developers of anti-censorship workarounds face.

### Thoughts

This paper is old enough to vote. However, it is a milestone in the publicized arms race between firewall architects and people who build technology to dodge censorship, and it correctly predicts that the firewall will increase in complexity by detecting encrypted data. The one line `iptables` command being all it takes to completely circumvent the firewall at this point is still shocking to me, I don't know how I don't remember that from my first time around.

## Towards a Comprehensive Picture of the Great Firewall's DNS Censorship

Published to USENIX Security in 2014.

The background section claims that there are a finite list of "malicious" IPs that are the result of the censors injecting DNS responses when trying to resolve "bad" domains. At that time, it was possible to distinguish between injected and legitimate packets. At the time this paper was authored, the number of malicious IPs numbered 174.

The methodology section mentions the King method, cited in source \[8], to trigger DNS queries indirectly to open resolvers for domain names under our control.

Section four, title "DNS Injection Effectiveness", details how the researchers found all open DNS Resolvers inside China by probing the entire IPv4 address space on UDP port 53, finding those that are consistently reachable, and that MaxMind's GeoIP listed as located in China. This method resulted in about 150k open resolvers. Running the King method, they found that of the 78 resolvers that failed, the majority went to Google's public DNS. It also claims a single resolver operates wholly outside of the purview of the firewall.

In section five, the authors attempt to locate the DNS injectors. The stated goal of the Great Firewall is to prevent foreign websites from being viewed by Chinese citizens, so it would make sense if these expensive and complex censorship systems lived at the boundary of where Chinese backbone cables met foreign cables. However, there was some debate at the time of authorship on if censorship happened within China, as well as traffic from outside China. The authors designed an experiment to settle this debate.

Section six deals with reverse-engineering the GFW rule when censoring DNS replies. Queried about 130 million names constructed by taking the Alexa 1 Million and the zone files for `.com`, `.net`, `.org`, and `.info` and adding the `www` subdomain. From the eight months between August 2013 to April 2014 the number of censored domains increased by about 10%. The data they produced implies that the controllers spend significantly more time adding new keywords to censor than removing previously censored keywords. Using that list of 130 million domains, the researchers were able to use a simple binary search to work out exactly what portion of the domain triggered the block. They extracted 35,332 blocked names 14,495 keywords. The top blocked domains were: `facebook.com`, `twitter.com`, `youtube.com`, `was.info`, `33a.com`, `88sf.com`, `appspot.com`, `kproxy.com`, `mefans.com`, and `sf888.com`.

Section seven attempts to reverse-engineer the structure of a single node in the GFW by selecting a /24 space within China to raise the chances that all of the hosts would by behind the same censor. By triggering the GFW, the researchers were able to glean that there were 4 separate interfaces that injecting poisoned DNS packets. The researchers also were able to reverse engineer the load balancing algorithm at the node.

### Thoughts

This paper established a couple of important ground truths for the academic community to build future experiments upon, at least on the DNS censorship half of the system:

- The Great Firewall only censors at the country's borders, and doesn't do DNS injection censorship within China.
    
- Creating a list of keywords used by the GFW when deciding to censor a packet.
    
- Reverse engineer the architecture of an individual node of the Great Firewall.
    

## Automatically Generating a Large, Culture-specific Blocklist for China

The introduction claims that they improved upon the Filtered-Web method of extracting a block list by using sensitive Chinese phrases, and created and analyzed a list of 1125 previously undiscovered censored domains.

The Background section states that previously constructed block lists are either not available, outdated, are not particular to Chinese culture and language, and are unable to detect newly censored sites.

Natural Language Processing (NLP) is a field that combines linguistic, statistics, and computer science with the goal of processing human language in any medium, but typically in text. According to [this](https://medium.com/@abhishekjainindore24/n-grams-in-nlp-a7c05c1aff12) Medium post by [Abhishek Jain](https://medium.com/@abhishekjainindore24?source=post_page-----a7c05c1aff12--------------------------------), N-grams are "contiguous sequences of 'n' items... These items can be characters, words, or even syllables." These can be unigrams, with single words like "cat" and "dog", bigrams like "machine learning", trigrams like "Chinese Human Rights", ad infinitum. Differentiating between the n of different n-grams is important because the context of a word can greatly change the meaning. For example, plenty of the operators of the Great Firewall wouldn't bat an eye at the mention of "Tiananmen Square", given that it's a famous landmark across the street from China's 2nd most famous landmark. However, mentioning "1989" anywhere near that is sure to draw attention. The paper gives the example of the phrase "Destroy the Communist Party" being parsed as "Destroy", "the", "Communist", "Party" under an approach that doesn't use n-grams. This approach is relatively straightforward to implement for alphabet based languages where individual words are separated by a space like English, Spanish, Arabic, Russian, Hindi et cetera.

The process for creating the block list follows the following steps:

_Step 0_: Start with an initial list of websites that are known to be blocked. This experiment used Citizen Lab's [test-lists](https://github.com/citizenlab/test-lists/blob/master/lists/cn.csv) repository, which at the time of authorship, held 220 websites that were blocked by the GFW. Some of the more notable websites include `falundafa.org`, home page of the Falun Gong, and `whitehouse.gov`.

_Step 1_: Access each website in the list and extract both English and Chinese n-grams (phrases) from the content using Stanford CoreNLP, a commonly used collection of NLP tools.

_Step 2_: Rank each phrase in the website using the TF-IDF technique, comparing against a culturally Chinese-skewed corpus.

_Step 3_: Perform a search query on the most important phrases using a non-censored search engine and collect the search results.

_Step 4_: Test each search result for DNS manipulation within China.

_Step 5_: Update the list of known censored domains with those that show signs of censorship through DNS manipulation.

_Step 6_: Repeat steps 1 through 5 until mixed well. If you can't build your own computer within Chinese borders, store-bought is fine.

This system is an improvement of previous blocklist-building techniques because it both populates the list by "learning" from the contents of each banned site and is able to Chinese-language content.

In this particular experiment, the authors opted to block search results in step 3 from Blogspot, Facebook, Twitter, Youtube, and Tumblr. These sites were already known to be blocked.

Here's the results:

### Thoughts

I'm a big fan of this paper. It introduces a system that can basically autonomously tell what information the Chinese government has an interest in keeping hidden. I kind wish this experiment was running now to see the current list.s

## Machine Learning Based Network Censorship

Page 2 has some ethical justification for this paper's existence.

Section 3 talks about different companies that do what the authors consider censorship:

- Facebook: Suicide prevention on Live and Messenger, detecting if user's are suicidal.
    
- Youtube: Detected 'terrorism related' content.
    
- Twitter: The entire NLP algorithm of Twitter is a form of censorship.
    

"Behavior Analysis" to help with network censorship.

Section 4: Machine learning algorithm leverages the assumption that if a user attempts to access a blocked website, they will attempt to hunt down the information on other websites, informing the algorithm what websites are likely to contain similar blocked information. The paper proposes three possible systems to accomplish the task of seeing if subsequently visited websites should be blocked, a human-based process, a machine-based process, and human-machine teaming

### Thoughts

It is entirely possible that this paper isn't describing the existing state of the Great Firewall, or even a proposed extension to the Great Firewall, but perhaps a system developed for lower throughput private corporate networks. In fact, most high-end commodity firewalls have the ability to automatically block web pages if they relate to broad categories like "Hacking", "Pornography", and "Gambling". This is a highly desirable feature in an enterprise environment, but also is, if my understanding is correct, nearly an accidental bonus feature that is produced when building a system meant to filter out malicious traffic, malware, and network intrusions. However, evidence for this paper being meant to improve corporate firewalls is scant, especially since this paper was funded by *whoever the hell, I'm pretty sure they control the great firewall*. The stated moral justification that does exist in the paper reeks of self-censorship and tongue-biting:

71 percent of respondents agreed that "censorship should exist in some form on the Internet". Sometimes countries block websites that contain topics that are held to be antithetical to accepted societal norms, especially to protect children from being exposed to unsuitable contents. However, in the same survey, 83 percent agree "access to the Internet should be considered as a basic human right", since blocking websites which might be useful to provide content that they want will be really annoying.

Perhaps the dismissive nature that the paper takes to the people on the "Against" side of network censorship is an issue with translating from the authors' native Mandarin to academic English. However, the framing of the issue of censorship ends up having two sides: who protect children from harmful content and those who would be minorly inconvenienced by disrupted access to trivial and unsubstantive information. Maybe this is poor writing, or maybe this framing seeks to remove the conversation of censorship as a system of control completely antithetical to Western-style democracy and subtly displays those who fight for freedom of speech and free flow of information as impatient and demanding, as well as unsympathetic to the instincts of parents to protect their children in favor of easy access to unsubstantive schlock.

In section 3, the authors give three examples of American private companies exercising censorship on their platforms, using the examples of Facebook detecting suicidal behavior to take steps to intervene, Youtube taking down videos related to terrorism, and Twitter using an inherently Natural Language Processing in their algorithm instead of a typical reverse chronological order.

The selection of the actions of these three private American seems to show the author's unwillingness to admit that the most likely use of this work is to stem the free flow of information between borders, rather than prevent suicides or stop terrorists. In the background section, they even introduce the field of Behavioral Analysis using the example of maximizing productivity in a work environment as the exemplary application of the field. This careful selection of a benign and relatively agreeable example could be used to drive any thought of a more sinister use case for the field, particularly in the hands of an authoritarian government.

If I was writing this article thirty years ago, I would have had to sneak into the Berkeley or USF library, physically locate a print or microfilm copy of the IEEE conference proceedings, then sit, digest the paper, and potentially write this post all within the operating hours of the library. Now with the increased openness and approachability of academic resources with modern information technology, papers are under more scrutiny than ever before by both layman and experts. I congratulate Xiangyu Gao of NYU, Meikang Qiu of Texas A&M Commerce, and Meiqin Liu of Zhejiang University for ensuring that their ideas get shared with the world, and writing a fantastic and innovative paper, and I wish them well in their already illustrious academic careers.

While I do not agree with work being done to advance the field of internet censorship, I understand that the Chinese Communist Party will continue to chip away at their perceived problem of inadequate control of free information, regardless of if this paper was made public. I am thankful I live in the world where I have a publicly available academic paper documenting advances in internet censorship that fails to meaningfully address the ethical complexities of the work, instead of the world that has this information sequestered away in internal documentation. I also appreciate the candor that the authors present this information with. It would have been simple to present this work as a "Novel ML-Based Web Filtering Framework" couching the paper entirely in a private enterprise context instead of a national context. The fact that three researchers working with the Chinese government on a national censorship project chose to publish their work to a prestigious American journal without mincing words on their goal to be more palatable to a Western audience, to me, shows the strength of American academic culture, and our comfort with allowing disagreeable and harmful ideas to be subject to the same academic scrutiny that useful and productive ideas are.

## Understanding the Practices of Global Censorship through Accurate, End-to-End Measurements

Published 2021 to ACM Measurement and Analysis of Computing Systems.

This paper is 26 pages, much longer than typical papers in this field.

Establishing a "ground truth" in the context of internet censorship is very difficult as often you need to compare between data sources in multiple countries. This means that attempting to resolve the same domain name in different geographic locations could obtain different IPs. Previous attempts to address this used servers that would repeat bytes received back to the sender, but these don't run on port 80 or 443, the typical ports for HTTP and HTTPS requests. Many censorship systems only check those ports, rendering this particular method useless.

The authors introduce _Disguiser_, a system that uses a control server to be the target of all network requests from various vantage points to be the ground truth. These vantage points will be from RIPE Atlas, a common internet measurement platform, nodes the SOCKS proxy list, and some VPNs. The system removes any responses that are from caches, and achieves an incredibly high accuracy rate of 10^-6 false positive rates.

The paper identifies 3 different censorship techniques, all living at the Application layer, a suite of protocols that deals with application to application communication over a network.

_DNS Blocking_: Blocking DNS requests using RST/FIN injections to end connections.

_HTTP Blocking_: Blocking HTTP requests using RST/FIN injections or dropping requests.

_HTTPS Blocking_: Blocking HTTPS requests based off the domain name sent in the `Client Hello` portion of a TLS negotiation using RST/FIN injections, dropping packets, or injecting a forged certificate.

Section three is a walkthrough of the more technical information of the _Disguiser_ system. It employs different methods for detecting DNS, HTTP, and HTTPS censorship, but each method boils down to knowing what a legitimate, uncensored result looks like, and comparing it to the actual result received experimentally. In order to minimize the impact of cached content in proxies at the boundary point of some networks, the vantage points effectively query a server that changes it's content twice, and if the vantage point receives the same result, a proxy is shown to be present, and that data point is removed. The system also used `traceroute` to detect how many hops through a connection a censor is. `traceroute` increments up the Time to Live (TTL) field of an IP packet that contains censored information. Once the packet reaches a censor, the censorship is triggered.

Section four dives into the data. There were two measurement periods, from April 2020 to May 2020 and June 2021 to August 2021, totaling about 58 million measurements within 177 countries. Of course Iran, China, the United Arab Emirates, and Saudi Arabia made the top four. France was shockingly in fifth. Upon closer inspection this was likely a local censorship implementation, as 4 out of the 159 vantage points within France were triggered. When looking at HTTP censorship, about 52% of censors used a block page, 38% reset the connection, and the remaining 10% let the connection time out. In HTTPS, 82% of censors tore down the connection, 16% timed out, and only 2% injected malicious certificates.

This one has really sick graphics, absolutely give it a look.

### Thoughts

This paper shows that China's censorship system is not the MOST draconian in the world, however I would be incredibly surprised if someone was able to beat Iran in anything with the word "draconian" in it. I did appreciate the enumeration of the different censorship methods by protocol, though I wonder if that list is exhaustive.

# Music from this week

[Sixteen Tons](https://open.spotify.com/track/7oRhPLG0SE4hawbLwVmnZS?go=1&sp_cid=0ac96f7482ca38554f220c9b07346566&utm_source=embed_player_p&utm_medium=desktop&nd=1&dlsi=75fce6c0d4584d32) - Johnny Cash

[Femininomenon](https://open.spotify.com/track/53IRnAWx13PYmoVYtemUBS?go=1&sp_cid=0ac96f7482ca38554f220c9b07346566&utm_source=embed_player_p&utm_medium=desktop&nd=1&dlsi=219e28f27faf497a) - Chappell Roan

[Stuff is Messed Up](https://open.spotify.com/track/3BQmmSfxwwGH8VCvja9uWV?go=1&sp_cid=0ac96f7482ca38554f220c9b07346566&utm_source=embed_player_p&utm_medium=desktop&nd=1&dlsi=59f0fa86b51f4264) - The Offspring

[Te Han Prometido](https://open.spotify.com/track/7Et3UkjbCjRhRaACPBXRQg?go=1&sp_cid=0ac96f7482ca38554f220c9b07346566&utm_source=embed_player_p&utm_medium=desktop&nd=1&dlsi=841a3c7756404854) - Leo Dan
