---
layout: post
title:  "Password Cracking in the Cloud with Hashcat and Vast.ai"
date:   2022-03-23 13:04:04 -0500
categories: red-team pentest password-cracking cloud-computing
permalink: /password-cracking-in-the-cloud-with-hashcat-vastai/
---

Cracking hashes with the power of cloud compute is nothing new and there have been several methods to accomplish this over the years. Recently I've been toying around with [Vast.ai](https://vast.ai/) as a cost-effective way to perform password cracking with Hashcat in the cloud. I was very impressed with how simple it was to get up and running compared to some other solutions.

_At the time of this writing_, you can rent 4x 3090s for about $1.5/hr and run through a large wordlist in less than an hour on average (depending on the complexity and hash types you want to crack of course). The prices seem to change depending on availability, geolocation, bandwidth speed, etc. Naturally, it would take around 600 hours of renting these GPUS at $2/hr to reach the MSRP of a single RTX 3090, so I'm very interested in this solution as a cost-effective way to quickly crack a series of hashes.

Vast.ai lets you rent compute by spinning up a docker container image of your choice and giving you SSH access. Some instances have certain limitations or prices on bandwidth, so keep that in mind if you are going to be downloading hundreds of GBs of data to/from the instance. Other instances may have limitations on the time they can run. For the most part, I've found they are pretty flexible and quite cheap.

> You should always use extreme caution when utilizing compute owned by unknown parties. At the very least, consider redacting all sensitive information from your hash types (usernames, domains, etc).

## Gimmie the Loot!

If you want to give it a spin, here's a quick example to get you up and running.

**1. Create an account at [https://vast.ai](https://vast.ai)**

**2. Load up your account with [some credits](https://vast.ai/console/billing/). At this time, only credit cards are supported.**

**3. Navigate to [Create Instances](https://vast.ai/console/instances/) and adjust the filters to your liking.**

You should change the Docker image from the default to `dizcza/docker-hashcat:cuda` or another docker image that includes both hashcat and CUDA support for nVIDIA GPUs. Click on the "EDIT IMAGE & CONFIG" button to accomplish this.

![Vast.ai](/assets/images/vastai_1.png)

Personally, I set the disk space to just over 100GB as the wordlists I'll be downloading to the instance sometimes come near that amount. This affects the hourly pricing of course, so chose what you think you'll need.

**4. Rent an instance that looks juicy.**

![Yum!](/assets/images/vastai_2.png)

**5. Navigate to the [Instances](https://vast.ai/console/instances/) page and wait for your instance to become available.**

**6. Once the instance is initialized, click on CONNECT and copy/paste the SSH command into the terminal application of your choice.**

**NOTE** 
You must configure an SSH key in the Vast.ai Account page, and may need append `-i ~/.ssh/<your-key>` to the ssh command to use key auth.

![Connection String](/assets/images/vastai_3.png)

After connecting over SSH you will be dropped into a tmux session of your instance, running the docker container you chose in the config options.

I'm going to install one of the wordlists from WeakPass for this demonstration.

Remember that hashcat can [support wordlists in the zip or gzip format](https://twitter.com/adamsvoboda/status/1428715349059506184), so if you download a wordlist already in that format you do not have to extract it before using it!

```bash
$ apt install p7zip
$ wget https://download.weakpass.com/wordlists/1947/weakpass_3.7z
$ 7zr e weakpass_3.7z
```

**7. Crack some hashes!**

I placed my example hashes into a file named `ntlm-hashes.txt` and started hashcat (in NTLM mode 1000) targetting the weakpass_3 wordlist.

`hashcat -m 1000 -O -w4 ntlm-hashes.txt weakpass_3 -o cracked.txt`

![Warming up the engines...](/assets/images/vastai_4.png)

![Not too shabby!](/assets/images/vastai_5.png)

**8. Don't forget to destroy your running instances when finished!**

Most of this process could be automated for engagements, customized as you see fit.

Vast offers a [CLI package](https://vast.ai/console/cli/) that lets you do most of this from the command-line. Play around with it and let me know what you think!

Know of any other cloud offerings that are competitive? Feel free to reach out on twitter and let me know [@adamsvoboda](https://twitter.com/adamsvoboda).