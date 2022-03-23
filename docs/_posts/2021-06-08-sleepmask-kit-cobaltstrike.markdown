---
layout: post
title:  "Sleeping with a Mask On (Cobalt Strike)"
date:   2021-06-08 00:00:00 -0500
categories: red-team pentest cobalt-strike c2
permalink: /sleeping-with-a-mask-on-cobaltstrike/
---

In Cobalt Strike 4.4, Sleep Mask Kit was released to help operators customize the encryption algorithm used to obfuscate the data and strings within beacon's memory. By default it uses a 13-byte XOR key, however this key size easily changed by modifying a single variable and rebuilding the Sleep Mask Kit. If you want to get even more creative, you can change the algorithm entirely.

I haven't seen much information on this topic yet so I wanted to put together a very simple post that will show you how to hunt for beacons in-memory and change the default sleep_mask encryption behavior! Huge shoutout to the research done by Elastic at this post, whose tactics I borrow heavily from: [Detecting Cobalt Strike with Memory Signatures](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures).

# Mask Off

Out-of-the-box, Cobalt Strike (as of 4.4) does not use `sleep_mask` to encrypt the beacon payload in-memory. We can prove that with the following exercise:

First, let's spin up a teamserver using the default profile (no custom profile specified), generate a stageless x64 binary and execute it on our Windows 10 machine.

I'm going to inject this beacon into a `notepad.exe` process as an easy example:

![Image](/assets/images/sleepmask_1.png)

Let's find our beacon in-memory. Taking a hint from the [great article by Elastic Security](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures) we can track this down by looking for calls to SleepEx from running threads within the process our beacon was injected into.

![Image](/assets/images/sleepmask_2.png)

We can copy the offset directly under that at `0x1a0ffcecd9f` and look for it in the Memory tab of Process Hacker:

![Image](/assets/images/sleepmask_3.png)

Scrolling through this memory region we can see our entire beacon unencrypted in memory. Not good OPSEC!

![Image](/assets/images/sleepmask_4.png)

# [**** it, Mask On](https://www.youtube.com/watch?v=xvZqHgFz51I)

Let's repeat the process using a C2 profile that specifics the `sleep_mask` command, among a few others...

We'll be using the [reference profile located here](https://github.com/Cobalt-Strike/Malleable-C2-Profiles/blob/master/normal/reference.profile), but making a few changes...

```python
# Obfuscate Beacon, in-memory, prior to sleeping
set sleep_mask "true";

# The size of memory beacon will allocate in our target process (500KB)
set image_size_x64 "500000";

# Mark the memory region as RWX
set userwx "true";
```
We are enabling the `sleep_mask` function using Cobalt Strike's default sleep masking algorithm, and also setting the memory region size to 500KB and marking that region as RWX, the latter two just make it easier to find in Process Hacker for research.

Repeating the steps above to deploy our beacon and inject it into a process, we can now track down the memory region of our beacon by using Process Hacker to look for a memory region size of roughly 500KB that's marked as RWX.

![Image](/assets/images/sleepmask_5.png)

*Injecting our `sleep_mask` payload into an instance of notepad.exe*

![Image](/assets/images/sleepmask_6.png)

*Check the running threads to see any calls to `SleepEx`*

Let's check out the memory tab of `notepad.exe` and look for a ~500KB map with RWX protection at `0x1b6a834bd51`

![Image](/assets/images/sleepmask_7.png)

*Bingo. Our beacon in memory.*

![Image](/assets/images/sleepmask_8.png)

*It's all XOR'd up!*

Reading the memory in Process Hacker, we can now see that it's strings and data are obfuscated. By default (as of CS 4.2+), the obfuscation is using XOR with a 13 byte key.

If we set the beacon to interactive mode using `sleep 0` and then Re-read the memory in Process Hacker we will see the fully unencrypted beacon:

![Image](/assets/images/sleepmask_9.png)

You may have to click on Re-read several times until you see the decrypted beacon, because after every C2 check-in it will re-encrypt the data and strings.

![Image](/assets/images/sleepmask_10.png)

*Ta-da!*

# Customizing Sleep Mask Kit

Let's have a look at Elastic's CS 4.2 beacon yara rule for the xor deobfuscation algorithm:
```
rule cobaltstrike_beacon_4_2_decrypt
{
meta:
    author = "Elastic"
    description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2."
strings:
    $a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
    $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
condition:
     any of them
}
```

![Image](/assets/images/sleepmask_11.png)
*The default deobfuscation routine the yara rule checks for, present in a memory-dump of our masked beacon.*

Running this yara rule quickly reveals that we have a CS beacon running in our `notepad.exe` process at PID `5724`!

![Image](/assets/images/sleepmask_12.png)
*We also got a detection for PID 10264, which is our instance of Process Hacker with the beacon's memory browser open.*

> Now that Sleep Mask Kit lets us compile the sleep mask algorithm as a BOF, simply compiling the defaults with the 13-byte xor key will evade this yara rule since the static byte signature has changed.

To customize and build your own Sleep Mask Kit, open Cobalt Strike, navigate to Help -> Arsenal and download the Sleep Mask Kit.

You'll see files that allow you to change the sleep mask behavior for HTTP beacons, TCP beacons and SMB beacons. We'll focus on `sleepmask.c` for now. Since this code is only for licensed customers of Cobalt Strike, I won't be revealing too much of it in this post, but you will see the XOR encryption algorithm in the `sleep_mask` function, and the default size is defined at the top of the file:

```c
#define MASK_SIZE 13
```

![Image](/assets/images/sleepmask_13.png)

*Check the mask size and rebuild!*

In my example, I changed the `MASK_SIZE` to `8`. We can now tell Cobalt Strike to use our new sleep mask BOFs by importing the `sleepmask.cna` file generated by `build.sh` (Cobalt Strike -> Script Manager -> Load).

Deploy a new beacon, inject it into another process, and run the yara rule signature scan just for fun:

![Image](/assets/images/sleepmask_14.png)

![Image](/assets/images/sleepmask_15.png)

*👻*

This was just a basic example to show you the tactics necessary to find your beacon in-memory, and make a super simple change to Sleep Mask Kit that might aid in any static evasion techniques.

Detecting the changes we made are very trivial, but they were also trivial changes to make as an operator. In the future, I look forward to discussing sleep mask in more detail, as well as seeing what the community comes up with.

## References
- [Detecting Cobalt Strike with Memory Signatures](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures)
- [Obfuscate and Sleep](https://www.youtube.com/watch?v=AV4XjxYe4GM)
- [Sleep Mask Kit](https://www.cobaltstrike.com/help-sleep-mask-kit)