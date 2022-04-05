---
layout: post
title:  "Some New Security Defaults Coming to Windows 11"
date:   2022-04-05 01:30:00 -0600
categories: security windows windows-11 lsass hvci credguard asr red-team blue-team
permalink: /new-security-defaults-in-windows-11/
---

I was perusing my twitter feed this morning and came across [this tweet](https://twitter.com/dwizzzleMSFT/status/1511368944380100608) from David Weston at Microsoft:

![](/assets/images/windows11-security-announcements-tweet.png)

Microsoft has been making several positive moves in promoting better defaults for Windows security features and I thought it would be good to break a few of these down and understand their impact on organizational security posture as it relates to adversary activity and red-teaming. You can also get a good general overview of some of these changes [here](https://www.microsoft.com/security/blog/2022/04/05/new-security-features-for-windows-11-will-help-protect-hybrid-work/).

_Please note that many of these features require Windows 11 Enterprise._

# HVCI and VBS

Hypervisor-protected code integrity (HVCI) is a part of virtualization based security (VBS) and will be moving towards an enabled-by-default configuration on all *supported* CPUs. 

You can think of HVCI as a form of Memory Integrity. It leverages VBS to enforce code integrity policies, using kernel mode code integrity checks on all drivers and binaries before they are ran. It is able to prevent unsigned drivers or system files from being loaded into system memory.

Restrictions are enforced by the Windows Hyper-V hypervisor, running the code integrity service inside a secure enfironment. Memory pages are only made executable after code integrity checks inside the secure environment have passed. Executable pages are not writable, so if a driver had a vulnerability such as a buffer overflow, modified memory could not be made executable.

Taking it a step further, devices with HVCI enabled can enable the [vulnerable driver blocklist feature](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules) of Windows Defender Application Control.

## Impact 
Adversaries using known vulnerable kernel drivers will presumably not be allowed to load or use the driver any longer if the hash or signature is blacklisted by Microsoft

You often see this used with malware leveraging leaked code-signing certificates (such as the recent NVIDIA certificates leaked by LAPSUS$, which are blocked when using this feature!)

Adversaries may load kernel drivers using these techniques to silence EDR callbacks or further disguise their presence on the machine.

Take some time to familiarize yourself with the [blacklist](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules) and you'll notice that drivers for Process Hacker and Cheat Engine are also there, as they are could be leveraged for nefarious purposes. Process Explorer (signed by Microsoft) is still allowed however, which could be used nefariously to [terminate PPL processes](https://github.com/Yaxser/Backstab) among other things, so as with anything you need to familiarize yourself with the edge-cases.


# Credential Guard

Credguard is only avaiable in the Enterprise edition of Windows 10 and 11, and will be enabled by default going forward (for Windows 11 only).

The goal of credential guard is to stop adversaries from obtaining system secrets even with local administrator rights. It does this by isolating the LSA process from the rest of the operating system using VBS. `lsass.exe` then communicates to the isolated LSA process using remote procedure calls. 

There are many caveats around authentication support to be aware of when using Credguard and you should check the [official documentation here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works).

## Impact
Adversaries have a harder time dumping secrets from the `lsass.exe` process using traditional tooling such as Mimikatz. 

Adversaries may attempt to read these secrets by enabling WDigest using memory patching in an attempt to get Windows to store future credentials insecurely where they can be easily obtained in plaintext.

Adam Chester (@_xpn_) demonstrates how to harvest these secrets from a Credential Guard enabled machine by memory-patching wdigest.dll to enable `UseLogonCredentials` in this [great post](https://blog.xpnsec.com/exploring-mimikatz-part-1/).

Be aware of adversaries leveraging WDigest to circumvent the secure isolation of these secrets within your organization.

# Attack Surface Reduction Enabled for LSA

Attack Surface Reduction (ASR) is a "feature that helps prevent actions and apps that are typically used by exploit-seeking malware to infect machines." One example of this would be an adversary attempting to dump the process memory of `lsass.exe` to obtain credentials or other secrets. 

| The default state for the ASR rule “Block credential stealing from the Windows local security authority subsystem (lsass.exe)” will change from Not Configured to Configured and the default mode set to Block.

Check out the full list of [pre-defined ASR rules here](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide).

This also includes things such as:
- Blocking untrusted/unsigned processes that run from USB
- Blocking JS/VBS from launching downloaded executable content
- Blocking office applications from creating executable content
- Blocking process creations originating from PsExec/WMI commands
- Blocking Win32 API calls from office macros

_I'm not sure which of these are actually switching to enabled by default..., other than the LSA block rule mentioned above._

## Impact

ASR is a great step in the right direction towards hardening windows from a series of commonly abused attack vectors, but it's often not enough by itself.

There are a few ASR bypasses out there in the wild already, so [be aware](https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf) of [them](https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3)!

Windows Defender maintains a whitelist of certain executables that it may allow to dump `lsass.exe` even with these ASR Protection rules enabled. One such example of this is demonstrated in this [video](https://www.youtube.com/watch?v=Ie831jF0bb0). See [this tweet](https://twitter.com/_xpn_/status/1491557187168178176) by Adam Chester (@_xpn_) for more information.

For another great resource to learn more about ASR and potential ways around it, see this [write-up by commial](https://github.com/commial/experiments/tree/master/windows-defender/ASR).


# Signed/Reputable EXEs

Windows Defender Application Control (WDAC) lets you have control over the apps and drivers allowed to run on your endpoints. 

WDAC isn't to be confused with AppLocker (introduced with Windows 7) as there is some overlap, but it's an entirely different beast itself. 

With WDAC, you could enforce a policy that prevents all unsigned executables from running. You can also take a look at the reputation of that executable and determine if it should be allowed to run.

Take a look at a few of the [Template Base Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-wizard-create-base-policy), namely the "Signed and Reputable mode"

![](/assets/images/wdac-sr-policy.png)

And compare that with the "Default Windows Mode"

![](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/images/wdac-wizard-template-selection.png)

## Impact

Organizations can easily prevent the execution of unsigned or unreputable binaries using WDAC, restricting the flexibility of the adversary playbook for delivering malicious payloads to endpoints. 

WDAC/AppLocker is still not a silver-bullet as it may be possible for adversaries to use LOLBINs and AppLocker bypass techniques to work around these limitations. Many of these LOLBINs are already included on the Microsoft recommended block rules [list here](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules).