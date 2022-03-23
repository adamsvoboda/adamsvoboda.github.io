---
layout: post
title:  "Evading EDR in 15 Minutes with ScareCrow"
date:   2021-07-30 01:30:00 -0600
categories: red-team pentest cobalt-strike c2 edr evasion
permalink: /evading-edr-with-scarecrow/
---

> During red team engagements, we frequently encounter EDR solutions. We deploy a lot of Cobalt Strike, and I wanted to write up a short blog post on how you can quickly deploy a beacon (or your own choice of raw shellcode) on an endpoint protected by one of these solutions.

# Understanding the EDR Behavior Monitoring Strategy

In an effort to keep this post short and sweet, this will be a brief explanation of a much more complex topic, but it's good to understand how EDR is detecting your payloads and behaviors, to help you understand the steps we take to avoid it's prying eyes. Check out the Read More section at the bottom of this post for more in-depth posts regarding EDR functionality.

Back in the "old times", before Microsoft enforced [Kernel Patch Protection (KPP)](https://en.wikipedia.org/wiki/Kernel_Patch_Protection), anti-virus software would typically load a kernel-mode driver to monitor behavior outside of user-mode, where all of your normal applications run and reside. These kernel-mode drivers that attempted to patch the Windows Kernel to intercept or monitor activity would frequently cause [stability issues](https://www.zdnet.com/article/symantec-antivirus-products-vulnerable-to-horrid-overflow-bug/) by doing unspeakable things. In an effort to increase the stability of the Windows Kernel, KPP was invented, which restricts what internal structures kernel drivers are allowed to modify, restricting these tools to user-mode monitoring techniques, which makes life a little easier for those of us trying to evade them!

Most EDR products these days now resort to user-mode API hooking to monitor your behaviors. When a process starts on Windows, one of the DLLs loaded is `NTDLL.DLL`, which contains a myriad of Windows API calls that applications use to interface with the operating system and it's components (Processes / Files / etc).

When you spawn a new process on a Windows machine, the EDR will load it's own DLL into your process space, and place funciton hooks on these `NTDLL.DLL` functions, allowing it to monitor relevant process behaviors by essentially being a man-in-the-middle of every request that process makes to the Windows API. If you create a new child process, open a file, inject code – they can see it in real-time and even stop it before it's allowed to happen. It used to be possible to thwart this EDR DLL injection by simply applying a process creation mitigation policy that would only allow DLLs signed by Microsoft to be loaded into your process space, however, most defense products have this Microsoft signing and we can no longer leverage this clever trick.

Fortunately, there are still several ways around this.. (unhooking the hooked functions, loading a clean copy of NTDLL from the disk that's unhooked, using syscalls to evade detection, etc). Read on, comrade!

# Hey You, Meet ScareCrow
![ScareCrow](/assets/images/scarecrow_1.png)

[ScareCrow](https://github.com/optiv/ScareCrow) is described as a "payload creation framework". You can read all about how it works on its [README page here](https://github.com/optiv/ScareCrow/blob/main/README.md).

In short, we can generate some raw shellcode from the software of our choice (Cobalt Strike, Metasploit, PoshC2, etc) and pass it to the homie to get a loader back that will implement some common EDR evasion techniques.

ScareCrow takes your raw shellcode and encrypts it using AES, which is beneficial to avoid static detection on-disk when a defense product scans the loader you generated. Windows Defender is pretty good about detecting the shellcode from Cobalt Strike's beacon, so this step is crucial.

After executing the generated loader, it will bypass the EDR's hooks on `NTDLL.DLL` by loading a clean copy of `NTDLL.DLL` (as well as `kernel32.dll` and `kernelbase.dll`) from disk and replacing it with the hooked one in your process space, thus removing the EDR's hooks entirely. From there, it leverages syscalls to load, decrypt and run your shellcode in-memory. Using syscalls is a great way to evade hooks and behavioral monitoring, and even though it already removed the EDR hooks, there are other solutions that may still detect these API call events such as Event Tracing for Windows, which ScareCrow will also bypass. I won't go into more detail here, you can read more about how this works on GitHub repository, which I highly recommend. As a red team operator, it's important to understand as much as you can about your tools and techniques.

To make things even more interesting, ScareCrow uses a [golang port of the tool LimeLighter](https://github.com/Tylous/Limelighter) to spoof code signing certificates on the binary/dll files it generates. It  also supports applying custom File Attributes to help mask a binary as legitimate:

![Image](/assets/images/scarecrow_2.png)

*File Attributes on the generated loader are copied from CMD.EXE*

![Image](/assets/images/scarecrow_3.png)

*A fake code signing signature applied by ScareCrow via LimeLighter integration.*

# Okay, But How?

I thought you'd never ask.

Here's the steps taken to generate some raw shellcode from Cobalt Strike (if you are using Metasploit, you can use msfvenom. Check out the [blog post](https://www.grahamhelton.com/blog/scarecrow/) by [@GrahamHelton3](https://twitter.com/GrahamHelton3) here for more information on that)

> If you are using Cobalt Strike, it's always recommended to use a custom Malleable C2 profile, avoid using staged payloads, and apply customizations with the Artifact Kit to help avoid detection!

> If you are using HTTP, always use HTTPS with a free, legitimate certificate from Let's Encrypt or a paid provider of your choice.

> You can actually disable staging in your Malleable C2 profile (`set host_stage "false";`) which helps out with your C2 OPSEC, since CS will always send stager data when a request is made... potentially blowing your cover or getting your C2 on a blacklist somewhere.

## Acquiring Shellcode

### Stageless Beacon
Open up CS. Navigate to Attacks -> Packages -> Windows Executable (S)

![Image](/assets/images/scarecrow_4.png)

Pick your listener, output as `Raw`, and make sure to tick `Use x64 Payload`, ScareCrow only supports x64 shellcode at this time! You should get a `payload.bin` file.

Clone the ScareCrow repository and follow the install instructions in the [README](https://github.com/optiv/ScareCrow/blob/main/README.md). There's a few dependencies, such as golang, mingw-w64, etc. I'd recommend installing it on Linux if you can to streamline the process. Kali or another debian-based distro like Ubuntu keeps it simple.

Feel free to modify the `main.json` file if you want to apply any custom File Attributes. This is optional. If you do this, make sure to pass it to the calls below using the `-configfile main.json` argument.

You should read the full help documentation using `./ScareCrow -h`, but if you just want to get rocking and rolling right away, here's how to generate a binary loader from the raw shellcode:

`./ScareCrow -I /path/to/your/payload.bin -etw -domain www.microsoft.com`

I'm using the `-etw` argument to enable ETW patching to prevent ETW events from being generated. Try it out, its free :)

Feel free to use whatever domain you'd like for the fake code signing certificate. I picked `www.microsoft.com`.

ScareCrow will take your shellcode, encrypt it, and generate a .exe binary from it's built-in list of predefined binaries and file attributes. Feel free to customize them to your liking.

In my case, the RNG Gods blessed me with `cmd.exe`.

![Image](/assets/images/scarecrow_5.png)

Behold, a new beacon:

![Image](/assets/images/scarecrow_6.png)

# Windows Defender Evasion

UPDATE (08/01/2021):

You may have seen a [previous tweet](https://twitter.com/adamsvoboda/status/1421519490781786115) I made about Windows Defender evasion. This content has been removed from the blog post because while it may work for some, it's not exactly what Defender is flagging and it also breaks the integrity of the binary by modifying the hash post-compilation.

Turns out, the code emitted in the final binary loader that's causing the flag is related to how [ScareCrow hides the Console Window](https://github.com/optiv/ScareCrow/blob/main/Struct/Struct.go#L506) after execution:


`/Struct/Struct.go`

```go
func {{.Variables.Console}}(show bool) {
    {{.Variables.getWin}} := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow")
    {{.Variables.showWin}} := syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow")
    {{.Variables.hwnd}}, _, _ := {{.Variables.getWin}}.Call()
    if {{.Variables.hwnd}} == 0 {
            return
    }
    if show {
        var {{.Variables.SW_RESTORE}} uintptr = 9
        {{.Variables.showWin}}.Call({{.Variables.hwnd}}, {{.Variables.SW_RESTORE}})
    } else {
        var {{.Variables.SW_HIDE}} uintptr = 0
        {{.Variables.showWin}}.Call({{.Variables.hwnd}}, {{.Variables.SW_HIDE}})
    }
}
```

*Defender doesn't much care for this.*

[@Tyl0us](https://twitter.com/Tyl0us) was kind enough to lend his time to this issue, and after some testing I can present to you FOUR additional methods you can use to bypass the latest Windows Defender detection right now. A patch is planned for ScareCrow that will change this window hide code in an attempt to thwart the latest Windows Defender signature, but in the meantime read on:

## Defender Bypass #1 - Sandbox Evasion Mode

Try building your payloads using the `-sandbox` option. This seems to evade the Defender detection for now. Either by happenstance (lucky heuristic evasion), or by actually preventing some sort of cloud/execution sandbox analysis that Defender has used on these payloads to build heuristic detection for their behavior.

Caveats:

Requires that the machines you execute on be joined to a domain, via a call to [NetGetJoinInformation](https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetjoininformation), or it [won't run](https://github.com/optiv/ScareCrow/blob/main/Struct/Struct.go#L5).

## Defender Bypass #2 - Process Injection Mode

Process Injection works great against the EDR product I've been testing on, as well as Windows Defender. It contains none of the Console Window code above and still gives you full EDR evasion by unhooking it's own loader process and then flushing the EDR hooks from the relevant DLLs in the remote process.

`./ScareCrow -I stageless.bin -domain www.microsoft.com -injection C:\\Windows\\System32\\notepad.exe`

Tack on the `-console` flag while testing to see interesting output on how this works, or to debug unexpected results.

**Caveats:**

You cannot use `-etw` to patch Event Tracing for Windows using the `-injection` loader.

## Defender Bypass #3 - Console Mode

Building using the `-console` flag removes the code to hide the Console Window, evading detection.

**Caveats:**

There is a visible Console window shown during execution that contains debug information.

## Defender Bypass #4 - Binary Mode (GUI Application)

Instead of having ScareCrow build our binary payloads as Console Applications (which are causing the Defender flagging discussed above), we can tell `go build` to make a `windowsgui` application instead, which has no visibile window to hide.

ScareCrow doesn't do this by default for a good reason:

![Image](/assets/images/scarecrow_7.png)

*ScareCrow builds as a Console Application on purpose to evade specific EDR products*

But alas, Windows Defender currently doesn't mind this type of behavior.

To do this yourself, make an edit to `ScareCrow.go` like this:

[https://github.com/adamsvoboda/ScareCrow/blob/windows-gui-test/ScareCrow.go#L81](https://github.com/adamsvoboda/ScareCrow/blob/windows-gui-test/ScareCrow.go#L81)

Replace the existing string:

```go
cmd = exec.Command(bin, "GOROOT_FINAL=/dev/null", "GOOS=windows", "GOARCH=amd64", "go", "build", "-a", "-trimpath", "-ldflags", "-s -w", "-o", ""+name+".exe")
```

With this one:

```go
cmd = exec.Command(bin, "GOROOT_FINAL=/dev/null", "GOOS=windows", "GOARCH=amd64", "go", "build", "-a", "-trimpath", "-ldflags", "-H=windowsgui -s -w", "-o", ""+name+".exe")
```

Then you'll need to go edit `Struct/Struct.go` and comment out the sections where the Console Window Hide code could be emitted in the final binary:

[https://github.com/adamsvoboda/ScareCrow/commit/a7b62c85d89d4734a29147a1f7d0c7d4c10dcf3e#diff-5e95797a7202b61fa219b1e55526f360534b909ec74ae46a29058c7914735516](https://github.com/adamsvoboda/ScareCrow/commit/a7b62c85d89d4734a29147a1f7d0c7d4c10dcf3e#diff-5e95797a7202b61fa219b1e55526f360534b909ec74ae46a29058c7914735516)

From there, you can run `go build ScareCrow.go` and build a new binary payload that should fly under Defender's radar for now. To take it a step further, you could add a check for the `-console` argument and only emit the console-window related code in `Struct.go` if it's enabled.

> I do not recommend using my fork linked in the examples above (although it works for now), it's a few patches behind master. and I don't plan to update it. Create your own fork and just use it as inspiration.

**Caveats:**

May not evade detection on specific EDR products, but still good for Windows Defender engagements (for now).

**Windows Defender Version Last Tested:**

![Image](/assets/images/scarecrow_8.png)


# Read More:
- [Endpoint Detection and Response: How Hackers Have Evolved](https://www.optiv.com/insights/source-zero/blog/endpoint-detection-and-response-how-hackers-have-evolved)
- [EDR and Blending In: How Attackers Avoid Getting Caught](https://www.optiv.com/insights/source-zero/blog/edr-and-blending-how-attackers-avoid-getting-caught)
- [A Tale of EDR Bypass Methods](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [Let's Create An EDR... And Bypass It!](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/)
- [HackThePlanet Video about ScareCrow](https://hackplanet.io/aiovg_videos/scarecrow-and-office-365-app-phishing/page/2)


Huge props to @Tyl0us and the team at Optiv for this incredible piece of kit. Go follow him!