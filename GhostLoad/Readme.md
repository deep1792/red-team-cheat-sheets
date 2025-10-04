Imagine a busy nightclub — A bouncer (here GhostLoad) stands at the door and checks everyone coming in. He’s sloppy as he lets dangerous gangsters (here malicious processes), but the moment a sherif (EDR dlls such as “amsi.dll”, “mpoav.dll”, “mpengine.dl”, etc.) tries to enter, the bouncer slams the door (here blocks the EDR dlls). The people inside (malicious files threads or processes) keep partying, completely unaware that the one group who could have stopped bad things from happening never got in.

That’s what a runtime DLL-blocking tool does to endpoint security: it prevents the security “inspectors” (EDR/AMSI libraries) from ever entering the running program, while leaving the program otherwise working at least from the program’s point of view.

Ghostload code — Github Repo

Press enter or click to view image in full size

What this means ?
Every process in Windows loads multiple DLLs (Dynamic Link Libraries). They act like plugins, extending what a program can do. For example:
  - user32.dll helps with UI elements,
  - kernel32.dll manages memory and files,
  - amsi.dll (Antimalware Scan Interface) lets antivirus tools scan scripts before they execute.
Hence, Modern EDRs (Endpoint Detection and Response tools) also use this concept as they inject their own DLLs into running processes to observe API calls, scan scripts, or monitor behaviors. So if you block those DLLs from ever loading, the EDR becomes blind inside that process.

How EDR monitoring works
Normally, when you run a program (say, PowerShell), the following happens:

PowerShell.exe → loads AMSI.dll + EDRHook.dll + System DLLs
EDR’s DLL sits quietly, watching your PowerShell commands and scanning any script text that goes through.
So, what this means?

Process: a running program (e.g., powershell.exe).
DLL (dynamic-link library): a module of code that can be loaded into a process (like a plugin).
EDR (Endpoint Detection & Response): software that watches processes for suspicious behavior. Many EDRs load their own DLLs into other processes to monitor API calls in user mode.
amsi.dll (AMSI): Microsoft’s Antimalware Scan Interface — a common hook used to scan scripts and dynamic code for malware before execution.
ntdll.dll / LdrLoadDll: low-level Windows library and the loader function that actually brings DLLs into process memory.
Why it matters? if an EDR’s DLL never gets loaded into a process, the EDR loses a major visibility channel for that process’s internal behavior (user-mode API calls, in-process script content, etc.). A runtime blocker aims to stop those DLLs from entering in the first place.

But a tool like GhostLoad changes the story to:
PowerShell.exe → GhostLoad (LdrBlocker) → AMSI.dll tries to enter → denied
PowerShell runs as usual but without the AMSI scanner or EDR visibility. That means no hooks, no detections, no behavioral logging at user-mode level.
What is GhostLoad?
GhostLoad is a Python-based tool that monitors the EDR security monitoring DLL loading in real-time and can disable the security libraries before they get injected into the malicious processes. This is achieved by simulating pre-load interception techniques, getting closer to true prevention rather than post-load remediation.

Key Features:
  Real-time DLL load monitoring
  Security DLL detection and blocking
  AMSI block capabilities
  Clean, professional output

Let’s simplify what happens under the hood:
  Launches the target app under debug control — like running PowerShell while “watching” it as a debugger.
  Hooks into LdrLoadDll, a low-level Windows function in ntdll.dll that loads every DLL.
  Intercepts each load request when an app says, “load AMSI.dll,” the hook checks a blocklist.
  If on blocklist → fake failure — it pretends the DLL failed to load.
  If not on blocklist → allow normal behavior.
  That’s it. The result: the target program runs, but some security DLLs never make it inside.

![Bouncer analogy — GhostLoad LdrBlocker](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*0aaGFGMSFbIC2GXh-e4hUQ.png)

  

Conclusion
So, as conclusion most user-mode monitoring techniques rely on one or more of these visibility channels:
  In-process DLLs or libraries that register hooks or callbacks
  API hooking / user-mode trampoline techniques to observe function calls
  Intercepted script content (e.g., AMSI scanning text before execution)
  Instrumentation via runtime frameworks that live inside the target process
  When those channels are removed or neutralized, EDRs may lose critical signals like script content, in-process API calls, and script block logging significantly reducing detection effectiveness.

📢 Share it on LinkedIn, Reddit, and with your team

Disclaimer: this post discusses detection and defense only. Any testing should be limited to isolated lab environments or authorized engagements.
