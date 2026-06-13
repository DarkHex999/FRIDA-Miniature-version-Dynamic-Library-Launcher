FRIDA-Miniature-Dynamic-Library-Launcher
A lightweight, single-purpose Android tool that loads any shared library (.so) into a remote process — just like a miniature, no-frills version of FRIDA's frida-gadget injection, but stripped to its bare essentials. This project is not malware, not a rooting exploit, and not a backdoor. It is a legitimate launcher for dynamic libraries on Android, designed for developers, security researchers, and reverse engineers who need a clean, transparent way to inject custom code into running apps for debugging, instrumentation, or analysis — all with explicit user consent and full control.

What it does
The system consists of two tiny, self-contained programs:

A server that runs on the Android device. It listens on a local Unix socket and waits for requests.

A client that sends a simple message: the target process ID (PID) and the full path to the shared library you want to load.

When a request arrives, the server safely loads the specified library into the target process without modifying the app's APK, without touching its files, and without altering its normal behaviour. After injection, the library runs within the process context — exactly as if the app itself had called dlopen() — and the target continues executing as if nothing happened.


How it is different from FRIDA
FRIDA is a powerful, full-featured dynamic instrumentation framework that offers scripting, hooking, process discovery, and much more. This project does one thing only: it takes a PID and a library path, and it makes that process load the library. No JavaScript engine, no gadget, no session management. It is the smallest possible “dynamic library launcher” — hence the name “miniature version”. Use it when you already have your own instrumentation code compiled into a .so and you just need a reliable way to launch it inside a running app.

Not a malicious tool
This software performs no hidden actions. It does not:

Steal data, log keystrokes, or exfiltrate information.

Modify system partitions or install any permanent changes.

Try to bypass Android security boundaries unless explicitly given root access (a requirement clearly documented).

Launch without a clear, intentional request from a local client.

It is a developer's utility, comparable to standard debugging tools like gdbserver or lldb-server, but specialised for dynamic library Loading.

Licensing — Public Domain
This project is released under The Unlicense, which means it is free and unencumbered software released into the public domain. Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, without any restriction whatsoever.

By choosing The Unlicense, the author dedicates the work to the public domain, waiving all copyright and related rights to the fullest extent allowed by law. You do not need to ask for permission or give attribution (though a mention is always appreciated).

Final word
This project is a precision tool — nothing more, nothing less. It exists because sometimes you just need to load a library into a running process, and you don't want the overhead or complexity of a full instrumentation suite. Treat it as a friendly helper in your Android reverse‑engineering toolbox, and always respect the legal boundaries of your testing environment.
