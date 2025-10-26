---
title: "Analyzing HTA file"
date: 2024-06-23
---

# Overview
In this blog, we'll analyze a HTA deobfuscated payload from [MalwareAnalysisForHedgehogs](https://www.youtube.com/watch?v=5-OY3ISH6Bk) video.

**SHA256**: 139daeff3a7f4f1ec42ade0fe5cc604808c01edcb2fa287c3be1a35856ca46ef \
**Malshare**: https://malshare.com/sample.php?action=detail&hash=139daeff3a7f4f1ec42ade0fe5cc604808c01edcb2fa287c3be1a35856ca46ef

# Analysis
Skimming through the code, `a0BU();` seems to be the only expression calling a function, which would be our `main` function.
<img width="218" height="135" alt="image" src="https://github.com/user-attachments/assets/4dd3cb8e-21cc-4be1-9452-d10eee558550" />

Function structure: \
<img width="733" height="264" alt="image" src="https://github.com/user-attachments/assets/ce88f141-157b-4426-8ff5-1c0ce70e83c8" />

This function is basically doing arithemtic functions, though there are some methods that `QC()`, which holds the function `aOQ()`.
```
function a0BU() {
    var QC = a0BO, B = {
            '\x63\x75\x5a\x4e\x65': function (A, v) {
                return A + v;
            },
            '\x68\x4f\x56\x44\x51': function (A, v) {
                return A + v;
            },
<snip>
```
<img width="668" height="78" alt="image" src="https://github.com/user-attachments/assets/3f22cc2f-6c30-4226-8f9b-e0bcd12bd641" />

The first thing that `a0Q()` does, is to call `a0B`, which just holds an array of strings with hex content, and returns it. We'll rename it `return_hex_array`.
<img width="1050" height="187" alt="image" src="https://github.com/user-attachments/assets/4df2c13a-1f84-4935-b768-9e6760e8e32e" />


<img width="563" height="76" alt="image" src="https://github.com/user-attachments/assets/a46d6f24-9935-4dac-acd3-05ec7cc889bc" />
