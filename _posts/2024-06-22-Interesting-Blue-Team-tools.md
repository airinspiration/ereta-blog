---
title: "Interesting Blue Team tools"
date: 2024-06-22
---

# 1768.py
While watching a video called [Cobalt Strike from a Blue Team Perspective](https://www.youtube.com/watch?v=ZtenI_9Byek), one of the exponents - *Didier Stevens* - utilized a tool that I wasn't aware of `1768.py`.

It let's you get more context on this threat such as the process it is targeting to inject shellcode `rundll32.exe` in this case; the `Team Server` IP `192.168.1.5`, port used `3334`, type of payload `windows-beacon_http-revers_http`, among other.

Output retrieved utilizing a beacon file I got from a HackTheBox sherlock room.
```
remnux@remnux:~/path$ python3 1768.py cs-windows.exe 
File: cs-windows.exe
payloadType: 0x00002610
payloadSize: 0x00040200
intxorkey: 0x56efb653
id2: 0x00000000
MZ header found position 4
Config found: xorkey b'.' 0x0003aa30 0x000401fc
0x0001 payload type                     0x0001 0x0002 0 windows-beacon_http-reverse_http
0x0002 port                             0x0001 0x0002 3334
0x0003 sleeptime                        0x0002 0x0004 60000
0x0004 maxgetsize                       0x0002 0x0004 1048576
0x0005 jitter                           0x0001 0x0002 0
0x0007 publickey                        0x0003 0x0100 30819f300d06092a864886f70d010101050003818d00308189028181009872e9417999ab6cc4b5b541e04dae76bd09ff8c6cdb26ec4adfdf376d12624b4774c6f104a637c9d8d12da6d6412fdca185ff082306cc043a898f87ee56f52c1eb436e99931bf42ab12eb88a3ad01519e3715cbe2d55179e79b7834bd7030e30fa33f4d731a5227567e026e2f95a1934a0fc5c71ebfd3f321f9440c71962f3b020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0x0008 server,get-uri                   0x0003 0x0100 '192.168.1.5,/visit.js'
0x0043 DNS_STRATEGY                     0x0001 0x0002 1
0x0044 DNS_STRATEGY_ROTATE_SECONDS      0x0002 0x0004 -1
0x0045 DNS_STRATEGY_FAIL_X              0x0002 0x0004 -1
0x0046 DNS_STRATEGY_FAIL_SECONDS        0x0002 0x0004 -1
0x000e SpawnTo                          0x0003 0x0010 (NULL ...)
0x001d spawnto_x86                      0x0003 0x0040 '%windir%\\syswow64\\rundll32.exe'
0x001e spawnto_x64                      0x0003 0x0040 '%windir%\\sysnative\\rundll32.exe'
0x001f CryptoScheme                     0x0001 0x0002 0
0x001a get-verb                         0x0003 0x0010 'GET'
0x001b post-verb                        0x0003 0x0010 'POST'
0x001c HttpPostChunk                    0x0002 0x0004 0
0x0025 license-id                       0x0002 0x0004 426352781
0x0026 bStageCleanup                    0x0001 0x0002 0
0x0027 bCFGCaution                      0x0001 0x0002 0
0x0009 useragent                        0x0003 0x0100 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; MASAJS)'
0x000a post-uri                         0x0003 0x0040 '/submit.php'
0x000b Malleable_C2_Instructions        0x0003 0x0100
  Transform Input: [7:Input,4]
   Print
0x000c http_get_header                  0x0003 0x0200
  Build Metadata: [7:Metadata,3,6:Cookie]
   BASE64
   Header Cookie
0x000d http_post_header                 0x0003 0x0200
  Const_header Content-Type: application/octet-stream
  Build SessionId: [7:SessionId,5:id]
   Parameter id
  Build Output: [7:Output,4]
   Print
0x0036 HostHeader                       0x0003 0x0080 (NULL ...)
0x0032 UsesCookies                      0x0001 0x0002 1
0x0023 proxy_type                       0x0001 0x0002 1 no proxy
0x003a TCP_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0039 SMB_FRAME_HEADER                 0x0003 0x0080 '\x00\x04'
0x0037 EXIT_FUNK                        0x0001 0x0002 0
0x0028 killdate                         0x0002 0x0004 0
0x0029 textSectionEnd                   0x0002 0x0004 0
0x002b process-inject-start-rwx         0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002c process-inject-use-rwx           0x0001 0x0002 64 PAGE_EXECUTE_READWRITE
0x002d process-inject-min_alloc         0x0002 0x0004 0
0x002e process-inject-transform-x86     0x0003 0x0100 (NULL ...)
0x002f process-inject-transform-x64     0x0003 0x0100 (NULL ...)
0x0035 process-inject-stub              0x0003 0x0010 (NULL ...)
0x0033 process-inject-execute           0x0003 0x0080 '\x01\x02\x03\x04'
0x0034 process-inject-allocation-method 0x0001 0x0002 0
0x0000
Guessing Cobalt Strike version: 4.3 (max 0x0046)
Sanity check Cobalt Strike config: OK
Sleep mask 64-bit 4.2 deobfuscation routine found: 0x0000feb9 (LSFIF: b't3E;')
Public key config entry found: 0x0003aa60 (xorKey 0x2e) (LSFIF: b'././.,...,./.,#(.-.,.*..')
Public key header found: 0x0003aa66 (xorKey 0x2e) (LSFIF: b'N.*.,.*.>...+./.,...).-/.')
remnux@remnux:~/path$ 

```
