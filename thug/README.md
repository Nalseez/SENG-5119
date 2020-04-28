# My Analysis of `thug`

## Setup

## Prerequisites

* Container Engine (e.g., Podman, Docker, etc)
  * I'll be using `Podman` for this example, because `Docker` is old school and the f***ing Docker deamon drives me crazy. Even companies like RedHat are dropping support for the Docker Container Engine in RHEL 8 / CentOS dock8

Download Thug image

```
$ podman pull buffer/thug
```

# Download & unzip 

```
$ https://github.com/buffer/thug
```

# Start container

```
$ podman run -it -v /home/user/Downloads/thug-master/samples:/home/thug/samples -v /home/user/logs/thug:/tmp/thug/logs buffer/thug /bin/sh
```

# Run Sample Analysis on 10 files

```
$ for item in $(find samples/ -type f | xargs shuf -e |tail -n 10); do thug -Z -F -l $item; done
```

---

# Targeted Sample

## Invocation on file
```
$ thug -Z -F -l 4042.html
[2020-04-28 04:28:44] <object classid="clsid:DCE2F8B1-A520-11D4-8FD0-00D0B7730277" id="target"></object>
[2020-04-28 04:28:44] ActiveXObject: DCE2F8B1-A520-11D4-8FD0-00D0B7730277
[2020-04-28 04:28:44] [Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow
[2020-04-28 04:28:44] [EXPLOIT Classifier] URL: 4042.html (Rule: CVE-2007-4391, Classification: None)
[2020-04-28 04:28:44] [Shellcode Profile] UINT WINAPI WinExec (
     LPCSTR lpCmdLine = 0x4170a7 => 
           = "calc.exe";
     UINT uCmdShow = 0;
) =  0x20;
void ExitProcess (
     UINT uExitCode = 0;
) =  0x0;
```
## Logs