# go-msfdb
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/vulsio/go-msfdb/blob/master/LICENSE)

This is a tool for searching CVEs in Metasploit-Framework modules from [msfdb-list](https://github.com/vulsio/msfdb-list).
Metasploit modules are inserted at sqlite database(go-msfdb) can be searched by command line interface.
In server mode, a simple Web API can be used.

### Docker Deployment
There's a Docker image available `docker pull vuls/go-msfdb`. When using the container, it takes the same arguments as the normal command line.

### Installation for local deployment  
###### Requirements  
go-msfdb requires the following packages.
- git
- SQLite3, MySQL, PostgreSQL, Redis
- lastest version of go
    - https://golang.org/doc/install

###### Install go-msfdb
```bash
$ mkdir -p $GOPATH/src/github.com/vulsio
$ cd $GOPATH/src/github.com/vulsio
$ git clone https://github.com/vulsio/go-msfdb.git
$ cd go-msfdb
$ make install
```

----

### Usage: Fetch and Insert Module's info  
```bash
$ go-msfdb fetch -h
Fetch the data of msfdb-list

Usage:
  go-msfdb fetch [command]

Available Commands:
  msfdb       Fetch the data of metasploit-framework cve's list

Flags:
      --batch-size int      The number of batch size to insert. (default 50)
      --dbpath string       /path/to/sqlite3 or SQL connection string (default "$PWD/go-msfdb.sqlite3")
      --dbtype string       Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
      --debug-sql           SQL debug mode
  -h, --help                help for fetch
      --http-proxy string   http://proxy-url:port

Global Flags:
      --config string    config file (default is $HOME/.go-msfdb.yaml)
      --debug            debug mode
      --log-dir string   /path/to/log (default "/var/log/go-msfdb")
      --log-json         output log as JSON
      --log-to-file      output log to file

Use "go-msfdb fetch [command] --help" for more information about a command.
```

###### Fetch and Insert msfdb-list  
```bash
$ go-msfdb fetch msfdb
```

### Usage: Search Module's info  
```bash
$ go-msfdb search -h
Search the data of exploit

Usage:
  go-msfdb search [flags]

Flags:
      --dbpath string   /path/to/sqlite3 or SQL connection string (default "$PWD/go-msfdb.sqlite3")
      --dbtype string   Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
      --debug-sql       SQL debug mode
  -h, --help            help for search
      --param string    All Metasploit Framework modules: None  |  by CVE: [CVE-xxxx]  | by EDB: [EDB-xxxx]
      --type string     All Metasploit Framework modules by CVE: CVE  |  by EDB: EDB (default "CVE")

Global Flags:
      --config string    config file (default is $HOME/.go-msfdb.yaml)
      --debug            debug mode
      --log-dir string   /path/to/log (default "/var/log/go-msfdb")
      --log-json         output log as JSON
      --log-to-file      output log to file
```

###### Search Modules by CVE(eg. CVE-2014-0160)
```bash
$ go-msfdb search --type CVE --param CVE-2014-0160

Results: CVE-Metasploit Record
---------------------------------------

[*] CVE: CVE-2014-0160
  Name: openssl_heartbleed.rb
  Title: OpenSSL Heartbeat (Heartbleed) Information Leak
  Description: This module implements the OpenSSL Heartbleed attack. The problem exists in the handling of heartbeat requests, where a fake length can be used to leak memory data in the response. Services that support STARTTLS may also be vulnerable.  The module supports several actions, allowing for scanning, dumping of memory contents to loot, and private key recovery.  The LEAK_COUNT option can be used to specify leaks per SCAN or DUMP.  The repeat command can be used to make running the SCAN or DUMP many times more powerful. As in: repeat -t 60 run; sleep 2 To run every two seconds for one minute.

[-] References
  URL: http://www.kb.cert.org/vuls/id/720951
  URL: https://www.us-cert.gov/ncas/alerts/TA14-098A
  URL: http://heartbleed.com/
  URL: https://github.com/FiloSottile/Heartbleed
  URL: https://gist.github.com/takeshixx/10107280
  URL: http://filippo.io/Heartbleed/

---------------------------------------

[*] CVE: CVE-2014-0160
  Name: openssl_heartbeat_client_memory.rb
  Title: OpenSSL Heartbeat (Heartbleed) Client Memory Exposure
  Description: This module provides a fake SSL service that is intended to leak memory from client systems as they connect. This module is hardcoded for using the AES-128-CBC-SHA1 cipher.

[-] References
  URL: http://www.kb.cert.org/vuls/id/720951
  URL: https://www.us-cert.gov/ncas/alerts/TA14-098A
  URL: http://heartbleed.com/

---------------------------------------
```

### Usage: Start go-msfdb as REST API server  
```bash
$ go-msfdb server -h
Start go-msfdb HTTP server

Usage:
  go-msfdb server [flags]

Flags:
      --bind string     HTTP server bind to IP address (default "127.0.0.1")
      --dbpath string   /path/to/sqlite3 or SQL connection string (default "$PWD/go-msfdb.sqlite3")
      --dbtype string   Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
      --debug-sql       SQL debug mode
  -h, --help            help for server
      --port string     HTTP server port number (default "1327")

Global Flags:
      --config string    config file (default is $HOME/.go-msfdb.yaml)
      --debug            debug mode
      --log-dir string   /path/to/log (default "/var/log/go-msfdb")
      --log-json         output log as JSON
      --log-to-file      output log to file
```

###### Starting Server  
```bash
$ go-msfdb server

INFO[06-18|17:23:14] Starting HTTP Server...
INFO[06-18|17:23:14] Listening...                             URL=127.0.0.1:1327
```

###### Search Modules Get by cURL for CVE(eg. CVE-2019-0708)
```bash
$ curl http://127.0.0.1:1327/cves/CVE-2019-0708 | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1992  100  1992    0     0   628k      0 --:--:-- --:--:-- --:--:--  648k
[
  {
    "Name": "cve_2019_0708_bluekeep.rb",
    "Title": "CVE-2019-0708 BlueKeep Microsoft Remote Desktop RCE Check",
    "Description": "This module checks a range of hosts for the CVE-2019-0708 vulnerability by binding the MS_T120 channel outside of its normal slot and sending non-DoS packets which respond differently on patched and vulnerable hosts. It can optionally trigger the DoS vulnerability.",
    "CveID": "CVE-2019-0708",
    "References": [
      {
        "ID": 3058,
        "Link": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708"
      },
      {
        "ID": 3059,
        "Link": "https://zerosum0x0.blogspot.com/2019/05/avoiding-dos-how-bluekeep-scanners-work.html"
      }
    ]
  },
  {
    "Name": "cve_2019_0708_bluekeep_rce.rb",
    "Title": "CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free",
    "Description": "The RDP termdd.sys driver improperly handles binds to internal-only channel MS_T120, allowing a malformed Disconnect Provider Indication message to cause use-after-free. With a controllable data/size remote nonpaged pool spray, an indirect call gadget of the freed channel is used to achieve arbitrary code execution.  Windows 7 SP1 and Windows Server 2008 R2 are the only currently supported targets.  Windows 7 SP1 should be exploitable in its default configuration, assuming your target selection is correctly matched to the system's memory layout.  HKLM\\SYSTEM\\CurrentControlSet\\Control\\TerminalServer\\Winstations\\RDP-Tcp\\fDisableCam *needs* to be set to 0 for exploitation to succeed against Windows Server 2008 R2. This is a non-standard configuration for normal servers, and the target will crash if the aforementioned Registry key is not set!  If the target is crashing regardless, you will likely need to determine the non-paged pool base in kernel memory and set it as the GROOMBASE option.",
    "CveID": "CVE-2019-0708",
    "References": [
      {
        "ID": 3060,
        "Link": "https://github.com/zerosum0x0/CVE-2019-0708"
      },
      {
        "ID": 3061,
        "Link": "https://zerosum0x0.blogspot.com/2019/11/fixing-remote-windows-kernel-payloads-meltdown.html"
      }
    ]
  }
]
```
