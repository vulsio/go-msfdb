# go-msfdb
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/takuzoo3868/go-msfdb/blob/master/LICENSE)

This is a tool for searching CVEs in Metasploit-Framework modules from [msfdb-list](https://github.com/vulsio/msfdb-list).
<!-- Exploits are inserted at sqlite database(go-msfdb) can be searched by command line interface.
In server mode, a simple Web API can be used. -->

### Installation for local deployment  
###### Requirements  
go-exploitdb requires the following packages.
- git
- SQLite3, MySQL, PostgreSQL
- lastest version of go
    - https://golang.org/doc/install

###### Install go-exploitdb
```bash
$ mkdir -p $GOPATH/src/github.com/takuzoo3868
$ cd $GOPATH/src/github.com/takuzoo3868
$ git clone https://github.com/takuzoo3868/go-msfdb.git
$ cd go-msfdb
$ make install
```

----

### Usage: Fetch and Insert Module's data  
```bash
$ Fetch the data of msfdb-list

Usage:
  go-msfdb fetch [command]

Available Commands:
  msfdb       Fetch the data of metasploit-framework cve's list

Flags:
  -h, --help   help for fetch

Global Flags:
      --config string       config file (default is $HOME/.go-msfdb.yaml)
      --dbpath string       /path/to/sqlite3 or SQL connection string
      --dbtype string       Database type to store data in (sqlite3, mysql, postgres or redis supported)
      --debug               debug mode (default: false)
      --debug-sql           SQL debug mode
      --http-proxy string   http://proxy-url:port (default: empty)
      --log-dir string      /path/to/log
      --log-json            output log as JSON
      --quiet               quiet mode (no output)

Use "go-msfdb fetch [command] --help" for more information about a command.
```

###### Fetch and Insert msfdb-list  
```bash
$ go-msfdbdb fetch msfdb
```