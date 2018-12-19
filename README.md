# UIND

UIND is a very simple DNS server and proxy.

## Command Line

```
./uind [-d/-dd] [IP:PORT] [CONF-FILE]
```

Note: the order is fixed.

* `-d` prints more information which might be interesting
* `-dd` prints debugging information
* `IP:PORT` (default: 202.141.178.13:53) points to the remote DNS server, in case no local answers are found.
* `CONF-FILE` (default: `dnsrelay.txt`) is the local hosts file. The config file must exist.
