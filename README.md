# certman - Certificate Management Service

issues self-signed CA and TLS Web Server certificates

## Requirements

* .NET 6 SDK
* GNU Make

## Installation

if you build on the server, simply do:
```sh
make && sudo make install
```

or you can cross-build for your target platform:
```sh
make RID=linux-x64
```

## Troubleshooting

```sh
# Linux
journalctl -fu certman -o cat

# FreeBSD/macOS
tail -f /var/log/certman.log
````
