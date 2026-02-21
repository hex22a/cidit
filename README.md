# CLI CIDR calculator for IPv4 and IPv6

Calculate Network Ranges for a given CIDR (IPv4 and IPv6)

![Crates.io Version](https://img.shields.io/crates/v/cidit)
![CI](https://github.com/hex22a/cidit/actions/workflows/test.yml/badge.svg)

For example, `cidit 10.122.33.44/24` prints out the following information:

```shell
 ip_ver   cidr              address        prefix   network       first_usable   last_usable     broadcast       available   netmask   hostmask
 v4       10.122.33.44/24   10.122.33.44   24       10.122.33.0   10.122.33.1    10.122.33.254   10.122.33.255
```

**CIDR** stands for **Classless Inter-Domain Routing**. Learn more about CIDR [here](https://aws.amazon.com/what-is/cidr/)
or [here](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

## Install

With [Homebrew](https://brew.sh/) (recommended)

```shell
brew tap hex22a/cidit
```

```shell
brew install cidit
```

### Binaries

Check out [Releases](https://github.com/hex22a/cidit/releases) page to find binaries for Your platform

## Usage

```shell
# cidit --help to get more usage info
cidit 10.122.33.44/24
```

### Supports multiple CIDRs

```shell
cidit 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64
```

Output:

```shell
 ip_ver   cidr                          address                    prefix   network        first_usable   last_usable     broadcast       available   netmask                 hostmask
 v4       10.122.33.44/24               10.122.33.44               24       10.122.33.0    10.122.33.1    10.122.33.254   10.122.33.255
 v4       10.255.55.66/20               10.255.55.66               20       10.255.48.0    10.255.48.1    10.255.63.254   10.255.63.255
 v6       2001:db8:1::ab9:c0a8:102/64   2001:db8:1::ab9:c0a8:102   64       2001:db8:1::                                                  2^64        ffff:ffff:ffff:ffff::   ::ffff:ffff:ffff:ffff
```

### Different output formats

```shell
cidit -f json 10.122.33.44/24
# Prints: {"version":2,"data":[{"ip_version":"v4","cidr":"10.122.33.44/24","address":"10.122.33.44","prefix_length":24,"first_usable":"10.122.33.1","last_usable":"10.122.33.254","network":"10.122.33.0","broadcast":"10.122.33.255"}]}
```

Pretty print:

```shell
cidit -f json -p 10.122.33.44/24
```

Output:

```shell
{
  "version": 2,
  "data": [
    {
      "ip_version": "v4",
      "cidr": "10.122.33.44/24",
      "address": "10.122.33.44",
      "prefix_length": 24,
      "first_usable": "10.122.33.1",
      "last_usable": "10.122.33.254",
      "network": "10.122.33.0",
      "broadcast": "10.122.33.255"
    }
  ]
}
```

ndjson:

```shell
cidit 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64 -f ndjson

{"ip_version":"v4","cidr":"10.122.33.44/24","address":"10.122.33.44","prefix_length":24,"first_usable":"10.122.33.1","last_usable":"10.122.33.254","network":"10.122.33.0","broadcast":"10.122.33.255"}
{"ip_version":"v4","cidr":"10.255.55.66/20","address":"10.255.55.66","prefix_length":20,"first_usable":"10.255.48.1","last_usable":"10.255.63.254","network":"10.255.48.0","broadcast":"10.255.63.255"}
{"ip_version":"v6","cidr":"2001:db8:1::ab9:c0a8:102/64","address":"2001:db8:1::ab9:c0a8:102","prefix_length":64,"netmask":"ffff:ffff:ffff:ffff::","hostmask":"::ffff:ffff:ffff:ffff","network":"2001:db8:1::","subnet_size":"2^64"}
```

### Compile from sources

[Install Rust](https://rust-lang.org/tools/install/)

Clone this repo:

```shell
git clone git@github.com:hex22a/cidit.git && cd ./cidit
```

Run tests:

```shell
cargo test
```

Build the binary

```shell
cargo build
```

This will create a binary in `target > debug` directory
