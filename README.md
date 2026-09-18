# CLI CIDR calculator for IPv4 and IPv6

Calculate Network Ranges for a given CIDR (IPv4 and IPv6)

![Crates.io Version](https://img.shields.io/crates/v/cidit)
![CI](https://github.com/hex22a/cidit/actions/workflows/test.yml/badge.svg)

For example, `cidit 10.122.33.44/24` prints out the following information:

```shell
 IP_VER   CIDR              ADDRESS        PREFIX   NETWORK       FIRST_USABLE   LAST_USABLE     BROADCAST       AVAILABLE   NETMASK   HOSTMASK
 v4       10.122.33.44/24   10.122.33.44   24       10.122.33.0   10.122.33.1    10.122.33.254   10.122.33.255
```

**CIDR** stands for **Classless Inter-Domain Routing**.
Learn more about CIDR on [AWS](https://aws.amazon.com/what-is/cidr/)
or on [Wikipedia](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

## Install

With [Homebrew](https://brew.sh/) (recommended)

```bash
brew tap hex22a/cidit
```

```bash
brew install cidit
```

### Binaries

Check out [Releases](https://github.com/hex22a/cidit/releases) page
to find binaries for Your platform

## Usage

```bash
# cidit --help to get more usage info
cidit 10.122.33.44/24
```

### Supports multiple CIDRs

```bash
cidit 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64
```

Output:

```bash
 IP_VER   CIDR                          ADDRESS                    PREFIX   NETWORK        FIRST_USABLE   LAST_USABLE     BROADCAST       AVAILABLE   NETMASK                 HOSTMASK
 v4       10.122.33.44/24               10.122.33.44               24       10.122.33.0    10.122.33.1    10.122.33.254   10.122.33.255
 v4       10.255.55.66/20               10.255.55.66               20       10.255.48.0    10.255.48.1    10.255.63.254   10.255.63.255
 v6       2001:db8:1::ab9:c0a8:102/64   2001:db8:1::ab9:c0a8:102   64       2001:db8:1::                                                  2^64        ffff:ffff:ffff:ffff::   ::ffff:ffff:ffff:ffff
```

### Different output formats

```bash
cidit -f json 10.122.33.44/24
# Prints: {"version":2,"data":[{"ip_version":"v4","cidr":"10.122.33.44/24","address":"10.122.33.44","prefix_length":24,"first_usable":"10.122.33.1","last_usable":"10.122.33.254","network":"10.122.33.0","broadcast":"10.122.33.255"}]}
```

Pretty print:

```bash
cidit -f json -p 10.122.33.44/24
```

Output:

```bash
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

```bash
cidit 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64 -f ndjson

{"ip_version":"v4","cidr":"10.122.33.44/24","address":"10.122.33.44","prefix_length":24,"first_usable":"10.122.33.1","last_usable":"10.122.33.254","network":"10.122.33.0","broadcast":"10.122.33.255"}
{"ip_version":"v4","cidr":"10.255.55.66/20","address":"10.255.55.66","prefix_length":20,"first_usable":"10.255.48.1","last_usable":"10.255.63.254","network":"10.255.48.0","broadcast":"10.255.63.255"}
{"ip_version":"v6","cidr":"2001:db8:1::ab9:c0a8:102/64","address":"2001:db8:1::ab9:c0a8:102","prefix_length":64,"netmask":"ffff:ffff:ffff:ffff::","hostmask":"::ffff:ffff:ffff:ffff","network":"2001:db8:1::","subnet_size":"2^64"}
```

### CIDR from a range

Use **--range** option and provide a list of ranges to find CIDRs
that fit each range. Ranges are treated separately.
Supported formats: `ip..ip`, `ip-ip`, `ip ip`.
By default it finds a smallest CIDR that fits the entire range.

```bash
cidit -r 10.0.0.10..10.0.0.20
 IP_VER   START       END         CIDR           CIDR_START   CIDR_END
 v4       10.0.0.10   10.0.0.20   10.0.0.0/27    10.0.0.0     10.0.0.31
 v4       10.0.0.20   10.0.0.30   10.0.0.20/28   10.0.0.16    10.0.0.31
```

To find an exact match use **--exact** option

```bash
cidit -er 10.0.0.10..10.0.0.20
 IP_VER   START       END         CIDR           CIDR_START   CIDR_END
 v4       10.0.0.10   10.0.0.20   10.0.0.10/31   10.0.0.10    10.0.0.11
 v4       10.0.0.10   10.0.0.20   10.0.0.12/30   10.0.0.12    10.0.0.15
 v4       10.0.0.10   10.0.0.20   10.0.0.16/30   10.0.0.16    10.0.0.19
 v4       10.0.0.10   10.0.0.20   10.0.0.20/32   10.0.0.20    10.0.0.20
```

### Parallel execution

cidit is a single-threaded app.
To not confuse the users it will not support concurrent jobs.
However, If You want to process large amount of
data You can do so with tools like **GNU parallel** or **xargs**

```bash
parallel cidit -H ::: 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64
```

```bash
echo 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64 | xargs -n 1 -P0 cidit -H
```

> _Note:_ It performs best used with `--format ndjson` option
> as ndjson mode is lazy and uses **O(1)** memory

```bash
parallel cidit -f ndjson ::: 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64
```

```bash
echo 10.122.33.44/24 10.255.55.66/20 2001:db8:1::ab9:c0a8:102/64 | xargs -n 1 -P0 cidit -f ndson
```

### Compile from sources

To get the latest unreleased version of cidit

[Install Rust](https://rust-lang.org/tools/install/)

Clone this repo:

```bash
git clone git@github.com:hex22a/cidit.git && cd ./cidit
```

Run tests:

```bash
cargo test
```

Build the binary

```bash
cargo build --release
```

This will create a binary in `target > release` directory
