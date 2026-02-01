# CIDR calculator for CLI

Calculate Network Ranges for a given CIDR.

![Crates.io Version](https://img.shields.io/crates/v/cidit)
![CI](https://github.com/hex22a/cidit/actions/workflows/test.yml/badge.svg)

For example, `cidit 10.122.33.44/24` prints out the following information:

```
 cidr              first_usable   last_usable     subnet        broadcast     
 10.122.33.44/24   10.122.33.1    10.122.33.254   10.122.33.0   10.122.33.255 
```

**CIDR** stands for **Classless Inter-Domain Routing**. Learn more about CIDR [here](https://aws.amazon.com/what-is/cidr/)
or [here](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

### Install

With [Homebrew](https://brew.sh/) (recommended)

```shell
brew tap hex22a/cidit
```

```shell
brew install cidit
```

##### Binaries

Check out [Releases](https://github.com/hex22a/cidit/releases) page to find binaries for Your platform

### Usage

```shell
# cidit --help to get more usage info
cidit 10.122.33.44/24
```

#### Different output formats

```shell
cidit -f json 10.122.33.44/24
# Prints: {"cidr":"10.122.33.44/24","first_usable":"10.122.33.1","last_usable":"10.122.33.254","subnet":"10.122.33.0","broadcast":"10.122.33.255"}
```

or alternatively You can run it via cargo from the project root

```shell
cargo run -- 10.122.33.44/24
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