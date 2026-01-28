# CIDR calculator for CLI

Calculate Network Ranges for a given CIDR.

For example, 10.122.33.44/24 prints out the following information:

```
Subnet mask: 255.255.255.0
First usable IP: 10.122.33.1
Last usable IP: 10.122.33.254
Broadcast IP: 10.122.33.255
```

**CIDR** stands for **Classless Inter-Domain Routing**. Learn more about CIDR [here](https://aws.amazon.com/what-is/cidr/)
or [here](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

### Install binary

*TBD*

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

### Run

```shell
cd target/debug
```

```shell
# ./cidit --help is also supported
./cidit 10.122.33.44/24
```

or alternatively You can run it via cargo from the project root

```shell
cargo run -- 10.122.33.44/24
```