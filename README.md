<h1 align="center">
    <br/>
    <!-- href to crates.io/butterfly -->
    <img src="./logo.png" width="128" height="auto">
    <br/>
    butterfly
    <br/>
</h1>
<div align="center">
    <!--
    badges:
        shields.io
            crates.io version
            docs.rs quick link
            crates.io license
    -->
    <a href="TODO" target="_blank">
        <img src="https://img.shields.io/static/v1?label=docs&message=online&color=success">
    </a>
</div>

## Description
This crate brings stateful fuzzing capabilities to LibAFL via
1. __Packet-based Inputs__: Inputs that are vectors of packets and can be loaded from pcap files
2. __Packet-based Mutations__: Mutators that can be applied to selected packets only (havoc and protocol-aware mutations like packet insertion, deletion and reordering)
3. __State-Graph Inference__: Observe which states your target goes through as it processes the individual packets and identify when it enters a new state or makes a new state transition

## Installation
`butterfly` uses rust 2021 edition, so execute
```sh
rustup toolchain install nightly
```

and in your `Cargo.toml` insert
```toml
[dependencies]
butterfly = "*"
```

__Warning about LibAFL version:__      
Unfortunately the version of LibAFL on crates.io is fairly old (0.7.1 at the time of writing this) so we use the [github version](https://github.com/AFLplusplus/LibAFL) with more features and bug fixes. This means
that you have to use the github version in your application too.     
Add the following patch note to your `Cargo.toml` file:
```toml
[patch.crates-io]
libafl = { git = "https://github.com/AFLplusplus/LibAFL" }
```

## How to use
Start with [the wiki]() and [the documentation]().    
Also, [some examples]() may be helpful.

<hr/>
<div align="center">
&#169; by Fraunhofer FKIE 2022
</div>

<!--
WIKI
====

- A theoretical introduction
    - note to skip to next part if not interested in theory
    - a little bit from AFLNet paper / StateAFL paper
- Components overview
    - Input: HasPackets, HasPcapRepresentation, HasHavocMutations
    - Mutators:
        - (all mutators)
        - Scheduler
    - Observer:
        - builds a StateGraph (example image FTP)
        - `TargetState` type
    - Feedback
    - Monitor
    - Executor
        - responsible for recording state
        - custom executor needed
- How to create a fuzzer
    - have compile-tests here
    
EXAMPLES
========
- AFLNet
-->
