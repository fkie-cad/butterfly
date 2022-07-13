<h1 align="center">
    <br/>
    <a href="https://crates.io/crates/butterfly-fuzz">
        <img src="./logo.png" width="128" height="auto">
    </a>
    <br/>
    butterfly
    <br/>
</h1>
<div align="center">
    <a href="https://crates.io/crates/butterfly-fuzz">
        <img src="https://img.shields.io/crates/v/butterfly-fuzz?color=success">
    </a>&nbsp;
    <a href="https://docs.rs/butterfly-fuzz">
        <img src="https://img.shields.io/static/v1?label=docs&message=online&color=success">
    </a>&nbsp;
    <img src="https://img.shields.io/crates/l/butterfly-fuzz">
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
butterfly = { version = "0.1.0", package = "butterfly-fuzz" }
```

## How to use
Start with [the wiki](https://github.com/fkie-cad/butterfly/wiki) and [the docs](https://docs.rs/butterfly-fuzz).
Also, [some examples](./examples) may be helpful.

For questions, feature requests or bug reports please [create an issue](https://github.com/fkie-cad/butterfly/issues/new).

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
    - create a new input type
        - all traits...
    - how to observe state in the executor (which type)
        - create StateObserver
        - create StateFeedback
    - mutations
    
EXAMPLES
========
- AFLNet
-->
