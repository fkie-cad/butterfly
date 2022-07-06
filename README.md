<h1 align="center">
    <!-- href to docs.rs/butterfly -->
    <img src="./logo.png" width="128" height="auto">
    <br/>
    butterfly
    <br/>
</h1>
<p align="center">
    LibAFL components for stateful fuzzing
</p>
<div align="center">
    <!--
    badges:
        shields.io
            crates.io version
            (crates.io downloads)
            docs.rs quick link
            crates.io license
    -->
    <a href="TODO" target="_blank">
        <img src="https://img.shields.io/static/v1?label=docs&message=online&color=success">
    </a>
</div>

## Description
This crate contains
- Inputs that are vectors of packets
- can be loaded from pcap files
- mutations that mutate one packet individually
- protocol-aware mutations
    - packet insertion, deletion, reordering
- state observation channel that builds a StateGraph
  paire with feedback mechanism that detects new states or state transitions

## Installation
Dependencies:
- nightly rust
- LibAFL certain version

## How to use
see the docs
