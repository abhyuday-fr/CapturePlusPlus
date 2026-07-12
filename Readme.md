# CapturePlusPLus

This is a Network Monitor and packets analaysing CLI tool made entirely in C++ and TUI is done with the FTXUI library.

# Example
![demo gif](demo.gif)

# How to build and run
1. Just run `./scripts/build.sh` and an executable will be generated in a `build/` dir.
2. `cd build/` and then run the executable, it can be done by two ways
    - Live analaysis: `./cappp -i wlp3s0-c 10`
    - .pcap file analysis: `./cappp -r ../tests/fixtures/sample.pcap -c 5`

