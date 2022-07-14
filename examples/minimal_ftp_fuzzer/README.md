# Minimal FTP fuzzer

This example demonstrates how to setup a blackbox FTP fuzzer
with butterfly.    
A detailed walkthrough that explains every part of the harness
can be found in [the wiki](TODO: Path to page).

## Building
```
git submodule update --init --recursive
cd LightFTP/Source/Release
CC=clang CFLAGS='-fsanitize=address' make
cd ../../..

# Setup the FTP root
mkdir -p /tmp/ftproot/dir
echo content > /tmp/ftproot/dir/file
```

## Running
Start the FTP server
```
nohup ./LightFTP/Source/Release/fftp fuzz.conf > /dev/null &
```

Start the fuzzer
```
cargo run --release
```

Eventually, kill the server
```
killall -w fftp
```

## Results
After 50 iterations with only basic mutations like duplication, reordering and deletion we get the following state graph:     
<br>
![](./state-graph.png)
<br><br>

