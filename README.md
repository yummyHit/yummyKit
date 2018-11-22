# yummyKit
The yummyKit is a tool for spoofing, it to be used as a pentesting tool.
This tool is still in development and is under development.
We are currently adding a WiFi password cracking tool, and we are adding the ssl strip feature to spoofing already created.
Currently the yummyKit tool is the only tool that can perform basic arp spoofing functions.
If you want to use this tool, you can do the following.

First, you need to download the repository you are looking at. To do this, write the command as shown below.
```bash
$ git clone https://github.com/yummyHit/yummyKit
```

And once the download is complete, you must run the shell script. After giving permission to execute, execute it.
```bash
$ chmod +x repository.sh
$ ./repository.sh
```

You are downloading the necessary files to use the yummyKit tool. Required packages are listed below.
```bash
packages:
build-essential
libfontconfig1
mesa-common-dev
libglu1-mesa-dev
libpcap*
libnet1-*
qt5-qmake
qt5-default
libcurl4-gnutls-dev
```

If you using ubuntu version less than 12 major version, add to repository for qt and qtdeclarative5-dev instead of qt5-something.
```bash
repository: ppa:canonical-qt5-edgers/ubuntu1204-qt5
packages:
build-essential
libfontconfig1
mesa-common-dev
libglu1-mesa-dev
libpcap*
libnet1-*
qtdeclarative5-dev
```

It does not matter if you are using 32bit or 64bit.

Finally, you can run yummyKit.
```bash
$ ./yummyKit
```

Have fun!
