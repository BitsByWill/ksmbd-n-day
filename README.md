# README

This repo accompanies my research article [Eternal-Tux: Crafting a Linux Kernel KSMBD 0-Click RCE Exploit from N-Days](https://www.willsroot.io/2025/09/ksmbd-0-click.html), in which I develop a POC for n-days from 2023: CVE-2023-52440 and CVE-2023-4130.

I provide the kernel .config, a kernel run script, an image build script, and the POC.

The image creation script comes from [Syzkaller](https://github.com/google/syzkaller/blob/master/tools/create-image.sh). The diff for [impacket](https://github.com/fortra/impacket/tree/master) comes from commit 7561038277f4b08a16f37aac886cfe0193e75434.

This is solely for research purposes only. In fact, this POC was designed on an extremely out of date LTS kernel (6.1.45), on a custom kernel config, and on a custom build toolchain. 
