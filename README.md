# SyzMini: Optimizing Input Minimization in Kernel Fuzzing

## Main Components

1. Influence-guided call removal optimization strategy
2. Type-informed argument simplification optimization strategy

## Setup
1. Dependencies
    ```
    sudo apt-get update
    sudo apt-get install -y make git gcc flex bison libelf-dev libssl-dev bc qemu-system-x86 build-essential debootstrap
    ```

2. Install Go language support before compiling SyzMini.

    ```
    wget https://dl.google.com/go/go1.22.1.linux-amd64.tar.gz
    tar -xf go1.22.1.linux-amd64.tar.gz
    export GOROOT=`pwd`/go
    export PATH=$GOROOT/bin:$PATH
    ``` 

3. Also, SyzMini requires [**KVM**](https://help.ubuntu.com/community/KVM/Installation)  enabled.

4. Build kernel (taking v5.15 as example)

    ``` 
    **  Checkout Linux Kernel source
    git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
    cd linux
    git checkout v5.15

    ** Generate default configs
    make defconfig

    **  Enable required config options
    # Coverage collection.
    CONFIG_KCOV=y
    # Debug info for symbolization.
    CONFIG_DEBUG_INFO_DWARF4=y
    # Memory bug detector
    CONFIG_KASAN=y
    CONFIG_KASAN_INLINE=y
    # Required for Debian Stretch and later
    CONFIG_CONFIGFS_FS=y
    CONFIG_SECURITYFS=y

    ** make olddefconfig

    ** Build the Kernel
    make -j`nproc`
    ``` 

5. Image

    ``` 
    ** Install debootstrap
    sudo apt install debootstrap

    ** Create Debian Bullseye Linux image
    mkdir image
    cd image/
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
    chmod +x create-image.sh
    ./create-image.sh
    ``` 

6. Build SyzMini

    ```
    ** Clone SyzMini and compile the fuzzer. Make sure Go is installed.
    cd SyzMini
    make
    ```

7. Run SyzMini (take v515 as example)

    ```
    cd SyzMini/bin 
    ./syz-manager -config your.cfg -influence_read ./influencev5.15.txt
    ```

    The `syz-manager` process will wind up VMs and start fuzzing in them.
    The `-config` command line option gives the location of the configuration file, which is described [here](configuration.md).
    Found crashes, statistics and other information is exposed on the HTTP address specified in the manager config.
    The "-influence_read" command line option gives the location of the influence file, if you don't configure it, SyzMini will adopt the static influence relation.

