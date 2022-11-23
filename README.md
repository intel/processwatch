Process Watch
=============

This is an example of Process Watch running on an Intel® NUC running the [LULESH](https://github.com/LLNL/LULESH) workload. Note the presence of AVX, AVX2, and VFMA instructions.
![image](https://user-images.githubusercontent.com/87155110/203642236-756ae342-b860-4cb4-8f8d-7de494218eeb.png)

Overview
--------

Process Watch displays per-process instruction mix in real-time, organizing these
instructions into categories. It offers a simple, `curses`-style interface as well
as a CSV output.

Runtime Requirements
--------------------

For the binary releases, the only requirement is that you have BTF metadata in your kernel.  If the file
`/sys/kernel/btf/vmlinux` exists on your system, then you have it. If not, then your
kernel does not have BTF metadata.

If your kernel does not have this feature, you can enable it by installing or compiling
a kernel with the `CONFIG_DEBUG_INFO_BTF` configuration option enabled.  Keep in mind that
if you're compiling the kernel yourself, you need to install the `pahole` commandline utility
to compile a kernel with this option enabled.

There are two ways to compile Process Watch:
1. `./build.sh`. This executable should work in kernel version `5.8.0` and newer.
2. `./build.sh --legacy`. This executable is for kernels before `5.8.0`.

Building
--------

First, clone the repository:
```
git clone --recursive https://github.com/intel/processwatch.git
```

If you've already cloned without `--recursive`, go into the repository directory and issue:
```
git submodule init
git submodule update
```

If you want to compile the tool, there are a few common packages that you'll need to install
on your system:
1. CMake
2. Clang
3. LLVM (e.g. `llvm-strip`)
4. `bpftool`
5. NCURSES
6. POSIX Threads
7. `libelf`

You can install these on Ubuntu 20.04, 21.10, or 22.04 by issuing the following:
```
sudo apt-get update
sudo apt-get install libelf-dev cmake clang llvm linux-tools-generic
```

On CentOS 8.4, CentOS 8 Stream, and CentOS 9 Stream:
```
sudo yum update
sudo yum install cmake bpftool clang llvm-toolset ncurses-devel
```

On Amazon Linux 2, you can do:
```
sudo yum update
sudo yum install bpftool zlib-devel zlib-static \
  elfutils-libelf-devel-static clang cmake3 ncurses-static llvm \
  glibc-static
```

Please keep in mind that if you're running a custom kernel, you'll need to compile
and install `bpftool` in the  `tools/bpf/bpftool` directory of your kernel's source tree.

Now, check your kernel version:
```
uname -a
```

If you have a kernel older than 5.8.0, compile with:
```
./build.sh --legacy
```

If your kernel is 5.8.0 or newer, do:
```
./build.sh
```
   
Interactive Mode
----------------

This is the default mode, so no command-line arguments are necessary to enable it.
Use `q` to quit and use the right and left arrow keys to scroll.

CSV Mode
----------

To enable this mode, pass `--csv=[filename]` on the command-line. Output will go to
`[filename]`. Send `SIGTERM` to kill it.

Usage
-----

| Long Form                  | Short Form | Description                                                          |
|----------------------------|------------|----------------------------------------------------------------------|
| `--interval=[sec]`         | `-i`       | Modifies the interval length. Default is 2.                          |
| `--csv=[filename]`         | `-c`       | Enables CSV output to `[filename]`. Kill with SIGTERM.               |
| `--pid=[pid]`              | `-p`       | Profiles a specific PID rather than all processes.                   |
| `--mnemonics`              | `-m`       | Displays individual instruction mnemonics instead of categories.     |
| `--sample_period=[val]`    | `-s`       | Sets the `perf` rate at which to sample instructions.                |
| `--filter=[val]`           | `-f`       | Filters instruction mnemonics or categories. Ignores case.           |
| `--time=[val]`             | `-t`       | In CSV mode, limits runtime to a number of seconds.                  |

Known Build Issues
------------------

# Ubuntu `bpftool` Issue

_This happens particularly on Ubuntu 20.04, which includes a version of `bpftool` that
is too old to read the kernel's BTF information._

Sometimes when you install `linux-tools-common` or `linux-tools-generic`, you get
a version of `bpftool` that is not associated with the kernel that you're currently running.
This happens when there is a kernel package update, but you're still running an older kernel.
Similarly, on Ubuntu 20.04, you may get a `bpftool` version that fails to read the BTF
information (which is stored in `/sys/kernel/btf/vmlinux`).

Resolving this issue is simple, but depends on your situation.
1. If you're on Ubuntu 20.04, install `linux-tools-*` for a _newer_ kernel. I chose the
   `linux-tools-5.8.0-63-generic` package.
2. If you're running a newer Ubuntu version, you might just want to install `linux-tools-$(uname -r)`
   to install the Linux tools for your currently-running kernel.
3. A longer-term solution is to simply upgrade your system (`sudo apt-get update && sudo apt-get upgrade`),
   install the `linux-tools-generic` package, and then reboot the machine into the updated kernel.

If you need to tell the build system to use a specific version of `bpftool`, simply edit the `BPFTOOL` variable
in `build.sh`. For example, if you're on Ubuntu 20.04 and have installed ``linux-tools-5.8.0-63-generic`,
you might want to edit that variable to become something like:
```
export BPFTOOL="/usr/lib/linux-tools/5.8.0-63-generic/bpftool"
```
