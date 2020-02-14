#!/usr/bin/env python3

from .definitions import *
import logging

## Class used to build Mimikatz-compatible minidump
class Minidump:
    ## Class constructor
    def __init__(self):
        self.systeminfo = {}
        self.memoryinfo = []
        self.memory64 = []
        self.modules = []

        # TODO: Some of the constants are specific to building Mimikatz-compatible minidumps
        self.MINIDUMP_HEADER_LEN = 32
        self.STREAM_COUNT = 4

    ## Parse memory dump.
    #
    # Not implemented
    # @param data dump
    def parse(self, data):
        print("Not implemented yet")

    ## Parse memory dump.
    #
    # Not implemented
    # @param filepath path to memory dump.
    def parsefile(self, filepath):
        print("Not implemented yet")

    ## Build systeminfo stream.
    #
    # @param rva address of data.
    def _build_systeminfo_stream(self, rva):
        logging.debug(self.systeminfo)
        self.systeminfo['CSDVersionRva'] = rva
        blob = MINIDUMP_STRING.build(dict(String=''))
        stream = MINIDUMP_SYSTEM_INFO.build(self.systeminfo)
        return stream, blob

    ## System info setter.
    #
    # @param si system info
    def set_systeminfo(self, si):
        logging.debug("Setting systeminfo", si)
        self.systeminfo = si

    ## Build memoryinfo list stream.
    def _build_memoryinfo_list_stream(self):
        return MINIDUMP_MEMORY_INFO_LIST.build(dict(NumberOfEntries=len(self.memoryinfo), memory_infos=self.memoryinfo))

    ## Memory info list info setter.
    #
    # @param mi_list memory info list
    def set_memoryinfo_list(self, mi_list):
        logging.debug("Setting memoryinfo list")
        self.memoryinfo = mi_list

    ## Build memory64 stream.
    #
    # @param BaseRva addres of data
    def _build_memory64_stream(self, BaseRva):
        memory_ranges = []
        blob = []
        for m in self.memory64:
            start, size, data = m
            memory_ranges.append(dict(StartOfMemoryRange=start, DataSize=size))
            blob.append(data)

        stream = MINIDUMP_MEMORY64_LIST.build(dict(NumberOfMemoryRanges=len(self.memory64), BaseRva=BaseRva, MemoryRanges=memory_ranges))
        blob = b''.join(blob)

        logging.debug("Done")
        return stream, blob

    ## memory64 setter.
    #
    # @param m64_list memory64 list
    def set_memory64(self, m64_list):
        logging.debug("Setting memory64 list")
        self.memory64 = m64_list

    def _build_modulelist_stream(self, rva):
        logging.debug("RVA1: %x" % (rva))
        blobs = []
        modules = []
        for m in self.modules:
            module_name = m[0]
            blob = MINIDUMP_STRING.build(dict(String=module_name))
            blobs.append(blob)
            module = dict(BaseOfImage=m[1], SizeOfImage=m[2], ModuleNameRva=rva)
            rva += len(blob)
            modules.append(module)
        logging.debug("RVA2: %x" % (rva))

        stream = MINIDUMP_MODULE_LIST.build(dict(NumberOfModules=len(modules), modules=modules))
        blobs = b''.join(blobs)
        return rva, stream, blobs

    ## Module list setter.
    #
    # @param module_list module list
    def set_module_list(self, module_list):
        logging.debug("Setting module list")
        self.modules = module_list

    ## Build minidump
    def build(self):
        logging.debug("Building minidump")

        # Build header, set offset to directory
        output = b''
        hdr = MINIDUMP_HEADER.build(dict(NumberOfStreams=self.STREAM_COUNT, StreamDirectoryRva=self.MINIDUMP_HEADER_LEN))
        output += hdr

        rva = self.MINIDUMP_HEADER_LEN + minidump_directory_entry.sizeof()*self.STREAM_COUNT
        logging.debug(hex(rva))

        wanted_streams = [Memory64ListStream, MemoryInfoListStream, SystemInfoStream, ModuleListStream]
        stream_data = []
        # Build directory, read stream data, set new offsets to streams
        for t in wanted_streams:            
            s = dict(StreamType=t,Location={})
            if t == Memory64ListStream:
                logging.debug("Memory64ListStream should be at offset", hex(rva))
                s['Location']['DataSize'] = 16 + MINIDUMP_MEMORY_DESCRIPTOR64.sizeof()*len(self.memory64)
            elif t == SystemInfoStream:
                logging.debug("SystemInfoStream should be at offset", hex(rva))
                s['Location']['DataSize'] = MINIDUMP_SYSTEM_INFO.sizeof()
            elif t == MemoryInfoListStream:
                logging.debug("MemoryInfoListStream should be at offset", hex(rva))
                s['Location']['DataSize'] = 16 + MINIDUMP_MEMORY_INFO.sizeof()*len(self.memoryinfo)
            elif t == ModuleListStream:
                logging.debug("ModuleListStream should be at offset", hex(rva))
                s['Location']['DataSize'] = 4 + MINIDUMP_MODULE.sizeof()*len(self.modules)
        
            s['Location']['RVA'] = rva
            rva += s['Location']['DataSize']
            output += minidump_directory_entry.build(s)

            stream_data.append(s)

        expected_tail_start = rva
        logging.debug(hex(expected_tail_start))
        tail = b''

        # Set offsets, build streams
        for i,d in enumerate(stream_data):
            t = wanted_streams[i]

            if t == Memory64ListStream:
                rva_before = rva
                logging.debug("\nRVA before: %x" % (rva_before))

                stream, blob = self._build_memory64_stream(rva)
                tail += blob
                rva += len(blob)
                logging.debug("Writing %x bytes of Memory64ListStream to offset %x" % (len(stream), len(output)))
                output += stream
                logging.debug("rva is now %x" % (rva))
                logging.debug("Advanced RVA %x bytes, tail length is %x" % (rva-rva_before, len(tail)))
            elif t == SystemInfoStream:
                rva_before = rva
                logging.debug("\nRVA before: %x" % (rva_before))

                stream, blob = self._build_systeminfo_stream(rva)
                tail += blob
                rva += len(blob)
                logging.debug("Writing SystemInfoStream to offset", hex(len(output)))
                output += stream
                logging.debug("rva is now %x" % (rva))
                logging.debug("Advanced RVA %x bytes, tail length is %x" % (rva-rva_before, len(tail)))
            elif t == MemoryInfoListStream:
                rva_before = rva
                logging.debug("\nRVA before: %x" % (rva_before))

                logging.debug("Writing MemoryInfoListStream to offset", hex(len(output)))
                output += self._build_memoryinfo_list_stream()
                logging.debug("Advanced RVA %x bytes, tail length is %x" % (rva-rva_before, len(tail)))
            elif t ==  ModuleListStream:
                rva_before = rva
                logging.debug("\nRVA before: %x" % (rva_before))

                rva, stream, blob = self._build_modulelist_stream(rva)
                tail += blob
                logging.debug("Writing ModuleListStream to offset", hex(len(output)))
                output += stream
                logging.debug("rva is now %x, output length is %x" % (rva, len(output)))
                logging.debug("Advanced RVA %x bytes, tail length is %x" % (rva-rva_before, len(tail)))
        
        logging.debug("Expected tail start: %x, got: %x" % (expected_tail_start, len(output)))
        logging.debug(len(output) + len(tail), rva)
        return output + tail