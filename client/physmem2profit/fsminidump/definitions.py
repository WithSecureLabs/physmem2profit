#!/usr/bin/env python3

from construct import Struct, Const, Int64ul, Int32ul, Int16ul, Int8ul, Hex, Array, this, Probe, GreedyBytes, Pointer, Switch, Byte, PascalString, Tell, len_, RawCopy, Rebuild, Computed, Default

MINIDUMP_SIGNATURE = b'\x4d\x44\x4d\x50'
MINIDUMP_VERSION = b'\x93\xa7'

# https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
VS_FIXEFILEINFO_SIGNATURE = 0xFEEF04BD

SystemInfoStream = 7
Memory64ListStream = 9
MemoryInfoListStream = 16
ModuleListStream = 4

minidump_location_descriptor = Struct(
    "DataSize" / Int32ul,
    "RVA" / Int32ul
)

# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_system_info
MINIDUMP_SYSTEM_INFO = Struct(
    "ProcessorArchitecture" / Default(Int16ul, 9),
    "ProcessorLevel" / Default(Int16ul, 6),
    "ProcessorRevision" / Default(Int16ul, 0),
    "NumberOfProcessors" / Default(Int8ul, 1),
    "ProductType" / Default(Int8ul, 0),
    "MajorVersion" / Int32ul,
    "MinorVersion" / Int32ul,
    "BuildNumber" / Int32ul,
    "PlatformId" / Default(Int32ul, 0),
    "CSDVersionRva" / Hex(Int32ul),
    "Reserved1" / Default(Int32ul, 0),
    "CPUInformation" / Default(Int32ul[6], [0,0,0,0,0,0])

    #"CSDVersion" / Pointer(this.CSDVersionRVA, PascalString(Int32ul, "utf-16"))
    #"CSDVersion" / Rebuild(Computed(lambda this: get_string(Pointer(this.CSDVersionRVA, PascalString(Int32ul, "utf-16")))), 0)
)

# https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
VS_FIXEDFILEINFO = Struct(
    "dwSignature" / Hex(Const(VS_FIXEFILEINFO_SIGNATURE, Int32ul)),
    "dwStructVersion" / Default(Int32ul, 0),
    "dwFileVersionMS" / Default(Int32ul, 0),
    "dwFileVersionLS" / Default(Int32ul, 0),
    "dwProductVersionMS" / Default(Int32ul, 0),
    "dwProductVersionLS" / Default(Int32ul, 0),
    "dwFileFlagsMask" / Default(Hex(Int32ul), 0),
    "dwFileFlags" / Default(Hex(Int32ul), 0),
    "dwFileOS" / Default(Int32ul, 0),
    "dwFileType" / Default(Int32ul, 0),
    "dwFileSubType" / Default(Int32ul, 0),
    "dwFileDateMS" / Default(Int32ul, 0),
    "dwFileDateLS" / Default(Int32ul, 0)
)

MINIDUMP_MODULE = Struct(
    "BaseOfImage" / Hex(Int64ul),
    "SizeOfImage" / Int32ul,
    "CheckSum" / Default(Int32ul, 0),
    "TimeDateStamp" / Default(Int32ul, 0),
    "ModuleNameRva" / Hex(Int32ul),
    "VersionInfo" / VS_FIXEDFILEINFO,
    "CvRecord" / Default(minidump_location_descriptor, dict(RVA=0, DataSize=0)),
    "MiscRecord" / Default(minidump_location_descriptor, dict(RVA=0, DataSize=0)),
    "Reserved0" / Default(Int64ul, 0),
    "Reserved1" / Default(Int64ul, 0),

    #"ModuleName" / Pointer(this.ModuleNameRva, PascalString(Int32ul, "utf-16")),
    #"CvRecordData" / Pointer(this.CvRecord.RVA, Byte[this.CvRecord.DataSize]),
    #

    #"ModuleName" / Computed(lambda this: get_string(Pointer(this.ModuleNameRva, PascalString(Int32ul, "utf-16")))),
    #"CvRecordData" / Computed(lambda this: get_string(Pointer(this.CvRecord.RVA, Byte[this.CvRecord.DataSize]))),
    #"MiscRecordData" / Computed(lambda this: get_string(Pointer(this.MiscRecord.RVA, Byte[this.MiscRecord.DataSize])))
)

MINIDUMP_MODULE_LIST = Struct(
    "NumberOfModules" / Int32ul,
    "modules" / MINIDUMP_MODULE[this.NumberOfModules]
)

# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_info
MINIDUMP_MEMORY_INFO = Struct(
    "BaseAddress" / Hex(Int64ul),
    "AllocationBase" / Hex(Int64ul),
    "AllocationProtect" / Hex(Int32ul),
    "__alignment1" / Default(Int32ul, 0),
    "RegionSize" / Int64ul,
    "State" / Int32ul,
    "Protect" / Hex(Int32ul),
    "Type" / Int32ul,
    "__alignment2" / Default(Int32ul, 0)
)

# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_info_list
MINIDUMP_MEMORY_INFO_LIST = Struct(
    "SizeOfHeader" / Default(Int32ul, 16),
    "SizeOfEntry" / Default(Int32ul, MINIDUMP_MEMORY_INFO.sizeof()),
    "NumberOfEntries" / Int64ul,
    "memory_infos" / MINIDUMP_MEMORY_INFO[this.NumberOfEntries]
)

# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_descriptor
minidump_memory_descriptor = Struct(
    "StartOfMemoryRange" / Hex(Int64ul),
    "Memory" / minidump_location_descriptor,
)

# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_descriptor
MINIDUMP_MEMORY_DESCRIPTOR64 = Struct(
    "StartOfMemoryRange" / Hex(Int64ul),
    "DataSize" / Hex(Int64ul),
)

# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list
MINIDUMP_MEMORY64_LIST = Struct(
    "NumberOfMemoryRanges" / Int64ul,
    "BaseRva" / Hex(Int64ul),
    "MemoryRanges" / MINIDUMP_MEMORY_DESCRIPTOR64[this.NumberOfMemoryRanges]
)

minidump_directory_entry = Struct(
    "StreamType" / Int32ul,
    "Location" / minidump_location_descriptor,
#    "Data" / Switch(this.StreamType, {
#        SystemInfoStream: Computed(lambda this: get_string(Pointer(this.Location.RVA, minidump_system_info))),
#        Memory64ListStream: Computed(lambda this: get_string(Pointer(this.Location.RVA, minidump_memory64_list))),
#        MemoryInfoListStream: Computed(lambda this: get_string(Pointer(this.Location.RVA, minidump_memory_info_list))),
#        ModuleListStream: Computed(lambda this: get_string(Pointer(this.Location.RVA, minidump_module_list))),
#    })
)

# TODO: More meaningful defaults
MINIDUMP_HEADER = Struct(
    "Signature" / Const(MINIDUMP_SIGNATURE),
    "Version" / Const(MINIDUMP_VERSION),
    "VersionInternal" / Default(Int16ul, 0),
    "NumberOfStreams" / Int32ul,
    "StreamDirectoryRva" / Hex(Int32ul),
    "Checksum" / Default(Hex(Int32ul), 0),
    "TimeDateStamp" / Default(Int32ul, 0),
    "Flags" / Default(Hex(Int64ul), 0x421826),
#    "Directory" / Computed(lambda this: get_string(Pointer(this.StreamDirectoryRva, minidump_directory[this.NumberOfStreams])))
)

MINIDUMP_STRING = Struct(
    "String" / PascalString(Int32ul, "utf_16_le"),
    "ZeroTermination" / Const(b'\x00\x00')
)
