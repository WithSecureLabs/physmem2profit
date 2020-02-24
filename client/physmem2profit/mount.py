#!/usr/bin/env python3

import os
import sys
import errno
import stat
from binascii import unhexlify, hexlify
from fuse import FUSE, FuseOSError, Operations
import struct
import os
import socket
import json
import tempfile

## Class used to mimic file access to external memory.
class Physmem(Operations):
    ## Functions exposed by each driver class on server.
    order = ['install', 'map', 'read']

    ## Class constructor.
    #
    # Install driver and recover data necessary to read memory.
    # @param sock socket connection with server.
    # @param mountpoint path to file with mounted memory.
    # @param driver driver class used by server to expose memory.
    # @param installArguments additional data defined by driver class.
    # @exceptions Exception if server was unable to deliver basic data.
    def __init__(self, sock, mountpoint, driver, installArguments):
        self.FILENAME = "memimage.raw"
        self.read_total = 0
        self.read_stat_cached = 0

        self.host = sock.getsockname()[0]
        self.port = sock.getsockname()[1]
        self.socket = sock
        self.driver = driver
        self.installArguments = installArguments

        # send first order to install driver.
        order = ('%s\n%s\n%s' % (self.driver, self.order[0], self.installArguments)).encode('utf-8')
        msg = struct.pack("<I%ds" % len(order), len(order), order)
        self.socket.sendall(msg)
        received = self.socket.recv(4)
        response = struct.unpack("<I", received)[0]
        if (response):
            raise Exception(struct.unpack("<%ds" % response, self.socket.recv(response))[0].decode('utf-8'))

        print("[*] Driver installed")
        # send map order.
        order = ('%s\n%s\n' % (self.driver, self.order[1])).encode('utf-8')
        msg = struct.pack("<I%ds" % len(order), len(order), order)
        self.socket.sendall(msg)

        # Receive map data from the server
        received = self.socket.recv(32)
        dtb, build, kernel_base, n = struct.unpack("<QQQQ", received)
        #print("DTB", hex(dtb))
        #print("build", build)
        #print("kernel_base", hex(kernel_base))

        if kernel_base == 0:
            kernel_base = None

        self.runs = []
        for x in range(n):
            received = self.socket.recv(16)
            start, size = struct.unpack("<QQ", received)
            #print(hex(start), size)
            self.runs.append((start,size))
            self.image_size = start + size
        #print("Image size: %u MB" % (self.image_size/(1024*1024)))

        self.read_progress = 0
        self.read_stat_cached = 0

        # Caching
        self.PAGE_SIZE = 4096
        self.cache = {}
        self.queued_offset = None
        self.queued_size = 0
        self.gathered = []
        self.extra = []

        # Write the config to JSON file
        config = dict(dtb=dtb, kernel_base=kernel_base, build=build, image=os.path.join(mountpoint, self.FILENAME))
        #print(config)
        with open('config.json', 'w') as f:
            json.dump(config, f)
        print("[*] Wrote config to config.json")
        print("[*] Exposing the physical memory as a file")

    ## Destructor closing connection.
    def __del__(self):
        print("[*] Read %u MB, cached reads %u MB" % (self.read_total / (1024*1024), self.read_stat_cached / (1024*1024)))
        self.socket.close()

    ## Fuse, read attributes of files/directories.
    #
    # @param path path of file/directory.
    # @param fh flags, not used.
    # @exceptions FuseOSError if path was other than one supported file, or file dir.
    def getattr(self, path, fh=None):
        if path == "/":
            dir =  { 'st_mode' : stat.S_IFDIR | 0o555, 'st_nlink' : 2 }
            return dir
        elif path == os.path.join('/', self.FILENAME):
            #size = os.stat(self.root).st_size
            size = self.image_size
            f = { 'st_mode' : stat.S_IFREG | 0o444,  'st_nlink' : 1, 'st_size' : size }
            return f

        raise FuseOSError(errno.ENOENT)

    ## Fuse, provide directory content.
    #
    # Only one file is supported.
    # @param path path of file/directory, not used.
    # @param fh flags, not used.
    def readdir(self, path, fh):
        dirents = ['.', '..', self.FILENAME]
        for r in dirents:
            yield r

    # Fuse, open file.
    #
    # Always successful. __init__ ensures data is accessible.
    def open(self, path, flags):
        return 0

    ## Internal, retrive page.
    #
    # Function retrives page from cache, or adds page to queue.
    # Can triger fetching queued data from server.
    # @param pagenum number of page to retrive.
    def _gather_page(self, pagenum):
        #print("Gathering page %u (offset %x)" % (pagenum, pagenum*self.PAGE_SIZE))
        if len(self.extra) > 0 or (self.queued_size != 0 and pagenum*self.PAGE_SIZE != self.queued_offset+self.queued_size):
            #print("Fetching queued data (requested %x, queued %x-%x)" % (pagenum*self.PAGE_SIZE, self.queued_offset, self.queued_offset+self.queued_size))
            #print("Fetching queued data")
            self._recv_queued()

        if self.read_progress > 1024*1024:
            self.read_total += self.read_progress
            self.read_progress = 0
            #print("Read %u MB, cached reads %u MB" % (self.read_total / (1024*1024), self.read_stat_cached / (1024*1024)))

        if pagenum in self.cache:
            #print("Returning page %u (offset %x) from cache" % (pagenum, pagenum*self.PAGE_SIZE))
            self.read_stat_cached += self.PAGE_SIZE
            self.read_progress += self.PAGE_SIZE
            #print("Appending cached")
            #self.gathered.append(self.cache[pagenum])
            self.extra.append(self.cache[pagenum])
            return

        requested_length = length = self.PAGE_SIZE
        offset = pagenum*self.PAGE_SIZE
        for start,size in self.runs:
            if start <= offset < (start + size):
                if (offset + length) > (start + size):
                    padlen = (offset + length) - (start + size)
                    #print("We have extra")
                    self.extra.append(b'\x00'*padlen)
                    length = requested_length - padlen
                break
        else:
            # We don't want to cache these
            #print("Appending zeros")
            self.extra.append(b'\x00'*length)
            return

        self.queued_size += length
        if self.queued_offset is None:
            self.queued_offset = offset

        self.read_progress += length
        
        return

    ## Internal, retrive queued data from server.
    def _recv_queued(self):
        # Is there anything to read from network?
        if self.queued_size == 0:
            # Add the stuff from extra anyway
            if len(self.extra) > 0:
                self.gathered.extend(self.extra)
                self.extra = []
            return

        assert((self.queued_offset % self.PAGE_SIZE) == 0)

        order = ('%s\n%s\n' % (self.driver, self.order[2])).encode('utf-8')
        msg = struct.pack("<I%dsQQ" % len(order), len(order) + 16, order, self.queued_offset, self.queued_size)
        self.socket.send(msg)
        
        to_read = self.queued_size
        blobs = []
        while to_read > 0:
            blob = self.socket.recv(to_read)
            if not blob:
                break

            blobs.append(blob)
            to_read -= len(blob)

        # Add data to cache
        # self.queued_offset is guaranteed to be a multiple of self.PAGE_SIZE
        data = b''.join(blobs)
        #print("Received %u bytes from offset %x" % (len(data), self.queued_offset))
        for i in range(len(data)//self.PAGE_SIZE):
            #print("Caching page %u" % (self.queued_offset//self.PAGE_SIZE))
            assert((self.queued_offset//self.PAGE_SIZE + i) not in self.cache)
            self.cache[self.queued_offset//self.PAGE_SIZE + i] = data[i*self.PAGE_SIZE:(i+1)*self.PAGE_SIZE]

        #print("Items in gathered before: %u" % (len(self.gathered)))
        self.gathered.extend(blobs)
        self.gathered.extend(self.extra)
        self.extra = []
        self.queued_offset = None
        self.queued_size = 0
        return

    ## Internal, get all gathered data.
    #
    #  Trigers fetching queued data.
    def _get_all(self):
        self._recv_queued()
        buf = b''.join(self.gathered)
        self.gathered = []
        return buf

    ## Fuse, read uncached data.
    #
    # Function will fetch data, without checking cache. New data will not be cached.
    # @param path path ot file. Not used, only one file is supported.
    # @param requsted_length requested size of data.
    # @param offset offset from file start.
    # @param fh flags, not used.
    def read_uncached(self, path, requsted_length, offset, fh):
        length = requsted_length
        extra = b''
        for start,size in self.runs:
            if start <= offset < (start + size):
                if (offset + length) > (start + size):
                    padlen = (offset + length) - (start + size)
                    extra = b'\x00'*padlen
                    length = requsted_length - padlen
                break
        else:
            #print("Returning zeros")
            return b'\x00'*length

        #print("Reading %u bytes from 0x%x" % (length, offset))
        self.read_progress += length
        #print("Sending")
        order = ('%s\n%s\n' % (self.driver, self.order[2])).encode('utf-8')
        msg = struct.pack("<I%dsQQ" % len(order), len(order) + 16, order, offset, length)
        self.socket.send(msg)

        #print("Sent %u bytes. Receiving" % (sent))
        
        amount_received = 0
        to_read = length
        blobs = []
        while amount_received < length:
            blob = self.socket.recv(to_read)
            if not blob:
                break

            blobs.append(blob)
            amount_received += len(blob)
            to_read -= len(blob)

        data = b''.join(blobs)
        data += extra
        #print("Received %u bytes" % (len(data)))

        if self.read_progress > 1024*1024:
            self.read_total += self.read_progress
            self.read_progress = 0
            #print("Read %u megabytes" % (self.read_total / (1024*1024)))

        return data

    ## Fuse, read data.
    #
    # Function will first look in cache, missing data will be fetched. New data will be cached.
    # @param path path ot file. Not used, only one file is supported.
    # @param requsted_length requested size of data.
    # @param offset offset from file start.
    # @param fh flags, not used.
    def read_cached(self, path, requested_length, offset, fh):
        #print("[read] offset %x, length: %u" % (offset, requested_length))
        for pagenum in range(offset // self.PAGE_SIZE, (offset+requested_length) // self.PAGE_SIZE+1, 1):
            self._gather_page(pagenum)
        buf = self._get_all()
        #print("Len buf %u" % (len(buf)))
        buf = buf[offset % self.PAGE_SIZE:-(self.PAGE_SIZE-((offset+requested_length) % self.PAGE_SIZE))]
        #print("Len buf %u" % (len(buf)), hex(offset % self.PAGE_SIZE), hex(self.PAGE_SIZE-((offset+requested_length) % self.PAGE_SIZE)))
        return buf

    ## Fuse, read data.
    #
    # Same as read_cached.
    # Function will first look in cache, missing data will be fetched. New data will be cached.
    # @param path path ot file. Not used, only one file is supported.
    # @param requsted_length requested size of data.
    # @param offset offset from file start.
    # @param fh flags, not used.
    def read(self, path, requested_length, offset, fh):
        #print("[read] offset %x, length: %u" % (offset, requested_length))
        #data1 = self.read_uncached(path, requested_length, offset, fh)
        data2 = self.read_cached(path, requested_length, offset, fh)
        return data2

    ## Fuse, write data.
    #
    # Not supported.
    def write(self, path, buf, offset, fh):
        # Not implemented
        return -1

## Open socket connection with server.
#
#  @param host ip address of host to connect.
#  @param port number of port to connect.
#  @param removeOldConfig function will delate outdated config file.
#  @exceptions Exception if connection was not created.
def init(host, port, removeOldConfig = True):
    try:
        if (removeOldConfig and os.path.exists("config.json")):
            os.remove("config.json")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("[*] Connecting to %s on port %u" % (host, port))
        # Connect to server and send data
        sock.connect((host, port))
        print("[*] Connected")
        return sock
    except ConnectionRefusedError:
        raise Exception("[-] Failed to connect, quitting")

## Mount external memory exposed by socket as file.
#
#  Use Fuse to create abstract file. File location and parameters are provided in config.json.
#  @param sock socket connection with server.
#  @param driver name of driver to be used.
#  @param installArguments data required by driver. Defined by driver Install function on server.
#  @exceptions Exception if connection was not created.
def mount(sock, driver, installArguments):
    with tempfile.TemporaryDirectory() as mountpoint:
        fuse = FUSE(Physmem(sock, mountpoint, driver, installArguments), mountpoint, nothreads=True, foreground=True)