from multiprocessing import Process
import argparse
import signal
import sys
import time
import mount
import physmem2minidump
import os

jobs = []

## Ensure correct close.
#
#  @param _sig unused parameter.
#  @param _frame unused parameter.
def close(_sig = None, _frame = None):
    for job in jobs:
        if job.is_alive():
            job.terminate()

## Check if required argument was provided.
#
#  @param arg argument to check.
#  @param str custom name for argument.
#  @exceptions Exception if arg was not provided.
def checkArgument(arg, str):
    if (arg is None): raise Exception("[-] Required command line argument " + str + " not provided")

## Parse command line. Ensure required parameters exist, generate optional.
#
#  @return object with all information required to start program.
#  @exceptions Exception if not all required parameter were provided.
def parseInput():
    parser = argparse.ArgumentParser(description='physmem2profit')
    parser.add_argument('--mode', choices=['mount', 'dump', 'all'], default='all', help="Mode of operation.")
    parser.add_argument('--host', help="Target host (use with mount)")
    parser.add_argument('--port', type=int, default=8080, help="Target port (use with mount)")
    parser.add_argument('--driver', choices=['winpmem'], default='winpmem', help="Specifies class used by server to handle driver (use with mount)")
    parser.add_argument('--install', help="Provides parameters needed for driver installation eg path (use with mount)")
    parser.add_argument('--label', default=('dump'), help="Label to include in the minidump filename (use with dump)")
    parser.add_argument('--vmem', help="Path to .vmem file (support Credential Guard)")
    args = parser.parse_args()

    if args.vmem:
        if not os.path.exists(args.vmem):
            raise Exception("[-] --vmem specified but file %s does not exist" % (args.vmem))
        if not args.mode == 'dump':
            raise Exception("[-] Pleae use --mode dump with --vmem switch")
        return args

    if args.mode == 'all' or args.mode == 'mount':
        checkArgument(args.host, "'host'")
        checkArgument(args.install, "'install'")

    return args


## Main function of package.
def main():
    try:
        args = parseInput()

        if args.mode == 'all' or args.mode == 'mount':
            socket = mount.init(args.host, args.port)                                               # wait for connection, before creating child process.
            jobs.append(Process(target=lambda: mount.mount(socket, args.driver, args.install)))     # mount will block thread, it need to be handled by child process.
        if args.mode == 'all' or args.mode == 'dump':
            jobs.append(Process(target=lambda: physmem2minidump.dump(args.label, args.vmem)))

        for job in jobs:
            job.start()

        jobs[-1].join() # wait only for last child.
        close()         # when last child joined, rest can be terminated.

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e)

## Call main if file is used as entry point.
if __name__ == '__main__':
    main()