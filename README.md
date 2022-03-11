# dirty.py

## Description
This is an exploit for the Linux kernel vulnerability [CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847) (DirtyPipe) discovered by [Max Kellerman](https://dirtypipe.cm4all.com/).

This code combines two existing DirtyPipe POC's into one:
- [febinrev](https://github.com/febinrev/dirtypipez-exploit)
	- Overwrites sudo binary to directly pop a root shell
- [eremus-dev](https://github.com/eremus-dev/Dirty-Pipe-sudo-poc)
	- A direct copy of Kellerman's POC into Python

As a result, this is a Python-based POC that directly pops a root shell by overwriting the sudo binary.

For an excellent explanation of the vulnerability itself, see [Kellerman's writeup](https://dirtypipe.cm4all.com/).

## Getting Started

Requires python 10.X for the use of os.splice
Make sure your target user has read access to sudo

## Usage

```console
vulnerable@kali:~$ which sudo
/usr/bin/sudo

vulnerable@kali:~$ python dirty.py /usr/bin/sudo
```

## Cleanup

The script writes 2 files to /tmp: 
 - /tmp/backup_sudo
 - /tmp/sh

Both can be removed to clean up.

##  Dealing with errors

This exploit will overwrite a page of the file that resides in the page cache. It is unlikely to corrupt the actual file. If there is corruption or an error, you likely just need to wait until the page is overwritten in the cache, or restart your computer to fix any problems. That being said, I bear no responsibility for damage done by this code, so please read carefully and hack responsibly. Be sure to check out Max Kellerman's writeup at cm4all.com as well.

## Acknowledgements

- [Max Kellerman](https://dirtypipe.cm4all.com/)
- [febinrev](https://github.com/febinrev/dirtypipez-exploit)
- [eremus-dev](https://github.com/eremus-dev/Dirty-Pipe-sudo-poc)
