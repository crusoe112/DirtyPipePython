# dirty.py

## Description
This is an exploit for the Linux kernel vulnerability [CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847) (DirtyPipe) discovered by [Max Kellerman](https://dirtypipe.cm4all.com/).

This code combines two existing DirtyPipe POC's into one:
- [febinrev](https://github.com/febinrev/dirtypipez-exploit)
	- Overwrites sudo binary to directly pop a root shell
- [eremus-dev](https://github.com/eremus-dev/Dirty-Pipe-sudo-poc)
	- A direct copy of Kellerman's POC into Python

This code checks if:
  - /etc/passwd can be overwritten to get a root shell
  - The sudo binary can be overwritten to get a root shell
  - The su binary can be overwritten to get a root shell

It then executes the first option that is possible in that order.

For an excellent explanation of the vulnerability itself, see [Kellerman's writeup](https://dirtypipe.cm4all.com/).

## Getting Started

Requires python 10.X for the use of os.splice

## Usage

```console
vulnerable@kali:~$ python dirty.py
```

## Cleanup

The script may write several files to /tmp: 
 - /tmp/backup_sudo
 - /tmp/backup_su
 - /tmp/passwd
 - /tmp/sh

The generated files should be removed after execution, but may require root access to do so.

##  Dealing with errors

This exploit will overwrite a page of the file that resides in the page cache. It is unlikely to corrupt the actual file. If there is corruption or an error, you likely just need to wait until the page is overwritten in the cache, or restart your computer to fix any problems. That being said, I bear no responsibility for damage done by this code, so please read carefully and hack responsibly. Be sure to check out Max Kellerman's writeup at cm4all.com as well.

## Acknowledgements

- [Max Kellerman](https://dirtypipe.cm4all.com/)
- [febinrev](https://github.com/febinrev/dirtypipez-exploit)
- [eremus-dev](https://github.com/eremus-dev/Dirty-Pipe-sudo-poc)
