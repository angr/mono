The file `multiarch_main_main.o` is part of valgrind, and has the following license:

```
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2004-2015 OpenWorks LLP
      info@open-works.net

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.

   The GNU General Public License is contained in the file COPYING.

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.
```

The files `cat`, `true`, and `decompiler/coreutils_sum_O2` are from `coreutils`, and have the following license:

```
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

The `paste` binary is from GNU coreutils 9.1 and has the following license:

```
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

It was derived from DecBench revision
`4b42a0dc6158913db0648a9123e76d6ddd9ab9cf` at
`binaries/O2-noinline/coreutils/paste`, then stripped of debug sections with
`objcopy --strip-debug`. The source binary's SHA-256 digest is
`9c32fa84a1260d50224c008180ababd41f47c8ba8e7d021671c6f6e93d964d92`;
the resulting fixture's SHA-256 digest is
`01fcdf629c4994d0fe733c10a92dc142909be74c9d8c9efe04b703ae6cbf103d`.
The file `decompiler/coreutils_sum_O2` is the unchanged GNU/Linux `sum` artifact
from pinned DecBench revision `4b42a0dc6158913db0648a9123e76d6ddd9ab9cf`:

<https://huggingface.co/datasets/noelo-lab/decbench-dataset/blob/4b42a0dc6158913db0648a9123e76d6ddd9ab9cf/binaries/O2/coreutils/sum>

Its SHA-256 is
`2d700fcb7e47688324231eb3463284a4b8dcf7579df746ddb1ecceb24723b33e`.

The file `decompiler/openssh_scp_O2_noinline` is GNU/Linux OpenSSH portable
`scp`, derived from DecBench revision
`4b42a0dc6158913db0648a9123e76d6ddd9ab9cf` by removing debug sections with
GNU `objcopy --strip-debug`. The public source artifact is pinned at
<https://huggingface.co/datasets/noelo-lab/decbench-dataset/blob/4b42a0dc6158913db0648a9123e76d6ddd9ab9cf/binaries/O2-noinline/openssh-portable/scp>.
The source artifact has SHA-256
`102cbce7585c1662dfa7dfd35344ab2d6da5d08ce415f9db6cb165e70db21fa3`; the
committed derivative has SHA-256
`70475811049560f671bf9df207f99a2ff8ebc4c0c4fa69a0915d5082c515ff57`.
OpenSSH portable is distributed under the copyright notices and permissive
licenses reproduced in `decompiler/openssh-portable-LICENCE`. The original is
pinned at:

<https://github.com/openssh/openssh-portable/blob/0ffb46f2ee2ffcc4daf45ee679e484da8fcf338c/LICENCE>
The file `decompiler/libbsd.so.0.11.7` is copied unchanged from the DecBench
Decompiler Benchmark Dataset at revision
[`4b42a0dc6158913db0648a9123e76d6ddd9ab9cf`](https://huggingface.co/datasets/noelo-lab/decbench-dataset/tree/4b42a0dc6158913db0648a9123e76d6ddd9ab9cf).
Its source path is `binaries/O2/libbsd/libbsd.so.0.11.7`; the pinned Git LFS
object is 342,640 bytes with SHA-256
`50c8329c57981e6553cfa906a8d5ee7cd6d676bc849d23d6b4ea30234b93bb61`.
The dataset is distributed under the BSD-2-Clause license, as recorded in its
[dataset card](https://huggingface.co/datasets/noelo-lab/decbench-dataset/blob/4b42a0dc6158913db0648a9123e76d6ddd9ab9cf/README.md).

The binary is an optimized build of libbsd 0.11.7. The release's complete
copyright and license record is reproduced verbatim in the adjacent
[`decompiler/libbsd.so.0.11.7.COPYING`](decompiler/libbsd.so.0.11.7.COPYING),
from the pinned upstream
[`0.11.7` source](https://gitlab.freedesktop.org/libbsd/libbsd/-/raw/0.11.7/COPYING),
with SHA-256
`7aab3a07716d31ca72e66c1073ef8a0fa0be0daa5df7c3b2cc0c668589142336`.
The file `decompiler/gnutls_certtool_O0` is GnuTLS 3.7.8 `certtool`, derived from
pinned DecBench revision `e5eb576d66ee36793b800a4dd45e291e0add4472` by
removing debug sections with GNU `objcopy --strip-debug`. The public source
artifact is pinned at:

<https://huggingface.co/datasets/noelo-lab/decbench-dataset/blob/e5eb576d66ee36793b800a4dd45e291e0add4472/binaries/O0/gnutls/certtool>

The source artifact has SHA-256
`be6106508f70816a4c8f88786a1719f703c4b259a73609902308aff2e5aba026`; the
committed derivative has SHA-256
`8796fa118358142d7abd5c239a25e78063be225410afafdbb6659344f3e06a2a`.

GnuTLS `src/certtool.c` is licensed under GPLv3 or later:

```
Copyright (C) 2003-2016 Free Software Foundation, Inc.
Copyright (C) 2015-2019 Red Hat, Inc.
License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```
