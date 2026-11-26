This directory contains the production yespower 1.0 implementation copied
from Openwall yespower commit
`1977c283bc43eed5a2c2579e02d6d996e49866b0`.

The production build uses `yespower-opt.c` and its bundled SHA-256
implementation. The accompanying platform and header files are required by
those sources. Upstream copyright, redistribution conditions, and disclaimers
are retained in each source/header file. Do not remove those notices.

This copy is built offline and has no dependency on the prototype tree or
RandomX. Production MAIN proof-of-work validation and candidate checks call
the frozen yespower implementation through the header-based PoW verifier.
