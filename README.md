# VAQYRON Core

VAQYRON Core is source software for an independent, native proof-of-work blockchain.
This codebase is based on Bitcoin Core and retains the upstream attribution and
license terms in `COPYING` and `THIRD_PARTY_NOTICES.txt`.

## Network and implementation status

- Ticker: `VQRN`
- Architecture: independent native PoW blockchain
- Proof of work: Yespower 1.0
- Yespower parameters: `N=2048`, `r=16`
- MAINNET block spacing: 150 seconds
- MAINNET ASERT half-life: 43200 seconds
- Initial subsidy: 12 VQRN
- Halving interval: 1,000,000 blocks
- Maximum supply policy: 24,000,000 VQRN
- Native precision: 8 decimal places
- Public TESTNET: operational
- Public MAINNET: not established
- Exchange trading: not established
- MAINNET circulating supply: not established
- CoinMarketCap application: submitted; approval pending
- CoinGecko preview application: submitted; approval pending
- CoinCodex application: submitted; approval pending
- Independent security audit: not claimed

## Official resources

- Website: https://vaqyron.com/
- Explorer: https://explorer.vaqyron.com/
- Logo: https://vaqyron.com/assets/vaqyron-logo.png
- Whitepaper: https://vaqyron.com/whitepaper/VAQYRON_WHITEPAPER_V7_PREMAINNET_UPDATED.pdf
- Security contact: contact@vaqyron.com

## MAINNET and TESTNET separation

MAINNET and VAQYRON TESTNET use separate chain identities, genesis data, ports,
and genesis blocks. The TESTNET ASERT setting remains disabled and is not
enabled here. MAINNET genesis block hash:
`6632757c19c74eadb7605077994de2de96625cc6abab68f94f303e55fa3fe4e4`.
VAQYRON TESTNET genesis block hash:
`e4bccdb17adaa76a26e23f67f21062674d30f4476493dfb5f8cf297dc523ef97`.

## Build

The Windows x64 candidate was independently compiled using
Visual Studio 2022, Boost 1.87 and Libevent 2.1.12.

Configure using CMake with the Visual Studio 17 2022 generator,
x64 architecture and an existing vcpkg dependency installation.

Required configuration options:

    -DCMAKE_TOOLCHAIN_FILE=<vcpkg-toolchain-file>
    -DVCPKG_INSTALLED_DIR=<installed-dependencies>
    -DVCPKG_TARGET_TRIPLET=x64-windows
    -DVCPKG_MANIFEST_INSTALL=OFF
    -DBUILD_GUI=OFF
    -DENABLE_WALLET=OFF
    -DENABLE_IPC=OFF
    -DBUILD_TESTS=ON
    -DWITH_ZMQ=OFF
    -DENABLE_EXTERNAL_SIGNER=OFF

Build the Release configuration using CMake.

See doc/dependencies.md and doc/build-windows-msvc.md.

Full-featured production builds and clean-machine
reproducibility remain unverified.


## Tests

Independent Windows x64 Release build passed. Final functional tests, security and licensing verification remain pending.

Configure tests with `-DBUILD_TESTS=ON`, build `test_bitcoin`, and run it
offline with CTest or the test executable. Applicable suites cover:

- monetary policy and subsidy halving
- genesis and network identity
- Yespower known-answer vectors
- ASERT calculations
- consensus validation
- RPC named-pipe support
- Windows service support

Do not start nodes, mine, search for genesis, use live RPC, wallets, or network
services for public-source verification. No public MAINNET operations are
performed by this documentation or this candidate.

## Security disclosure

Do not place private keys, wallet recovery material, RPC credentials, API
tokens, or internal infrastructure details in issues or source submissions.
Report suspected vulnerabilities privately to `contact@vaqyron.com`. This
candidate does not claim that an independent security audit has been completed.

## Licensing and attribution

The Bitcoin Core-derived source is MIT-licensed; preserve `COPYING` and
copyright notices throughout redistributions. Yespower is a third-party PoW
component and remains subject to its upstream notices in
`THIRD_PARTY_NOTICES.txt` and the vendored source headers. This README does not
replace any upstream license or redistribute code beyond those source notices.


---

## Upstream Bitcoin Core documentation

Bitcoin Core integration/staging tree
=====================================

https://bitcoincore.org

For an immediately usable, binary version of the Bitcoin Core software, see
https://bitcoincore.org/en/download/.

What is Bitcoin Core?
---------------------

Bitcoin Core connects to the Bitcoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Bitcoin Core is available in the [doc folder](/doc).

License
-------

Bitcoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/license/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Tags](https://github.com/bitcoin/bitcoin/tags) are created
regularly from release branches to indicate new official, stable release versions of Bitcoin Core.

The https://github.com/bitcoin-core/gui repository is used exclusively for the
development of the GUI. Its master branch is identical in all monotree
repositories. Release branches and tags do not exist, so please do not fork
that repository unless it is for development reasons.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled during the generation of the build system) with: `ctest`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python.
These tests can be run (if the [test dependencies](/test) are installed) with: `build/test/functional/test_runner.py`
(assuming `build` is your build directory).

The CI (Continuous Integration) systems make sure that every pull request is tested on Windows, Linux, and macOS.
The CI must pass on all commits before merge to avoid unrelated CI failures on new pull requests.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://explore.transifex.com/bitcoin/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.
