# PRL fast runner

Small public container for a controlled Clore experiment. It contains only a
Go launcher and Ubuntu. It **does not redistribute SRBMiner**: at runtime it
streams the official 3.8.3 release, checks the full pinned SHA-256, then runs
the unmodified miner. GPU identification and a TLS pool reachability probe run
in parallel with the download. A local HTTP endpoint reports startup stages,
hashrate, and accepted/rejected shares without exposing the wallet address.

Build the public x86-64 image with the included GitHub Actions workflow. It
uses no user credentials in the image or repository. Set these only on an
authorized rental:

- `PRL_WALLET`: authorized public PRL payout address (required).
- `STATUS_TOKEN`: random secret of at least 32 characters (required).
- `EXPECTED_GPU`: e.g. `RTX 5090` (recommended).
- `PRL_POOL`: defaults to `prl-eu.kryptex.network:8048`.
- `PRL_WORKER`: defaults to `clore-fast`.

Forward container port 8080 as TCP. `GET /status` requires
`Authorization: Bearer <STATUS_TOKEN>`. Keep that token outside public logs and
repositories. The endpoint has no wallet or command output.

The pool TLS preflight only checks reachability; the miner cannot submit work
until its verified binary is running. Startup improvement is **unverified**
until measured against a live host. Container provisioning before Clore marks
an order running is not assumed billable.

SRBMiner's source is unavailable and its license prohibits redistributing or
modifying its proprietary GPU binaries. The public image contains no miner
binary. See the upstream [license](https://github.com/doktor83/SRBMiner-Multi#license).
