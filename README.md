# MiningEmbed

MiningEmbed 0.1.0 is an Arduino/PlatformIO library for AploCoin session-key mining. It reads miner parameters, searches a bounded batch, rechecks the challenge and submits a share. It depends on AploEmbed's session API, ABI encoder, Keccak, hardware CSPRNG, native transaction signing and TLS/RPC transport.

The application owns Wi-Fi, TLS trust configuration, provisioning, scheduling, display, retry policy and key persistence. MiningEmbed never receives an owner private key and never falls back to owner signing.

## Install

Clone MiningEmbed and [AploEmbed](https://github.com/AploCoin/AploEmbed) from GitHub. For a ready-to-build board project with exact library revisions, see [FirmwareEmbed](https://github.com/AploCoin/FirmwareEmbed).

For Arduino, put the two library directories in your sketchbook `libraries/` directory and include `<MiningEmbed.h>`. Supported architectures: ESP8266 and ESP32, including ESP32-C3.

From the MiningEmbed checkout, build the example with PlatformIO. It uses this checkout and installs AploEmbed from its pinned GitHub commit.

~~~sh
pio run -d examples/SessionMining -e esp12e -e esp32dev -e esp32-c3-devkitm-1
~~~

For Arduino IDE, install both libraries in your sketchbook `libraries/` directory and open `examples/SessionMining/SessionMining.ino`. Its implementation is in the sketch's `src/main.cpp`, which Arduino compiles automatically. Configure networking/TLS in `setup()` and replace `loadConfirmedSession()` with your provisioning source. That function is the explicit handoff for the session key and the public authorization copied from a confirmed registration. The default zero secret prevents sending; no real key belongs in the source tree. A synthetic test session must also be registered on the selected test network before use.

## API

```cpp
#include <Web3.h>
#include <MiningEmbed.h>
using namespace miningembed;

// Configure the network and TLS first. Provision and confirm authorization outside this library.
aplo::SessionKeys rpc(web3);                // borrows application's Web3
MiningEmbed miner(rpc, sessionKey, session); // borrows RPC and RAM-only SessionKey; copies public config
Submission share;
Status status = miner.step(2000, share); // Call once per application-selected interval.
```

`MiningSession` contains `owner`, `signer`, `chainId` (uint256), `gaploBudget` (uint256, original approved budget in base units), and inclusive `expiry` (uint64). Copy these public values from a **confirmed owner-approved registration** with exactly GAplo `0x1234`, selector `mine(bytes32)` (`0x2fdc505e`), zero APLO and a finite positive GAPLO allowance. Provision only the session secret. Do not change or clear the borrowed key concurrently with a call. Clearing or importing a different key between calls invalidates the configured identity; create a new miner for a newly approved session after reconciling any outstanding transaction. `rpc` and `sessionKey` must outlive the miner. Do not concurrently access a signer from another task or device.

For numeric configuration, use integer arithmetic or explicit `0x` strings. AploEmbed's `uint256_t` string constructor always reads hexadecimal. One GAPLO in base units is `uint256_t(UINT64_C(1000000000000000000))` or `uint256_t("0xde0b6b3a7640000")`. Firmware accepting decimal text must use a checked decimal parser before constructing the public configuration.

`readParams`, `findCandidate`, `revalidate`, `submit` and `receipt` return `Status`; `statusName()` provides display text and `rpcError()` retains the latest checked base RPC/signing diagnostic. `findCandidate` accepts 1–2,000 attempts, uses hardware randomness and calls `delay(0)` at least every 64 attempts. Run it only when `readParams` returns `Ok`; `Cooldown` is not permission to submit.

The proof packs `signer[20] || nonce[32] || target[32] || prevHash[32] || totalMined[32]`. All words use big-endian encoding and the entire 256-bit mining count is retained. `miner_params` uses the signer argument and owner `from`; stake and GAPLO balance use the owner. A zero initial target is replaced by the contract's `DEFAULT_DIFFICULTY()`, as in WebMiner.

Before signing, `submit` checks the live chain domain, registry owner/target/zero-APLO/budget/expiry, estimates gas as the session signer to check native selector permission, checks owner stake and funds, re-reads session state and pending signer nonce, then re-reads the challenge at an explicit block height and recomputes the proof. The gas limit is estimate + 10,000, capped at the original miner's 200,000 ceiling. It rejects estimates below 21,000 or above 190,000, zero gas price and fee arithmetic overflow. No nonce is narrowed to uint32.

Applications can parse the confirmed session's decimal chain ID and GAplo budget using parseMiningSession. The step method polls an unresolved share before starting another batch. The individual methods remain available for applications with their own scheduling.

## Submission states

- `Broadcast`: RPC accepted the locally computed transaction hash; execution remains unconfirmed.
- `Pending`: accepted transaction currently has no receipt.
- `Confirmed`: receipt status 1. This is one successful receipt, not multi-block finality. The caller must track deeper confirmation/reorg policy if required; this facade releases its send lock after that receipt.
- `Reverted`: receipt status 0; it is not counted as a successful share.
- `Uncertain`: the send response failed or returned a different hash. The expected local hash is retained; a null receipt does not turn it into an accepted pending transaction.

Until a successful/reverted receipt resolves the outstanding hash, every new `submit` returns `Busy`. Receipt RPC errors keep the hash and previous state. The library never retries automatically. Neither a timeout, expiry nor revocation clears an outstanding hash. An uncertain transaction that was never accepted can remain locked indefinitely: the firmware/operator must reconcile its hash and signer nonce on the original network before replacing the miner object. Preserve the outstanding hash across restarts in application-controlled storage if needed; this library has no durable transaction journal.

The final recheck is a client-side guard: the chain can change after signing, so on-chain execution may still revert. Independent RPC reads are not an atomic state snapshot; pinned miner reads, repeated authorization checks and pending simulation reduce races but cannot make an untrusted server truthful. Supply a trusted compatible AploNode endpoint. Registry `getSession` does not expose its selector list; native `eth_estimateGas` enforces it for the exact mine calldata, and the application must provision the approved one-selector registration.

## Example, tests and migration

`examples/SessionMining/` is a compilable API sample with intentionally invalid secret/expiry placeholders and an explicit `loadConfirmedSession()` handoff. It requires application Wi-Fi/TLS setup. A complete firmware must perform network configuration and session provisioning. It must stop sending on any session/RPC/policy error. See [migration](docs/migration.md) and [protocol sources](docs/protocol.md).

```sh
# From MiningEmbed, using the same dependency checkout as the board build:
python3 tests/run.py --aploembed /path/to/AploEmbed
```

Host tests use the dependency's actual uint256, SessionKeys and Trezor code under ASan/UBSan, an injected RPC fixture, and a host-only platform adapter. Production uses AploEmbed `Contract`/`Crypto` and Arduino yielding. They verify portable behavior; they do not establish live ESP heap, TLS performance or hash rate.

Derived portions retain the AploEmbed MIT license and original attribution. No second cryptographic implementation or network stack is bundled.

## HTTPS trust

Set the CA on Web3 or place a generated AploTrustProfile.h in the example's include directory. See [AploEmbed TLS trust](https://github.com/AploCoin/AploEmbed/blob/master/docs/tls-trust.md) for local, public and custom RPCs. The example also needs Wi-Fi, time synchronization and a confirmed mining session. Use FirmwareEmbed for complete board applications.
