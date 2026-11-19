# Protocol ownership and provenance

Source of extraction: `AploEmbed` at `1d16a91f5709cc73ed5b96fd792f5cf33858458f`, `src/Web3.cpp` (`AploGetMinerParams`, ABI `mine(bytes32)`) and `examples/Aplo Mining/src/main.cpp` (148-byte preimage, fixed arrays, bounded work, yield, challenge/receipt checks). The existing `tests/test_static_regressions.py` was inspected for invariants; new executable behavior tests replace source-string assertions for the extracted functionality.

Protocol source: `AploNode` at `addcc444e0934246d8fc8f73eaeb0efda7a2c050`:

- `builtin/sessionkeys/registry.go`: native registry 0x1237, inclusive expiry, allowances and scope, `getSession` six words, signer account nonce, persistent owner recipient mapping.
- `params/bootnodes.go`: canonical GAplo runtime `GAPLO`, address 0x1234 and mine selector 0x2fdc505e. The checkout contains runtime bytecode rather than a GAplo Solidity source.
- `core/state_transition.go`: session owner pays GAS; owner APLO stake qualifies mining rewards; fees/rewards refund to payer. A session signs in its own nonce lane.
- `internal/ethapi/api.go:GetBalance`: `eth_getBalance` on AploNode is GAPLO, matching `SessionKeys::Balance`.

Reference client: `WebMiner` at `bc5823a8861f66a63a62f6debf237b4810d7ba9e`:

- `src/features/webminer/session-keys/protocol.ts`: mining-only session scope, zero APLO, bounded GAPLO, expiry/domain checks, no owner-key fallback.
- `src/features/webminer/services/client.ts`: signer metadata, owner caller, DEFAULT_DIFFICULTY fallback for fresh sessions, owner stake.
- `src/features/webminer/services/transactions.ts`: pending signer nonce, current chainId, estimate + 10,000 GAS, distinct broadcast/receipt behavior.
- `src/workers/miningWorker.ts`: packed preimage order and strict hash < target test. This library preserves the full uint256 count rather than the reference worker's JavaScript number narrowing.

The work test's Keccak vector was independently generated with WebMiner's installed Web3 `encodePacked`/`keccak256`, including a count above 2^255. No production endpoint or owner secret was used.

The base dependency owns Keccak, CSPRNG, ECDSA, EIP-155 serialization/signing, strict RPC parsing, transaction receipts, TLS and ABI encoding. MiningEmbed owns fixed mining scope, challenge validation, budget/funding guards and one outstanding share. Firmware owns networking, lifecycle, provisioning and user feedback.

The 2026-11-19 extension was checked against the current local AploNode sources without modifying them: `builtin/sessionkeys/registry.go:Get/Used/remove` preserves signer-account nonce and permanent registration tombstones; `core/state_transition.go:preCheck` selects delegation for previously registered keys and otherwise uses ordinary account semantics. MiningEmbed keeps the same work preimage and session scope, adds an explicit ordinary EIP155 constructor, and journals one exact signed transaction before sending. Latest/pending nonce evidence never substitutes for an exact receipt result.
