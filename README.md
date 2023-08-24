# security-checklist
[[Test stuff in remix]]

# Methodology
- [ ] Read through codebase to get a basic high-level understanding
- [ ] Read through the documentation
- [ ] Construct a mental model of how the protocol should work
- [ ] Map out how the contracts interact with each other
- [ ] Map out theoretical high level attack vectors
- [ ] Map the value exchanges `transfer`, `transferFrom`, `call`, `delegatecall` etc
- [ ] Check external assumptions i.e. how the protocol assumes external contracts will behave
- [ ] Line by line review
- [ ] Define different actors and interact with the contract from their pov
- [ ] Look at tests and code coverage
- [ ] Run [[Slither]] (todo not part of active auditing process)
- [ ] Test invariants with echidna (todo not part of active auditing process)

# General Solidity
[Solidity by example](https://solidity-by-example.org/) #solidityByExample is a solid resource for basic examples
[Smart contract weakness classification ](https://swcregistry.io/) #SWC #smartContractWeakness

## Variables
- `V1` - Can it be `internal`?
- `V2` - Can it be `constant`?
- `V3` - Can it be `immutable`?
- `V4` - Is its visibility set? (SWC-108)
- `V5` - Is the purpose of the variable and other important information documented using natspec?
- `V6` - Can it be packed with an adjacent storage variable?
- `V7` - Can it be packed in a struct with more than 1 other variable?
- `V8` - Use full 256 bit types unless packing with other variables.
- `V9` - If it's a public array, is a separate function provided to return the full array?
- `V10` - Only use `private` to intentionally prevent child contracts from accessing the variable, prefer `internal` for flexibility.

## Structs
- `S1` - Is a struct necessary? Can the variable be packed raw in storage?
- `S2` - Are its fields packed together (if possible)?
- `S3` - Is the purpose of the struct and all fields documented using natspec?

## Functions
- `F1` - Can it be `external`?
- `F2` - Should it be `internal`?
- `F3` - Should it be `payable`?
- `F4` - Can it be combined with another similar function?
- `F5` - Validate all parameters are within safe bounds, even if the function can only be called by a trusted users.
- `F6` - Is the checks before effects pattern followed? (SWC-107)
- `F7` - Check for front-running possibilities, such as the approve function. (SWC-114)
- `F8` - Is insufficient gas griefing possible? (SWC-126)
- `F9` - Are the correct modifiers applied, such as `onlyOwner`/`requiresAuth`?
- `F10` - Are return values always assigned?
- `F11` - Write down and test invariants about state before a function can run correctly.
- `F12` - Write down and test invariants about the return or any changes to state after a function has run.
- `F13` - Take care when naming functions, because people will assume behavior based on the name.
- `F14` - If a function is intentionally unsafe (to save gas, etc), use an unwieldy name to draw attention to its risk.
- `F15` - Are all arguments, return values, side effects and other information documented using natspec?
- `F16` - If the function allows operating on another user in the system, do not assume `msg.sender` is the user being operated on.
- `F17` - If the function requires the contract be in an uninitialized state, check an explicit `initialized` variable. Do not use `owner == address(0)` or other similar checks as substitutes.
- `F18` - Only use `private` to intentionally prevent child contracts from calling the function, prefer `internal` for flexibility.
- `F19` - Use `virtual` if there are legitimate (and safe) instances where a child contract may wish to override the function's behavior.

## Modifiers
- `M1` - Are no storage updates made (except in a reentrancy lock)?
- `M2` - Are external calls avoided?
- `M3` - Is the purpose of the modifier and other important information documented using natspec?

## Code 
- `C1` - Using SafeMath or 0.8 checked math? (SWC-101)
- `C2` - Are any storage slots read multiple times?
- `C3` - Are any unbounded loops/arrays used that can cause DoS? (SWC-128)
- `C4` - Use `block.timestamp` only for long intervals. (SWC-116)
- `C5` - Don't use block.number for elapsed time. (SWC-116)
- `C7` - Avoid delegatecall wherever possible, especially to external (even if trusted) contracts. (SWC-112)
- `C8` - Do not update the length of an array while iterating over it.
- `C9` - Don't use `blockhash()`, etc for randomness. (SWC-120)
- `C10` - Are signatures protected against replay with a nonce and `block.chainid` (SWC-121)
- `C11` - Ensure all signatures use EIP-712. (SWC-117 SWC-122)
- `C12` - Output of `abi.encodePacked()` shouldn't be hashed if using >2 dynamic types. Prefer using `abi.encode()` in general. (SWC-133)
- `C13` - Careful with assembly, don't use any arbitrary data. (SWC-127)
- `C14` - Don't assume a specific ETH balance. (SWC-132)
- `C15` - Avoid insufficient gas griefing. (SWC-126)
- `C16` - Private data isn't private. (SWC-136)
- `C17` - Updating a struct/array in memory won't modify it in storage.
- `C18` - Never shadow state variables. (SWC-119)
- `C19` - Do not mutate function parameters.
- `C20` - Is calculating a value on the fly cheaper than storing it?
- `C21` - Are all state variables read from the correct contract (master vs. clone)?
- `C22` - Are comparison operators used correctly (`>`, `<`, `>=`, `<=`), especially to prevent off-by-one errors?
- `C23` - Are logical operators used correctly (`==`, `!=`, `&&`, `||`, `!`), especially to prevent off-by-one errors?
- `C24` - Always multiply before dividing, unless the multiplication could overflow.
- `C25` - Are magic numbers replaced by a constant with an intuitive name?
- `C26` - If the recipient of ETH had a fallback function that reverted, could it cause DoS? (SWC-113)
- `C27` - Use SafeERC20 or check return values safely.
- `C28` - Don't use `msg.value` in a loop.
- `C29` - Don't use `msg.value` if recursive delegatecalls are possible (like if the contract inherits `Multicall`/`Batchable`).
- `C30` - Don't assume `msg.sender` is always a relevant user.
- `C31` - Don't use `assert()` unless for fuzzing or formal verification. (SWC-110)
- `C32` - Don't use `tx.origin` for authorization. (SWC-115)
- `C33` - Don't use `address.transfer()` or `address.send()`. Use `.call.value(...)("")` instead. (SWC-134)
- `C34` - When using low-level calls, ensure the contract exists before calling.
- `C35` - When calling a function with many parameters, use the named argument syntax.
- `C36` - Do not use assembly for create2. Prefer the modern salted contract creation syntax.
- `C37` - Do not use assembly to access chainid or contract code/size/hash. Prefer the modern Solidity syntax.
- `C38` - Use the `delete` keyword when setting a variable to a zero value (`0`, `false`, `""`, etc).
- `C39` - Comment the "why" as much as possible. 
- `C40` - Comment the "what" if using obscure syntax or writing unconventional code.
- `C41` - Comment explanations + example inputs/outputs next to complex and fixed point math.
- `C42` - Comment explanations wherever optimizations are done, along with an estimate of much gas they save.
- `C43` - Comment explanations wherever certain optimizations are purposely avoided, along with an estimate of much gas they would/wouldn't save if implemented.
- `C44` - Use `unchecked` blocks where overflow/underflow is impossible, or where an overflow/underflow is unrealistic on human timescales (counters, etc). Comment explanations wherever `unchecked` is used, along with an estimate of how much gas it saves (if relevant).
- `C45` - Do not depend on Solidity's arithmetic operator precedence rules. In addition to the use of parentheses to override default operator precedence, parentheses should also be used to emphasise it.
- `C46` - Expressions passed to logical/comparison operators (`&&`/`||`/`>=`/`==`/etc) should not have side-effects.
- `C47` - Wherever arithmetic operations are performed that could result in precision loss, ensure it benefits the right actors in the system, and document it with comments. 
- `C48` - Document the reason why a reentrancy lock is necessary whenever it's used with an inline or `@dev` natspec comment.
- `C49` - When fuzzing functions that only operate on specific numerical ranges use modulo to tighten the fuzzer's inputs (such as `x = x % 10000 + 1` to restrict from 1 to 10,000).
- `C50` - Use ternary expressions to simplify branching logic wherever possible.
- `C51` - When operating on more than one address, ask yourself what happens if they're the same.

## External Calls
- `X1` - Is an external contract call actually needed?
- `X2` - If there is an error, could it cause DoS? Like `balanceOf()` reverting. (SWC-113)
- `X3` - Would it be harmful if the call reentered into the current function?
- `X4` - Would it be harmful if the call reentered into another function?
- `X5` - Is the result checked and errors dealt with? (SWC-104)
- `X6` - What if it uses all the gas provided?
- `X7` - Could it cause an out-of-gas in the calling contract if it returns a massive amount of data?
- `X8` - If you are calling a particular function, do not assume that `success` implies that the function exists (phantom functions).

## Static Calls
- `S1` - Is an external contract call actually needed?
- `S2` - Is it actually marked as view in the interface?
- `S3` - If there is an error, could it cause DoS? Like `balanceOf()` reverting. (SWC-113)
- `S4` - If the call entered an infinite loop, could it cause DoS?

## Events
- `E1` - Should any fields be indexed?
- `E2` - Is the creator of the relevant action included as an indexed field?
- `E3` - Do not index dynamic types like strings or bytes.
- `E4` - Is when the event emitted and all fields documented using natspec?
- `E5` - Are all users/ids that are operated on in functions that emit the event stored as indexed fields?
- `E6` - Avoid function calls and evaluation of expressions within event arguments. Their order of evaluation is unpredictable.

## Contract

- `T2` - Are events emitted for every storage mutating function?
- `T3` - Check for correct inheritance, keep it simple and linear. (SWC-125)
- `T4` - Use a `receive() external payable` function if the contract should accept transferred ETH.
- `T5` - Write down and test invariants about relationships between stored state.
- `T6` - Is the purpose of the contract and how it interacts with others documented using natspec?
- `T7` - The contract should be marked `abstract` if another contract must inherit it to unlock its full functionality.
- `T8` - Emit an appropriate event for any non-immutable variable set in the constructor that emits an event when mutated elsewhere.
- `T9` - Avoid over-inheritance as it masks complexity and encourages over-abstraction.
- `T10` - Always use the named import syntax to explicitly declare which contracts are being imported from another file.
- `T11` - Group imports by their folder/package. Separate groups with an empty line. Groups of external dependencies should come first, then mock/testing contracts (if relevant), and finally local imports.
- `T12` - Summarize the purpose and functionality of the contract with a `@notice` natspec comment. Document how the contract interacts with other contracts inside/outside the project in a `@dev` natspec comment.

# Defi 
[Defi concepts glossary](https://www.gemini.com/cryptopedia/glossary)

- `D1` - Check your assumptions about what other contracts do and return.
- `D2` - Don't mix internal accounting with actual balances.
- `D3` - Don't use spot price from an AMM as an oracle.
- `D4` - Do not trade on AMMs without receiving a price target off-chain or via an oracle.
- `D5` - Use sanity checks to prevent oracle/price manipulation.
- `D6` - Watch out for rebasing tokens. If they are unsupported, ensure that property is documented.
- `D7` - Watch out for ERC-777 tokens. Even a token you trust could preform reentrancy if it's an ERC-777.
- `D8` - Watch out for fee-on-transfer tokens. If they are unsupported, ensure that property is documented.
- `D9` - Watch out for tokens that use too many or too few decimals. Ensure the max and min supported values are documented.
- `D10` - Be careful of relying on the raw token balance of a contract to determine earnings. Contracts which provide a way to recover assets sent directly to them can mess up share price functions that rely on the raw Ether or token balances of an address.
- `D11` - If your contract is a target for token approvals, do not make arbitrary calls from user input.

# Uncategorized checks
- [ ] Check if maps such as balances update correctly
- [ ] Do threshold checks

# Overflow/underflow attack vectors
Resources:
- [[Overflows and underflows]] theory
- [[Overflows and underflows - POC]]

Checks:
- [ ] Compiler < 0.80 or Unchecked {}
	- [ ] check for overflow/underflow

# Reentrancy attack vectors (calling other contracts)
Resources:
- [[Reentrancy]]

Checks:
 - [ ] Check for CEI pattern
 - [ ] Check for reentrancy guard
 - [ ] Does the contract use `_safeMint`?
 - [ ] Does the contract use `_safeTransfer`?

# Token Integration Checklist 
For convenience, all Slither [utilities](https://github.com/crytic/slither#tools) can be run directly on a token address, as shown below:

```bash
slither-check-erc 0xdac17f958d2ee523a2206206994597c13d831ec7 TetherToken --erc erc20
slither-check-erc 0x06012c8cf97BEaD5deAe237070F9587f8E7A266d KittyCore --erc erc721
```

Use the following Slither output for the token to follow this checklist:

```bash
- slither-check-erc [target] [contractName] [optional: --erc ERC_NUMBER]
- slither [target] --print human-summary
- slither [target] --print contract-summary
- slither-prop . --contract ContractName # requires configuration, and use of Echidna and Manticore
```
## General Considerations

- [ ] **The contract has a security review.** Avoid interacting with contracts that lack a security review. Assess the review's duration (i.e., the level of effort), the reputation of the security firm, and the number and severity of findings.

## Contract Composition

- [ ] **The token has only one address.** Tokens with multiple entry points for balance updates can break internal bookkeeping based on the address (e.g., `balances[token_address][msg.sender]` might not reflect the actual balance).

## Owner Privileges

- [ ] **The token is not upgradeable.** Upgradeable contracts may change their rules over time. Use Slither’s [`human-summary` printer](https://github.com/crytic/slither/wiki/Printer-documentation#contract-summary) to determine if the contract is upgradeable.
- [ ] **The owner has limited minting capabilities.** Malicious or compromised owners can abuse minting capabilities. Use Slither’s [`human-summary` printer](https://github.com/crytic/slither/wiki/Printer-documentation#contract-summary) to review minting capabilities and consider manually reviewing the code.
- [ ] **The token is not pausable.** Malicious or compromised owners can trap contracts relying on pausable tokens. Identify pausable code manually.
- [ ] **The owner cannot blacklist the contract.** Malicious or compromised owners can trap contracts relying on tokens with a blacklist. Identify blacklisting features manually.

## ERC20 Tokens

### ERC20 Conformity Checks

Slither includes the [`slither-check-erc`](https://github.com/crytic/slither/wiki/ERC-Conformance) utility that checks a token's conformance to various ERC standards. Use `slither-check-erc` to review the following:

- [ ] **`Transfer` and `transferFrom` return a boolean.** Some tokens do not return a boolean for these functions, which may cause their calls in the contract to fail.
- [ ] **The `name`, `decimals`, and `symbol` functions are present if used.** These functions are optional in the ERC20 standard and may not be present.
- [ ] **`Decimals` returns a `uint8`.** Some tokens incorrectly return a `uint256`. In these cases, ensure the returned value is below 255.
- [ ] **The token mitigates the known [ERC20 race condition](https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729).** The ERC20 standard has a known race condition that must be mitigated to prevent attackers from stealing tokens.

Slither includes the [`slither-prop`](https://github.com/crytic/slither/wiki/Property-generation) utility, which generates unit tests and security properties to find many common ERC flaws. Use slither-prop to review the following:

- [ ] **The contract passes all unit tests and security properties from `slither-prop`.** Run the generated unit tests, then check the properties with [Echidna](https://github.com/crytic/echidna) and [Manticore](https://manticore.readthedocs.io/en/latest/verifier.html).

### Risks of ERC20 Extensions

The behavior of certain contracts may differ from the original ERC specification. Review the following conditions manually:

- [ ] **The token is not an ERC777 token and has no external function call in `transfer` or `transferFrom`.** External calls in the transfer functions can lead to reentrancies.
- [ ] **`Transfer` and `transferFrom` should not take a fee.** Deflationary tokens can lead to unexpected behavior.
- [ ] **Consider any interest earned from the token.** Some tokens distribute interest to token holders. If not taken into account, this interest may become trapped in the contract.

### Token Scarcity

Token scarcity issues must be reviewed manually. Check for the following conditions:

- [ ] **The supply is owned by more than a few users.** If a few users own most of the tokens, they can influence operations based on the tokens' distribution.
- [ ] **The total supply is sufficient.** Tokens with a low total supply can be easily manipulated.
- [ ] **The tokens are located in more than a few exchanges.** If all tokens are in one exchange, compromising the exchange could compromise the contract relying on the token.
- [ ] **Users understand the risks associated with large funds or flash loans.** Contracts relying on the token balance must account for attackers with large funds or attacks executed through flash loans.
- [ ] **The token does not allow flash minting.** Flash minting can lead to drastic changes in balance and total supply, requiring strict and comprehensive overflow checks in the token operation.

## ERC721 Tokens

### ERC721 Conformity Checks

The behavior of certain contracts may differ from the original ERC specification. Review the following conditions manually:

- [ ] **Transfers of tokens to the 0x0 address revert.** Some tokens allow transfers to 0x0 and consider tokens sent to that address to have been burned; however, the ERC721 standard requires that such transfers revert.
- [ ] **`safeTransferFrom` functions are implemented with the correct signature.** Some token contracts do not implement these functions. Transferring NFTs to one of those contracts can result in a loss of assets.
- [ ] **The `name`, `decimals`, and `symbol` functions are present if used.** These functions are optional in the ERC721 standard and may not be present.
- [ ] **If used, `decimals` returns a `uint8(0)`.** Other values are invalid.
- [ ] **The `name` and `symbol` functions can return an empty string.** This behavior is allowed by the standard.
- [ ] **The `ownerOf` function reverts if the `tokenId` is invalid or refers to a token that has already been burned.** The function cannot return 0x0. This behavior is required by the standard but may not always be implemented correctly.
- [ ] **A transfer of an NFT clears its approvals.** This is required by the standard.
- [ ] **The token ID of an NFT cannot be changed during its lifetime.** This is required by the standard.

### Common Risks of the ERC721 Standard

Mitigate the risks associated with ERC721 contracts by conducting a manual review of the following conditions:

- [ ] **The `onERC721Received` callback is taken into account.** External calls in the transfer functions can lead to reentrancies, especially when the callback is not explicit (e.g., in [`safeMint`](https://www.paradigm.xyz/2021/08/the-dangers-of-surprising-code/) calls).
- [ ] **When an NFT is minted, it is safely transferred to a smart contract.** If a minting function exists, it should behave similarly to `safeTransferFrom` and handle the minting of new tokens to a smart contract properly, preventing asset loss.
- [ ] **Burning a token clears its approvals.** If a burning function exists, it should clear the token’s previous approvals.

# Sources

- [Crytic token integration checklist](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/token_integration.md)
- [Transmissions11 security checklist](https://github.com/transmissions11/solcurity/tree/main)

