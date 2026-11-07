# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Wallety is a Burp Suite extension (Montoya API) that decodes Ethereum JSON-RPC traffic: history notes/highlights and a read-only "Web3" editor tab with ABI-decoded calldata.

## Architecture

- **Main Entry Point**: `src/main/java/Extension.java` - `BurpExtension` + `HttpHandler`; registers the settings panel, the "Web3" request editor tab, and no-op tamper hooks
- `src/main/java/Web3Summary.java` - JSON-RPC body -> history note, highlight, and detail text (pure, testable)
- `src/main/java/Abi.java` - selector table (bundled `src/main/resources/selectors.txt` + user setting) and ABI calldata decoder
- `src/main/java/Keccak.java` - Keccak-256 (the JDK only has SHA3-256, which pads differently)
- **Build System**: Gradle with Kotlin DSL, JDK 21 via toolchain
- **Dependencies**: Montoya API (compile-only), Jackson databind (bundled into the JAR), JUnit 5 for tests

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` and can be loaded directly into Burp Suite.

## Extension Loading in Burp

1. Build the JAR using `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Documentation Structure

- See @docs/bapp-store-requirements.md for BApp Store submission requirements
- See @docs/montoya-api-examples.md for code patterns and extension structure  
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links

## Current State

Decoding works for `eth_call`-style transaction objects (static, dynamic, array, and tuple ABI types) and for signed raw transactions via `src/main/java/Rlp.java` (legacy and types 1-4, calldata through the ABI decoder). Sender recovery (needs secp256k1), response decoding, and an editable decoded view are not implemented. The `tamperCall`/`tamperRawTransaction` hooks are no-ops. Unit tests run outside Burp; the tab and annotations need a live Burp load to verify.
