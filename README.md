# Extension Template Project

This project was created by PortSwigger to help you quickly start developing extensions in Java.

## Wallety: Web3 JSON-RPC for Burp

Wallety makes Ethereum JSON-RPC traffic readable inside Burp. It registers a
Montoya `HttpHandler`, so Proxy, Repeater, Intruder, and Scanner traffic are
all covered.

**History notes and highlights.** Every JSON-RPC 2.0 request gets a note in
the Proxy history, e.g. `eth_call transfer → 0x1234…5678` or
`batch[4]: eth_call eth_blockNumberx3`. Requests that send or sign
(`eth_sendRawTransaction`, `eth_sendTransaction`, `personal_sign`,
`eth_signTypedData_v4`, ...) are highlighted orange. Existing user notes and
highlights are never overwritten.

**Web3 editor tab.** Any request whose body is a JSON-RPC 2.0 request or batch
gets a read-only "Web3" tab in the message editor showing method, id, `to`,
`from`, `value` (in wei and ether), block tag, and the ABI-decoded calldata:
function selector, matched signature, and each argument including dynamic
types, arrays, and tuples. Unknown selectors show raw 32-byte words. Raw
transactions currently show only their length and envelope type (legacy,
EIP-1559, EIP-4844, EIP-7702); RLP decoding is not yet implemented.

**Signatures.** [selectors.txt](src/main/resources/selectors.txt) bundles
common ERC-20/721/1155, proxy, multicall, Uniswap, Permit2, Safe, and
ERC-4337 signatures; selectors are computed with a built-in Keccak-256 at
load, so the tool works offline. Add project-specific signatures under
**Settings > Extensions > Wallety**, space-separated, e.g.
`swap(address,uint256) claim(uint256[])`.

**Tamper hooks.** [Extension.java](src/main/java/Extension.java) still carries
two no-op hooks on the send path, `tamperCall(ObjectNode)` and
`tamperRawTransaction(String)`, and logs one JSON record per targeted RPC to
the extension Output tab. They predate the decoder and will likely be replaced
by an editable decoded view; Repeater already covers manual tampering.

Processing is bounded to 1 MiB per body, 256 entries per batch, and 64 levels
of JSON nesting. Compressed bodies, any Transfer-Encoding framing, invalid
UTF-8, and malformed JSON are passed through untouched and get no note or tab.

Build and test (Gradle picks up a local JDK 21 via the toolchain setting):

```bash
./gradlew test jar
```

Load `build/libs/extension-template-project.jar` through **Extensions >
Installed > Add**. Jackson is bundled; Montoya is supplied by Burp. The unit
tests cover hashing, ABI decoding, and summaries outside Burp; a live Burp
load remains necessary to verify the tab and history annotations.

## Contents
* [Before you start](#before-you-start)
* [Writing your extension](#writing-your-extension)
* [Building your extension](#building-your-extension)
* [Loading the JAR file into Burp](#loading-the-jar-file-into-burp)
* [Sharing your extension](#sharing-your-extension)


## Before you start

Before you begin development, make sure that your project's JDK is set to version "21".


## Writing your extension

To begin development, open the [Extension.java](src/main/java/Extension.java) file. It includes an example of setting your extension's name, which you can customize with your own logic.

The template contains the following components for building your extension:

* The `initialize` method. This is the entry point for your extension. It is called when the extension is loaded and receives a [montoyaApi](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html) argument, which provides access to all Montoya API features.
* The `Extension` class. This implements the BurpExtension interface, so your extension is recognized and loaded by Burp.

#### Related resources

* For more information on Montoya API features, see the [JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html).
* To explore example extensions, visit our [GitHub repository](https://github.com/PortSwigger/burp-extensions-montoya-api-examples).
* For more information on creating extensions, see our [documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating).
* For a beginner tutorial, see [Writing your first extension](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/first-extension).
* If you have any questions or need help from the community, join our [Discord channel](https://discord.com/channels/1159124119074381945/1164175825474686996).

### Vibe Coding Your Extension with AI

You can use an LLM to help you write your extension. To support this, we've included a [`CLAUDE.md`](./CLAUDE.md) file and supporting [documentation](./docs) that provide essential context for the model.

#### Vibe Coding with Claude Code

To use this file with Claude Code:

1. Open a terminal and navigate to the `ExtensionTemplateProject` folder.
2. Run Claude Code using the following command: `claude`.
3. Prompt Claude to create some code for your extension.

Claude should automatically read the contents of the `ExtensionTemplateProject` folder, including the `CLAUDE.md` file, then create draft code for you to review. If you think it hasn't read the `CLAUDE.md` file, directly prompt it to do so before continuing.

#### Vibe Coding with Other LLMs

If you're using an LLM other than Claude Code, prompt the LLM to read the `CLAUDE.md` file and supporting documentation from the `docs` folder, or provide their contents as part of your context window.

---

## Building your extension

When you're ready to test and use your extension, follow these steps to build a JAR file and load it into Burp.

### Building the JAR file

To build the JAR file, run the following command in the root directory of this project:

* For UNIX-based systems: `./gradlew jar`
* For Windows systems: `gradlew jar`

If successful, the JAR file is saved to `<project_root_directory>/build/libs/<project_name>.jar`. If the build fails, errors are shown in the console. By default, the project name is `extension-template-project`. You can change this in the [settings.gradle.kts](./settings.gradle.kts) file.


## Loading the JAR file into Burp

To load the JAR file into Burp:

1. In Burp, go to **Extensions > Installed**.
2. Click **Add**.
3. Under **Extension details**, click **Select file**.
4. Select the JAR file you just built, then click **Open**.
5. [Optional] Under **Standard output** and **Standard error**, choose where to save output and error messages.
6. Click **Next**. The extension is loaded into Burp.
7. Review any messages displayed in the **Output** and **Errors** tabs.
8. Click **Close**.

Your extension is loaded and listed in the **Burp extensions** table. You can test its behavior and make changes to the code as necessary.

### Reloading the JAR file in Burp

If you make changes to the code, you must rebuild the JAR file and reload your extension in Burp for the changes to take effect.

To rebuild the JAR file, follow the steps for [building the JAR file](#building-the-jar-file).

To quickly reload your extension in Burp:

1. In Burp, go to **Extensions > Installed**.
2. Hold `Ctrl` or `⌘`, and select the **Loaded** checkbox next to your extension.

---

## Sharing your extension

Once you've built your extension, we'd love to see what you've created!

Share your extension on our [PortSwigger Discord](https://discord.com/channels/1159124119074381945/1164175825474686996) #extensions channel to get feedback, showcase your work, and connect with other developers.
Then take it to the next level by submitting your extension to the BApp store, making it available to the community of 80,000+ users worldwide.

For guidance on the submission process, see [Submitting extensions to the BApp store](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-submitting-extensions).
