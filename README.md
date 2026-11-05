# Extension Template Project

This project was created by PortSwigger to help you quickly start developing extensions in Java.

## Wallety Web3 JSON-RPC implementation

[Extension.java](src/main/java/Extension.java) registers a Montoya
`ProxyRequestHandler` for JSON-RPC 2.0 requests passing through Burp Proxy.
It processes `eth_call` and `eth_sendRawTransaction` immediately before
forwarding, including matching entries in JSON-RPC batches. Other Burp tools,
such as Repeater and Scanner, require a separate `HttpHandler` registration.

The hooks initially leave every payload unchanged. Customize these methods:

* `tamperCall(ObjectNode transaction)` receives `params[0]` and can modify
  hexadecimal calldata in `data` or `input`, or transaction address fields.
* `tamperRawTransaction(String signedTransactionHex)` receives the entire
  signed transaction string in `params[0]`. Changing its encoded bytes can
  invalidate the signature or change the recovered sender. Decode, modify,
  and re-sign with an authorized test key when testing a valid modified
  transaction. No transaction signing or key handling is built in.

`tamperWeb3Payload(String jsonBody)` is the standalone JSON helper. It preserves
unchanged input verbatim and rolls back the whole body if parsing or a hook
fails. Changed bodies are serialized as JSON, encoded as UTF-8, and applied
using Montoya's `withBody(ByteArray)` to update Content-Length automatically.

Each targeted RPC produces one escaped JSON record in the extension's Output
tab with its UTC timestamp, HTTP message ID, URL, RPC ID, batch index, method,
original and final parameters, and modification status. Records describe the
request prepared for forwarding; they do not assert node acceptance or a
confirmed vulnerability. Parameter values are recorded in full, so treat
exported logs as captured request data. Parse/preparation failures produce
rate-limited error records and preserve the original request.

Processing is bounded to 1 MiB per body, 256 entries per batch, and 64 levels
of JSON nesting. Empty, malformed, duplicate-key, or trailing-token JSON is
passed through unchanged. Compressed bodies, any Transfer-Encoding framing,
invalid UTF-8, and unsupported parameter shapes are also passed through.
These are deliberate processing limits, adjustable in the implementation.

Build and test with a Java 21 JDK:

```bash
./gradlew test jar
```

Load `build/libs/extension-template-project.jar` through **Extensions >
Installed > Add**. Jackson is bundled; Montoya is supplied by Burp. The unit
tests exercise payload behavior outside Burp; a live Burp load/forwarding
check remains necessary for runtime validation.

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
