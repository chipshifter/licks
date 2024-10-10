<br>
<p align="center">
  <img alt="Logo for Licks!" height=150 src="licks/logo.svg" />
</p>
<br>

Licks! is a silly and **experimental** instant messenger project.

## Experimental warning

Because it is an experiment, it is not meant for serious real-world usage, and should not expected to be secure and reliable enough for this use case.

## Status

Licks is still a work in progress and is not yet in a functional state. Our work is done in the open, and you can check out (and give us your feedback) our progress on the [Issues](https://github.com/chipshifter/licks/issues) page.

We currently do not accept feature requests or pull requests aimed at adding or modifying features, however, if you notice a bug feel free to report it to us so we can fix it.

## How to run

#### Running tests

Running tests is always a good idea to make sure everything's ok. Run `cargo test` on the root folder `licks/`. Please note that some integration tests require the server to be open, so make sure to have it run on localhost (see below)

#### Running the Dioxus client

You need Dioxus's prerequisites and `dioxus-cli`. Please visit Dioxus's ["Getting Started" page to learn more](https://dioxuslabs.com/learn/0.5/getting_started). You may also need `libx11` on Linux for the clipboard plugin.

If this all works out, then you can start a debug client by running `dx serve` in the `licks/client-dioxus` folder.

#### Running the server

The debug client automatically assumes (for now) a server being open on the localhost address.

To open the server, run `cargo run --package server` in the root folder `licks/` using another shell.

## Project goals

#### Goals ("Our priority")

- Experiment with innovative cryptography protocols and techniques
- Efficient group messaging thanks to the MLS Protocol.
- Familiar, no-bullshit, easy-to-use UX/UI
- Self-hostable servers
- Decently fast client and server.

#### Non-goals ("Not a priority")

- Safely implemented cryptography: constant time, no vulnerabilities...
- Personalized, modular client configuration
- Backwards compatiblity with older clients/servers (not prioritized to accelerate initial development)

#### Anti-goals ("Not what we want")

- Become a replacement for other "real" private messengers e.g. Matrix, Signal, Simplex...
- Interoperability with third-party clients of any kind