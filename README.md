# procactivity

⚠️ experimental, does not work yet, i'm learning Rust and writing tests

Monitor process activity

A simple tool to get a summary of a Linux process activity


Started as a fork of [lurk](https://github.com/JakWai01/lurk)



## Usage (eventually)

```sh
procactivity <command>
```

This command produces a report of process activity:
- List of files opened
- List of files read
- List of files written to
- List of [origins](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin) (and IP addresses the hostname they resolved to) accessed
- List of commands of sub-processes




## Tests

You need [nextest](https://nexte.st/docs/installation/pre-built-binaries/) to run the tests

To run tests : 
```sh
cargo nextest run
```

or

```sh
cargo nextest run --no-capture
```


There were failures with `cargo tests` as soon as i had 2 tests (they ran fine individually)
I haven't inverstigated, but suppose there is a problem with creating 2 Tracer instances simulteneously




