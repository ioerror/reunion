# REUNION

REUNION: rendezvous unobservability

This is the reference implementation of the REUNION cryptographic redezvous
protocol.

# What is REUNION?

REUNION is a privacy preserving transitionally post-quantum cryptographic
protocol for rendezvous between two or more participants. With the use of an
arbitrary shared passphrase and an agreed upon location or communications
medium, two or more participants may exchange a message, usually contact
information such as addresses or public keys.

## Status of `reunion` implementing REUNION

[![status-badge](https://ci.codeberg.org/api/badges/13701/status.svg)](https://ci.codeberg.org/repos/13701)

This is pre-release software, under active development.

# How to use REUNION?

It may be used on a local-area network with multicast with
`reunion-on-an-ethernet` or experimentally with `reunion-client` for use with a
`reunion-server`.

## Using REUNION on an ethernet

After installing the Python `reunion` module it is possible to run purpose
built specific commands for the specific usecase that is interesting:
```
$ reunion-on-an-ethernet --help
Usage: reunion-on-an-ethernet [OPTIONS]

  This implements REUNION on an ethernet.

  If you run it with no arguments, you will be prompted for a passphrase and
  message.

Options:
  -I, --interval INTEGER  Interval at which to start new sessions  [default:
                          60]
  --multicast-group TEXT  [default: 224.3.29.71]
  --bind-addr TEXT        [default: 0.0.0.0]
  --port INTEGER          [default: 9005]
  --reveal-once           Only reveal the message to the first person with the
                          correct passphrase
  --passphrase TEXT       The passphrase
  --message TEXT          The message
  --help                  Show this message and exit.

```

## Using REUNION on a Single Point of Failure (SPOF)

Using `reunion` outside of a local-area network is possible. We have
implemented a web server in `reunion-server`. The `reunion-server` is a
location where `reunion` clients may send and receive messsages to run the
REUNION protocol.

The `reunion-server` program provides an HTTP interface which by design is
bound only to localhost by default:
```
$ reunion-server
mode http
 * Serving Flask app 'reunion.server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

The `reunion-client` client program connects to a `reunion-server` and
performs REUNION protocol runs until it is manually stopped:
```
$ reunion-client --msg 'hello world' --passphrase 'I am a jelly donut'
```

## ReunionSession API

The `reunion` module provides an API for Python developers to integrate the
REUNION protocol into their applications. Import it from the `rendez` package
with: `from rendez.vous import reunion` to use it.

The `reunion.session` python module provides a sans IO implementation of the
cryptographic protocol which applications can use. So far, `reunion.multicast`
is the only user of this module.

### Notes

* There is no replay protection here. In the ReunionSession API, replays of
  the same t2 to the same t1 should always produce the same t3, regardless of
  if it is a dummy. Applications are currently responsible for implementing
  replay protection if they desire it.

* Deviating slightly from the algorithm in the paper, we introduce a new value
  `dummy_seed` which is used with an Hkdf to produce dummy t3 messages. REUNION
  as described in the paper requires replay protection to maintain
  unobservability, as its dummy t3s are specified to be random while it's
  legitimate t3s are deterministic.

* Different T2 messages from the same T1 will produce different T3s. The
  latest T2 received from a given T1 is used when computing the decryption key
  for its incoming T3 messages.

* The size of the payload is not specified here. Applications may implement
  their own requirement that T1 messages be a fixed size, but the
  ReunionSession API does not require them to do so.

### Setting up REUNION for development

We recommend using a Python virtual environment and installing the `rendez`
package with `pip` in editable mode:
```
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Running the tests

Run the test suite with `pytest`:

* `pytest -v`

### Building a Debian package

Generate a Debian package (e.g.: `python3-rendez`) for local use:
```
make deb
```

This is a deterministic reproducible build.

### Running the local Woodpecker continuous integration

Install `woodpecker-cli` to run the pipeline locally:
```
woodpecker-cli exec .woodpecker.yml 
```
