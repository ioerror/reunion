# REUNION

REUNION: rendezvous unobservability

This is the reference implementation of the REUNION cryptographic redezvous
protocol.

This is pre-release software, under active development.

## Using REUNION on an ethernet

```
$ python -m reunion.multicast --help
Usage: python -m reunion.multicast [OPTIONS]

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

## Using REUNION on a SPOF

* coming soon

## ReunionSession API

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

### Running the tests
* `pytest`
