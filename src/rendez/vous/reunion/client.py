"""
REUNION client

>>> assert logger is not None
"""

# TODO: do something about hardcoded message length (96)
# TODO: more click options for ports, ips, etc.
# TODO: add epoch handling.
# TODO: port the multicast client over here (send_udp_multicast?)

from rendez.vous import reunion
from rendez.vous.reunion.primitives import Hash

# TODO: Hash should have a property specifying byte length
from rendez.vous.reunion.session import ReunionSession, T1
from rendez.vous.reunion.__version__ import __version__

# process_t1: should probably case to T1()
import requests
import time
import random
import asyncio

import datetime
import json  # for the output
import click # for the cli
import socks # type: ignore

import logging
logger = logging.getLogger('reunion-client')



def through_socks_proxy(socks_addr, socks_port, target_addr, target_port,
                        username=None, password=None):
    s = socks.socksocket()
    # set_proxy(proxy_type, addr[, port[, rdns[, username[, password]]]])
    s.set_proxy(socks.SOCKS4, socks_addr, socks_port, rdns=True,
                username=username, password=password)
    print((target_addr, target_port))
    s.connect((target_addr, target_port))
    return asyncio.open_connection(socks=s)

async def send_tor(where, what, chunk_size):
    rw = await through_socks_proxy(
        '127.0.0.1', 9050,
        '62fkbxb2jqxnjvigkpihj32qoyv4ht576im3vi7oq7zbyf2tg7kwopyd.onion', 1921,
        username='reunion',)
    logger.debug('have a socks connection %s', rw)
    async for x in send_tcp(where, what, chunk_size,
                            reader_writer=rw):
        logger.debug('yielded from send_tcp %s', x)
        yield x

async def send_tcp(where, what, chunk_size, reader_writer=None):
    '''chunk_size is used to group the results'''
    async def internal():
        if not reader_writer:
            reader_writer = await asyncio.open_connection('127.0.0.2', '1921')
        else:
            reader, writer = reader_writer
        logger.debug('got a connection %s', reader)
        writer.write(where[1].encode())
        for record in what:
            writer.write(record)
        writer.write_eof()
        await writer.drain()
        logger.debug('wrote records')
        while not reader.at_eof():
            logger.debug('reading more')
            try:
                record = await reader.readexactly(chunk_size)
            except asyncio.exceptions.IncompleteReadError:
                logger.debug('incomplete')
                break # EOF I guess?
            logger.debug('yielding record')
            yield record
        writer.close()
    # we ignore connection errors since we'll eventually converge.
    try:
        async for x in internal():
            yield x
    except ConnectionRefusedError as e:
        logger.warning('connection refused %s', e)
    except ConnectionResetError:
        logger.warning('connection reset during %s', where)
    logger.debug('done with send %s', where)

async def send_http(where, what, chunk_size):
    '''chunk_size is used to group the results'''
    assert len(set(what)) == len(what)
    try:
        p = requests.post('http://127.0.0.1:5000/'+where,
                          data=b''.join(what))
    except Exception as e:
        # TODO log that it failed
        logger.warning('request failed', e)
        return
    if not p.ok:
        return
    for idx in range(0, len(p.content), chunk_size):
        yield p.content[idx : idx + chunk_size]

async def store_result(result:bytes):
    try:
        dumpable = ['utf8', result.decode()]
    except UnicodeDecodeError as e:
        logger.warn('result decode error: %s', e)
        # fallback to hex in case we can't decode it as unicode
        dumpable = ['hex', result.hex()]
    print(json.dumps(dumpable))

async def launch(passphrase, message, mode, verbose, duration: int,
                 mandatory_sleep=0.5, randomized_sleep=2):
    start_time = datetime.datetime.now()
    duration_delta = datetime.timedelta(seconds=duration)

    if verbose:
        logger.setLevel(logging.DEBUG)
        logging.debug('TODO why is this needed to get logger working?')
    logger.info(f'Running Reunion in {mode} mode for {duration}')
    if 'http' == mode:
        send = send_http
    elif 'tcp' == mode:
        send = send_tcp
    elif 'tor' == mode:
        send = send_tor
    else:
        raise Exception(f'invalid --mode {repr(mode)}')

    Me = ReunionSession.create(passphrase.encode(),
                               message.encode()[:96].ljust(96) # TODO truncation?
                               # TODO pass in salt= epoch id here, e.g. tor shared random
                               )
    my_t1 = Me.t1 # Me.t1.ljust(256)
    own_t1_hash = my_t1.id
    logger.debug('my_t1: %s', my_t1[:8].hex())

    answered_t1s = set( (own_t1_hash,) ) # don't answer own T1
    answered_t2s = set( )
    answered_t3s = set( )

    while datetime.datetime.now() < start_time + duration_delta:
        t2s = []
        logger.debug('t1s, my_t1 is %s', my_t1[:8].hex())
        stat_current_t1s = len(answered_t1s)
        async for t1 in send('t1', [my_t1], len(my_t1)):
            t1 = T1(t1)
            # TODO assert own_t1_hash in response
            logger.debug('Seen T1 %s', t1[:8].hex())
            if t1.id in answered_t1s:
                continue # skip already processed
            try:
                t2 = Me.process_t1(t1)
            except:
                # process_t1 can throw:
                #   File "reunion/session.py", line 250, in __init__
                #    csidh_ss = csidh.dh(session.csidh_sk, csidh_pk)
                #  File "sibc/sibc/csidh/__init__.py", line 118, in dh
                #    ss = self.curve.coeff(self.gae.GAE_at_A(sk, pk)).x.to_bytes(
                #  File "sibc/sibc/csidh/gae_df.py", line 64, in GAE_at_A
                #    assert self.curve.issupersingular(A), "non-supersingular input curve"
                # AssertionError: non-supersingular input curve
                continue # skip to next T1
            answered_t1s.add(t1.id) # TODO shouldn't update before we manage to send
            answered_t2s.add(own_t1_hash + t2) # we'll skip T2s we emitted
            t2s.append(own_t1_hash + t2)
        logger.debug('answered %d/%d T1s, moving on to T2',
                     len(answered_t1s) - stat_current_t1s,
                     len(answered_t1s))
        t3s = []
        async for t2 in send('t2', t2s, 64):
            t2_id = t2[:32]
            if t2 in answered_t2s:
                continue # skipping already processed
            t3, is_dummy = Me.process_t2(t2_id, t2[32:])
            t3s.append(own_t1_hash + t3)
            answered_t3s.add(own_t1_hash + t3) # we'll skip our own uploads
            answered_t2s.add(t2)
        logger.debug('answered %d/%d T2s, moving on to T3', len(t3s), len(answered_t3s))
        # TODO this is where we should update answered_t2s
        stat_current_t3s = len(answered_t3s)
        async for t3 in send('t3', t3s, 64):
            t3_id, t3_payload = t3[:32], t3[32:]
            if t3 in answered_t3s:
                continue # skipping already processed
            processed_result = Me.process_t3(t3_id, t3_payload)
            logger.debug('t3: %s %s', t3_id.hex(), processed_result)
            if processed_result:
                await store_result(processed_result)
            answered_t3s.add(t3)
        logger.debug('processed %d/%d T3s, looping',
                     len(answered_t3s) - stat_current_t3s,
                     len(answered_t3s))
        # TODO should update answered_t3s here
        await asyncio.sleep(mandatory_sleep + randomized_sleep*random.random())
        logger.debug('looping')

@click.command()
@click.version_option(__version__)
@click.option("--duration", type=int,
              default=24*3600,
              show_default=True,
              help="Duration to run the protocol for", )
@click.option("--verbose", is_flag=True,
              help="Show verbose debug output", )
@click.option("--mode", type=str, default='http',
              show_default=True,
              help='http/tcp/tor', )
@click.option("--message", prompt=True, required=True, type=str,
              help="Message to deliver to people using the same password", )
@click.option("--passphrase", prompt=True, required=True, type=str, help="Passphrase/password")
def client(**kw):
    """
    REUNION http/tcp/tor client
    """
    asyncio.run(launch(**kw))

def main(**kw):
    client(**kw)

if '__main__' == __name__:
    import doctest
    doctest.testmod(verbose=True)
