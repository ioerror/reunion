#!/usr/bin/env python3

# TODO: Tor stuff is not finished yet.
# TODO: should probably persist messages to an on-disk thing to survive restarts

HASH_LEN = 32 # output of primitives.Hash()
MSG_LEN  = 96 # padded message size, would be nice if this could be given as a parameter to ReunionSession
KIND_CHUNK_SIZE = {
    't1': 32 + 64 + 16 + MSG_LEN+16, # ?? + prp + mac + msg + mac
    't2': HASH_LEN + 32, # Hash(t1) + t2
    't3': HASH_LEN + 32, # Hash(t1) + t3
}

import click
import asyncio
from flask import Flask, stream_with_context, request, Response

import logging
logger = logging.getLogger('reunion-server')

app = Flask(__name__)

t1s = set()
t2s = set()
t3s = set()

# @stream_with_context
# def stream_list(lst):
#   for item in lst:
#     yield lst

def status(ctx):
    global t1s, t2s, t3s
    logger.debug('%s: t1:%d t2:%d t3:%d', ctx, len(t1s), len(t2s), len(t3s))

def update(kind, items:bytes):
    '''Insert in sorted order, ignoring duplicates.'''
    status(kind.decode())
    if not items:
        # TODO actually this is fine: logger.error('no get_data() in update')
        return
    required_length = KIND_CHUNK_SIZE['t'+kind.decode()]
    if len(items) % required_length != 0:
        logger.error('length mismatch %d %% %d != 0',
                     len(items), required_length)
        return
    if b'1' == kind: lst = t1s
    elif b'2' == kind: lst = t2s
    elif b'3' == kind: lst = t3s
    else: assert False
    for item in (items[idx : idx + required_length]
                 for idx in range(0, len(items), required_length)):
        if item in lst:
            logger.debug('inserting new T%s: prefix %s',
                         kind.decode(),
                         item[:8].hex(), )
        lst.add(item)
    return True

@app.route('/t1', methods=['POST','GET'], endpoint='t1')
async def serve_t1():
    global t1s
    update(b'1', request.get_data())
    resp = Response(b''.join(t1s))
    resp.headers.set('Content-Type', 'application/octet-stream')
    return resp

@app.route('/t2', methods=['POST','GET'], endpoint='t2')
async def serve_t2():
    global t2s
    update(b'2', request.get_data())
    resp = Response(b''.join(t2s))
    resp.headers.set('Content-Type', 'application/octet-stream')
    return resp

@app.route('/t3', methods=['POST','GET'], endpoint='t3')
async def serve_t3():
    global t3s
    update(b'3', request.get_data())
    resp = Response(b''.join(t3s))
    resp.headers.set('Content-Type', 'application/octet-stream')
    return resp



def setup_tor(bind_ip):
    from stem.control import Controller
    controller = Controller.from_port(address="127.0.0.1", port=9051)
    # after enabling ControlPort in torrc
    controller.authenticate(password="")

    # tor shared random (for epoch):
    # also available from
    # grep shared-rnd-(previous|current)-value /var/lib/tor/cached-microdesc-consensus

    print('current rnd', controller.get_info('sr/current'))
    # 'Ujtd/Zqjx0OlO4xubf9MBoqS12nraI6TYzyJwiZzsqA='
    print('previous rnd', controller.get_info('sr/previous'))
    # 'mdr2FK+N8Pgxqy7kKqcNXWZIiHP1981LlHczEIwFkrc='

    hostname = self.controller.create_ephemeral_hidden_service(
        {
            1921: bind_ip + ':1921'
        },
        await_publication = True).service_id + '.onion'
    print(hostname)

async def tcp_client_cb(reader, writer):
    global t1s
    global t2s
    global t3s
    print('got a connection', reader,'will now read kind')
    try:
        kind = await reader.readexactly(1)
    except asyncio.exceptions.IncompleteReadError:
        print('closing because bad')
        writer.close()
        return
    if kind not in (b'1', b'2', b'3'):
        print('wrong kind, closing')
        writer.close()
        return
    chunk_size = KIND_CHUNK_SIZE['t'+kind.decode()]
    # debug: kind
    status('tcp.t'+kind.decode())
    # TODO: update() looks at request.method etc, it shouldn't
    while reader.at_eof() != True:
        try:
            chunk = await reader.readexactly(chunk_size)
        except asyncio.exceptions.IncompleteReadError:
            break
        update(kind, chunk)
    if b'1' == kind:
        writer.write(b''.join(t1s))
    if b'2' == kind:
        writer.write(b''.join(t2s))
    if b'3' == kind:
        writer.write(b''.join(t3s))
    try: writer.write_eof()
    except: pass # that fails if they killed us
    await writer.drain()
    writer.close()
    await writer.wait_closed()
    logger.debug('goodbye to client %s %s', reader, writer)

async def serve_tcp(bind_ip):
    server = await asyncio.start_server(tcp_client_cb, host=bind_ip, port=1921,
                               reuse_address=True, reuse_port=True)
    while True:
        await asyncio.sleep(10)
    # async with server:
    #   await server.serve_forever()

def launch(mode, verbose, bind):
    global logger
    if 'http' == mode:
        if verbose:
            app.debug=True
        logger = app.logger
        app.run()
    elif mode in ('tor', 'tcp'):
        if verbose:
            logger.setLevel(logging.DEBUG)
            logging.debug('for some reason this is needed to get logger to show debug/info wtf') # TODO
        if 'tor' == 'mode':
            setup_tor(bind)
        asyncio.run(serve_tcp(bind))

@click.command()
@click.option("--bind", type=str, show_default=True,
              default='127.0.0.2',
              help="IP to bind to in TCP/tor mode", )
@click.option("--verbose", is_flag=True,
              help="Show verbose debug output", )
@click.option("--mode", type=str, default='http',
              show_default=True,
              help='http/tcp/tor', ) # TODO this should be a choice somehow
def main(**kw):
    launch(**kw)

if '__main__' == __name__:
    main()
