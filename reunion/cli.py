import click

from reunion.__version__ import __version__
from reunion.client import client
from reunion.server import server
from reunion.multicast import multicast

@click.version_option(__version__)
@click.group()
@click.pass_context
def cli(ctx):
  """ reunion is for rendezvous """
  pass

def main():
  """
  Entrypoint for *setup.py* *reunion* console script.

  >>> import click
  >>> from reunion.client import client
  >>> from reunion.server import server
  >>> from reunion.multicast import multicast
  """
  cli.add_command(client)
  cli.add_command(server)
  cli.add_command(multicast)
  cli()

if __name__ == '__main__':
   import doctest
   doctest.testmod(verbose=True)
