import click
from click import Context

from rendez.vous.reunion.__version__ import __version__
from rendez.vous.reunion.client import client
from rendez.vous.reunion.server import server
from rendez.vous.reunion.multicast import multicast

@click.version_option(__version__)
@click.group()
@click.pass_context
def cli(ctx: Context) -> None:
  """ rendez.vous.reunion is for rendezvous """
  pass

def main() -> None:
  """
  Entrypoint for *setup.py* *reunion* console script.

  >>> import click
  >>> from rendez.vous.reunion.client import client
  >>> from rendez.vous.reunion.server import server
  >>> from rendez.vous.reunion.multicast import multicast
  """
  cli.add_command(client)
  cli.add_command(server)
  cli.add_command(multicast)
  cli()

if __name__ == '__main__':
   import doctest
   doctest.testmod(verbose=True)
