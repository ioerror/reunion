"""
Enable a single source of truth for module version metadata for all code within
the reunion package. The current version is available as *__version__* and may
be imported as *reunion.__version__.__version__*.

>>> from importlib import metadata
>>> __version__ == metadata.version('reunion')
True
"""

try:
  from importlib import metadata
  __version__: str = metadata.version('reunion')
except:
  __version__: str = '3.140000'

if '__main__' == __name__:
    import doctest
    doctest.testmod(verbose=True)
