try:
  from importlib import metadata
  __version__: str = metadata.version('reunion')
except:
  __version__: str = '3.140000'
