"""
General utility functions

>>> get_pairs is not None
True
"""

from typing import Any, Generator, Tuple

def get_pairs(items: str) -> Generator[Tuple[Any, Any], None, None]:
    """
    Helper function to get all unique pairs from a list of items.

    >>> list(get_pairs("ABCD"))
    [('A', 'B'), ('A', 'C'), ('A', 'D'), ('B', 'C'), ('B', 'D'), ('C', 'D')]
    """
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            yield items[i], items[j]
