"""
Run with python3 setup.py {test,install,version,...}
"""
import time
import os
from subprocess import check_output, CalledProcessError
import setuptools
from setuptools.command.build_ext import build_ext as hookBuild_ext
import toml

try:
    from stdeb.command.bdist_deb import bdist_deb
except ImportError:
    bdist_deb = None

try:
    from click_man.commands.man_pages import man_pages
except ImportError:
    man_pages = None

try:
    os.environ["SOURCE_DATE_EPOCH"] = (
        check_output("git log -1 --pretty=%ct", shell=True).decode().strip()
    )
except CalledProcessError:
    os.environ["SOURCE_DATE_EPOCH"] = str(int(time.time()))

if os.path.exists("pyproject.toml"):
    VERSION = toml.load("pyproject.toml")['project']['version']

if os.path.exists("requirements.txt"):
    with open("requirements.txt", "r") as obj:
        requirements = obj.read().splitlines()
else:
    requirements = []

with open("README.md", "r") as obj:
    long_description = obj.read()


class PrintVersion(hookBuild_ext):
    """
    A quick VERSION printing function.
    """

    def run(self):
        print(VERSION)


setuptools.setup(
    name="reunion",
    version=VERSION,
    author="REUNION Authors",
    author_email="git@rendezvous.contact",
    description=("REUNION is for rendezvous"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GPLv3",
    url="https://codeberg.org/rendezvous/reunion",
    packages=["reunion"],
    keywords="post-quantum, REUNION, rendezvous, encryption, meeting-people-is-easy",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    entry_points={
    "console_scripts": [
        "reunion-on-an-ethernet=reunion.multicast:main",
        "reunion-client=reunion.client:main",
        "reunion-server=reunion.server:main",
        ]
    },
    install_requires=requirements,
    data_files=[],
    package_data={},
    include_package_data=False,
    zip_safe=True,
    cmdclass=dict(
        bdist_deb=bdist_deb,
        man_pages=man_pages,
        version=PrintVersion,
    ),
)
