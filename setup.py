from distutils.core import setup
from setuptools import find_packages

VERSION = '0.1'

setup(
    name='truenas_connect_utils',
    description='TrueNAS Scale System TrueNAS Connect Utils',
    version=VERSION,
    include_package_data=True,
    packages=find_packages(include=[
        'truenas_connect_utils',
        'truenas_connect_utils.*',
    ]),
    license='GNU3',
    platforms='any',
)
