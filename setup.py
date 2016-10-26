#!/usr/bin/env python
import pip
import sys

from setuptools import find_packages
from setuptools import setup

from ldap_sync import __version__ as version


def install(*packages):
    """Install a new package using pip"""
    for package in packages:
        pip.main(['install', package])


with open('README.rst') as f:
    readme = f.read()

setup(
    name='django-ldap-sync',
    version=version,
    description='A Django application for synchronizing LDAP users and groups',
    long_description=readme,
    license='BSD',
    author='Jason Bittel',
    author_email='jason.bittel@gmail.com',
    url='https://github.com/jbittel/django-ldap-sync',
    download_url='https://github.com/jbittel/django-ldap-sync',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Programming Language :: Python',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
    keywords=['django', 'ldap', 'active directory', 'synchronize', 'sync'],
)

if __name__ == '__main__':
    if sys.platform.startswith('win'):
        install('pyad')
    else:
        install('python-ldap>=2.4.13')
