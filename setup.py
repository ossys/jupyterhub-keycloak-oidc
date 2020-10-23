#!/usr/bin/env python

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(name='keycloakoauth',
      version='1.0',
      description='Keycloak OAuth for Jupyterhub',
      author='Andrew Zah',
      author_email='zah@andrewzah.com',
      url='https://github.com/ossys/jupyterhub-keycloak-oidc',
      long_description=long_description,
      long_description_content_type='text/markdown',
      packages=setuptools.find_packages(),
     )
