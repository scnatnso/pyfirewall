#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# First release: October 07 2014
#
#
#########################################################
# Name: setup.py
# Porpose: script for building pyfirewall package
# Platform: Linux Slackware
# Writer: Gianluca Pernigoto <jeanlucperni@gmail.com>
# Copyright: (c) 2014 Gianluca Pernigoto <jeanlucperni@gmail.com>
# license: GPL3
# Rev (00) October 07 2014
#########################################################

from distutils.core import setup
from setuptools import setup
import platform
from glob import glob
import sys
import os


VERSION = '0.12'
LICENSE = 'Gnu GPL3 (See LICENSE)'
DESCRIPTION = 'Firewall iptables based'

LONG_DESCRIPTION = """Firewall for single machines with Gnu/Linux's OS.
"""

def glob_files(pattern):
	"""
	this is a simple function for globbing that iterate 
	for list files in dir
	"""
	
	return [f for f in glob(pattern) if os.path.isfile(f)]



def LINUX(distro):
	
	setup(name = 'pyfirewall',
		version = VERSION,
		description = DESCRIPTION,
		long_description = LONG_DESCRIPTION,
		author = 'Gianluca Pernigotto',
		author_email = 'jeanlucperni@gmail.com',
		url = 'https://github.com/jeanslack/pyfirewall',
		license = LICENSE,
		platforms = ['Linux (%s)' % (distro)],
		packages = ['firewall_package'],
		scripts = ['pyfirewall']
		)
		
	
if sys.platform.startswith('linux2'):
	
	distro = platform.linux_distribution()[0]
	LINUX(distro)
	
else:
	print 'OS not supported'
