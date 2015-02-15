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

NAME = 'pyfirewall'
VERSION = '0.13'
LICENSE = 'Gnu GPL3 (See LICENSE)'
DESCRIPTION = 'Firewall iptables based'

LONG_DESCRIPTION = """ Pyfirewall is a user-interface based on iptables that facilitates 
the configuration of your firewall. Can work with any type of network 
interface and is designed to handle a single PC in a normal home network.
Immediately provides the necessary rules to make stateful firewall and 
quick customizations such as management of TCP/UDP ports and web-sites 
filtering.
"""
URL = 'https://github.com/jeanslack/pyfirewall'


def glob_files(pattern):
	"""
	this is a simple function for globbing that iterate 
	for list files in dir
	"""
	
	return [f for f in glob(pattern) if os.path.isfile(f)]



def  LINUX_SLACKWARE(id_distro, id_version):
	
	setup(name = NAME,
		version = VERSION,
		description = DESCRIPTION,
		long_description = LONG_DESCRIPTION,
		author = 'Gianluca Pernigotto',
		author_email = 'jeanlucperni@gmail.com',
		url = URL,
		license = LICENSE,
		platforms = ['Gnu/Linux (%s %s)' % (id_distro, id_version)],
		packages = ['pyfirewall_pack'],
		scripts = [NAME],
		)
		
	
def LINUX_DEBIAN_UBUNTU(id_distro, id_version):
	"""
		------------------------------------------------
		setup build videomass debian package
		------------------------------------------------
		
		TOOLS: 
		apt-get install python-all python-stdeb fakeroot

		USAGE: 
		- for generate both source and binary packages :
			python setup.py --command-packages=stdeb.command bdist_deb
			
		- Or you can generate source packages only :
			python setup.py --command-packages=stdeb.command sdist_dsc
			
		RESOURCES:
		- look at there for major info:
			https://pypi.python.org/pypi/stdeb
			http://shallowsky.com/blog/programming/python-debian-packages-w-stdeb.html
	"""
	
	# this is DATA_FILE structure: 
	# ('dir/file destination of the data', ['dir/file on current place sources']
	# even path must be relative-path
	DATA_FILES = [
		('share/man/man8', ['man/pyfirewall.8.gz'],), 
		('share/doc/python-pyfirewall', glob_files('docs/*'),),
		('share/doc/python-pyfirewall', ['AUTHORS', 'BUGS', 'CHANGELOG', 
		'COPYING', 'README.md', 'TODO']),
		('/etc/init.d', ['config/demon/firewall'],),
		('/etc/pyfirewall', glob_files('config/rules/*'),),
		('/etc/sysctl.d', ['config/pyfirewall10net.conf'],),
				]
	
	DEPENDENCIES = ['python >=2.6']
	
	setup(name = NAME,
		version = VERSION,
		description = DESCRIPTION,
		long_description = LONG_DESCRIPTION,
		author = 'Gianluca Pernigotto',
		author_email = 'jeanlucperni@gmail.com',
		url = URL,
		license = LICENSE,
		platforms = ['Gnu/Linux (%s %s)' % (id_distro, id_version)],
		scripts = [NAME],
		packages = ['pyfirewall_pack'],
		data_files = DATA_FILES,
		install_requires = DEPENDENCIES,
		)

	
##################################################

if sys.platform.startswith('linux2'):
	
	dist_name = platform.linux_distribution()[0]
	dist_version = platform.linux_distribution()[1]
	
	if dist_name == 'Slackware ':
		LINUX_SLACKWARE(dist_name, dist_version)
		
	elif dist_name == 'debian' or dist_name == 'Ubuntu':
		LINUX_DEBIAN_UBUNTU(dist_name, dist_version)
		
	else:
		print 'this platform is not yet implemented: %s %s' % (dist_name, dist_version)
		

else:
	print 'OS not supported'
