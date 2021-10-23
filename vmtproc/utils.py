#!/usr/bin/python3

import argparse

import functools
import lief
import pydemangler
from . import dumper

import sys

def is_vtable(symbol):
	return symbol.name.startswith('_ZTV') and symbol.name[4].isnumeric()

@functools.lru_cache(maxsize = None)
def custom_demangle(sym_name):
	demangled = pydemangler.demangle(sym_name)
	if demangled:
		return demangled
	
	stub_names = {
		'__cxa_pure_virtual': '(pure virtual function)',
	}
	return stub_names[sym_name]

def dump_binary_vtables():
	parser = argparse.ArgumentParser()
	
	parser.add_argument('binary', type = lief.parse)
	parser.add_argument(
		'-o', '--output-file',
		nargs = '?', type = argparse.FileType('wt'), default = sys.stdout
	)
	
	args = parser.parse_args()
	
	processor = dumper.VTableProcessor(args.binary)
	for vtsym in sorted(filter(is_vtable, args.binary.symbols), key = lambda s: custom_demangle(s.name)):
		print(custom_demangle(vtsym.name), file = args.output_file)
		vmt, *_ = processor.get_class_vtables(vtsym.name[4:])
		for vfn in vmt:
			print('\t' + custom_demangle(vfn.name), file = args.output_file)
