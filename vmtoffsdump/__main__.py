#!/usr/bin/python3

from . import dumper
import argparse

import lief
import pydemangler

def demangle(input):
	fallbacks = {
		'__cxa_pure_virtual': '(pure virtual function)',
	}
	return pydemangler.demangle(input) or fallbacks.get(input, input)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('binary', help = "Binary file to validate", type = lief.parse)
	args = parser.parse_args()
	
	vtable_handler = dumper.VTableDumper(args.binary)
	
	def render_vtable(typename):
		linux_vmt, *_ = vtable_handler.get_class_vtables(typename)
		windows_vmt = list(vtable_handler.guesstimate_windows_mapping(typename))
		
		for n, f in enumerate(linux_vmt):
			try:
				wi = windows_vmt.index(f)
			except ValueError:
				wi = None
			print('L:{:3d}'.format(n), 'W:{:3d}'.format(wi) if wi is not None else '     ', demangle(f.name))
