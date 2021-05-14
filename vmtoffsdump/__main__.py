#!/usr/bin/python3

from . import dumper
import pydemangler

def demangle(input):
	fallbacks = {
		'__cxa_pure_virtual': '(pure virtual function)',
	}
	return pydemangler.demangle(input) or fallbacks.get(input, input)

def render_vtable(typename):
	linux_vmt, *_ = dumper.get_class_vtables(typename)
	windows_vmt = list(dumper.guesstimate_windows_mapping(typename))
	
	for n, f in enumerate(linux_vmt):
		try:
			wi = windows_vmt.index(f)
		except ValueError:
			wi = None
		print('L:{:3d}'.format(n), 'W:{:3d}'.format(wi) if wi is not None else '     ', demangle(f.name))
