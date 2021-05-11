#!/usr/bin/python3

import lief
import argparse
import itertools
import struct
import pickle
import collections
import pathlib

# lief doesn't seem to handle linux demangles yet
import pydemangler

import functools

parser = argparse.ArgumentParser()

parser.add_argument('binary', help = "Binary file to validate", type = pathlib.Path)

args = parser.parse_args()

elf_binary = lief.parse(str(args.binary))

# this is slow.
function_map = { f.address: f for f in elf_binary.functions }
symbol_map = { s.value: s for s in elf_binary.static_symbols }

imported_function_by_name = { f.name: f for f in elf_binary.imported_functions }

def dereference(addr):
	a, = struct.unpack('I', bytes(elf_binary.get_content_from_virtual_address(addr, 4)))
	return a

def demangle(input):
	fallbacks = {
		'__cxa_pure_virtual': '(pure virtual function)',
	}
	return pydemangler.demangle(input) or fallbacks.get(input, input)

def unpack_string(addr, encoding = 'utf-8', chunk = 16, **kwargs):
	''' unpacks a variable-length, zero-terminated string from the binary '''
	try:
		unpacker = itertools.takewhile(
			lambda x: x > 0,
			itertools.chain.from_iterable(
				elf_binary.get_content_from_virtual_address(addr + o, chunk)
				for o in itertools.count(0, chunk)
			)
		)
		return bytes(unpacker).decode(encoding, **kwargs)
	except:
		pass
	return ""

def get_function_from_virtual(addr):
	a, = struct.unpack('I', bytes(elf_binary.get_content_from_virtual_address(addr, 4)))
	fn = function_map.get(a, None)
	if fn is None:
		# resolve relocations
		rel = elf_binary.get_relocation(addr)
		if rel is not None and rel.has_symbol and rel.symbol.is_function:
			fn = imported_function_by_name.get(rel.symbol.name, None)
	return fn

def get_class_vtables(vt_name):
	vt = elf_binary.get_symbol(vt_name)
	
	# vtables are delimited by offset to base class + typeinfo
	# so the current table is complete once we run into a non-function
	vtable_entries = []
	for offs in range(0, vt.size, 4):
		fn = get_function_from_virtual(vt.value + offs)
		
		if fn:
			vtable_entries.append(fn)
		elif len(vtable_entries):
			yield vtable_entries.copy()
			vtable_entries.clear()
	if len(vtable_entries):
		yield vtable_entries.copy()

def pairwise_longest(iterable):
	"""
	Yields a tuple containing the current and next item in an iterable.
	Continues until the function yields (iterable[-1], None)
	"""
	a, b = itertools.tee(iterable)
	next(b, None)
	return itertools.zip_longest(a, b, fillvalue = None)

@functools.cache
def get_sym(name):
	return elf_binary.get_symbol(name)

def get_base_class_containing_vtable_index(subclass, vti):
	"""
	Returns the topmost class containing the given vtable index.
	"""
	for current, next in pairwise_longest(get_class_hierarchy(get_sym(f'_ZTI{subclass}'))):
		if next is None:
			return current
		vt_info = get_sym(f'_ZTV{next}')
		if (vt_info.size // 4) - 2 <= vti:
			return current
	return subclass

def guesstimate_windows_mapping(typename):
	"""
	Given an ordered list of functions within a Linux vtable, yield the order they are
	predicted to be in on Windows.  Some entries may be skipped.
	"""
	base_vmt, *inherited_vmts = get_class_vtables(f'_ZTV{typename}')
	
	vtable_thunks_by_name = {
		# strip prefix 'non-virtual thunk to '
		demangle(fn.name)[21:]: (n, fn)
		for n, fn in enumerate(list(itertools.chain(base_vmt, *inherited_vmts)))
		if fn and fn.name.startswith('_ZThn')
	}
	
	# MSVC places overloaded functions next to each other, so scan for them...
	vtable_fn_overloads = collections.defaultdict(list)
	for sym in base_vmt:
		if not sym or not sym.name or not sym.name.startswith('_ZN'):
			continue
		method_name = demangle(sym.name)
		
		# group them based on the superclass that contains them (i.e., in the same vtable)
		base_class_with_fn = get_base_class_containing_vtable_index(typename, base_vmt.index(sym))
		overload_key = base_class_with_fn + method_name[:method_name.rfind('(')]
		vtable_fn_overloads[overload_key].append(sym)
	
	# ... then insert them in reverse order before the first one, because MSVC does that too
	for sym, *other_overloads in vtable_fn_overloads.values():
		if len(other_overloads) == 0:
			continue
		base_vmt = [ s for s in base_vmt if s not in other_overloads ]
		position = base_vmt.index(sym)
		base_vmt[position:position] = reversed(other_overloads)
	
	for n, (cur_sym, next_sym) in enumerate(pairwise_longest(base_vmt)):
		if not next_sym:
			yield cur_sym
			continue
		
		if cur_sym:
			cur_name, next_name = (demangle(n) for n in [ cur_sym.name, next_sym.name ])
			
			# skip consecutive destructors, as MSVC doesn't generate those
			if next_name.find('::~') != -1 and cur_name == next_name:
				continue
			
			# skip functions with thunks further down the vtable
			# unless it's a destructor, which we keep
			thunk_index, thunk_sym = vtable_thunks_by_name.get(cur_name, (None, None))
			if thunk_sym and thunk_index > n and cur_name.find('::~') == -1:
				continue
		
		yield cur_sym

@functools.cache
def get_class_hierarchy(typeinfo):
	"""
	Returns a list of mangled typenames in ascending order (towards base classes at the end).
	"""
	typeinfo_class = elf_binary.get_relocation(typeinfo.value)
	typeinfo_name = unpack_string(dereference(typeinfo.value + 0x04))
	if typeinfo_class.symbol.name == '_ZTVN10__cxxabiv120__si_class_type_infoE':
		# single inheritance
		nested_type = symbol_map.get(dereference(typeinfo.value + 0x08), None)
		if nested_type:
			return [ typeinfo_name ] + get_class_hierarchy(nested_type)
	elif typeinfo_class.symbol.name == '_ZTVN10__cxxabiv121__vmi_class_type_infoE':
		# multiple inheritance
		nested_type = symbol_map.get(dereference(typeinfo.value + 0x10), None)
		if nested_type:
			return [ typeinfo_name ] + get_class_hierarchy(nested_type)
	elif typeinfo_class.symbol.name == '_ZTVN10__cxxabiv117__class_type_infoE':
		return [ typeinfo_name ]
	print('unknown typeinfo class', typeinfo_class)
	return [ typeinfo_name ]

def render_vtable(typename):
	linux_vmt, *_ = get_class_vtables(f'_ZTV{typename}')
	windows_vmt = list(guesstimate_windows_mapping(typename))
	
	for n, f in enumerate(linux_vmt):
		try:
			wi = windows_vmt.index(f)
		except ValueError:
			wi = None
		print('L:{:3d}'.format(n), 'W:{:3d}'.format(wi) if wi is not None else '     ', demangle(f.name))
