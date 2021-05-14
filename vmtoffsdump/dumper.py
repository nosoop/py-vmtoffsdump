import lief
import argparse
import itertools
import struct
import pickle
import collections
import pathlib
import functools

# lief doesn't seem to handle linux demangles yet
import pydemangler

parser = argparse.ArgumentParser()

parser.add_argument('binary', help = "Binary file to validate", type = pathlib.Path)

args = parser.parse_args()

elf_binary = lief.parse(str(args.binary))

function_map = { f.address: f for f in elf_binary.functions }
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

@functools.cache
def get_class_vtables(typename):
	"""
	Returns a list of lists of vtable functions, one for each table in the class.
	"""
	vt = elf_binary.get_symbol(f'_ZTV{typename}')
	
	# vtables are delimited by offset to base class + typeinfo
	# so the current table is complete once we run into a non-function
	vtable_list = []
	current_vtable_entries = []
	for offs in range(0, vt.size, 4):
		fn = get_function_from_virtual(vt.value + offs)
		
		if fn:
			current_vtable_entries.append(fn)
		elif len(current_vtable_entries):
			vtable_list.append(current_vtable_entries.copy())
			current_vtable_entries.clear()
	if len(current_vtable_entries):
		vtable_list.append(current_vtable_entries.copy())
	return vtable_list

@functools.cache
def get_sym(name):
	return elf_binary.get_symbol(name)

def get_base_class_containing_vtable_index(subclass, vti):
	"""
	Returns the topmost class containing the given vtable index.
	"""
	current_iter, next_iter = itertools.tee(get_class_hierarchy(get_sym(f'_ZTI{subclass}')))
	next(next_iter, None)
	for current, nextitem in itertools.zip_longest(current_iter, next_iter, fillvalue = None):
		if nextitem is None:
			return current
		vt_info = get_sym(f'_ZTV{nextitem}')
		if (vt_info.size // 4) - 2 <= vti:
			return current
	return subclass

def guesstimate_windows_mapping(typename):
	"""
	Given an ordered list of functions within a Linux vtable, yield the order they are
	predicted to be in on Windows.  Some entries may be skipped.
	"""
	base_vmt, *inherited_vmts = get_class_vtables(typename)
	
	vtable_thunks_by_name = {
		# strip prefix 'non-virtual thunk to '; ignore destructor thunks
		demangle(fn.name)[21:]: (n, fn)
		for n, fn in enumerate(list(itertools.chain(base_vmt, *inherited_vmts)))
		if fn and fn.name.startswith('_ZThn') and demangle(fn.name).find('::~') == -1
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
		# remove them first
		base_vmt = [ s for s in base_vmt if s not in other_overloads ]
		
		if demangle(sym.name).find('::~') != -1:
			# skip destructor overloads, as MSVC doesn't generate those
			# ... I think? asherkin's impl only ignored consecutive dtors
			# but I think overloaded makes more sense
			continue
		
		position = base_vmt.index(sym)
		base_vmt[position:position] = reversed(other_overloads)
	
	for n, sym in enumerate(base_vmt):
		demangled_name = demangle(sym.name)
		
		# skip functions with thunks further down the vtable
		thunk_index, thunk_sym = vtable_thunks_by_name.get(demangled_name, (None, None))
		if thunk_sym and thunk_index > n:
			continue
		
		yield sym

@functools.cache
def get_class_hierarchy(typeinfo):
	"""
	Returns a list of mangled typenames in ascending order (towards base classes at the end).
	"""
	return get_class_hierarchy_internal(typeinfo.value)

@functools.cache
def get_class_hierarchy_internal(typeinfo_ptr):
	"""
	Returns a list of mangled typenames in ascending order (towards base classes at the end).
	"""
	typeinfo_class = elf_binary.get_relocation(typeinfo_ptr)
	typeinfo_name = unpack_string(dereference(typeinfo_ptr + 0x04))
	if typeinfo_class.symbol.name == '_ZTVN10__cxxabiv120__si_class_type_infoE':
		# single inheritance
		nested_typeinfo_ptr = dereference(typeinfo_ptr + 0x08)
		return [ typeinfo_name ] + get_class_hierarchy_internal(nested_typeinfo_ptr)
	elif typeinfo_class.symbol.name == '_ZTVN10__cxxabiv121__vmi_class_type_infoE':
		# multiple inheritance
		nested_typeinfo_ptr = dereference(typeinfo_ptr + 0x10)
		return [ typeinfo_name ] + get_class_hierarchy_internal(nested_typeinfo_ptr)
	elif typeinfo_class.symbol.name == '_ZTVN10__cxxabiv117__class_type_infoE':
		return [ typeinfo_name ]
	print('unknown typeinfo class', typeinfo_class)
	return [ typeinfo_name ]
