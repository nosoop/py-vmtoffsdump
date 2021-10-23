import itertools
import struct
import collections
import functools

# lief only demangles on unix-based systems
import pydemangler

class VTableDumper:

	def __init__(self, binary):
		self.binary = binary
		self.function_map = { f.address: f for f in self.binary.functions }
		self.imported_function_by_name = { f.name: f for f in self.binary.imported_functions }

	def dereference(self, addr):
		a, = struct.unpack('I', bytes(self.binary.get_content_from_virtual_address(addr, 4)))
		return a

	def demangle(self, input):
		''' demangles a symbol '''
		# I don't think we actually need demangler, but I don't feel like figuring out the
		# symbol format at the moment
		fallbacks = {
			'__cxa_pure_virtual': '(pure virtual function)',
		}
		return pydemangler.demangle(input) or fallbacks.get(input, input)

	def unpack_string(self, addr, encoding = 'utf-8', chunk = 16, **kwargs):
		''' unpacks a variable-length, zero-terminated string from the binary '''
		try:
			unpacker = itertools.takewhile(
				lambda x: x > 0,
				itertools.chain.from_iterable(
					self.binary.get_content_from_virtual_address(addr + o, chunk)
					for o in itertools.count(0, chunk)
				)
			)
			return bytes(unpacker).decode(encoding, **kwargs)
		except:
			pass
		return ""

	def _get_function_from_raw_addr(self, raw_addr, fn_addr):
		"""
		Attempts to find a function from `fn_addr`, falling back to finding a relocation entry
		for `raw_addr`.
		"""
		fn = self.function_map.get(fn_addr, None)
		if fn is None:
			# resolve relocations
			rel = self.binary.get_relocation(raw_addr)
			if rel is not None and rel.has_symbol and rel.symbol.is_function:
				fn = self.imported_function_by_name.get(rel.symbol.name, None)
		return fn

	@functools.cache
	def get_class_vtables(self, typename):
		"""
		Returns a list of lists of vtable functions, one for each table in the class.
		"""
		vt = self.binary.get_symbol(f'_ZTV{typename}')
		
		# vtables are delimited by offset to base class + typeinfo
		# so the current table is complete once we run into a non-function
		vtable_list = []
		current_vtable_entries = []
		
		vtable_data = self.binary.get_content_from_virtual_address(vt.value, vt.size)
		addrs = zip(
			( itertools.count(vt.value, 4) ),
			( v for v, *_ in struct.iter_unpack('I', bytes(vtable_data)) )
		)
		for raw_addr, fn_addr in addrs:
			fn = self._get_function_from_raw_addr(raw_addr, fn_addr)
			if fn:
				current_vtable_entries.append(fn)
			elif len(current_vtable_entries):
				vtable_list.append(current_vtable_entries.copy())
				current_vtable_entries.clear()
		if len(current_vtable_entries):
			vtable_list.append(current_vtable_entries.copy())
		return vtable_list

	@functools.cache
	def get_sym(self, name):
		return self.binary.get_symbol(name)

	def get_base_class_containing_vtable_index(self, subclass, vti):
		"""
		Returns the topmost class containing the given vtable index.
		"""
		current_iter, next_iter = itertools.tee(self.get_class_hierarchy(subclass))
		next(next_iter, None)
		for current, nextitem in itertools.zip_longest(current_iter, next_iter, fillvalue = None):
			if nextitem is None:
				# we've reached the base class
				return current
			vt_info = self.get_sym(f'_ZTV{nextitem}')
			if (vt_info.size // 4) - 2 <= vti:
				return current
		return subclass

	def guesstimate_windows_mapping(self, typename):
		"""
		Given a type name, yield the order its functions are predicted to be in on Windows.
		Some entries may be skipped.
		"""
		base_vmt, *inherited_vmts = self.get_class_vtables(typename)
		
		vtable_thunks_by_name = {
			# strip prefix 'non-virtual thunk to '; ignore destructor thunks
			self.demangle(fn.name)[21:]: (n, fn)
			for n, fn in enumerate(list(itertools.chain(base_vmt, *inherited_vmts)))
			if fn and fn.name.startswith('_ZThn') and self.demangle(fn.name).find('::~') == -1
		}
		
		# MSVC places overloaded functions next to each other, so scan for them...
		vtable_fn_overloads = collections.defaultdict(list)
		for sym in base_vmt:
			if not sym or not sym.name or not sym.name.startswith('_ZN'):
				continue
			method_name = self.demangle(sym.name)
			
			# group them based on the superclass that contains them (i.e., in the same vtable)
			base_class_with_fn = self.get_base_class_containing_vtable_index(typename, base_vmt.index(sym))
			overload_key = base_class_with_fn + method_name[:method_name.rfind('(')]
			vtable_fn_overloads[overload_key].append(sym)
		
		# ... then insert them in reverse order before the first one, because MSVC does that too
		for sym, *other_overloads in vtable_fn_overloads.values():
			if len(other_overloads) == 0:
				continue
			# remove them first
			base_vmt = [ s for s in base_vmt if s not in other_overloads ]
			
			if self.demangle(sym.name).find('::~') != -1:
				# skip destructor overloads, as MSVC doesn't generate those
				# ... I think? asherkin's impl only ignored consecutive dtors
				# but I think overloaded makes more sense
				continue
			
			position = base_vmt.index(sym)
			base_vmt[position:position] = reversed(other_overloads)
		
		for n, sym in enumerate(base_vmt):
			demangled_name = self.demangle(sym.name)
			
			# skip functions with thunks further down the vtable
			thunk_index, thunk_sym = vtable_thunks_by_name.get(demangled_name, (None, None))
			if thunk_sym and thunk_index > n:
				continue
			
			yield sym

	@functools.cache
	def get_class_hierarchy(self, typename):
		"""
		Returns a list of mangled typenames in ascending order (towards base classes at the end).
		"""
		typeinfo = self.get_sym(f'_ZTI{typename}')
		return self._get_class_hierarchy_from_ptr(typeinfo.value)

	@functools.cache
	def _get_class_hierarchy_from_ptr(self, typeinfo_ptr):
		"""
		Returns a list of mangled typenames in ascending order (towards base classes at the end).
		This takes a pointer to the class's typeinfo structure.
		"""
		typeinfo_class = self.binary.get_relocation(typeinfo_ptr)
		typeinfo_name = self.unpack_string(self.dereference(typeinfo_ptr + 0x04))
		if typeinfo_class.symbol.name == '_ZTVN10__cxxabiv120__si_class_type_infoE':
			# single inheritance
			nested_typeinfo_ptr = self.dereference(typeinfo_ptr + 0x08)
			return [ typeinfo_name ] + self._get_class_hierarchy_from_ptr(nested_typeinfo_ptr)
		elif typeinfo_class.symbol.name == '_ZTVN10__cxxabiv121__vmi_class_type_infoE':
			# multiple inheritance
			nested_typeinfo_ptr = self.dereference(typeinfo_ptr + 0x10)
			return [ typeinfo_name ] + self._get_class_hierarchy_from_ptr(nested_typeinfo_ptr)
		elif typeinfo_class.symbol.name == '_ZTVN10__cxxabiv117__class_type_infoE':
			return [ typeinfo_name ]
		print('unknown typeinfo class', typeinfo_class)
		return [ typeinfo_name ]
