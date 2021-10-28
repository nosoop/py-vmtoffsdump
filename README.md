# vmtproc

A Python library to read and dump information on virtual tables in an unstripped Linux binary.
Is able to accurately guesstimate Windows virtual method offsets (at least more so than
[vtable(.js)][]).

Originally written to automate the process of obtaining that info from Team Fortress 2.

## Usage

Depends on [LIEF][] for ELF parsing and [pydemangler][] for symbol demangling.

```
# this will install vmtproc and its dependencies

$ python -m pip install --user git+https://github.com/nosoop/py-vmtoffsdump
```

The imported package is named `vmtproc`.

Main usage:
```python
import lief
import vmtproc

binary = lief.parse(path_to_unstripped_linux_binary)
processor = vmtproc.VTableProcessor(binary)

vt_first, *vt_others = processor.get_class_vtables('10MyTypeName')
print(vt_first)

win_vt = list(processor.guesstimate_windows_mapping('10MyTypeName'))
print(win_vt)
```

A `dump-binary-vtables` binary is also provided.  See `dump-binary-vtables --help` for more
information.

## Licensing / Credits

This repository is released under the MIT License.

Some of the Windows-specific conversion information (pure virtuals, reverse ordering of
overloads, ignoring of thunks) was taken from @asherkin's [vtable(.js)][] repository.

(The repository has no license, but I received permission from them to release my project under
MIT.)

Additional documentation on Windows-specific conversions comes from
[Dr!fter's guide on getting vtable offsets][].

[pydemangler][] is licensed with Apache License 2.0.

[LIEF][] is licensed with Apache License 2.0.

[vtable(.js)]: https://github.com/asherkin/vtable
[Dr!fter's guide on getting vtable offsets]: https://forums.alliedmods.net/showthread.php?t=191171
[pydemangler]: https://github.com/wbenny/pydemangler
[LIEF]: https://github.com/lief-project/LIEF
