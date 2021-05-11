# VTable Offset Dumper

A Python-based tool that estimates Windows virtual method offsets given an unstripped Linux
binary.

## Usage

Depends on [LIEF][] for ELF parsing and [pydemangler][] for symbol demangling.

Still requires work for library usage, but at the moment you'll need to drop into an interactive
Python shell, then provide a mangled typename to `render_vtable()`:

```
$ git clone https://github.com/nosoop/py-vmtoffsdump.git
$ cd py-vmtoffsdump
$ python3 -i -m vmtoffsdump /path/to/binary.so
>>> render_vtable('11CBaseObject')
```

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
