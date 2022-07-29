# http://docs.go-mono.com/?link=root:/embed

from .process import Process
from .process import Module

class MonoProcess(Process):
    domain: int
    assembly: int
    image: int

    def __init__(self, pid=None, name=None, assembly_name = "Assembly-CSharp") -> None:
        super().__init__(pid, name)

        self._libmono = None

        # Check if we can get libmono, if not we are proabably not running a mono app
        self.get_libmono()

        # read information from libmonobdwgc
        self.domain = self.get_libmonobdwgc_function('mono_get_root_domain')()
        assert self.domain != 0, 'Failed to get root domain'

        self.assembly = self.get_libmonobdwgc_function('mono_domain_assembly_open')(self.domain, assembly_name)
        assert self.assembly != 0, 'Failed to get assembly'

        self.image = self.get_libmonobdwgc_function('mono_assembly_get_image')(self.assembly)
        assert self.assembly != 0, 'Failed to get image'


    def get_libmono(self) -> Module:
        self._libmono = self._libmono or self.find_module('libmonobdwgc')
        assert self._libmono is not None, 'Process is not a Mono-Application!'

        return self._libmono


    def get_libmonobdwgc_function_addr(self, name: str) -> int:
        # for faster loading time check if function has been used already
        if name in self._function:
            return self._function[name]

        libmono = self.get_libmono()

        sym_addr = libmono.get_symbol_offset(name)
        self._function[name] = libmono.start + sym_addr

        return libmono.start + sym_addr


    def get_libmonobdwgc_function(self, name: str):
        func_addr = self.get_libmonobdwgc_function_addr(name)

        def run(*args) -> int:
            return self.run_function(func_addr, *args)
        return run

    def get_mono_class(self, name: str):
        return MonoClass(self, name)

class MonoClass():
    ptr: int
    name: str

    def __init__(self, process: MonoProcess, name: str) -> None:
        self.process = process
        self.name = name
        self.ptr = process.get_libmonobdwgc_function('mono_class_from_name')(process.image, '', name)
        assert self.ptr != 0, 'Class `%s` not found in mono' % name


    def get_field_offset(self, name: str):
        field = self.process.get_libmonobdwgc_function('mono_class_get_field_from_name')(self.ptr, name)
        assert field != 0, 'Failed to find field `%s` in class `%s`' % (self.name, name)

        return self.process.get_libmonobdwgc_function('mono_field_get_offset')(field)


    def get_method_addr(self, name: str):
        method = self.process.get_libmonobdwgc_function('mono_class_get_method_from_name')(self.ptr, name, -1)
        assert method != 0, 'Failed to find method `%s` in class `%s`' % (self.name, name)

        return self.process.get_libmonobdwgc_function('mono_compile_method')(method)

class MonoString():
    ptr: int

    def __init__(self, process: MonoProcess, text: str) -> None:
        self.process = process
        self.ptr = process.get_libmonobdwgc_function('mono_string_new')(process.image, text)

    @property
    def len(self):
        return self.process.get_libmonobdwgc_function('mono_string_length')(self.ptr)

    @property
    def data(self):
        ptr = self.process.get_libmonobdwgc_function('mono_string_chars')(self.ptr)
        return self.process.read(ptr, self.len).decode('utf-8')
