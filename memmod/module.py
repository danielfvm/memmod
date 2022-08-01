from dataclasses import dataclass

from elftools.elf.elffile import PAGESIZE, ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

@dataclass
class Module():
    start: int
    end: int
    mode: str
    offset: int
    major: int
    minor: int
    inode: int
    path: str

    @property
    def size(self):
        return self.end - self.start


    def contains_address(self, address):
        return self.start <= address and address < self.end


    def get_symbol_offset(self, name) -> int:
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            dynsym = elf.get_section_by_name('.dynsym')
            symtab = elf.get_section_by_name('.symtab')
            symbols = []

            if isinstance(dynsym, SymbolTableSection):
                symbols += list(dynsym.iter_symbols())
            if isinstance(symtab, SymbolTableSection):
                symbols += list(symtab.iter_symbols())

            results = list(filter(
                lambda x: x.name == name,
                symbols
            ))

            assert results, ("Symbol '%s' not found." % name)

            return results[0].entry['st_value']


    def get_symbols(self) -> list:
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            dynsym = elf.get_section_by_name('.dynsym')
            symtab = elf.get_section_by_name('.symtab')
            symbols = []

            if isinstance(dynsym, SymbolTableSection):
                symbols += list(dynsym.iter_symbols())
            if isinstance(symtab, SymbolTableSection):
                symbols += list(symtab.iter_symbols())

            return symbols


    def get_relocation_offset(self, name) -> int:
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            relaplt = elf.get_section_by_name('.rela.plt')
            reladyn = elf.get_section_by_name('.rela.dyn')
            dynsym = elf.get_section_by_name('.dynsym')

            assert isinstance(relaplt, RelocationSection), "Section is wrong instance"
            assert isinstance(reladyn, RelocationSection), "Section is wrong instance"
            assert isinstance(dynsym, SymbolTableSection), "Section is wrong instance"

            r_info_sym = list(filter(
                lambda x: x[0].name == name,
                zip(dynsym.iter_symbols(), range(dynsym.num_symbols()))
            ))

            assert r_info_sym, "Relocation '%s' not found." % name

            r_info_sym = r_info_sym[0][1]

            result = next(filter(
                lambda x: x['r_info_sym'] == r_info_sym,
                list(relaplt.iter_relocations()) + list(reladyn.iter_relocations())
            ))

            return result['r_offset']
