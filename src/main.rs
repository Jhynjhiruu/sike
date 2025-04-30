/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
 *             (C) 2025 Jhynjhiruu                                         *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

use std::{
    array,
    cmp::Ordering,
    collections::HashMap,
    fs::{read, write},
    hash::{DefaultHasher, Hash, Hasher},
    io::Cursor,
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use binrw::BinRead;
use clap::Parser;
use object::{
    elf::{
        EF_MIPS_ABI_O32, EF_MIPS_ARCH_1, EF_MIPS_ARCH_3, ELFOSABI_NONE, R_MIPS_26, R_MIPS_32,
        R_MIPS_GPREL16, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_REL32, SHF_ALLOC, SHF_EXECINSTR,
        SHF_WRITE, SHT_NOBITS, SHT_NULL, SHT_PROGBITS, STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_OBJECT,
        STT_SECTION, STV_DEFAULT,
    },
    write::{
        elf::{FileHeader, Rel, SectionHeader, SectionIndex, Sym, SymbolIndex, Writer},
        Relocation, SectionId, StringId, Symbol, SymbolId, SymbolSection,
    },
    Architecture, BinaryFormat, Endianness, FileFlags, RelocationFlags, SectionKind, SymbolFlags,
    SymbolKind, SymbolScope,
};
use sike::{ElfExpression, Expression, LnkFile, Opcode, RelocType};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input file
    infile: PathBuf,

    /// Output file
    outfile: PathBuf,

    /// Target the PlayStation (little-endian, mips1)
    #[arg(short, long)]
    playstation: bool,

    /// Verbose
    #[arg(short, long)]
    verbose: bool,
}

fn make_elf(obj: &LnkFile, playstation: bool) -> Result<Vec<u8>> {
    let mut program_type = None;

    const fn info(st_bind: u8, st_type: u8) -> u8 {
        ((st_bind & 0x0F) << 4) | (st_type & 0x0F)
    }

    #[derive(Debug)]
    struct Section {
        alignment: u8,
        name: String,
        contents: Vec<u8>,
        locals: Vec<LocalSym>,
        relocations: Vec<Rel>,
        offset: u16,
    }

    impl Section {
        fn kind(&self) -> SectionKind {
            match self.name.as_str() {
                ".text" => SectionKind::Text,
                ".data" => SectionKind::Data,
                ".bss" => SectionKind::UninitializedData,
                ".rdata" => SectionKind::ReadOnlyData,
                ".ctors" => SectionKind::ReadOnlyData,
                ".dtors" => SectionKind::ReadOnlyData,
                ".sdata" => SectionKind::Other,
                ".sbss" => SectionKind::UninitializedData,
                _ => todo!("{}", self.name),
            }
        }

        const fn st_info(&self) -> u8 {
            info(STB_LOCAL, STT_SECTION)
        }

        const fn st_other(&self) -> u8 {
            STV_DEFAULT
        }
    }

    #[derive(Debug)]
    enum SymType {
        Exported { sect: u16, offset: u32 },
        Imported,
        Uninit { sect: u16, size: u32 },
    }

    #[derive(Debug)]
    pub struct Sym {
        sym_type: SymType,
        name: String,
    }

    impl Sym {
        fn exported(sect: u16, offset: u32, name: String) -> Self {
            Self {
                sym_type: SymType::Exported { sect, offset },
                name,
            }
        }

        fn imported(name: String) -> Self {
            Self {
                sym_type: SymType::Imported,
                name,
            }
        }

        fn uninit(sect: u16, size: u32, name: String) -> Self {
            Self {
                sym_type: SymType::Uninit { sect, size },
                name,
            }
        }

        const fn value(&self) -> u32 {
            match &self.sym_type {
                SymType::Exported { offset, .. } => *offset,
                SymType::Imported => 0,
                SymType::Uninit { .. } => 0,
            }
        }

        const fn kind(&self) -> SymbolKind {
            SymbolKind::Data
        }

        const fn weak(&self) -> bool {
            match &self.sym_type {
                SymType::Exported { .. } => false,
                SymType::Imported => true,
                SymType::Uninit { .. } => false,
            }
        }

        fn sect(&self, sects: &HashMap<u16, SectionId>) -> SymbolSection {
            match &self.sym_type {
                SymType::Exported { sect, .. } => SymbolSection::Section(sects[sect]),
                SymType::Imported => SymbolSection::Undefined,
                SymType::Uninit { sect, .. } => SymbolSection::Section(sects[sect]),
            }
        }

        fn flags(&self) -> SymbolFlags<SectionId, SymbolId> {
            let st_info = match &self.sym_type {
                SymType::Exported { .. } => info(STB_GLOBAL, STT_OBJECT),
                SymType::Imported => info(STB_WEAK, STT_OBJECT),
                SymType::Uninit { .. } => info(STB_GLOBAL, STT_OBJECT),
            };

            let st_other = STV_DEFAULT;

            SymbolFlags::Elf { st_info, st_other }
        }
    }

    #[derive(Debug)]
    struct LocalSym {
        offset: u32,
        name: String,
    }

    impl LocalSym {
        const fn kind(&self) -> SymbolKind {
            SymbolKind::Data
        }
    }

    #[derive(Debug, Clone)]
    struct Rel {
        r_type: RelocType,
        offset: u16,
        expr: Expression,
    }

    impl Ord for Rel {
        fn cmp(&self, other: &Self) -> Ordering {
            if self.expr == other.expr {
                self.r_type.cmp(&other.r_type)
            } else {
                let hash = |ex: &Expression| {
                    let mut hasher = DefaultHasher::new();
                    ex.hash(&mut hasher);
                    hasher.finish()
                };

                hash(&self.expr).cmp(&hash(&other.expr))
            }
        }
    }

    impl PartialOrd for Rel {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl PartialEq for Rel {
        fn eq(&self, other: &Self) -> bool {
            self.cmp(other) == Ordering::Equal
        }
    }

    impl Eq for Rel {}

    impl Rel {
        const fn type_offset(&self) -> (u32, u16) {
            match &self.r_type {
                RelocType::Rel32BE | RelocType::Rel32 => (R_MIPS_32, self.offset & !3),
                RelocType::Rel26BE | RelocType::Rel26 => (R_MIPS_26, self.offset & !3),
                RelocType::Hi16BE | RelocType::Hi16 => (R_MIPS_HI16, self.offset & !3),
                RelocType::Lo16BE | RelocType::Lo16 => (R_MIPS_LO16, self.offset & !3),
                RelocType::GPRel16 => (R_MIPS_GPREL16, self.offset & !3),
            }
        }
    }

    let mut sections: HashMap<u16, Section> = HashMap::new();

    let mut files = HashMap::new();

    let mut cur_section = None;

    let mut symbols = HashMap::new();

    for i in &obj.opcodes {
        match i {
            Opcode::End => {}
            Opcode::Bytes(items) => {
                let mut cur_sect = sections.get_mut(&cur_section.unwrap());
                let sect = cur_sect.as_mut().unwrap();

                sect.offset = sect.contents.len().try_into()?;

                sect.contents.extend(items)
            }
            Opcode::Switch(which) => cur_section = Some(*which),
            Opcode::Zeroes(size) => {
                let mut cur_sect = sections.get_mut(&cur_section.unwrap());
                let sect = cur_sect.as_mut().unwrap();

                sect.offset = sect.contents.len().try_into()?;

                sect.contents
                    .resize(sect.contents.len() + *size as usize, 0);
            }
            Opcode::Relocation(r_type, offset, expr) => {
                let mut cur_sect = sections.get_mut(&cur_section.unwrap());
                let sect = cur_sect.as_mut().unwrap();

                sect.relocations.push(Rel {
                    r_type: *r_type,
                    offset: offset.wrapping_add(sect.offset),
                    expr: expr.clone(),
                })
            }
            Opcode::ExportedSymbol(idx, sect, offset, name) => {
                symbols.insert(*idx, Sym::exported(*sect, *offset, name.to_string()));
            }
            Opcode::ImportedSymbol(idx, name) => {
                symbols.insert(*idx, Sym::imported(name.to_string()));
            }
            Opcode::Section(idx, group, align, name) => {
                sections.insert(
                    *idx,
                    Section {
                        alignment: *align,
                        name: name.to_string(),
                        contents: vec![],
                        locals: vec![],
                        relocations: vec![],
                        offset: 0,
                    },
                );
            }
            Opcode::LocalSymbol(sect, offset, name) => {
                let mut cur_sect = sections.get_mut(sect);
                let sect = cur_sect.as_mut().unwrap();

                sect.locals.push(LocalSym {
                    offset: *offset,
                    name: name.to_string(),
                })
            }
            Opcode::Filename(idx, name) => {
                files.insert(*idx, name.to_string());
            }
            Opcode::ProgramType(t) => {
                if program_type.is_some() {
                    return Err(anyhow!("program type set more than once"));
                } else {
                    program_type = Some(*t)
                }
            }
            Opcode::Uninitialised(idx, sect, size, name) => {
                {
                    let mut cur_sect = sections.get_mut(sect);
                    let sect = cur_sect.as_mut().unwrap();

                    if !sect.kind().is_bss() {
                        return Err(anyhow!(
                            "tried to put uninitialised object {name} in non-bss section {}",
                            sect.name
                        ));
                    }
                }

                symbols.insert(*idx, Sym::uninit(*sect, *size, name.to_string()));
            }
            Opcode::IncSldLineNum(_) => todo!(),
            Opcode::IncSldLineNumByByte(_, _) => todo!(),
            Opcode::IncSldLineNumByWord(_, _) => todo!(),
            Opcode::SetSldLineNum(_, _) => todo!(),
            Opcode::SetSldLineNumFile(_, _, _) => todo!(),
            Opcode::EndSld(_) => todo!(),
            Opcode::Function(_, _, _, _, _, _, _, _, _, psyq_string) => todo!(),
            Opcode::FunctionEnd(_, _, _) => todo!(),
            Opcode::BlockStart(_, _, _) => todo!(),
            Opcode::BlockEnd(_, _, _) => todo!(),
            Opcode::SectionDef(section, value, class, section_type, size, name) => {
                println!("Section definition: section {section}, value {value}, class {class}, type {section_type}, size {size}, name {name}");
            }
            Opcode::SectionDef2(section, value, class, section_type, size, dims, tag, name) => {
                println!("Section definition 2: section {section}, value {value}, class {class}, type {section_type}, size {size}, dims {dims:?}, tag {tag}, name {name}");
            }
            Opcode::FunctionStart2(_, _, _, _, _, _, _, _, _, _, _, psyq_string) => todo!(),
        }
    }

    //println!("{:#02X?}", sections);
    //println!("{:#?}", files);
    //println!("{:#?}", symbols);

    let mut obj = object::write::Object::new(
        BinaryFormat::Elf,
        Architecture::Mips,
        if playstation {
            Endianness::Little
        } else {
            Endianness::Big
        },
    );

    obj.flags = FileFlags::Elf {
        os_abi: ELFOSABI_NONE,
        abi_version: 0,
        e_flags: EF_MIPS_ABI_O32
            | if playstation {
                EF_MIPS_ARCH_1
            } else {
                EF_MIPS_ARCH_3
            },
    };

    let mut section_indices = HashMap::new();

    let mut locals = HashMap::new();

    for (idx, sect) in &sections {
        let id = obj.add_section(vec![], sect.name.clone().into_bytes(), sect.kind());
        section_indices.insert(*idx, id);

        if obj.section(id).is_bss() {
            assert!(sect.contents.iter().all(|&b| b == 0));
            obj.append_section_bss(id, sect.contents.len() as _, sect.alignment.into());
        } else {
            obj.set_section_data(id, &sect.contents, sect.alignment.into());
        }

        for loc in &sect.locals {
            let id = obj.add_symbol(Symbol {
                name: loc.name.clone().into_bytes(),
                value: loc.offset.into(),
                size: 0,
                kind: loc.kind(),
                scope: SymbolScope::Compilation,
                weak: false,
                section: SymbolSection::Section(id),
                flags: SymbolFlags::Elf {
                    st_info: info(STB_LOCAL, STT_OBJECT),
                    st_other: STV_DEFAULT,
                },
            });

            locals.insert((*idx, loc.offset), id);
        }
    }

    let mut symbol_indices = HashMap::new();

    let mut sorted_symbols = symbols.into_iter().collect::<Vec<_>>();
    sorted_symbols.sort_by_key(|(i, _)| *i);

    for (idx, sym) in &sorted_symbols {
        let id = obj.add_symbol(Symbol {
            name: sym.name.clone().into_bytes(),
            value: sym.value().into(),
            size: 0,
            kind: sym.kind(),
            scope: SymbolScope::Linkage,
            weak: sym.weak(),
            section: sym.sect(&section_indices),
            flags: sym.flags(),
        });
        if let &SymType::Uninit { sect, size } = &sym.sym_type {
            obj.add_symbol_bss(
                id,
                section_indices[&sect],
                size.into(),
                u32::from(sections[&sect].alignment).min(size).into(),
            );
        }
        symbol_indices.insert(*idx, id);
    }

    /*for (uninit_idx, uninit) in &sect.uninits {
        let id = obj.add_symbol(Symbol {
            name: uninit.name.clone().into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_indices[idx]),
            flags: SymbolFlags::Elf {
                st_info: info(STB_GLOBAL, STT_OBJECT),
                st_other: STV_DEFAULT,
            },
        });
        let offset = obj.add_symbol_bss(
            id,
            section_indices[idx],
            uninit.size.into(),
            u32::from(sect.alignment).min(uninit.size).into(),
        );

        symbol_indices.insert(*uninit_idx, id);
        symbols.insert(
            *uninit_idx,
            Sym::exported(*idx, offset as _, uninit.name.clone()),
        );
    }*/

    //let mut sect_symbol_indices = HashMap::new();

    /*for (idx, sect) in &sections {
        let id = obj.add_symbol(Symbol {
            name: sect.name.clone().into_bytes(),
            value: 0,
            size: sect.contents.len() as _,
            kind: SymbolKind::Section,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(section_indices[idx]),
            flags: SymbolFlags::Elf {
                st_info: sect.st_info(),
                st_other: sect.st_other(),
            },
        });
        sect_symbol_indices.insert(*idx, id);

    }*/

    //let mut added_symbols = HashMap::new();

    for (idx, sect) in &sections {
        // psyq relocations contain more info than elf relocations (because of the expression system), so we need to sort them before adding them

        let mut relocs = sect.relocations.clone();
        relocs.sort();

        //println!("relocs for section {}", sect.name);
        for rel in relocs {
            //println!("{:?}", rel);
            let Ok(expr) = ElfExpression::try_from(&rel.expr) else {
                println!("unhandled expression: {:?}", rel.expr);
                continue;
            };

            let (symbol, addend) = match expr {
                ElfExpression::SectionOffset(s, o) => (obj.section_symbol(section_indices[&s]), o),
                ElfExpression::SymbolOffset(s, o) => (symbol_indices[&s], o),
            };

            let (r_type, offset) = rel.type_offset();

            if addend != 0 {
                // TODO: this needs to be more complex to handle HI16/LO16 properly

                let data = obj.section_mut(section_indices[idx]).data_mut();

                let bytes = array::from_fn::<_, 4, _>(|i| data[offset as usize + i]);
                let word = if playstation {
                    u32::from_le_bytes
                } else {
                    u32::from_be_bytes
                }(bytes);

                let (mask, shift) = match r_type {
                    R_MIPS_32 => (0xFFFFFFFF, 0),
                    R_MIPS_26 => (0x03FFFFFF, 2),
                    R_MIPS_HI16 => (0x0000FFFF, 16),
                    R_MIPS_LO16 => (0x0000FFFF, 0),
                    _ => todo!(),
                };

                let inv_mask = !mask;

                let new_word = (word & inv_mask) | ((addend >> shift) & mask);

                let new_word = if r_type == R_MIPS_HI16 && addend & 0x8000 != 0 {
                    new_word + 1
                } else {
                    new_word
                };

                let new_bytes = if playstation {
                    new_word.to_le_bytes()
                } else {
                    new_word.to_be_bytes()
                };

                data[offset as usize..offset as usize + 4].copy_from_slice(&new_bytes);
            }

            obj.add_relocation(
                section_indices[idx],
                Relocation {
                    offset: offset.into(),
                    symbol,
                    addend: 0,
                    flags: RelocationFlags::Elf { r_type },
                },
            )?;

            /*let symbol = match expr {
                ElfExpression::SectionOffset(s, o) => {
                    if o == 0 {
                        sect_symbol_indices[&s]
                    } else {
                        let sym = symbols
                            .iter()
                            .filter(|(_, sym)| match sym.sym_type {
                                SymType::Exported { sect, offset } => sect == s && offset == o,
                                SymType::Imported => false,
                            })
                            .map(|(idx, _)| *idx)
                            .next();

                        match sym {
                            Some(s) => symbol_indices[&s],
                            None => match added_symbols.get(&(s, o)) {
                                Some(id) => *id,
                                None => {
                                    let id = obj.add_symbol(Symbol {
                                        name: format!("{}_added_{:08X}", sections[&s].name, o)
                                            .into_bytes(),
                                        value: o.into(),
                                        size: 0,
                                        kind: SymbolKind::Data,
                                        scope: SymbolScope::Linkage,
                                        weak: false,
                                        section: SymbolSection::Section(section_indices[&s]),
                                        flags: SymbolFlags::Elf {
                                            st_info: info(STB_GLOBAL, STT_OBJECT),
                                            st_other: STV_DEFAULT,
                                        },
                                    });

                                    added_symbols.insert((s, o), id);

                                    id
                                }
                            },
                        }
                    }
                }
                ElfExpression::Symbol(s) => symbol_indices[&s],
            };

            let (r_type, offset) = rel.type_offset();

            obj.add_relocation(
                section_indices[idx],
                Relocation {
                    offset: offset.into(),
                    symbol,
                    addend: 0,
                    flags: RelocationFlags::Elf { r_type },
                },
            )?;*/
        }
    }

    let rv = obj.write()?;

    Ok(rv)

    /*let mut rv = vec![];

    let mut obj = Writer::new(Endianness::Big, true, &mut rv);

    obj.reserve_file_header();

    let shstrtab = obj.reserve_shstrtab_section_index();
    let strtab = obj.reserve_strtab_section_index();
    let symtab = obj.reserve_symtab_section_index();

    #[derive(Debug)]
    struct SectIndex {
        str_id: StringId,
        sect_idx: SectionIndex,
        offset: usize,
        sym_str_id: StringId,
        sym_idx: SymbolIndex,
        reloc_str_id: StringId,
        reloc_sect_idx: SectionIndex,
        reloc_offset: usize,
    }

    let mut section_indices = HashMap::new();

    let mut section_order = vec![];
    let mut section_order_rev = HashMap::new();

    for (idx, sect) in &sections {
        let str_id = obj.add_section_name(sect.name.as_bytes());
        let sect_idx = obj.reserve_section_index();
        let offset = obj.reserve(sect.contents.len(), sect.alignment.into());
        let sym_str_id = obj.add_string(sect.name.as_bytes());
        let sym_idx = obj.reserve_symbol_index(Some(symtab));
        let reloc_str_id = obj.add_section_name(sect.reloc_name.as_bytes());
        let reloc_sect_idx = obj.reserve_section_index();
        let reloc_offset = obj.reserve_relocations(sect.relocations.len(), false);
        section_indices.insert(
            *idx,
            SectIndex {
                str_id,
                sect_idx,
                offset,
                sym_str_id,
                sym_idx,
                reloc_str_id,
                reloc_sect_idx,
                reloc_offset,
            },
        );
        section_order_rev.insert(*idx, section_order.len());
        section_order.push(idx);
    }

    obj.reserve_section_headers();

    let mut symbol_indices = HashMap::new();

    let mut symbol_order = vec![&0];
    let mut symbol_order_rev = HashMap::new();

    for (idx, sym) in &symbols {
        let str_id = obj.add_string(sym.name.as_bytes());
        let sym_idx = obj.reserve_symbol_index(Some(symtab));
        symbol_indices.insert(*idx, (str_id, sym_idx));
        symbol_order_rev.insert(*idx, symbol_order.len());
        symbol_order.push(idx);
    }

    obj.reserve_symtab();

    obj.reserve_strtab();

    obj.reserve_shstrtab();

    obj.write_file_header(&FileHeader {
        os_abi: 0,
        abi_version: 0,
        e_type: 0,
        e_machine: 0,
        e_entry: 0,
        e_flags: 0,
    })?;



    obj.write_null_section_header();

    for &idx in &section_order {
        let sect_idx = &section_indices[idx];
        let sect = &sections[idx];

        obj.write_section_header(&SectionHeader {
            name: Some(sect_idx.str_id),
            sh_type: sect.sh_type(),
            sh_flags: sect.sh_flags(),
            sh_addr: 0,
            sh_offset: sect_idx.offset as _,
            sh_size: sect.contents.len() as _,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: sect.alignment.into(),
            sh_entsize: 0,
        });

        obj.write_relocation_section_header(
            sect_idx.reloc_str_id,
            sect_idx.sect_idx,
            SectionIndex(0),
            sect_idx.reloc_offset,
            sect.relocations.len(),
            false,
        );
    }

    for &idx in &section_order {
        let sect = &sections[idx];

        obj.write_align(sect.alignment.into());
        obj.write(&sect.contents);

        obj.write_align_relocation();

        for rel in &sect.relocations {
            let sym = match ElfExpression::try_from(&rel.expr) {
                Ok(e) => match e {
                    ElfExpression::SectionOffset(s, o) => symbols
                        .iter()
                        .filter(|(_, sym)| match &sym.sym_type {
                            SymbolType::Exported { sect, offset } => *sect == s && *offset == o,
                            SymbolType::Imported => false,
                        })
                        .map(|(idx, _)| symbol_order_rev[idx])
                        .next()
                        .unwrap_or(0),
                    ElfExpression::Symbol(s) => symbol_order_rev[&s],
                },
                Err(_) => 0,
            };

            obj.write_relocation(
                false,
                &Rel {
                    r_offset: rel.offset.into(),
                    r_sym: sym as _,
                    r_type: rel.r_type(),
                    r_addend: 0,
                },
            );
        }
    }

    obj.write_null_symbol();

    for &idx in &symbol_order {
        let (str_id, _) = &symbol_indices[idx];
        let sym = &symbols[idx];

        obj.write_symbol(&Sym {
            name: Some(*str_id),
            section: sym.section(&section_indices),
            st_info: sym.st_info(),
            st_other: sym.st_other(),
            st_shndx: 0,
            st_value: sym.st_value().into(),
            st_size: 0,
        });
    }

    for &idx in &section_order {
        let sect_idx = &section_indices[idx];
        let sect = &sections[idx];

        obj.write_symbol(&Sym {
            name: Some(sect_idx.str_id),
            section: Some(sect_idx.sect_idx),
            st_info: sect.st_info(),
            st_other: sect.st_other(),
            st_shndx: 0,
            st_value: 0,
            st_size: sect.contents.len() as _,
        })
    }

    obj.write_strtab();
    obj.write_shstrtab();

    //obj.write_relocation(count, is_rela);
    //obj.write_relocation_section_header(name, section, symtab, offset, count, is_rela);
    //obj.write_relative_relocation_section_header(name, offset, size);
    //obj.write_align_relocation();

    Ok(rv)*/
}

fn main() -> Result<()> {
    let args = Args::parse();

    let infile = read(args.infile)?;

    let mut cursor = Cursor::new(&infile);
    let obj = LnkFile::read_le(&mut cursor)?;

    if args.verbose {
        println!("{:#02X?}", obj);
    }

    let elf = make_elf(&obj, args.playstation)?;

    write(args.outfile, elf)?;

    Ok(())
}
