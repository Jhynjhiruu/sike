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

use std::fmt;

use binrw::binrw;
use binrw::helpers::{until, until_eof};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[binrw]
pub enum Expression {
    #[brw(magic(0x00u8))]
    Value(u32),
    #[brw(magic(0x02u8))]
    Symbol(u16),
    #[brw(magic(0x04u8))]
    SectionBase(u16),
    #[brw(magic(0x0Cu8))]
    SectionStart(u16),
    #[brw(magic(0x16u8))]
    SectionEnd(u16),
    #[brw(magic(0x2Cu8))]
    Add(Box<Self>, Box<Self>),
    #[brw(magic(0x2Eu8))]
    Sub(Box<Self>, Box<Self>),
    #[brw(magic(0x32u8))]
    Div(Box<Self>, Box<Self>),
}

pub enum ElfExpression {
    SectionOffset(u16, u32),
    SymbolOffset(u16, u32),
}

impl TryFrom<&Expression> for ElfExpression {
    type Error = ();

    fn try_from(value: &Expression) -> Result<Self, Self::Error> {
        match value {
            Expression::Symbol(s) => Ok(Self::SymbolOffset(*s, 0)),
            Expression::SectionBase(s) => Ok(Self::SectionOffset(*s, 0)),
            Expression::Add(l, r) => match (&**l, &**r) {
                (Expression::SectionBase(s), Expression::Value(o))
                | (Expression::Value(o), Expression::SectionBase(s)) => {
                    Ok(Self::SectionOffset(*s, *o))
                }
                (Expression::Value(o), Expression::Symbol(s)) => Ok(Self::SymbolOffset(*s, *o)),

                _ => Err(()),
            },
            _ => Err(()),
        }
    }
}

#[binrw]
#[derive(PartialEq, Eq)]
pub struct PsyqString {
    #[br(temp)]
    #[bw(try_calc(vec.len().try_into()))]
    len: u8,
    #[br(count(len))]
    vec: Vec<u8>,
}

impl fmt::Debug for PsyqString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PsyqString(\"{}\")",
            String::from_utf8_lossy(&self.vec).escape_debug()
        )
    }
}

impl fmt::Display for PsyqString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.vec).escape_default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[binrw]
pub enum RelocType {
    #[brw(magic(0x08u8))]
    Rel32BE,
    #[brw(magic(0x10u8))]
    Rel32,
    #[brw(magic(0x4Au8))]
    Rel26,
    #[brw(magic(0x52u8))]
    Hi16,
    #[brw(magic(0x54u8))]
    Lo16,
    #[brw(magic(0x5Cu8))]
    Rel26BE,
    #[brw(magic(0x60u8))]
    Hi16BE,
    #[brw(magic(0x62u8))]
    Lo16BE,
    #[brw(magic(0x64u8))]
    GPRel16,
}

#[binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum Opcode {
    #[brw(magic(0x00u8))]
    End,
    #[brw(magic(0x02u8))]
    Bytes(
        #[br(temp)]
        #[bw(try_calc(self_1.len().try_into()))]
        u16,
        #[br(count(self_0))] Vec<u8>,
    ),
    #[brw(magic(0x06u8))]
    Switch(u16),
    #[brw(magic(0x08u8))]
    Zeroes(u32),
    #[brw(magic(0x0Au8))]
    Relocation(RelocType, u16, Expression),
    #[brw(magic(0x0Cu8))]
    ExportedSymbol(u16, u16, u32, PsyqString),
    #[brw(magic(0x0Eu8))]
    ImportedSymbol(u16, PsyqString),
    #[brw(magic(0x10u8))]
    Section(u16, u16, u8, PsyqString),
    #[brw(magic(0x12u8))]
    LocalSymbol(u16, u32, PsyqString),
    #[brw(magic(0x1Cu8))]
    Filename(u16, PsyqString),
    #[brw(magic(0x2Eu8))]
    ProgramType(u8),
    #[brw(magic(0x30u8))]
    Uninitialised(u16, u16, u32, PsyqString),
    #[brw(magic(0x32u8))]
    IncSldLineNum(u16),
    #[brw(magic(0x34u8))]
    IncSldLineNumByByte(u16, u8),
    #[brw(magic(0x36u8))]
    IncSldLineNumByWord(u16, u16),
    #[brw(magic(0x38u8))]
    SetSldLineNum(u16, u32),
    #[brw(magic(0x3Au8))]
    SetSldLineNumFile(u16, u32, u16),
    #[brw(magic(0x3Cu8))]
    EndSld(#[brw(assert(self_0.eq(&0)))] u16),
    #[brw(magic(0x4Au8))]
    Function(u16, u32, u16, u32, u16, u32, u16, u32, u32, PsyqString),
    #[brw(magic(0x4Cu8))]
    FunctionEnd(u16, u32, u32),
    #[brw(magic(0x4Eu8))]
    BlockStart(u16, u32, u32),
    #[brw(magic(0x50u8))]
    BlockEnd(u16, u32, u32),
    #[brw(magic(0x52u8))]
    SectionDef(u16, u32, u16, u16, u32, PsyqString),
    #[brw(magic(0x54u8))]
    SectionDef2(
        u16,
        u32,
        u16,
        u16,
        u32,
        #[br(temp)]
        #[bw(try_calc(self_6.len().try_into()))]
        u16,
        #[br(count(self_5))] Vec<u16>,
        PsyqString,
        PsyqString,
    ),
    #[brw(magic(0x56u8))]
    FunctionStart2(
        u16,
        u32,
        u16,
        u32,
        u16,
        u32,
        u16,
        u32,
        u32,
        u32,
        u32,
        PsyqString,
    ),
}

#[derive(Debug)]
#[binrw]
#[brw(magic(b"LNK"))]
pub struct LnkFile {
    #[brw(assert(version.eq(&2), "Unknown version {version}"))]
    pub version: u8,
    #[br(parse_with(until(|opc| opc == &Opcode::End)))]
    pub opcodes: Vec<Opcode>,
}
