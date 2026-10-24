"""Decode mapped-file ELF bytes at a same-run strace image address.

The strace `-k` bracket address is an ELF image virtual address. Translate it
through one executable PT_LOAD segment before reading on-disk bytes. `objdump`
supplies the instruction boundary. The traced process may have modified its
executable mapping, so these file bytes are not verified runtime bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from common import need, sha


def _source_line_context(path, image_vaddr):
    """Retain DWARF line context without claiming a unique C expression."""
    tool = shutil.which('addr2line')
    if tool is None:
        return dict(status='tool_unavailable', frames=[])
    command = [tool, '-f', '-i', '-e', str(path), hex(image_vaddr)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                env=dict(os.environ, LC_ALL='C'))
    except (OSError, subprocess.SubprocessError) as error:
        return dict(status='not_resolved', reason=str(error), frames=[],
                    tool=dict(path=tool, sha256=sha(tool)))
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) % 2:
        return dict(status='not_resolved', reason='addr2line returned no frame pairs',
                    frames=[], tool=dict(path=tool, sha256=sha(tool)))
    frames = [dict(function=lines[index], location=lines[index+1])
              for index in range(0, len(lines), 2)]
    status = ('reported' if any(frame['location'] not in ('??:0', '??:?')
                                for frame in frames) else 'unresolved')
    return dict(status=status, frames=frames, image_vaddr=hex(image_vaddr),
                module_sha256=sha(path), tool=dict(path=tool, sha256=sha(tool)))


def _elf_load(path, address, runtime_pc):
    path = Path(path)
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(64)
        need(len(header) >= 52 and header[:4] == b'\x7fELF', 'Mapped object is not ELF')
        klass, encoding = header[4:6]
        need(klass in (1, 2) and encoding in (1, 2), 'Unsupported ELF class or byte order')
        need(len(header) >= (64 if klass == 2 else 52), 'Truncated ELF header')
        endian = '<' if encoding == 1 else '>'
        e_type = struct.unpack_from(endian+'H', header, 16)[0]
        need(e_type in (2, 3), 'Expected an executable or shared ELF image')
        if klass == 2:
            phoff = struct.unpack_from(endian+'Q', header, 32)[0]
            phentsize, phnum = struct.unpack_from(endian+'HH', header, 54)
            fmt, minimum = endian+'IIQQQQQQ', 56
        else:
            phoff = struct.unpack_from(endian+'I', header, 28)[0]
            phentsize, phnum = struct.unpack_from(endian+'HH', header, 42)
            fmt, minimum = endian+'IIIIIIII', 32
        need(phnum not in (0, 0xffff) and phentsize >= minimum and
             phoff + phentsize*phnum <= size, 'Invalid ELF program-header table')
        matches = []
        for index in range(phnum):
            stream.seek(phoff + index*phentsize)
            fields = struct.unpack(fmt, stream.read(minimum))
            if klass == 2:
                ptype, flags, offset, vaddr, _, filesz, _, align = fields
            else:
                ptype, offset, vaddr, _, filesz, _, flags, align = fields
            if ptype == 1 and flags & 1 and vaddr <= address < vaddr + filesz:
                candidate = offset + address - vaddr
                need(candidate < size, 'ELF instruction is outside mapped file bytes')
                matches.append((candidate, align))
        need(len(matches) == 1, 'ELF address does not identify one executable load')
        file_offset, _ = matches[0]
        bias = runtime_pc - address
        need(bias >= 0 and (bias == 0 if e_type == 2 else
                            bias % os.sysconf('SC_PAGE_SIZE') == 0),
             'Strace instruction pointer does not match ELF image address')
        return file_offset, bias


def decode_elf_instruction(path, image_vaddr, runtime_pc):
    """Return a stable mapped-file key at the terminating process's PC."""
    path = Path(path).resolve(strict=True)
    need(path.is_file(), 'Faulting module is unavailable')
    need(type(image_vaddr) is int and image_vaddr >= 0 and
         type(runtime_pc) is int and runtime_pc >= 0, 'Invalid instruction address')
    file_offset, bias = _elf_load(path, image_vaddr, runtime_pc)
    objdump = shutil.which('objdump')
    need(objdump is not None, 'objdump is required for instruction decoding')
    result = subprocess.run([objdump, '-d', '-w', '--insn-width=32',
                             '--start-address='+hex(image_vaddr),
                             '--stop-address='+hex(image_vaddr+32), str(path)],
                            capture_output=True, text=True, timeout=15,
                            env=dict(os.environ, LC_ALL='C'))
    need(result.returncode == 0, 'objdump could not decode the mapped instruction')
    instruction = None
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) < 3 or not fields[0].strip().endswith(':'):
            continue
        try:
            line_address = int(fields[0].strip()[:-1], 16)
            encoded = bytes.fromhex(fields[1])
        except ValueError:
            continue
        if line_address == image_vaddr and encoded and fields[2].strip():
            instruction = (encoded, fields[2].strip())
            break
    need(instruction is not None, 'ELF image address has no decoded instruction')
    encoded, assembly = instruction
    with path.open('rb') as stream:
        stream.seek(file_offset)
        need(stream.read(len(encoded)) == encoded,
             'Disassembled instruction differs from mapped ELF file bytes')
    module_sha = sha(path)
    site = dict(module_sha256=module_sha, file_offset=hex(file_offset),
                instruction_bytes=encoded.hex())
    stable = hashlib.sha256(json.dumps(site,sort_keys=True,separators=(',', ':'),
                                       ensure_ascii=False).encode()).hexdigest()
    return dict(**site, stable_site_key=stable, assembly=assembly,
                instruction_byte_source='mapped_elf_file',
                runtime_instruction_bytes_verified=False,
                image_vaddr=hex(image_vaddr), load_bias=hex(bias),
                resolved_module_path=str(path),
                source_line_context=_source_line_context(path, image_vaddr),
                decoder_tool=dict(path=objdump, sha256=sha(objdump)))
