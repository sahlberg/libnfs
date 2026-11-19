#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
zdrgen: generate libnfs ZDR code from an XDR (RFC 4506) .x file.

It replaces rpcgen plus the sed scripts that turned its output into
something that builds with -Wall -Werror. It handles the subset of the
language the libnfs .x files use: const, enum, struct, union, typedef and
program definitions, with fixed and variable arrays, opaque, string, bool
and optional data. The C types and names follow rpcgen's, as the headers
are installed and applications use them.

    zdrgen.py [options] file.x header.h source.c
"""

import argparse
import os
import re
import sys


class XdrError(Exception):
    pass


# ---------------------------------------------------------------- lexer

TOKEN_RE = re.compile(r'''
      (?P<ws>\s+)
    | (?P<comment>/\*.*?\*/|//[^\n]*)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<num>-?(?:0[xX][0-9A-Fa-f]+|[0-9]+))
    | (?P<punct>[{}()\[\]<>;:,=*])
''', re.S | re.X)


class Token:
    def __init__(self, kind, text, line):
        self.kind = kind
        self.text = text
        self.line = line


def tokenize(src, path):
    tokens = []
    pos = 0
    line = 1
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise XdrError("%s:%d: unexpected character %r" %
                           (path, line, src[pos]))
        kind = m.lastgroup
        text = m.group(kind)
        if kind not in ('ws', 'comment'):
            tokens.append(Token(kind, text, line))
        line += text.count('\n')
        pos = m.end()
    tokens.append(Token('eof', '', line))
    return tokens


def leading_comments(src):
    """The comments before the first definition, i.e. the license."""
    out = []
    pos = 0
    while True:
        m = re.compile(r'\s*(/\*.*?\*/)', re.S).match(src, pos)
        if not m:
            break
        out.append(m.group(1))
        pos = m.end()
    return '\n'.join(out)


# ---------------------------------------------------------------- model

class Decl:
    """
    One declaration: a struct member, union arm, typedef or discriminant.
    rel is 'alias', 'pointer', 'vector' (fixed array) or 'array'
    (variable array). type is 'void', 'opaque', 'string', a base type or
    a user type name.
    """
    def __init__(self, type_, name, rel='alias', bound=None, prefix=''):
        self.type = type_
        self.name = name
        self.rel = rel
        self.bound = bound
        self.prefix = prefix


class Definition:
    def __init__(self, kind, name, **kw):
        self.kind = kind
        self.name = name
        self.__dict__.update(kw)


# ---------------------------------------------------------------- parser

BASE_TYPES = {
    # xdr type: (C type, zdr function)
    'int': ('int', 'zdr_int'),
    'unsigned int': ('uint32_t', 'zdr_u_int'),
    'hyper': ('int64_t', 'zdr_int64_t'),
    'unsigned hyper': ('uint64_t', 'zdr_uint64_t'),
    'bool': ('uint32_t', 'zdr_bool'),
}


class Parser:
    def __init__(self, tokens, path):
        self.tokens = tokens
        self.pos = 0
        self.path = path

    def peek(self, n=0):
        return self.tokens[self.pos + n]

    def next(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def error(self, msg, tok=None):
        tok = tok or self.peek()
        raise XdrError("%s:%d: %s (at %r)" % (self.path, tok.line, msg,
                                              tok.text))

    def expect(self, text):
        tok = self.next()
        if tok.text != text:
            self.error("expected %r" % text, tok)
        return tok

    def accept(self, text):
        if self.peek().text == text:
            self.pos += 1
            return True
        return False

    def ident(self):
        tok = self.next()
        if tok.kind != 'ident':
            self.error("expected an identifier", tok)
        return tok.text

    def value(self):
        tok = self.next()
        if tok.kind not in ('num', 'ident'):
            self.error("expected a number or a constant", tok)
        return tok.text

    def parse(self):
        defs = []
        while self.peek().kind != 'eof':
            defs.append(self.definition())
        return defs

    def definition(self):
        kw = self.ident()
        if kw == 'const':
            name = self.ident()
            self.expect('=')
            value = self.value()
            self.expect(';')
            return Definition('const', name, value=value)
        if kw == 'typedef':
            decl = self.declaration()
            self.expect(';')
            return Definition('typedef', decl.name, decl=decl)
        if kw == 'enum':
            name = self.ident()
            values = self.enum_body()
            self.expect(';')
            return Definition('enum', name, values=values)
        if kw == 'struct':
            name = self.ident()
            members = self.struct_body()
            self.expect(';')
            return Definition('struct', name, members=members)
        if kw == 'union':
            name = self.ident()
            disc, arms, default = self.union_body()
            self.expect(';')
            return Definition('union', name, disc=disc, arms=arms,
                              default=default)
        if kw == 'program':
            return self.program()
        self.error("unknown definition %r" % kw)

    def enum_body(self):
        self.expect('{')
        values = []
        while True:
            name = self.ident()
            value = None
            if self.accept('='):
                value = self.value()
            values.append((name, value))
            if self.accept('}'):
                return values
            self.expect(',')
            if self.accept('}'):
                return values

    def struct_body(self):
        self.expect('{')
        members = []
        while not self.accept('}'):
            members.append(self.declaration())
            self.expect(';')
        return members

    def union_body(self):
        self.expect('switch')
        self.expect('(')
        disc = self.declaration()
        self.expect(')')
        self.expect('{')
        arms = []
        default = None
        while not self.accept('}'):
            if self.accept('default'):
                self.expect(':')
                default = self.declaration()
                self.expect(';')
                continue
            cases = []
            while self.accept('case'):
                cases.append(self.value())
                self.expect(':')
            if not cases:
                self.error("expected case or default")
            decl = self.declaration()
            self.expect(';')
            arms.append((cases, decl))
        return disc, arms, default

    def type_specifier(self):
        """Returns (type, prefix)."""
        if self.accept('unsigned'):
            if self.accept('hyper'):
                return 'unsigned hyper', ''
            self.accept('int')
            return 'unsigned int', ''
        if self.peek().text in ('struct', 'enum', 'union'):
            prefix = self.next().text + ' '
            return self.ident(), prefix
        return self.ident(), ''

    def declaration(self):
        if self.accept('void'):
            return Decl('void', None)
        type_, prefix = self.type_specifier()
        if type_ in ('opaque', 'string'):
            name = self.ident()
            if self.accept('['):
                if type_ == 'string':
                    self.error("string needs <>")
                bound = self.value()
                self.expect(']')
                return Decl(type_, name, 'vector', bound)
            self.expect('<')
            bound = None if self.peek().text == '>' else self.value()
            self.expect('>')
            return Decl(type_, name, 'array', bound)
        if self.accept('*'):
            return Decl(type_, self.ident(), 'pointer', prefix=prefix)
        name = self.ident()
        if self.accept('['):
            bound = self.value()
            self.expect(']')
            return Decl(type_, name, 'vector', bound, prefix)
        if self.accept('<'):
            bound = None if self.peek().text == '>' else self.value()
            self.expect('>')
            return Decl(type_, name, 'array', bound, prefix)
        return Decl(type_, name, 'alias', prefix=prefix)

    def program(self):
        name = self.ident()
        self.expect('{')
        versions = []
        while not self.accept('}'):
            self.expect('version')
            vname = self.ident()
            self.expect('{')
            procs = []
            while not self.accept('}'):
                # The types are only rpcgen stub prototypes, which we omit.
                self.type_specifier()
                self.accept('*')
                pname = self.ident()
                self.expect('(')
                while not self.accept(')'):
                    self.next()
                self.expect('=')
                pnum = self.value()
                self.expect(';')
                procs.append((pname, pnum))
            self.expect('=')
            vnum = self.value()
            self.expect(';')
            versions.append((vname, vnum, procs))
        self.expect('=')
        num = self.value()
        self.expect(';')
        return Definition('program', name, number=num, versions=versions)


# ---------------------------------------------------------------- codegen

class Generator:
    def __init__(self, defs, skip):
        self.defs = defs
        self.skip = set(skip)
        self.typedefs = {d.name: d.decl for d in defs if d.kind == 'typedef'}
        self.defined = {d.name for d in defs
                        if d.kind in ('struct', 'union', 'enum', 'typedef')}
        self.lists = {d.name for d in defs if self.is_list(d)}

    def is_list(self, d):
        """A struct whose last member points to the next one of its kind."""
        if d.kind != 'struct' or not d.members:
            return False
        last = d.members[-1]
        if last.rel == 'alias' and last.type in self.typedefs:
            last = self.typedefs[last.type]
        return last.rel == 'pointer' and last.type == d.name

    def sizeof(self, decl):
        # Every type defined here has a typedef, which rpcgen uses.
        if decl.type in self.defined:
            return decl.type
        return self.ctype(decl)

    @staticmethod
    def ctype(decl):
        if decl.type in BASE_TYPES:
            return BASE_TYPES[decl.type][0]
        return decl.prefix + decl.type

    @staticmethod
    def zdr_proc(decl):
        if decl.type in BASE_TYPES:
            return BASE_TYPES[decl.type][1]
        return 'zdr_' + decl.type

    def is_vector_type(self, name):
        """A typedef of a fixed array is passed by value, not by pointer."""
        seen = set()
        while name in self.typedefs and name not in seen:
            seen.add(name)
            decl = self.typedefs[name]
            if decl.rel == 'vector':
                return True
            if decl.rel != 'alias':
                return False
            name = decl.type
        return False

    # --- header

    def member(self, decl, indent, owner=None):
        """C declaration of a struct member or union arm."""
        t = '\t' * indent
        ctype = self.ctype(decl)
        if decl.type == 'string':
            return '%schar *%s;\n' % (t, decl.name)
        if decl.type == 'opaque':
            if decl.rel == 'vector':
                return '%schar %s[%s];\n' % (t, decl.name, decl.bound)
            ctype = 'char'
        if decl.rel == 'pointer':
            if decl.type == owner and not decl.prefix:
                ctype = 'struct ' + ctype
            return '%s%s *%s;\n' % (t, ctype, decl.name)
        if decl.rel == 'vector':
            return '%s%s %s[%s];\n' % (t, ctype, decl.name, decl.bound)
        if decl.rel == 'array':
            return ('%sstruct {\n%s\tuint32_t %s_len;\n%s\t%s *%s_val;\n'
                    '%s} %s;\n' % (t, t, decl.name, t, ctype, decl.name, t,
                                   decl.name))
        return '%s%s %s;\n' % (t, ctype, decl.name)

    def header_def(self, d):
        if d.kind == 'const':
            return '#define %s %s\n' % (d.name, d.value)
        if d.kind == 'enum':
            body = ''.join('\t%s = %s,\n' % (n, v) if v is not None
                           else '\t%s,\n' % n for n, v in d.values)
            return ('enum %s {\n%s};\ntypedef enum %s %s;\n\n' %
                    (d.name, body, d.name, d.name))
        if d.kind == 'struct':
            body = ''.join(self.member(m, 1, d.name) for m in d.members)
            return ('struct %s {\n%s};\ntypedef struct %s %s;\n\n' %
                    (d.name, body, d.name, d.name))
        if d.kind == 'union':
            body = self.member(d.disc, 1)
            arms = [decl for _, decl in d.arms if decl.type != 'void']
            if d.default and d.default.type != 'void':
                arms.append(d.default)
            if arms:
                body += '\tunion {\n%s\t} %s_u;\n' % (
                    ''.join(self.member(a, 2, d.name) for a in arms), d.name)
            return ('struct %s {\n%s};\ntypedef struct %s %s;\n\n' %
                    (d.name, body, d.name, d.name))
        if d.kind == 'typedef':
            decl = d.decl
            ctype = self.ctype(decl)
            if decl.type == 'string':
                return 'typedef char *%s;\n\n' % d.name
            if decl.type == 'opaque':
                if decl.rel == 'vector':
                    return 'typedef char %s[%s];\n\n' % (d.name, decl.bound)
                ctype = 'char'
            if decl.rel == 'pointer':
                return 'typedef %s *%s;\n\n' % (ctype, d.name)
            if decl.rel == 'vector':
                return 'typedef %s %s[%s];\n\n' % (ctype, d.name, decl.bound)
            if decl.rel == 'array':
                return ('typedef struct {\n\tuint32_t %s_len;\n'
                        '\t%s *%s_val;\n} %s;\n\n' %
                        (d.name, ctype, d.name, d.name))
            return 'typedef %s %s;\n\n' % (ctype, d.name)
        if d.kind == 'program':
            out = '#define %s %s\n' % (d.name, d.number)
            for vname, vnum, procs in d.versions:
                out += '#define %s %s\n\n' % (vname, vnum)
                out += ''.join('#define %s %s\n' % p for p in procs)
                out += '\n'
            return out
        raise XdrError("cannot emit %s" % d.kind)

    def prototype(self, d):
        arg = d.name if self.is_vector_type(d.name) else d.name + ' *'
        return 'extern uint32_t zdr_%s (ZDR *, %s);\n' % (d.name, arg)

    def header(self, guard, preamble, extra):
        out = [preamble, '\n/*\n * Please do not edit this file.\n'
               ' * It was generated by tools/zdrgen.py.\n */\n\n',
               '#ifndef %s\n#define %s\n\n' % (guard, guard),
               '#include <nfsc/libnfs-zdr.h>\n\n',
               '#ifdef __cplusplus\nextern "C" {\n#endif\n\n']
        out += [self.header_def(d) for d in self.defs]
        out.append('/* the zdr functions */\n\n')
        out += [self.prototype(d) for d in self.defs
                if d.kind in ('enum', 'struct', 'union', 'typedef')]
        out.append('\n')
        if extra:
            out.append(extra.rstrip('\n') + '\n\n')
        out.append('#ifdef __cplusplus\n}\n#endif\n\n#endif /* !%s */\n' %
                   guard)
        return ''.join(out)

    # --- source

    def stmt(self, decl, obj):
        """The zdr call for one declaration; obj is the C object."""
        if decl.type == 'opaque':
            return 'zdr_opaque (zdrs, %s, %s)' % (obj, decl.bound)
        if decl.type == 'string':
            return 'zdr_string (zdrs, &%s, %s)' % (obj, decl.bound or '~0')
        proc = self.zdr_proc(decl)
        if decl.rel == 'pointer':
            return ('zdr_pointer (zdrs, (char **)&%s, sizeof (%s), '
                    '(zdrproc_t) %s)' % (obj, self.sizeof(decl), proc))
        if decl.rel == 'vector':
            return ('zdr_vector (zdrs, (char *)%s, %s,\n\t\tsizeof (%s), '
                    '(zdrproc_t) %s)' % (obj, decl.bound, self.sizeof(decl),
                                         proc))
        if decl.type in BASE_TYPES:
            return '%s (zdrs, &%s)' % (proc, obj)
        if self.is_vector_type(decl.type):
            return '%s (zdrs, %s)' % (proc, obj)
        return '%s (zdrs, &%s)' % (proc, obj)

    @staticmethod
    def check(call, indent=1):
        t = '\t' * indent
        return '%s if (!%s)\n%s\t return FALSE;\n' % (t, call, t)

    def source_def(self, d):
        if d.kind not in ('enum', 'struct', 'union', 'typedef'):
            return ''
        if d.name in self.skip:
            return ''
        vector = self.is_vector_type(d.name)
        arg = '%s objp' % d.name if vector else '%s *objp' % d.name
        out = 'uint32_t\nzdr_%s (ZDR *zdrs, %s)\n{\n' % (d.name, arg)
        if d.kind == 'enum':
            out += self.check('zdr_enum (zdrs, (enum_t *) objp)')
        elif d.kind == 'struct' and d.name in self.lists:
            return out + self.list_body(d)
        elif d.kind == 'struct':
            for m in d.members:
                out += self.check(self.field(m, 'objp->'))
        elif d.kind == 'union':
            out += self.check(self.field(d.disc, 'objp->'))
            out += '\tswitch (objp->%s) {\n' % d.disc.name
            for cases, decl in d.arms:
                out += ''.join('\tcase %s:\n' % c for c in cases)
                if decl.type != 'void':
                    out += self.check(self.field(decl, 'objp->%s_u.' %
                                                 d.name), 2)
                out += '\t\tbreak;\n'
            if d.default is None:
                out += '\tdefault:\n\t\treturn FALSE;\n'
            elif d.default.type == 'void':
                out += '\tdefault:\n\t\tbreak;\n'
            else:
                out += '\tdefault:\n'
                out += self.check(self.field(d.default, 'objp->%s_u.' %
                                             d.name), 2)
                out += '\t\tbreak;\n'
            out += '\t}\n'
        elif d.kind == 'typedef':
            out += self.check(self.typedef_stmt(d.decl, d.name))
        return out + '\treturn TRUE;\n}\n\n'

    def list_body(self, d):
        """
        Walk a list iteratively. Recursing through zdr_pointer once per
        element lets a long list, e.g. a READDIR reply, exhaust the stack.
        """
        nxt = 'objp->' + d.members[-1].name
        out = '\tbool_t more_data;\n\n\twhile (1) {\n'
        for m in d.members[:-1]:
            out += self.check(self.field(m, 'objp->'), 2)
        out += ('\t\tmore_data = (%(n)s != NULL);\n'
                '\t\tif (!zdr_bool (zdrs, &more_data))\n'
                '\t\t\treturn FALSE;\n'
                '\t\tif (!more_data) {\n'
                '\t\t\t%(n)s = NULL;\n'
                '\t\t\treturn TRUE;\n'
                '\t\t}\n'
                '\t\tif (zdrs->x_op == ZDR_DECODE) {\n'
                '\t\t\t%(n)s = zdr_malloc (zdrs, sizeof (%(t)s));\n'
                '\t\t\tif (%(n)s == NULL)\n'
                '\t\t\t\treturn FALSE;\n'
                '\t\t\tmemset (%(n)s, 0, sizeof (%(t)s));\n'
                '\t\t}\n'
                '\t\tobjp = %(n)s;\n'
                '\t}\n}\n\n') % {'n': nxt, 't': d.name}
        return out

    def field(self, decl, prefix):
        """zdr call for a struct member or union arm reached via prefix."""
        obj = prefix + decl.name
        if decl.rel == 'array' or (decl.type == 'opaque' and
                                   decl.rel == 'array'):
            name = decl.name
            bound = decl.bound or '~0'
            if decl.type == 'opaque':
                return ('zdr_bytes (zdrs, (char **)&%s.%s_val, &%s.%s_len, '
                        '%s)' % (obj, name, obj, name, bound))
            if decl.type == 'string':
                return 'zdr_string (zdrs, &%s, %s)' % (obj, bound)
            return ('zdr_array (zdrs, (char **)&%s.%s_val, &%s.%s_len, %s,\n'
                    '\t\tsizeof (%s), (zdrproc_t) %s)' %
                    (obj, name, obj, name, bound, self.sizeof(decl),
                     self.zdr_proc(decl)))
        return self.stmt(decl, obj)

    def typedef_stmt(self, decl, name):
        """zdr call for a typedef, whose object is objp itself."""
        bound = decl.bound or '~0'
        if decl.type == 'string':
            return 'zdr_string (zdrs, objp, %s)' % bound
        if decl.type == 'opaque':
            if decl.rel == 'vector':
                return 'zdr_opaque (zdrs, objp, %s)' % decl.bound
            return ('zdr_bytes (zdrs, (char **)&objp->%s_val, &objp->%s_len, '
                    '%s)' % (name, name, bound))
        proc = self.zdr_proc(decl)
        size = self.sizeof(decl)
        if decl.rel == 'pointer':
            return ('zdr_pointer (zdrs, (char **)objp, sizeof (%s), '
                    '(zdrproc_t) %s)' % (size, proc))
        if decl.rel == 'vector':
            return ('zdr_vector (zdrs, (char *)objp, %s,\n\t\tsizeof (%s), '
                    '(zdrproc_t) %s)' % (decl.bound, size, proc))
        if decl.rel == 'array':
            return ('zdr_array (zdrs, (char **)&objp->%s_val, &objp->%s_len, '
                    '%s,\n\t\tsizeof (%s), (zdrproc_t) %s)' %
                    (name, name, bound, size, proc))
        return '%s (zdrs, objp)' % proc

    def source(self, header_name, preamble, extra, includes):
        out = [preamble, '\n/*\n * Please do not edit this file.\n'
               ' * It was generated by tools/zdrgen.py.\n */\n\n']
        if self.lists - self.skip:
            includes = ['<string.h>'] + [i for i in includes
                                         if i != '<string.h>']
        out += ['#include %s\n' % i for i in includes]
        out.append('#include "libnfs-zdr.h"\n#include "%s"\n\n' % header_name)
        out += [self.source_def(d) for d in self.defs]
        if extra:
            out.append(extra.rstrip('\n') + '\n')
        return ''.join(out).rstrip('\n') + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split('\n')[0])
    ap.add_argument('xfile')
    ap.add_argument('header')
    ap.add_argument('source')
    ap.add_argument('--header-extra',
                    help='text appended to the header, before its end')
    ap.add_argument('--source-extra', help='text appended to the source')
    ap.add_argument('--skip', action='append', default=[],
                    help='type whose zdr function is written by hand')
    ap.add_argument('--include', action='append', default=[],
                    help='extra #include for the source, e.g. <string.h>')
    args = ap.parse_args()

    with open(args.xfile) as f:
        src = f.read()
    try:
        defs = Parser(tokenize(src, args.xfile), args.xfile).parse()
    except XdrError as e:
        sys.exit(str(e))

    def read(path):
        if not path:
            return ''
        with open(path) as f:
            return f.read()

    base = os.path.splitext(os.path.basename(args.xfile))[0]
    guard = '_%s_H_RPCGEN' % base.upper()
    preamble = leading_comments(src)
    gen = Generator(defs, args.skip)
    with open(args.header, 'w') as f:
        f.write(gen.header(guard, preamble, read(args.header_extra)))
    with open(args.source, 'w') as f:
        f.write(gen.source(os.path.basename(args.header), preamble,
                           read(args.source_extra), args.include))


if __name__ == '__main__':
    main()
