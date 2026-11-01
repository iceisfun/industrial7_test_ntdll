#!/usr/bin/env python3
"""Reproduce the named ntdll documentation and installed-header surface.

Run from any directory: python3 tools/map_public_surface.py
Replay without network: add --offline (the complete disk cache is required).
Only exact/variant FUNCTION pages enter public_surface.txt; that list includes
partial evidence and is NOT a list of fully documented user-mode contracts.
The JSON records full/partial/unknown contracts separately for every export.
Mentions, guides, PDB names, and guessed header membership never qualify.

Requests are serial, cached atomically, resumable, and retry 503/transport
failures with capped exponential backoff. Cache keys include the server URL.
Nt/Zw twins share a query ONLY if both actual exports have the same entry RVA.
For each spelling we recompute exact/variant and contract, preserving the API's
original context/contract as well. A user-context exact page is 'full' in the
API's matching sense, not a completeness audit of that page's prose.
Conservatively, driver-reference repositories never establish a full user-mode
contract, even when the API infers user/both from an api_location DLL entry.

Headers are parsed with the installed libclang C API (no Python bindings).
Every installed .h containing an export identifier is parsed as C with windows.h
as a preamble (DDK headers instead use their own dependencies/ntddk.h).
FunctionDecl cursors, not textual mentions/macros/typedefs, count.
Conditional declarations inactive under this target/configuration can be missed.
Parse diagnostics and header hashes are retained; declarations recovered from
imperfect translation units remain real declarations, not compile-pass claims.
Header presence does not promise ntdll import-library ownership or Win10 support.
"""

import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def variants(name):
    result = {name}
    if name.endswith(('A', 'W')):
        result.add(name[:-1])
    for spelling in list(result):
        if spelling.startswith('Nt'):
            result.add('Zw' + spelling[2:])
        elif spelling.startswith('Zw'):
            result.add('Nt' + spelling[2:])
    return {spelling.casefold() for spelling in result}


def write_json(path, value):
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(data)
    temporary.replace(path)


class API:
    def __init__(self, args):
        self.base = args.base_url.rstrip('/')
        self.cache = args.cache
        self.cache.mkdir(parents=True, exist_ok=True)
        self.offline = args.offline
        self.retries = args.retries
        self.paths = set()
        self.requests = self.hits = self.retry_count = 0

    def get(self, path):
        self.paths.add(path)
        dest = self.cache / (digest((self.base + path).encode()) + '.json')
        if dest.exists():
            self.hits += 1
            return json.loads(dest.read_text())
        if self.offline:
            raise RuntimeError('uncached request in --offline mode: ' + path)
        for attempt in range(self.retries + 1):
            try:
                self.requests += 1
                with urllib.request.urlopen(self.base + path, timeout=120) as response:
                    value = json.load(response)
                write_json(dest, value)
                return value
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                if isinstance(error, urllib.error.HTTPError) and error.code == 404:
                    value = {'http_status': 404, 'error': error.read().decode(errors='replace')}
                    write_json(dest, value)
                    return value
                if isinstance(error, urllib.error.HTTPError) and error.code not in (429, 500, 502, 503, 504):
                    raise
                if attempt == self.retries:
                    raise
                self.retry_count += 1
                delay = min(60, 2 ** (attempt + 1))
                if isinstance(error, urllib.error.HTTPError):
                    try:
                        delay = max(delay, float(error.headers.get('Retry-After', '0')))
                    except ValueError:
                        pass
                print(f'retry {path}: {error}; sleeping {delay}s', file=sys.stderr, flush=True)
                time.sleep(delay)

    def listing(self, path):
        items, offset = [], 0
        while True:
            page = self.get(path + ('&' if '?' in path else '?') + f'limit=1000&offset={offset}')
            items.extend(page['items'])
            offset += len(page['items'])
            if offset >= page['total']:
                return items
            if not page['items']:
                raise RuntimeError('empty incomplete page: ' + path)

    def docs(self, name):
        path = '/api/function/ntdll/' + urllib.parse.quote(name, safe='') + '/docs'
        first = self.get(path + '?limit=200&offset=0')
        if first.get('http_status') == 404:
            # Data/entry-point exports need not resolve to a corpus function.
            # Still check their actual symbol, but do not invent context fields.
            path = '/api/docs/for-symbol?name=' + urllib.parse.quote(name, safe='')
            first = self.get(path + '&limit=200&offset=0')
            first['function_resolution'] = '404; symbol-only fallback, context not supplied by API'
        separator = '&' if '?' in path else '?'
        items = list(first['items'])
        # Exact/variant rank before mentions. Do not fetch pages of mentions.
        while len(items) < first['total'] and items and items[-1]['match'] != 'mention':
            page = self.get(path + separator + f'limit=200&offset={len(items)}')
            if not page['items']:
                raise RuntimeError('empty incomplete docs page: ' + path)
            items.extend(page['items'])
        return first, items


class CXString(C.Structure):
    _fields_ = [('data', C.c_void_p), ('flags', C.c_uint)]


class Cursor(C.Structure):
    _fields_ = [('kind', C.c_int), ('xdata', C.c_int), ('data', C.c_void_p * 3)]


class Location(C.Structure):
    _fields_ = [('ptr_data', C.c_void_p * 2), ('int_data', C.c_uint)]


def headers(args, names):
    lib = C.CDLL(args.libclang)
    callback = C.CFUNCTYPE(C.c_uint, Cursor, Cursor, C.c_void_p)
    signatures = {
        'clang_createIndex': (C.c_void_p, [C.c_int, C.c_int]),
        'clang_parseTranslationUnit': (C.c_void_p, [C.c_void_p, C.c_char_p, C.POINTER(C.c_char_p), C.c_int, C.c_void_p, C.c_uint, C.c_uint]),
        'clang_getTranslationUnitCursor': (Cursor, [C.c_void_p]),
        'clang_visitChildren': (C.c_uint, [Cursor, callback, C.c_void_p]),
        'clang_getCursorSpelling': (CXString, [Cursor]),
        'clang_getCString': (C.c_char_p, [CXString]),
        'clang_disposeString': (None, [CXString]),
        'clang_getCursorLocation': (Location, [Cursor]),
        'clang_getSpellingLocation': (None, [Location, C.POINTER(C.c_void_p), C.POINTER(C.c_uint), C.POINTER(C.c_uint), C.POINTER(C.c_uint)]),
        'clang_getFileName': (CXString, [C.c_void_p]),
        'clang_getNumDiagnostics': (C.c_uint, [C.c_void_p]),
        'clang_getDiagnostic': (C.c_void_p, [C.c_void_p, C.c_uint]),
        'clang_getDiagnosticSeverity': (C.c_uint, [C.c_void_p]),
        'clang_formatDiagnostic': (CXString, [C.c_void_p, C.c_uint]),
        'clang_disposeDiagnostic': (None, [C.c_void_p]),
        'clang_disposeTranslationUnit': (None, [C.c_void_p]),
        'clang_disposeIndex': (None, [C.c_void_p]),
        'clang_getClangVersion': (CXString, []),
    }
    for key, (result, arguments) in signatures.items():
        function = getattr(lib, key)
        function.restype, function.argtypes = result, arguments

    def text(value):
        result = lib.clang_getCString(value)
        decoded = result.decode(errors='replace') if result else ''
        lib.clang_disposeString(value)
        return decoded

    include = args.include.resolve()
    identifiers = {n.encode() for n in names}
    tokens = re.compile(rb'\b[A-Za-z_]\w*\b')
    candidates = [p for p in sorted(include.rglob('*.h')) if not identifiers.isdisjoint(tokens.findall(p.read_bytes()))]
    declarations = {n: {} for n in names}
    diagnostics, source_hashes, source_lines, parse_arguments = {}, {}, {}, {}
    callback_errors = []

    @callback
    def visit(cursor, parent, client_data):
        try:
            if cursor.kind == 8:  # CXCursor_FunctionDecl, excludes macros/typedefs/calls
                name = text(lib.clang_getCursorSpelling(cursor))
                if name in declarations:
                    file = C.c_void_p()
                    line, column, offset = C.c_uint(), C.c_uint(), C.c_uint()
                    lib.clang_getSpellingLocation(lib.clang_getCursorLocation(cursor), C.byref(file), C.byref(line), C.byref(column), C.byref(offset))
                    if file:
                        path = Path(text(lib.clang_getFileName(file))).resolve()
                        if path.is_relative_to(include):
                            relative = str(path.relative_to(include))
                            key = (relative, line.value, column.value)
                            if key not in declarations[name]:
                                if relative not in source_lines:
                                    data = path.read_bytes()
                                    source_lines[relative] = data.decode(errors='replace').splitlines()
                                    source_hashes[relative] = digest(data)
                                declarations[name][key] = {'header': relative, 'line': line.value, 'column': column.value,
                                                           'header_family': 'ddk' if relative.startswith('ddk/') else 'sdk-crt',
                                                           'source_line': source_lines[relative][line.value - 1].strip()}
        except Exception as error:
            # ctypes otherwise prints and ignores callback exceptions.
            callback_errors.append(str(error))
            return 0
        return 2  # CXChildVisit_Recurse

    index = lib.clang_createIndex(0, 0)
    options = ['-x', 'c', '-target', 'x86_64-w64-windows-gnu', '-std=gnu11',
               '-resource-dir=' + str(args.resource_dir),
               '-D_WIN32_WINNT=0x0A00', '-DWINVER=0x0A00', '-ferror-limit=0', '-I' + str(include)]
    for number, path in enumerate(candidates, 1):
        relative = str(path.relative_to(include))
        if relative.startswith('ddk/'):
            extra = ['-I' + str(include / 'ddk')]
            if path.name not in ('ntddk.h', 'ntifs.h', 'wdm.h'):
                extra += ['-include', 'ntddk.h']
        else:
            extra = ['-include', 'windows.h']
        arguments = options + extra
        parse_arguments[relative] = arguments
        argv = (C.c_char_p * len(arguments))(*(s.encode() for s in arguments))
        unit = lib.clang_parseTranslationUnit(index, str(path).encode(), argv, len(arguments), None, 0, 0)
        source_hashes[relative] = digest(path.read_bytes())
        if not unit:
            raise RuntimeError('libclang could not parse ' + str(path))
        errors = []
        for i in range(lib.clang_getNumDiagnostics(unit)):
            diagnostic = lib.clang_getDiagnostic(unit, i)
            if lib.clang_getDiagnosticSeverity(diagnostic) >= 3:
                errors.append(text(lib.clang_formatDiagnostic(diagnostic, 3)))
            lib.clang_disposeDiagnostic(diagnostic)
        if errors:
            diagnostics[relative] = errors
        lib.clang_visitChildren(lib.clang_getTranslationUnitCursor(unit), visit, None)
        lib.clang_disposeTranslationUnit(unit)
        if callback_errors:
            raise RuntimeError('header cursor traversal failed: ' + '; '.join(callback_errors))
        if number % 25 == 0:
            print(f'headers {number}/{len(candidates)}', file=sys.stderr, flush=True)
    lib.clang_disposeIndex(index)
    return {n: [v[k] for k in sorted(v)] for n, v in declarations.items()}, {
        'include': str(include), 'libclang_version': text(lib.clang_getClangVersion()),
        'arguments_by_header': parse_arguments, 'candidate_headers': len(candidates),
        'parsed_headers': [str(p.relative_to(include)) for p in candidates],
        'source_sha256': source_hashes, 'error_diagnostics': diagnostics,
        'method': 'libclang FunctionDecl spelling locations; all candidate .h individually; windows.h preamble for SDK/CRT, own dependencies or ntddk.h for DDK; inactive conditionals and unparseable constructs may be missed; DDK declaration presence is not a user-mode contract',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base-url', default='http://docker1.dev.moonlightcompanies.com:8765')
    parser.add_argument('--cache', type=Path, default=Path('/tmp/opencode/ntdll_surface_cache'))
    parser.add_argument('--offline', action='store_true', help='require cached API responses; no HTTP requests')
    parser.add_argument('--retries', type=int, default=12, help='retries per request (default: 12)')
    parser.add_argument('--include', type=Path, default=Path('/usr/share/mingw-w64/include'))
    parser.add_argument('--libclang', default='/usr/lib/llvm-15/lib/libclang.so.1')
    parser.add_argument('--resource-dir', type=Path, default=Path('/usr/lib/llvm-15/lib/clang/15.0.7'),
                        help='installed Clang builtin headers matching --libclang')
    parser.add_argument('--output-dir', type=Path, default=ROOT)
    args = parser.parse_args()
    if args.retries < 0:
        parser.error('--retries must be nonnegative')
    if not args.include.is_dir():
        parser.error('--include must name an installed header directory')
    if not args.resource_dir.is_dir():
        parser.error('--resource-dir must name the installed Clang resource directory')
    names = sorted(set(ROOT.joinpath('ntdll_exports.txt').read_text().splitlines()))
    if len(names) != 2432 or any(not name for name in names):
        raise RuntimeError('expected exactly 2432 named exports')
    api = API(args)
    stats = api.get('/api/docs/stats')
    module = api.get('/api/modules/ntdll')
    exports = api.listing('/api/modules/ntdll/exports')
    actual = {item['name']: item for item in exports if item['name']}
    if set(actual) != set(names):
        raise RuntimeError('named export input differs from corpus export table')
    groups = {}
    for name in names:
        twin = 'Nt' + name[2:] if name.startswith('Zw') else None
        canonical = twin if twin in actual and actual[twin]['rva'] == actual[name]['rva'] and not actual[name]['forwarder'] and not actual[twin]['forwarder'] else name
        groups.setdefault(canonical, []).append(name)
    evidence = {}
    for number, (canonical, spellings) in enumerate(sorted(groups.items()), 1):
        summary, items = api.docs(canonical)
        function_docs = [d for d in items if d['match'] in ('exact', 'variant') and d['kind'] == 'function']
        for name in spellings:
            docs = []
            for item in function_docs:
                if item['via'].casefold() not in variants(name):
                    continue
                doc = dict(item)
                doc['query_match'] = doc['match']
                doc['query_contract'] = doc.get('contract', 'unknown')
                doc['match'] = 'exact' if doc['via'].casefold() == name.casefold() else 'variant'
                # A variant is always partial, even if an Nt/Zw alias shares code.
                context = doc.get('doc_context', 'unknown')
                doc['contract'] = ('full' if doc['match'] == 'exact' else 'partial') if context in ('user', 'both') else ('partial' if context == 'kernel' else 'unknown')
                if doc['repo'].startswith('windows-driver-docs'):
                    doc['contract'] = 'partial'
                    doc['caveat'] = 'Driver reference only: not accepted as a full user-mode contract, regardless of API DLL-based context inference.'
                elif context == 'kernel':
                    doc['caveat'] = 'Kernel DDI is not a full user-mode contract; PreviousMode and Nt/Zw semantics can differ.'
                elif doc['match'] == 'variant':
                    doc['caveat'] = 'Variant spelling only; shared entry RVA does not make the page an exact-name contract.'
                docs.append(doc)
            evidence[name] = {'rva': actual[name]['rva'], 'ordinal': actual[name]['ordinal'],
                              'query_name': canonical, 'query_group': spellings, 'impl_context': 'user',
                              'api_impl_context': summary.get('impl_context', 'not supplied'),
                              'alias_evidence': 'same_entry_rva' if name != canonical else None,
                              'api_aliases': summary.get('aliases', []), 'docs_total_including_mentions': summary['total'],
                              'function_resolution': summary.get('function_resolution', 'resolved'),
                              'mention_matches_returned': sum(d['match'] == 'mention' for d in items),
                              'non_function_name_matches': [d for d in items if d['match'] != 'mention' and d['kind'] != 'function'],
                              'docs': sorted(docs, key=lambda d: d['ref'])}
        if number % 50 == 0:
            print(f'docs {number}/{len(groups)}; network attempts {api.requests}', file=sys.stderr, flush=True)
    declarations, header_info = headers(args, set(names))
    for name in names:
        evidence[name]['header_declarations'] = declarations[name]
    documented = [n for n in names if evidence[n]['docs']]
    full = [n for n in names if any(d['contract'] == 'full' for d in evidence[n]['docs'])]
    partial = [n for n in names if any(d['contract'] == 'partial' for d in evidence[n]['docs'])]
    partial_only = [n for n in documented if n not in full and any(d['contract'] == 'partial' for d in evidence[n]['docs'])]
    declared = [n for n in names if declarations[n]]
    totals = {'exports': len(names), 'docs_query_groups': len(groups), 'deduplicated_twins': len(names) - len(groups),
              'unique_api_urls': len(api.paths), 'docs_names': len(documented), 'full_user_contract_names': len(full),
              'partial_evidence_names': len(partial), 'partial_only_names': len(partial_only),
              'unknown_only_names': sum(n not in full and n not in partial_only for n in documented),
              'header_declared_names': len(declared), 'header_declaration_locations': sum(len(v) for v in declarations.values()),
              'no_function_doc_names': len(names) - len(documented), 'no_full_user_contract_names': len(names) - len(full),
              'no_header_declaration_names': len(names) - len(declared)}
    output = {'schema_version': 1, 'method': __doc__, 'base_url': api.base,
              'exports_input_sha256': digest(ROOT.joinpath('ntdll_exports.txt').read_bytes()),
              'docs_stats': stats, 'module': module, 'totals': totals, 'headers': header_info, 'exports': evidence,
              'query_urls': sorted(api.paths)}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / 'public_surface_evidence.json', output)
    (args.output_dir / 'public_surface.txt').write_text('\n'.join(documented) + '\n')
    (args.output_dir / 'public_surface_by_header.txt').write_text('\n'.join(declared) + '\n')
    gaps = ['# Reproduce: python3 tools/map_public_surface.py (or --offline with completed cache)',
            '# public_surface.txt = exact/variant FUNCTION docs, including partial kernel evidence.',
            '# public_surface_by_header.txt = actual installed libclang FunctionDecl names, independent of docs.',
            '# Full means exact + user/both context in API matching, NOT a prose completeness audit.',
            '# Partial kernel/variant docs and unknown context are NOT full user-mode contracts.',
            '# Driver-reference repositories are conservatively partial even if API context is user/both.',
            '# Header scan is target/configuration-dependent; diagnostics and locations are in JSON.',
            '# No match is a gap in this corpus/scan, not proof an API is private or absent.',
            '# Counts: ' + json.dumps(totals, sort_keys=True),
            '# name\tdocumentation_gap\theader_gap']
    for name in names:
        if name not in full or not declarations[name]:
            gap = 'full-user-contract' if name in full else ('partial-only' if name in partial_only else ('unknown-context-only' if name in documented else ('mention-only' if evidence[name]['mention_matches_returned'] else 'no-function-doc')))
            gaps.append(name + '\t' + gap + '\t' + ('declared' if declarations[name] else 'no-declaration'))
    (args.output_dir / 'public_surface_gaps.txt').write_text('\n'.join(gaps) + '\n')
    print(json.dumps({'totals': totals, 'this_run': {'network_attempts': api.requests, 'cache_hits': api.hits, 'retries': api.retry_count}}, sort_keys=True))


if __name__ == '__main__':
    main()
