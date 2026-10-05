#!/usr/bin/env python3
"""Run the locked mutmut 2.4 operators in isolated, frozen backend copies.

Each mutant receives its own fresh pytest child. Forking preloaded third-party
libraries saves import time without sharing application modules or pytest state.
Only behavioral test-call failures are kills; syntax, collection, setup and
timeout outcomes remain distinct. Source scans, AST registries and value digests
cannot establish runtime kill credit. Digests identify frozen evidence only.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import functools
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import signal
import sys
import tempfile
import time
import tokenize
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER_SOURCE = pathlib.Path(__file__).read_bytes()
RUNNER_SHA256 = hashlib.sha256(RUNNER_SOURCE).hexdigest()

NON_BEHAVIORAL_TESTS = (
    'test_mutation_pins_2026_09_30.py',
    'test_contract_registry_2026_09_30.py',
    'test_encrypt_with_nonce_absent_from_production_paths',
    'test_production_code_never_calls_the_v1_patterns_analyzer',
    'test_es_function_words_carry_no_duplicate_literals',
)


def is_behavior_failure(failure):
    """Require an actual call failure rather than source inventory evidence."""
    return failure.get('phase') == 'call' and not any(
        name in failure.get('nodeid', '') for name in NON_BEHAVIORAL_TESTS
    )


def runtime_context_nodeid(context):
    """Keep parameter IDs containing pipes; discard import/setup contexts."""
    nodeid, separator, phase = context.rpartition('|')
    if separator and phase == 'run' and nodeid.startswith('tests/'):
        return nodeid
    return None


@functools.lru_cache(maxsize=128)
def _functions_in_tree(tree):
    return tuple(node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))


def full_runtime_covering_nodes(tree, line, contexts):
    """Return every call context for a line, then its enclosing function.

    Multiline arguments and unexecuted branches need the tests that exercise
    their function, rather than whichever unrelated module test is cheapest.
    Import-time changes and functions without call coverage still fall back
    to all module call contexts.
    """
    direct = set(contexts.get(str(line), []))
    if direct:
        return direct, 'line'
    enclosing = [node for node in _functions_in_tree(tree)
                 if node.lineno <= line <= node.end_lineno]
    if enclosing:
        function = min(enclosing, key=lambda node: node.end_lineno - node.lineno)
        covered = {nodeid for number, nodes in contexts.items()
                   if function.lineno <= int(number) <= function.end_lineno for nodeid in nodes}
        if covered:
            return covered, 'enclosing_function'
    return {nodeid for nodes in contexts.values() for nodeid in nodes}, 'module'


def grouped_shards(rows, workers, default_selectors):
    """Keep oracle groups together, splitting large groups for parallel work."""
    groups = {}
    for row in rows:
        key = tuple(row.get('selectors', default_selectors))
        groups.setdefault(key, []).append(row)
    target = max(1, (len(rows) + workers - 1) // workers)
    pieces = [group[start:start + target]
              for group in groups.values() for start in range(0, len(group), target)]
    shards = [[] for _ in range(min(workers, len(rows)))]
    for piece in sorted(pieces, key=len, reverse=True):
        shard = min(shards, key=len)
        shard.extend(piece)
    return shards


def parser_compatible_source(source):
    """Express grouped with-items with continuations for parso's old grammar.

    Runtime source is never normalized. AST equality verifies the parser-only
    representation; a character map transfers each small mutation back to the
    original. Newlines are retained, preserving canonical mutation line IDs.
    """
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    edits = []
    for index, token in enumerate(tokens):
        if token.string != 'with' or tokens[index + 1].string != '(':
            continue
        opening = tokens[index + 1]
        depth, commas, last, region = 1, [], None, []
        for token_index, following in enumerate(tokens[index + 2:], index + 2):
            if following.type == tokenize.OP:
                if following.string in '([{':
                    depth += 1
                elif following.string in ')]}':
                    depth -= 1
                    if depth == 0:
                        closing = following
                        break
                elif following.string == ',' and depth == 1:
                    commas.append(following)
            if following.type not in (tokenize.NL, tokenize.NEWLINE,
                                      tokenize.COMMENT, tokenize.INDENT,
                                      tokenize.DEDENT):
                last = following
            region.append(following)
        else:
            raise RuntimeError('unbalanced with-items')
        # A parenthesized expression followed by `as` is already supported.
        next_token = next((item for item in tokens[token_index + 1:]
                           if item.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT)), None)
        if next_token is None or next_token.string != ':':
            continue
        if last is None:
            continue  # Parenthesized empty tuple is not a with-item grouping.
        pos = lambda item: offsets[item.start[0] - 1] + item.start[1]
        edits.extend([(pos(opening), 1, ' '), (pos(closing), 1, ' ')])
        if commas and last is commas[-1]:
            edits.append((pos(last), 1, ' '))
        # Comments and blank lines are accepted by grouped-with syntax but
        # not by explicit continuation. Blank comment text in parser input,
        # and continue every physical line outside multiline string literals.
        for item in region:
            if item.type == tokenize.COMMENT:
                edits.append((pos(item), len(item.string), ' ' * len(item.string)))
        string_lines = {line for item in region if item.type == tokenize.STRING
                        for line in range(item.start[0], item.end[0])}
        for line in range(opening.start[0], closing.start[0]):
            if line not in string_lines:
                newline = offsets[line] - 1
                if source[newline - 1:newline] == '\r':
                    newline -= 1
                edits.append((newline, 0, '\\'))
    if not edits:
        return source, list(range(len(source)))
    result, mapping, cursor = [], [], 0
    for position, count, replacement in sorted(edits):
        result.append(source[cursor:position])
        mapping.extend(range(cursor, position))
        result.append(replacement)
        mapping.extend([position] * len(replacement))
        cursor = position + count
    result.append(source[cursor:])
    mapping.extend(range(cursor, len(source)))
    compatible = ''.join(result)
    if ast.dump(ast.parse(source)) != ast.dump(ast.parse(compatible)):
        raise RuntimeError('with parser normalization changed runtime AST')
    return compatible, mapping


def canonical_mutants(source, filename):
    """Produce canonical IDs, with local AST edits instead of repeated parsing.

    The pristine traversal uses the installed mutmut mutation functions. Its
    IDs are checked against mutmut.list_mutations; uncommon mismatches fall
    back to the canonical interpreter. Sampled patches are also checked byte
    for byte against mutmut.mutate. All patches are single-mutant edits.
    """
    import mutmut

    original = source
    source, source_map = parser_compatible_source(source)
    canonical = mutmut.list_mutations(mutmut.Context(source=source, filename=filename))
    tree = mutmut.parse(source, error_recovery=False)
    context = mutmut.Context(source=source, filename=filename)
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    patches = {}

    def visit_children(node):
        annotation = False
        for child in node.children:
            if child.type == 'operator' and child.value == '->':
                annotation = True
            if annotation and child.type == 'operator' and child.value == ':':
                annotation = False
            if not annotation:
                visit(child)

    def visit(node):
        context.stack.append(node)
        try:
            if node.type in ('tfpdef', 'import_from', 'import_name'):
                return
            if (node.type == 'atom_expr' and node.children
                    and node.children[0].type == 'name'
                    and node.children[0].value == '__import__'):
                return
            if node.start_pos[0] - 1 != context.current_line_index:
                context.current_line_index = node.start_pos[0] - 1
                context.index = 0
            if (node.type == 'expr_stmt' and node.children[0].type == 'name'
                    and node.children[0].value.startswith('__')
                    and node.children[0].value.endswith('__')
                    and node.children[0].value[2:-2] in mutmut.dunder_whitelist):
                return
            if node.type == 'annassign' and len(node.children) == 2:
                return
            if hasattr(node, 'children'):
                visit_children(node)
            mutation = mutmut.mutations_by_type.get(node.type)
            if not mutation:
                return
            for key, function in sorted(mutation.items()):
                old = getattr(node, key)
                if context.exclude_line():
                    continue
                new = function(context=context, node=node,
                               value=getattr(node, 'value', None),
                               children=getattr(node, 'children', None))
                choices = new if isinstance(new, list) and not isinstance(old, list) else [new]
                for replacement in reversed(choices):
                    if replacement is None or replacement == old:
                        continue
                    identity = context.mutation_id_of_current_index
                    before = node.get_code()
                    position = offsets[node.start_pos[0] - 1] + node.start_pos[1]
                    # Parso's get_code includes the first leaf's prefix.
                    position -= len(node.get_first_leaf().prefix if hasattr(node, 'get_first_leaf') else node.prefix)
                    setattr(node, key, replacement)
                    after = node.get_code()
                    setattr(node, key, old)
                    patches[(identity.line_number, identity.index)] = (position, before, after)
                    context.index += 1
        finally:
            context.stack.pop()

    visit_children(tree)
    rows = []
    for number, identity in enumerate(canonical):
        patch = patches.get((identity.line_number, identity.index))
        if patch:
            position, before, after = patch
            if source[position:position + len(before)] != before:
                patch = None
        # Check representative patches in every module with canonical mutmut.
        verify = number in {0, len(canonical) // 2, len(canonical) - 1}
        if not patch or verify:
            mutated, count = mutmut.mutate(mutmut.Context(
                source=source, filename=filename, mutation_id=identity))
            if count != 1:
                raise RuntimeError(f'canonical mutation count {count}: {filename} {identity}')
            if patch:
                candidate = source[:position] + after + source[position + len(before):]
                if candidate.replace(' not not ', ' ') != mutated:
                    patch = None
            if not patch:
                # Common prefix/suffix reduce the canonical result to a patch.
                position = 0
                while position < min(len(source), len(mutated)) and source[position] == mutated[position]:
                    position += 1
                tail = 0
                while (tail < min(len(source), len(mutated)) - position
                       and source[-1 - tail] == mutated[-1 - tail]):
                    tail += 1
                end = len(source) - tail if tail else len(source)
                mutated_end = len(mutated) - tail if tail else len(mutated)
                before, after = source[position:end], mutated[position:mutated_end]
        else:
            position, before, after = patch
        # Drop unchanged prefix/suffix before transferring the operator edit.
        prefix = 0
        while prefix < min(len(before), len(after)) and before[prefix] == after[prefix]:
            prefix += 1
        suffix = 0
        while suffix < min(len(before), len(after)) - prefix and before[-1-suffix] == after[-1-suffix]:
            suffix += 1
        normalized_start = position + prefix
        normalized_end = position + len(before) - suffix
        mapped_start = source_map[normalized_start] if normalized_start < len(source_map) else len(original)
        mapped_end = source_map[normalized_end - 1] + 1 if normalized_end > normalized_start else mapped_start
        before = original[mapped_start:mapped_end]
        after = after[prefix:len(after)-suffix if suffix else len(after)]
        position = mapped_start
        rows.append({'file': filename, 'line': identity.line_number + 1,
                     'index': identity.index, 'position': position,
                     'before': before, 'after': after,
                     'source_line': identity.line})
    return rows


def enumerate_campaign(snapshot, output):
    rows, modules = [], {}
    app_paths = sorted((snapshot / 'backend/app').rglob('*.py'))
    paths = [path for path in app_paths if path.name != 'models.py']
    paths.append(snapshot / 'backend/app/models.py')
    paths.extend(sorted(path for path in (snapshot / 'backend').rglob('*.py')
                        if not path.is_relative_to(snapshot / 'backend/app')
                        and 'tests' not in path.relative_to(snapshot / 'backend').parts
                        and '.venv' not in path.relative_to(snapshot / 'backend').parts
                        and '__pycache__' not in path.relative_to(snapshot / 'backend').parts))
    for path in paths:
        relative = path.relative_to(snapshot / 'backend').as_posix()
        source = path.read_text()
        generated = canonical_mutants(source, relative)
        modules[relative] = len(generated)
        for row in generated:
            row['id'] = f"M{len(rows) + 1:06d}"
            rows.append(row)
        print(f'{relative}: {len(generated)} ({len(rows)} total)', flush=True)
    (output / 'mutants.json').write_text(json.dumps(rows, indent=2))
    (output / 'scope.json').write_text(json.dumps({
        'modules': modules, 'total': len(rows),
        'excluded': {},
        'scope': 'Every production Python file in backend, including models, migrations, bootstrap and scripts; probe_brain included',
        'operator': 'mutmut 2.4.4 canonical IDs and mutation functions',
    }, indent=2))
    return rows


class Reporter:
    def __init__(self, capture_contracts=False, expected_contracts=None, capture_public_values=False):
        self.failures, self.errors, self.passed, self.skipped = [], [], 0, 0
        self.capture_contracts = capture_contracts
        self.expected_contracts = expected_contracts
        self.capture_public_values = capture_public_values
        self.contracts, self.current_events = {}, None

    def pytest_runtest_call(self, item):
        """Compare exercised HTTP status/error envelopes during the test call."""
        self.current_events = [] if self.capture_contracts else None
        try:
            result = yield
        finally:
            events = self.current_events
            self.current_events = None
            if events is not None:
                self.contracts[item.nodeid] = sorted(events, key=lambda value: json.dumps(value, sort_keys=True))
        if self.expected_contracts is not None:
            assert item.nodeid in self.expected_contracts, 'missing pristine HTTP contract baseline'
            assert self.contracts[item.nodeid] == self.expected_contracts[item.nodeid], (
                f'exercised customer HTTP status/error contract changed for {item.nodeid}\n'
                f'expected: {self.expected_contracts[item.nodeid]!r}\n'
                f'actual: {self.contracts[item.nodeid]!r}')
        return result

    def install_http_contract_capture(self):
        """Observe completed customer responses without consuming streams.

        Status, code, public error details and JSON wire structure are frontend
        contracts. Secret, ID and narrative values, dynamic input echoes and
        internal exception constructors are excluded. UUIDs/calendar values vary with
        fixtures; their shapes are retained without binding a cached baseline
        to a randomly generated identity or a particular wall-clock date.
        """
        import httpx
        original = httpx.AsyncClient.send
        reporter = self

        def stable(value):
            if isinstance(value, str):
                value = re.sub(r'\b[0-9a-fA-F]{32}\b', '<uuid>', value)
                value = re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b', '<uuid>', value)
                value = re.sub(r'\b\d{4}-\d{2}-\d{2}(?:T[^\s,;)]*)?', '<calendar>', value)
                # Seeded client entry IDs contain an independent short nonce
                # after their date. Both identity components vary on every
                # pristine run and are excluded from the route contract.
                value = re.sub(r'(?<=<calendar>-)[0-9a-fA-F]{8}(?=/|$)', '<nonce>', value)
                return value
            if isinstance(value, dict):
                return {key: stable(item) for key, item in value.items() if key != 'input'}
            if isinstance(value, list):
                return [stable(item) for item in value]
            return value

        enum_fields = {'role', 'key_scheme', 'recovery_scheme', 'phase', 'analyzer', 'status'}
        integer_fields = {'state_seq', 'version', 'content_version', 'custody_version',
                          'active_days', 'days_remaining', 'streak', 'patterns_stored',
                          'patterns_new', 'patterns_fading', 'entries_revision',
                          'measures_revision', 'notes_revision', 'patients_revision',
                          'consents_revision', 'expires_in', 'entry_count'}

        def wire_structure(value, field=None):
            if isinstance(value, dict):
                fields = [[stable(key), wire_structure(item, key)] for key, item in value.items()]
                return {'object_fields': sorted(fields, key=lambda pair: json.dumps(pair, sort_keys=True))}
            if isinstance(value, list):
                items = [wire_structure(item) for item in value]
                # Record identities are omitted, so arbitrary ordering of
                # otherwise equal seeded records must not pin random IDs.
                return {'array_length': len(value),
                        'items': sorted(items, key=lambda item: json.dumps(item, sort_keys=True))}
            if isinstance(value, bool):
                return {'boolean': value}
            if value is None:
                return 'null'
            if isinstance(value, str):
                if reporter.capture_public_values and field in enum_fields:
                    return {'public_enum': value}
                return 'string'
            if isinstance(value, int):
                if reporter.capture_public_values and field in integer_fields:
                    return {'public_integer': value}
                return 'integer'
            if isinstance(value, float):
                return 'number'
            raise TypeError(f'unsupported decoded JSON type {type(value).__name__}')

        async def send(client, request, *args, **kwargs):
            response = await original(client, request, *args, **kwargs)
            if (reporter.current_events is not None
                    and isinstance(client._transport, httpx.ASGITransport)
                    and request.url.path.startswith('/api/')):
                event = {'method': request.method, 'path': stable(request.url.path),
                         'status': response.status_code}
                if hasattr(response, '_content'):
                    try:
                        body = response.json()
                    except (ValueError, UnicodeError):
                        body = None
                    if response.status_code >= 400 and isinstance(body, dict):
                        event['error'] = stable({key: body[key] for key in ('code', 'detail') if key in body})
                    elif response.status_code < 400 and response.headers.get('content-type', '').startswith('application/json'):
                        event['wire_structure'] = wire_structure(body)
                reporter.current_events.append(event)
            return response
        httpx.AsyncClient.send = send

    def pytest_collectreport(self, report):
        if report.failed:
            self.errors.append({'nodeid': report.nodeid, 'phase': 'collection',
                                'detail': str(report.longrepr)})

    def pytest_runtest_logreport(self, report):
        if report.failed:
            record = {'nodeid': report.nodeid, 'phase': report.when,
                      'detail': str(report.longrepr)}
            (self.failures if report.when == 'call' else self.errors).append(record)
        elif report.when == 'call' and report.passed:
            self.passed += 1
        elif report.skipped:
            self.skipped += 1


def pytest_child(backend, selectors, log, timeout, capture_contracts=False, expected_contracts=None,
                 capture_public_values=False):
    result_path = log.with_suffix('.json')
    log.parent.mkdir(parents=True, exist_ok=True)
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=log.stem + '-tmp-', dir=log.parent)).resolve()
    started = time.monotonic()
    try:
        pid = os.fork()
    except BaseException:
        shutil.rmtree(temporary)
        raise
    if pid == 0:
        try:
            os.setpgid(0, 0)
            os.chdir(backend)
            os.environ['TMPDIR'] = str(temporary)
            tempfile.tempdir = str(temporary)
            fd = os.open(log, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            os.dup2(fd, 1)
            os.dup2(fd, 2)
            os.close(fd)
            sys.path.insert(0, str(backend))
            import pytest
            pytest.hookimpl(wrapper=True)(Reporter.pytest_runtest_call)
            reporter = Reporter(capture_contracts, expected_contracts, capture_public_values)
            if capture_contracts:
                reporter.install_http_contract_capture()
            status = pytest.main(['-x', '-q', '-m', 'not slow',
                                  '--basetemp', str(temporary / 'pytest'),
                                  '-p', 'pytest_asyncio.plugin',
                                  *selectors], plugins=[reporter])
            result_path.write_text(json.dumps({'returncode': int(status),
                'failures': reporter.failures, 'errors': reporter.errors,
                'passed': reporter.passed, 'skipped': reporter.skipped,
                'contracts': reporter.contracts}))
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(0)
        except BaseException as error:  # noqa: BLE001 -- report child process exits separately
            result_path.write_text(json.dumps({'returncode': -1, 'errors': [repr(error)],
                                              'failures': [], 'passed': 0, 'skipped': 0}))
            os._exit(1)
    timed_out = False
    try:
        while True:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            if time.monotonic() - started > timeout:
                timed_out = True
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
                break
            time.sleep(0.01)
    finally:
        # Completed tests must not leave spawned children or unclosed
        # tempfile.mkstemp files behind. Only this explicitly owned directory
        # is removed; system-wide pytest/temp directories are untouched.
        if not timed_out:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if temporary.is_symlink():
            temporary.unlink()
        elif temporary.exists():
            shutil.rmtree(temporary)
    row = json.loads(result_path.read_text()) if result_path.exists() else {
        'returncode': -1, 'failures': [], 'errors': ['child produced no result'],
        'passed': 0, 'skipped': 0}
    row['seconds'] = round(time.monotonic() - started, 4)
    row['log'] = str(log)
    row['timed_out'] = timed_out
    row['temporary_directory'] = str(temporary)
    row['temporary_restored'] = not temporary.exists()
    if timed_out:
        row['status'] = 'TIMEOUT'
    elif row['errors']:
        row['status'] = 'ORACLE_ERROR'
    elif row['returncode'] == 1 and row['failures']:
        row['behavior_failures'] = [f for f in row['failures'] if is_behavior_failure(f)]
        row['non_behavioral_failures'] = [f for f in row['failures'] if not is_behavior_failure(f)]
        row['status'] = 'KILLED' if row['behavior_failures'] else 'NON_BEHAVIORAL_FAILURE'
    elif row['returncode'] == 0 and row['passed']:
        row['status'] = 'SURVIVED'
    else:
        row['status'] = 'ORACLE_ERROR'
    return row


def preload():
    # No app, conftest, or test module may be imported in the fork parent.
    os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    sys.dont_write_bytecode = True
    os.environ['MINDPATTERN_ENV'] = 'development'
    import cryptography  # noqa: F401
    import pytest  # noqa: F401
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)


class FrozenFiles:
    """Restore touched frozen files and remove generated import candidates.

    Checking metadata avoids rewriting 39 MB before every mutant. Any changed
    metadata triggers a byte comparison against the frozen copy; source/test
    files are also verified byte-for-byte after each control. Generated files
    are removed without following linked dependencies or the private Git dir.
    """
    def __init__(self, root, files):
        self.root, self.files = root, files
        self.metadata = {name: self.stat(root / name) for name in files}
        self.code = [name for name in files if name.endswith('.py')]

    @staticmethod
    def stat(path):
        try:
            result = path.stat(follow_symlinks=False)
            return result.st_size, result.st_mtime_ns, result.st_ino
        except FileNotFoundError:
            return None

    def restore(self):
        for directory, dirs, names in os.walk(self.root, followlinks=False):
            retained = []
            for name in dirs:
                path = pathlib.Path(directory) / name
                if name in {'.git', '.venv', 'node_modules', '__pycache__', '.pytest_cache',
                            '.hypothesis', '.mypy_cache', '.ruff_cache'}:
                    if name == '__pycache__':
                        import shutil
                        if path.is_symlink():
                            path.unlink()
                        else:
                            shutil.rmtree(path)
                    continue
                if path.is_symlink():
                    path.unlink()
                    if any(key.startswith(path.relative_to(self.root).as_posix() + '/')
                           for key in self.files):
                        path.mkdir()
                        retained.append(name)
                else:
                    retained.append(name)
            dirs[:] = retained
            for name in names:
                path = pathlib.Path(directory) / name
                if path.is_symlink():
                    path.unlink()
        for name, content in self.files.items():
            path = self.root / name
            if self.stat(path) != self.metadata[name] or not path.is_file() or path.read_bytes() != content:
                if path.is_symlink():
                    path.unlink()
                if not path.is_file() or path.read_bytes() != content:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                self.metadata[name] = self.stat(path)
        for directory, dirs, names in os.walk(self.root, followlinks=False):
            dirs[:] = [name for name in dirs if name not in {
                '.git', '.venv', 'node_modules', '__pycache__', '.pytest_cache',
                '.hypothesis', '.mypy_cache', '.ruff_cache'}]
            for name in names:
                path = pathlib.Path(directory) / name
                relative = path.relative_to(self.root).as_posix()
                if relative not in self.files and not path.is_symlink():
                    path.unlink()
        return True


def run_shard(snapshot, output, rows, shard, selectors, timeout, capture_contracts=False,
              expected_runner_sha256=None, capture_public_values=False):
    from redteam.deep_backend_mutation.runner import make_copy

    if expected_runner_sha256 is not None and RUNNER_SHA256 != expected_runner_sha256:
        raise RuntimeError('runner changed between campaign launch and worker initialization')

    destination = output / 'copies' / f'worker-{shard:02d}'
    # Copy from the frozen source, never from the changing live checkout.
    files = {p.relative_to(snapshot).as_posix(): p.read_bytes()
             for p in snapshot.rglob('*') if p.is_file()
             and '.git' not in p.relative_to(snapshot).parts
             and '.venv' not in p.relative_to(snapshot).parts
             and '__pycache__' not in p.relative_to(snapshot).parts
             and not p.name.startswith('.coverage')}
    make_copy(destination, files)
    frozen = FrozenFiles(destination, files)
    frozen.restore()
    backend = destination / 'backend'
    for name in ('MINDPATTERN_TEST_DB_URL', 'MINDPATTERN_TEST_DB_ALLOW_EXISTING_SQLITE',
                 'MINDPATTERN_DB_URL', 'DB_URL'):
        os.environ.pop(name, None)
    os.environ['MINDPATTERN_LOCK_DIR'] = str(output / 'locks' / f'worker-{shard:02d}')
    pathlib.Path(os.environ['MINDPATTERN_LOCK_DIR']).mkdir(parents=True, exist_ok=True)
    preload()
    logs = output / 'logs' / f'worker-{shard:02d}'
    logs.mkdir(parents=True, exist_ok=True)
    baselines = {}
    result = output / f'results-{shard:02d}.jsonl'
    source = {name: (backend / name).read_text() for name in {row['file'] for row in rows}}
    with result.open('w') as handle:
        for mutant in rows:
            frozen.restore()
            selected = mutant.get('selectors', selectors)
            key = json.dumps(selected)
            if key not in baselines:
                baseline = pytest_child(backend, selected,
                    logs / f'baseline-{len(baselines):05d}.log', max(timeout, 60), capture_contracts,
                    capture_public_values=capture_public_values)
                baseline['restored'] = frozen.restore()
                baseline['selectors'] = selected
                baseline['baseline_id'] = f'{shard:02d}-{len(baselines):05d}'
                if baseline['status'] != 'SURVIVED':
                    raise RuntimeError(f'failed selector baseline: {baseline}')
                if capture_contracts:
                    repeated = pytest_child(backend, selected,
                        logs / f'baseline-repeat-{len(baselines):05d}.log', max(timeout, 60), True,
                        capture_public_values=capture_public_values)
                    repeated['restored'] = frozen.restore()
                    if repeated['status'] != 'SURVIVED' or repeated['contracts'] != baseline['contracts']:
                        raise RuntimeError(f'customer response contract baseline is not repeatable: {selected}')
                    baseline['repeated_log'] = repeated['log']
                    baseline['repeated_seconds'] = repeated['seconds']
                baselines[key] = baseline
                (output / f'baselines-{shard:02d}.json').write_text(json.dumps(baselines, indent=2))
            original = source[mutant['file']]
            position, before = mutant['position'], mutant['before']
            if original[position:position + len(before)] != before:
                raise RuntimeError(f'patch anchor changed: {mutant["id"]}')
            changed = original[:position] + mutant['after'] + original[position + len(before):]
            changed = changed.replace(' not not ', ' ')
            row = {**mutant, 'selectors': selected, 'baseline_id': baselines[key]['baseline_id']}
            row['public_response_values'] = capture_public_values
            baseline_time = max(baselines[key]['seconds'], baselines[key].get('repeated_seconds', 0))
            effective_timeout = max(timeout, baseline_time * 2 + 10)
            row['timeout_seconds'] = round(effective_timeout, 4)
            try:
                compile(changed, mutant['file'], 'exec')
            except (SyntaxError, ValueError) as error:
                row.update(status='INVALID_SYNTAX', detail=str(error), seconds=0)
            else:
                target = backend / mutant['file']
                target.write_text(changed)
                try:
                    row.update(pytest_child(backend, selected, logs / f'{mutant["id"]}.log', effective_timeout,
                                            capture_contracts,
                                            baselines[key]['contracts'] if capture_contracts else None,
                                            capture_public_values))
                finally:
                    target.write_text(original)
                row['restored'] = frozen.restore() and target.read_text() == original
                if not row['restored']:
                    row['status'] = 'RESTORE_ERROR'
            handle.write(json.dumps(row) + '\n')
            handle.flush()
    return str(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--enumerate-only', action='store_true')
    parser.add_argument('--workers', type=int, default=10)
    parser.add_argument('--timeout', type=float, default=20,
                        help='minimum mutant budget; also allow twice its pristine duration plus ten seconds')
    parser.add_argument('--selectors', nargs='+', default=['../tools/tests/test_backend_boot_contract.py'],
                        help='real pytest behavior oracles; source scans and digest pins cannot earn kill credit')
    parser.add_argument('--ids', nargs='*')
    parser.add_argument('--plan', type=pathlib.Path)
    parser.add_argument('--runtime-http-contracts', action='store_true')
    parser.add_argument('--runtime-public-values', action='store_true',
                        help='also verify documented frontend enum/counter/version values; implies HTTP contracts')
    args = parser.parse_args()
    snapshot, output = args.snapshot.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sources = {p.relative_to(snapshot).as_posix(): p.read_bytes()
               for p in snapshot.rglob('*') if p.is_file()
               and '.git' not in p.relative_to(snapshot).parts
               and '.venv' not in p.relative_to(snapshot).parts
               and '__pycache__' not in p.relative_to(snapshot).parts
               and '.pytest_cache' not in p.relative_to(snapshot).parts
               and '.hypothesis' not in p.relative_to(snapshot).parts}
    digest = hashlib.sha256()
    for name, content in sorted(sources.items()):
        digest.update(name.encode() + b'\0' + hashlib.sha256(content).digest())
    provenance = {'source_and_test_sha256': digest.hexdigest(), 'snapshot': str(snapshot),
                  'runner_sha256': RUNNER_SHA256}
    provenance_path = output / 'provenance.json'
    if provenance_path.exists() and json.loads(provenance_path.read_text()) != provenance:
        raise RuntimeError('manifest source provenance differs from frozen snapshot')
    provenance_path.write_text(json.dumps(provenance, indent=2))
    (output / 'runner.py').write_bytes(RUNNER_SOURCE)
    manifest = output / 'mutants.json'
    rows = json.loads(manifest.read_text()) if manifest.exists() else enumerate_campaign(snapshot, output)
    if not rows or len({row['id'] for row in rows}) != len(rows):
        raise ValueError('campaign scope is empty or contains duplicate IDs')
    manifest_ids = {row['id'] for row in rows}
    if args.enumerate_only:
        return 0
    if list(output.glob('results-*.jsonl')):
        raise RuntimeError('refusing to overwrite existing run results; use a new output directory')
    if args.ids:
        unknown = set(args.ids) - {row['id'] for row in rows}
        if unknown:
            raise ValueError(f'unknown mutation IDs: {sorted(unknown)}')
        rows = [row for row in rows if row['id'] in args.ids]
    if args.plan:
        plan = json.loads(args.plan.read_text())
        if not isinstance(plan, dict) or set(plan) - manifest_ids:
            raise ValueError('plan contains unknown mutation IDs or is not an ID mapping')
        if any(not isinstance(value, list) or not value
               or any(not isinstance(selector, str) or not selector.strip() for selector in value)
               for value in plan.values()):
            raise ValueError('every plan must contain a nonempty list of pytest selectors')
        if args.ids and set(args.ids) - set(plan):
            raise ValueError('selected mutation IDs are missing from the oracle plan')
        rows = [{**row, 'selectors': plan[row['id']]} for row in rows if row['id'] in plan]
    if not rows:
        raise ValueError('selected campaign scope is empty')
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(run_shard, snapshot, output, shard,
                               index, args.selectors, args.timeout,
                               args.runtime_http_contracts or args.runtime_public_values,
                               RUNNER_SHA256, args.runtime_public_values)
                   for index, shard in enumerate(grouped_shards(rows, args.workers, args.selectors))]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except BaseException as error:
                print(f'campaign worker failed: {error!r}', file=sys.stderr, flush=True)
                raise
            print(result, flush=True)
    results = [json.loads(line) for path in output.glob('results-*.jsonl')
               for line in path.read_text().splitlines()]
    counts = dict(Counter(row['status'] for row in results))
    (output / 'summary.json').write_text(json.dumps({'total': len(results), 'counts': counts}, indent=2))
    print(json.dumps(counts), flush=True)
    if len(results) != len(rows) or {row['id'] for row in results} != {row['id'] for row in rows}:
        return 1
    return 0 if all(row['status'] == 'KILLED' and row.get('restored') for row in results) else 1


if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
