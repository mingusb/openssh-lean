#!/usr/bin/env python3
"""Finite GNU fortified-format checks, separating execution from known boundaries.

Native abort witnesses use a physically larger destination than the explicit
object-size argument. They test glibc's checked failure without executing an
unfortified out-of-bounds write. A Cerberus refusal is recorded as a remaining
adapter boundary, never as reproduction of SIGABRT.
"""
import argparse
import json
from pathlib import Path
import re
import resource
import signal
import sys

from exercise_imported_c import invoke, sha


HELPER = '''
static int equal(const char *a, const char *b) {
  while (*a && *a==*b) { a++; b++; }
  return *a==*b;
}
'''

CASES = {
    'sprintf-literal': {'source': 'int main(void) { char b[16]; int n=__builtin___sprintf_chk(b,0,sizeof b,"abc"); return n!=3 || !equal(b,"abc"); }'},
    'sprintf-integers': {'source': 'int main(void) { char b[32]; int n=__builtin___sprintf_chk(b,0,sizeof b,"%d/%u",-7,9U); return n!=4 || !equal(b,"-7/9"); }'},
    'sprintf-negative-zero-padding': {'source': 'int main(void) { char b[16]; int n=__builtin___sprintf_chk(b,0,sizeof b,"%05d",-12); return n!=5 || !equal(b,"-0012"); }'},
    'sprintf-hex-prefix-zero-padding': {'source': 'int main(void) { char b[16]; int n=__builtin___sprintf_chk(b,0,sizeof b,"%#06x",0x2aU); return n!=6 || !equal(b,"0x002a"); }'},
    'sprintf-string-char-percent': {'source': 'int main(void) { char b[32]; int n=__builtin___sprintf_chk(b,0,sizeof b,"%s:%c:%%","abc",\'Z\'); return n!=7 || !equal(b,"abc:Z:%"); }'},
    'sprintf-unknown-size': {'source': 'int main(void) { char b[16]; int n=__builtin___sprintf_chk(b,0,(unsigned long)-1,"%s","abc"); return n!=3 || !equal(b,"abc"); }'},
    'sprintf-positive-flag': {'source': 'int main(void) { char b[16]; int n=__builtin___sprintf_chk(b,1,sizeof b,"%s","abc"); return n!=3 || !equal(b,"abc"); }'},
    'snprintf-truncation': {'source': 'int main(void) { char b[8]={88,88,88,88,88,88,88,88}; int n=__builtin___snprintf_chk(b,4,0,sizeof b,"abcdef"); return n!=6 || !equal(b,"abc") || b[4]!=88; }'},
    'snprintf-exact-fit': {'source': 'int main(void) { char b[4]; int n=__builtin___snprintf_chk(b,4,0,sizeof b,"abc"); return n!=3 || !equal(b,"abc"); }'},
    'snprintf-size-one': {'source': 'int main(void) { char b[2]={88,88}; int n=__builtin___snprintf_chk(b,1,0,sizeof b,"abc"); return n!=3 || b[0]!=0 || b[1]!=88; }'},
    'snprintf-zero-null': {'source': 'int main(void) { int n=__builtin___snprintf_chk((char*)0,0,0,0,"n=%d",12); return n!=4; }'},
    'snprintf-zero-no-write': {'source': 'int main(void) { char b=88; int n=__builtin___snprintf_chk(&b,0,0,0,"abcdef"); return n!=6 || b!=88; }'},
    'sprintf-empty': {'source': 'int main(void) { char b[2]={88,88}; int n=__builtin___sprintf_chk(b,0,1,""); return n || b[0]!=0 || b[1]!=88; }'},
    'arguments-evaluated-once': {'source': '''char b[32]; int dc,fc,sc,vc;
char *dest(void) { dc++; return b; }
int flag(void) { fc++; return 0; }
unsigned long size(void) { sc++; return sizeof b; }
int value(void) { vc++; return 7; }
int main(void) { int n=__builtin___sprintf_chk(dest(),flag(),size(),"%d",value()); return n!=1 || !equal(b,"7") || dc!=1 || fc!=1 || sc!=1 || vc!=1; }'''},
    'printf-output-return': {'source': 'int main(void) { int n=__builtin___printf_chk(1,"%s %d\\n","hi",7); return n!=5; }', 'stdout': 'hi 7\n'},
    'fprintf-stderr-output-return': {'source': '#include <stdio.h>\nint main(void) { int n=__builtin___fprintf_chk(stderr,1,"%s, %s\\n","ssh","OpenSSL"); return n!=13; }', 'stderr': 'ssh, OpenSSL\n', 'libc': True},
    'fprintf-direct-name-stderr-output-return': {'source': '#include <stdio.h>\nextern int __fprintf_chk(FILE *, int, const char *, ...);\nint main(void) { int n=__fprintf_chk(stderr,1,"%s, %s\\n","ssh","OpenSSL"); return n!=13; }', 'stderr': 'ssh, OpenSSL\n', 'libc': True},
    'snprintf-nul-character': {'source': 'int main(void) { char b[3]={88,88,88}; int n=__builtin___snprintf_chk(b,3,0,sizeof b,"%c",0); return n!=1 || b[0]!=0 || b[1]!=0 || b[2]!=88; }'},
    'sprintf-all-byte-characters': {'source': '''int main(void) {
  for (int i=0; i<256; i++) {
    char b[3]={88,88,88};
    int n=__builtin___sprintf_chk(b,0,sizeof b,"%c",i);
    if (n!=1 || (unsigned char)b[0]!=i || b[1]!=0 || b[2]!=88) return i<255 ? i+1 : 255;
  }
  return 0;
}'''},
    'argument-pack-forwarding': {'source': '''static inline __attribute__((always_inline)) int wrap(char *b,const char *fmt,...) { return __builtin___sprintf_chk(b,0,16,fmt,__builtin_va_arg_pack()); }
int main(void) { char b[16]; int n=wrap(b,"%d/%s",7,"xy"); return n!=4 || !equal(b,"7/xy"); }'''},
    'sprintf-address-identity-indirect': {'source': '''extern int __sprintf_chk(char*,int,unsigned long,const char*,...);
int main(void) { char b[16]; int (*f)(char*,int,unsigned long,const char*,...)=__builtin___sprintf_chk; if (f!=__sprintf_chk) return 1; int n=f(b,0,sizeof b,"%d",7); return n!=1 || !equal(b,"7"); }'''},
    'sprintf-local-callable-shadow': {'source': '''int alternate(char *b,int flag,unsigned long size,const char *fmt,...) { b[0]='Q'; b[1]=0; return 1; }
int main(void) { char b[16]; int (*__builtin___sprintf_chk)(char*,int,unsigned long,const char*,...)=alternate; int n=__builtin___sprintf_chk(b,0,sizeof b,"%d",7); return n!=1 || !equal(b,"Q"); }'''},
    'percent-n-flag-zero': {'source': 'int main(void) { char b[16], fmt[]="abc%n"; int count=-1; int n=__builtin___sprintf_chk(b,0,sizeof b,fmt,&count); return n!=3 || count!=3 || !equal(b,"abc"); }', 'boundary': 'percent_n'},
    'percent-n-positive-readonly': {'source': 'int main(void) { char b[16]; int count=-1; int n=__builtin___sprintf_chk(b,1,sizeof b,"abc%n",&count); return n!=3 || count!=3 || !equal(b,"abc"); }', 'boundary': 'percent_n'},
    'percent-n-positive-writable-abort': {'source': 'int main(void) { char b[16], fmt[]="abc%n"; int count=-1; __builtin___sprintf_chk(b,1,sizeof b,fmt,&count); return 99; }', 'native': 'sigabrt', 'native_abort_marker': '%n in writable', 'boundary': 'percent_n'},
    'sprintf-explicit-bound-abort': {'source': 'int main(void) { char b[16]; volatile unsigned long limit=2; __builtin___sprintf_chk(b,0,limit,"abc"); return 99; }', 'native': 'sigabrt', 'native_abort_marker': 'buffer overflow', 'boundary': 'abort'},
    'snprintf-maxlen-bound-abort': {'source': 'int main(void) { char b[16]; volatile unsigned long limit=2; __builtin___snprintf_chk(b,4,0,limit,""); return 99; }', 'native': 'sigabrt', 'native_abort_marker': 'buffer overflow', 'boundary': 'abort'},
    'sprintf-zero-bound-abort': {'source': 'int main(void) { char b[16]; volatile unsigned long limit=0; __builtin___sprintf_chk(b,0,limit,""); return 99; }', 'native': 'sigabrt', 'native_abort_marker': 'buffer overflow', 'boundary': 'abort'},
    'v-family-declarations': {'source': '''int f(char *b, __builtin_va_list ap) { return __builtin___vsprintf_chk(b,0,16,"%d",ap); }
int g(char *b, __builtin_va_list ap) { return __builtin___vsnprintf_chk(b,16,0,16,"%d",ap); }
int h(__builtin_va_list ap) { return __builtin___vprintf_chk(0,"%d",ap); }
int main(void) { return 0; }''', 'declaration_only': True},
    'file-family-declarations': {'source': '''struct _IO_FILE;
int f(struct _IO_FILE *file) { return __builtin___fprintf_chk(file,0,"%d",7); }
int g(struct _IO_FILE *file, __builtin_va_list ap) { return __builtin___vfprintf_chk(file,0,"%d",ap); }
int main(void) { return 0; }''', 'declaration_only': True, 'boundary': 'file_typedef', 'boundary_stage': 'frontend'},
    'file-visible-typedef-declarations': {'source': '''typedef struct _IO_FILE FILE;
int f(FILE *file) { return __builtin___fprintf_chk(file,0,"%d",7); }
int g(FILE *file, __builtin_va_list ap) { return __builtin___vfprintf_chk(file,0,"%d",ap); }
int main(void) { return 0; }''', 'declaration_only': True},
    'invalid-conflicting-return-prototype': {'source': '''extern int __sprintf_chk(char*,int,unsigned long,const char*,...);
extern long __sprintf_chk(char*,int,unsigned long,const char*,...);
int main(void) { return 0; }''', 'native': 'compile_reject'},
    'invalid-conflicting-va-list-prototype': {'source': '''extern int __vsnprintf_chk(char*,unsigned long,int,unsigned long,const char*,__builtin_va_list);
extern int __vsnprintf_chk(char*,unsigned long,int,unsigned long,const char*,int);
int main(void) { return 0; }''', 'native': 'compile_reject'},
    'invalid-local-noncallable-shadow': {'source': 'int main(void) { int __builtin___sprintf_chk=2; return __builtin___sprintf_chk(); }', 'native': 'compile_reject'},
    'ordinary-snprintf-truncation': {'source': 'extern int snprintf(char*,unsigned long,const char*,...); int main(void) { char b[4]; int n=snprintf(b,4,"abcdef"); return n!=6 || !equal(b,"abc"); }', 'libc': True},
    'ordinary-snprintf-zero-null': {'source': 'extern int snprintf(char*,unsigned long,const char*,...); int main(void) { return snprintf((char*)0,0,"n=%d",12)!=4; }', 'libc': True},
}

CRASH_MARKERS = ('internal error', 'uncaught exception', 'panic', 'segmentation fault', 'stack overflow')
REFUSALS = {
    'abort': 'GNU_fortify_failure_requires_process_abort_semantics',
    'percent_n': 'GNU fortified format %n is not yet supported',
    'file_typedef': 'GNU fortified stream builtin requires a visible file-scope FILE typedef and runtime proxy',
}
CONSTRAINT_DIAGNOSTICS = {
    'invalid-conflicting-return-prototype': ('DESUGAR', 'multiple declarations in the same scope with incompatible types'),
    'invalid-conflicting-va-list-prototype': ('DESUGAR', 'multiple declarations in the same scope with incompatible types'),
    'invalid-local-noncallable-shadow': ('AIL_TYPING', 'called object type is not a function or function pointer'),
}


def rejected_constraint(name, engine, record):
    """Match this fixture's frontend constraint, not an arbitrary failure.

    Lean currently prints the stage and ConstraintViolation category without
    the OCaml constraint detail. Require that exact stage/category, the source
    filename, and one Error record. OCaml must report the specific constraint.
    """
    if name not in CONSTRAINT_DIAGNOSTICS or record['exit_code']!=1 or record['timeout']:
        return False
    observation = record['stdout']+record['stderr']
    if any(marker in observation.lower() for marker in CRASH_MARKERS):
        return False
    if re.search(r'\b(?:Defined|Undefined)\s*\{',observation):
        return False
    stage,detail = CONSTRAINT_DIAGNOSTICS[name]
    if engine=='lean':
        verb = 'desugaring' if stage=='DESUGAR' else 'typechecking'
        pattern = r'Error \{msg: "'+verb+r' failed at ([^"\n]*); cause: '+stage+r' ConstraintViolation"\}\s*'
        match = re.fullmatch(pattern,record['stdout'])
        return match is not None and name+'.c:' in match.group(1) and record['stderr'].strip()==''
    if engine=='ocaml':
        diagnostic = re.sub(r'\x1b\[[0-9;]*m','',record['stderr'])
        pattern = r'(?m)^([^\n]*'+re.escape(name+'.c:')+r'[^\n]*)error:\s*constraint violation:\s*'+re.escape(detail)+r'\s*$'
        return record['stdout'].strip()=='' and re.search(pattern,diagnostic) is not None
    return False


def capture(argv, output, name, suffix, cwd, timeout=90):
    stdout, stderr = output / (name+'.'+suffix+'.stdout'), output / (name+'.'+suffix+'.stderr')
    result = invoke(argv, stdout, stderr, cwd, timeout=timeout)
    result.update(stdout=stdout.read_text(errors='replace'), stderr=stderr.read_text(errors='replace'))
    return result


def defined_output(text, value, stdout, stderr=''):
    expected = 'Defined {value: "Specified(%d)", stdout: %s, stderr: %s, blocked: "false"}' % (value,json.dumps(stdout),json.dumps(stderr))
    lines = text.strip().splitlines()
    return (lines == [expected] or bool(lines) and len(lines)%2==0 and all(
        lines[i] == f'EXECUTION {i//2}:' and lines[i+1] == expected for i in range(0,len(lines),2)))


def check_case(repo, runtime, driver, lean, output, name, case, native_only, libc_args):
    source, tree, binary = (output/(name+suffix) for suffix in ('.c','.json','.native'))
    source.write_text(HELPER+case['source']+'\n')
    row = {'source_text': source.read_text(), 'source_sha256': sha(source), 'expected': case,
           'status': 'check_failed', 'engines': {}}
    native = capture(['cc','-std=gnu23','-O2',str(source),'-o',str(binary)],output,name,'cc',repo,30)
    row['native_compile'] = native
    reject = case.get('native')=='compile_reject'
    native_ok = native['exit_code']==(1 if reject else 0) and not native['timeout']
    if native_ok and not reject:
        execution = capture([str(binary)],output,name,'native',repo,10)
        row['native_execute'] = execution
        if case.get('native') == 'sigabrt':
            native_ok = (execution['exit_code']==-signal.SIGABRT and not execution['timeout']
                         and case['native_abort_marker'] in execution['stderr'])
        else:
            native_ok = (execution['exit_code']==0 and not execution['timeout']
                         and execution['stdout']==case.get('stdout','') and execution['stderr']==case.get('stderr',''))
    row['native_verified'] = native_ok
    if native_only:
        row['status'] = 'native_matched' if native_ok else 'check_failed'
        return row
    parsed = invoke([str(driver),f'--runtime={runtime}','--cabs-json',str(source)],tree,output/(name+'.parser.stderr'),repo,30)
    parsed['stderr'] = (output/(name+'.parser.stderr')).read_text()
    row['parser'] = parsed
    if parsed['exit_code']!=0 or parsed['timeout']:
        row['failure_stage'] = 'parser'
        return row
    if case.get('libc') and libc_args is None:
        row['failure_stage'] = 'libc_preparation'
        return row
    commands = {
        'ocaml': [str(driver),f'--runtime={runtime}'] + ([] if case.get('libc') else ['--nolibc']) + ['--exec','--mode=exhaustive','--batch',str(source)],
        'lean': [str(lean),'--batch','--runtime',str(runtime)] + (libc_args if case.get('libc') else []) + [str(tree)],
    }
    for engine, command in commands.items():
        record = capture(command,output,name,engine,repo,180 if case.get('libc') else 90)
        observation = record['stdout']+record['stderr']
        if reject:
            outcome_ok = rejected_constraint(name,engine,record)
        elif case.get('boundary'):
            outcome_ok = (record['exit_code'] in (1,2) and REFUSALS[case['boundary']] in observation
                          and re.search(r'\b(?:Defined|Undefined)\s*\{',observation) is None)
        else:
            outcome_ok = record['exit_code']==0 and defined_output(record['stdout'],0,case.get('stdout',''),case.get('stderr',''))
        record['verified'] = (outcome_ok and not record['timeout']
                              and not any(m in observation.lower() for m in CRASH_MARKERS))
        row['engines'][engine] = record
    if native_ok and all(r['verified'] for r in row['engines'].values()):
        row['status'] = ('invalid_constraint_rejected' if reject else
                         'explicit_frontend_boundary' if case.get('boundary_stage')=='frontend' else
                         'explicit_runtime_boundary' if case.get('boundary') else
                         'declaration_translation_control' if case.get('declaration_only') else 'matched_execution')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cerberus',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--native-only',action='store_true')
    args = parser.parse_args()
    repo, output = args.cerberus.resolve(),args.output.resolve()
    output.mkdir(parents=True,exist_ok=True)
    # Abort fixtures must not leave large core dumps. This does not change their signal result.
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    runtime = repo/'_build/install/default'
    driver,lean = repo/'_build/default/backend/driver/main.exe',repo/'lean_frontend/.lake/build/bin/cerberus-lean'
    artifacts = {'parser_binary':driver,'lean_binary':lean,'runtime_core':runtime/'lib/cerberus-lib/runtime/libcore/std.core'}
    before = {} if args.native_only else {name:sha(path) for name,path in artifacts.items()}
    compiler = capture(['cc','--version'],output,'compiler','version',repo,10)
    libc_args,libc_preparation = None,None
    if not args.native_only:
        libc_preparation = capture(['bash',str(repo/'scripts/libc_prep.sh'),'--jsons',str(output/'libcjson')],output,'libc','prepare',repo,180)
        paths = [Path(s) for s in libc_preparation['stdout'].splitlines() if s.strip()]
        if libc_preparation['exit_code']==0 and not libc_preparation['timeout'] and len(paths)==12 and all(p.is_file() for p in paths):
            libc_args = ['--libc',str(repo/'tests/libc/libc.core')]
            for path in paths:
                libc_args += ['--libc-tu',str(path)]
            libc_preparation['verified_inputs'] = {str(p):sha(p) for p in paths+[repo/'tests/libc/libc.core']}
    rows = {}
    for name,case in CASES.items():
        rows[name] = check_case(repo,runtime,driver,lean,output,name,case,args.native_only,libc_args)
        print(json.dumps({'case':name,'status':rows[name]['status']}),flush=True)
    after = {} if args.native_only else {name:sha(path) for name,path in artifacts.items()}
    artifacts_unchanged = bool(before) and before==after
    native_passed = all(row['native_verified'] for row in rows.values())
    passed = artifacts_unchanged and all(row['status']!='check_failed' for row in rows.values())
    result = {'passed':passed,'dual_engine_verified':passed,'artifact_hashes_verified':artifacts_unchanged,
              'native_only':args.native_only,'native_passed':native_passed,'cases':rows,'compiler':compiler,
              'parser_binary_sha256':after.get('parser_binary'),'lean_binary_sha256':after.get('lean_binary'),
              'artifacts':after,'test_script_sha256':sha(Path(__file__)),'libc_preparation':libc_preparation,
              'scope':{'matched_execution_cases':sum(r['status']=='matched_execution' for r in rows.values()),
                       'explicit_runtime_boundary_cases':sum(r['status']=='explicit_runtime_boundary' for r in rows.values()),
                       'explicit_frontend_boundary_cases':sum(r['status']=='explicit_frontend_boundary' for r in rows.values()),
                       'declaration_only_cases':sum(r['status']=='declaration_translation_control' for r in rows.values()),
                       'invalid_constraint_cases':sum(r['status']=='invalid_constraint_rejected' for r in rows.values()),
                       'references':['https://gcc.gnu.org/onlinedocs/gcc/Object-Size-Checking.html',
                                     'https://sourceware.org/glibc/manual/latest/html_node/Source-Fortification.html'],
                       'limitations':['Native SIGABRT witnesses are compared with explicit refusal, not reproduced abort behavior',
                                      'Percent-n writes and read-only format mapping remain explicitly unsupported',
                                      'FILE and native AMD64 va_list wrappers are translated but not executed',
                                      'Fortified FILE builtin registration requires a visible file-scope FILE typedef',
                                      'Finite common-format corpus; not complete printf formatting, locale, or I/O equivalence'],
                       'preservation_theorem':False}}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':passed,'native_passed':native_passed,'cases':len(rows),
                      'failures':[n for n,r in rows.items() if r['status']=='check_failed']}),flush=True)
    return 0 if (native_passed if args.native_only else passed) else 1


if __name__=='__main__':
    sys.exit(main())
