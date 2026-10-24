#!/usr/bin/env python3
"""Native/OCaml/Lean checks for the implicit static const __func__ array."""
import argparse
import json
from pathlib import Path
import re

from exercise_imported_c import invoke, sha


CASES = {
    'main-name-array': 'int main(void) { return sizeof(__func__)!=5 || __func__[0]!=\'m\' || __func__[1]!=\'a\' || __func__[2]!=\'i\' || __func__[3]!=\'n\' || __func__[4]!=0; }',
    'name-bytes-size-type': '''static int alpha_Beta_123(void) {
      const char *want="alpha_Beta_123"; unsigned i;
      _Static_assert(sizeof(__func__)==15,"complete array");
      _Static_assert(_Generic(&__func__,const char (*)[15]:1,default:0),"const array type");
      for(i=0;i<sizeof(__func__);i++) if(__func__[i]!=want[i]) return 1;
      return _Alignof(__typeof__(__func__))!=_Alignof(char);
    } int main(void) { return alpha_Beta_123(); }''',
    'survives-return': '''const char *saved(void) { return __func__; }
      int main(void) { const char *p=saved(); int noise[64]; noise[0]=19;
      return p[0]!='s' || p[1]!='a' || p[2]!='v' || p[3]!='e' || p[4]!='d' || p[5]!=0 || noise[0]!=19; }''',
    'same-object-per-call': '''const char *identity(void) { return __func__; }
      int main(void) { const char *a=identity(),*b=identity(); return a!=b || a[0]!='i'; }''',
    'different-functions': '''const char *left(void) { return __func__; }
      const char *right(void) { return __func__; }
      int main(void) { const char *a=left(),*b=right(); return a==b || a[0]!='l' || b[0]!='r' || a[4]!=0 || b[5]!=0; }''',
    'recursive-identity': '''const char *first; int recurse(int n) {
      if(n==5) first=__func__; if(first!=__func__) return 1;
      if(n) return recurse(n-1); return __func__[0]!='r' || __func__[7]!=0;
    } int main(void) { return recurse(5); }''',
    'nested-block-lookup': '''int nested(void) { const char *p=__func__;
      { { if(p!=__func__ || sizeof(__func__)!=7) return 1; } }
      return __func__[6]!=0;
    } int main(void) { return nested(); }''',
    'static-address-initializer': '''const char *capture(void) {
      static const char *p=__func__; return p;
    } int main(void) { const char *p=capture(); return p[0]!='c' || p[7]!=0 || p!=capture(); }''',
    'name-with-linker-alias': '''const char *original(void) __asm__("other_symbol");
      const char *original(void) { return __func__; }
      int main(void) { const char *p=original(); return p[0]!='o' || p[1]!='r' || p[8]!=0; }''',
    'gnu-inline-original-name': '''extern inline __attribute__((gnu_inline)) const char *original(void) { return __func__; }
      const char *original(void) { return __func__; }
      int main(void) { const char *p=original(); return p[0]!='o' || p[8]!=0; }''',
    'unevaluated-size-effects': '''int calls; int test(void) {
      unsigned long n=sizeof((calls++,__func__));
      return calls!=0 || n!=sizeof(const char*);
    } int main(void) { return test(); }''',
    'decay-and-address': '''int test(void) { const char (*p)[5]=&__func__;
      const char *q=__func__; return &(*p)[0]!=q || q[4]!=0;
    } int main(void) { return test(); }''',
}
INVALID = {
    'write-const-element': "int main(void) { __func__[0]='x'; return 0; }",
    'assign-array': 'int main(void) { __func__="x"; return 0; }',
    'discard-const': 'int main(void) { char *p=__func__; return p[0]; }',
    'ordinary-const-array-write': 'int main(void) { const char a[2]="a"; a[0]=0; return 0; }',
    'ordinary-const-array-discard': 'int main(void) { const char a[2]="a"; char *p=a; return p[0]; }',
}
CASES.update({
    'ordinary-static-array-type': 'int main(void) { static const char a[2]="a"; _Static_assert(_Generic(&a,const char (*)[2]:1,default:0),"type"); return a[0]!=97; }',
    'mutable-array-control': 'int main(void) { char a[2]="a"; char *p=a; p[0]=98; return a[0]!=98; }',
})
CRASH = ('panic', 'internal error', 'uncaught exception', 'segmentation fault', 'stack overflow')


def defined_zero(stdout):
    expected = 'Defined {value: "Specified(0)", stdout: "", stderr: "", blocked: "false"}'
    lines = stdout.strip().splitlines()
    return lines == [expected] or (bool(lines) and len(lines)%2 == 0 and all(
        lines[i] == f'EXECUTION {i//2}:' and lines[i+1] == expected
        for i in range(0,len(lines),2)))


def diagnostics_ok(engine, stderr):
    return stderr == '' or (engine == 'ocaml' and re.fullmatch(
        r'Time spent: [0-9]+\.[0-9]{6} seconds\n', stderr) is not None)


def capture(argv, out, name, lane, repo):
    stdout, stderr = out/f'{name}.{lane}.stdout', out/f'{name}.{lane}.stderr'
    result = invoke(argv,stdout,stderr,repo)
    result.update(stdout=stdout.read_text(errors='replace'),stderr=stderr.read_text(errors='replace'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cerberus',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--native-only',action='store_true')
    args = parser.parse_args()
    repo,out = args.cerberus.resolve(),args.output.resolve()
    out.mkdir(parents=True,exist_ok=True)
    runtime = repo/'_build/install/default'
    driver,lean = repo/'_build/default/backend/driver/main.exe',repo/'lean_frontend/.lake/build/bin/cerberus-lean'
    before = {'parser_binary_sha256':sha(driver),'lean_binary_sha256':sha(lean)}
    rows = []
    for name,text in list(CASES.items())+list(INVALID.items()):
        invalid = name in INVALID
        source,tree,binary = out/f'{name}.c',out/f'{name}.json',out/f'{name}.native'
        source.write_text(text+'\n')
        row = {'case':name,'source_text':text,'source_sha256':sha(source),'invalid':invalid,'passed':False,'engines':{}}
        native_ok = True
        native = {}
        for optimization in ['-O0','-O2']:
            compiled = capture(['cc','-std=gnu23','-pedantic-errors',optimization,str(source),'-o',str(binary)],out,name,'cc'+optimization,repo)
            entry = {'compile':compiled}
            if invalid:
                good = compiled['exit_code']==1 and not compiled['timeout'] and 'error:' in compiled['stderr'] and source.name in compiled['stderr']
            else:
                good = compiled['exit_code']==0 and not compiled['timeout']
                if good:
                    execution = capture([str(binary)],out,name,'native'+optimization,repo)
                    entry['execution'] = execution
                    good = execution['exit_code']==0 and not execution['timeout'] and execution['stdout']=='' and execution['stderr']==''
            entry['verified']=good
            native[optimization]=entry
            native_ok = native_ok and good
        row['native']=native
        if not args.native_only:
            parsed = invoke([str(driver),f'--runtime={runtime}','--cabs-json',str(source)],tree,out/f'{name}.parser.stderr',repo)
            row['parser']=parsed
            if parsed['exit_code']==0 and not parsed['timeout']:
                json.loads(tree.read_text())
                commands = {
                    'ocaml':[str(driver),f'--runtime={runtime}','--nolibc','--exec','--mode=exhaustive','--batch',str(source)],
                    'lean':[str(lean),'--batch','--runtime',str(runtime),str(tree)],
                }
                for engine,command in commands.items():
                    result = capture(command,out,name,engine,repo)
                    all_output = result['stdout']+result['stderr']
                    if invalid:
                        good = (result['exit_code'] in (1,2) and 'constraint violation' in all_output.lower()) if engine=='ocaml' else (result['exit_code']==1 and 'AIL_TYPING ConstraintViolation' in result['stdout'])
                        good = good and re.search(r'\b(?:Defined|Undefined)\s*\{',all_output) is None and source.name in all_output
                    else:
                        good = result['exit_code']==0 and defined_zero(result['stdout']) and diagnostics_ok(engine,result['stderr'])
                    result['verified'] = good and not result['timeout'] and not any(x in all_output.lower() for x in CRASH)
                    row['engines'][engine]=result
            row['passed'] = native_ok and len(row['engines'])==2 and all(x['verified'] for x in row['engines'].values())
        else:
            row['passed']=native_ok
        rows.append(row)
        print(json.dumps({'case':name,'passed':row['passed']}),flush=True)
    after = {'parser_binary_sha256':sha(driver),'lean_binary_sha256':sha(lean)}
    passed = before==after and all(x['passed'] for x in rows)
    report = dict(after,passed=passed,artifact_hashes_verified=before==after,
                  dual_engine_verified=passed and not args.native_only,native_only=args.native_only,
                  test_script_sha256=sha(Path(__file__)),cases=rows,
                  scope={'executions':len(CASES),'invalid_constraints':len(INVALID),
                         'reference':'https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf#page=78',
                         'limits':['ASCII identifier profile; extended identifier encodings are not certified',
                                   'Reserved-name redeclarations are not ISO-defined behavior and are not part of this conformance corpus',
                                   'Finite checks, not whole-program preservation']})
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':passed,'cases':len(rows),'failures':[x['case'] for x in rows if not x['passed']]}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
