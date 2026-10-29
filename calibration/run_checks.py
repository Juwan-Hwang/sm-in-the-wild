"""Run selected existing assertions; --million includes the expensive SM4 anchor."""
from pathlib import Path
import runpy,sys,time
passed=0
for file in sorted((Path(__file__).parent/'tests').glob('test_*.py')):
    data=runpy.run_path(str(file))
    for name in sorted(n for n in data if n.startswith('test_')):
        if name=='test_example2_million_iterations' and '--million' not in sys.argv:
            print('NOT RUN',name,'(opt in with --million)');continue
        start=time.monotonic();data[name]();passed+=1
        print('PASS',file.name,name,f'{time.monotonic()-start:.3f}s')
print(passed,'assertions passed')
