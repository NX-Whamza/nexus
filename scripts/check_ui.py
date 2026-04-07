from pathlib import Path
p = Path(__file__).resolve().parents[1] / 'vm_deployment' / 'nexus.html'
s = p.read_text(encoding='utf-8')
print('len', len(s))
print('ftthModal', 'ftthModal' in s)
print('ftthQuickBtn', 'ftthQuickBtn' in s)
print('ftthGenerate', 'ftthGenerate' in s)
print('generateFtthBng', 'generateFtthBng' in s)
print('preview snippet:\n', s[s.find('ftthModal')-60:s.find('ftthModal')+60])
