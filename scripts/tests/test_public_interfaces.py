"""Exercise help/completion without launcher startup, privilege, or network actions."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]
COMPLETION=ROOT/'scripts/lib/tab_complete.cstk'
CLASSES={'O':'osint','P':'payload','X':'postx','E':'etc','D':'defense'}

class PublicInterfaceTests(unittest.TestCase):
    def complete(self,shell,words):
        if shell=='zsh' and not shutil.which('zsh'): self.skipTest('Zsh not installed')
        if shell=='bash':
            script='source "$COMPLETION"; COMP_WORDS=("$@"); COMP_CWORD=$(($#-1)); _cstk_bash_completion; printf "%s\\n" "${COMPREPLY[@]}"'
        else:
            script='compdef() { :; }; source "$COMPLETION"; compadd() { shift; printf "%s\\n" "$@"; }; words=("$@"); CURRENT=$#; _cstk_zsh_completion'
        proc=subprocess.run([shell,'-f' if shell=='zsh' else '--noprofile','-c',script,'fixture',*words],env=dict(os.environ,COMPLETION=str(COMPLETION)),capture_output=True,text=True,check=True)
        return set(filter(None,proc.stdout.splitlines()))
    def test_both_shells_complete_all_documented_combined_class_tools(self):
        text=(ROOT/'cstk.sh').read_text()
        for shell in ('bash','zsh'):
            for letter in CLASSES:
                keys=set(re.findall(r'^#//'+letter+r'.*?\s([a-z]) \| --',text,re.M))
                self.assertTrue(keys,letter)
                self.assertEqual(self.complete(shell,['cstk','-'+letter]),{'-'+letter+key for key in keys})
    def test_both_shells_complete_all_documented_long_tools(self):
        text=(ROOT/'cstk.sh').read_text()
        for shell in ('bash','zsh'):
            for letter,name in CLASSES.items():
                expected=set(re.findall(r'^#//'+letter+r'.*?\s[a-z] \| (--[a-z-]+)',text,re.M))
                self.assertEqual(self.complete(shell,['cstk','--'+name,'']),expected)
    def test_web_check_actions_and_control_alias(self):
        for shell in ('bash','zsh'):
            for prefix in (['cstk','-Dc'],['cstk','--defense','--web-check']):
                self.assertEqual(self.complete(shell,prefix+['']),{'start','stop','status'})
            self.assertEqual(self.complete(shell,['cstk','--control','']),{'engagements'})
    def test_global_aliases_and_engagement_prefixed_completion(self):
        for shell in ('bash','zsh'):
            options=self.complete(shell,['cstk',''])
            self.assertTrue({'-h','-H','-v','-V','--refresh-hashes','--use','--report'}<=options)
            self.assertEqual(self.complete(shell,['cstk','--use','client','-D']),{'-Dl','-Dw','-Dc','-Dp'})
            self.assertEqual(self.complete(shell,['cstk','--use','client','--defense','']),{'--linux-audit','--web-tls','--web-check','--project'})
    def test_help_output_matches_current_public_routes(self):
        source=(ROOT/'cstk.sh').read_text()
        block=source[source.index('if [[ $# -eq 1 ]]; then',source.index('######################### MAIN SCRIPT')):source.index('if [[ $# -eq 1 && "$1" == "--refresh-hashes"')]
        block=block.replace('${BASH_SOURCE[0]}','$HELP_SOURCE')
        for option in ('-h','-H','--help'):
            proc=subprocess.run(['bash','-c',block,'fixture',option],env=dict(os.environ,HELP_SOURCE=str(ROOT/'cstk.sh')),capture_output=True,text=True,check=True)
            self.assertIn('-Dc',proc.stdout)
            self.assertIn('-Dp',proc.stdout)
            self.assertNotIn('local API',proc.stdout)
        manual=(ROOT/'scripts/lib/cstk.1').read_text().replace('\\-','-')
        for option in ('--web-check','--project','--refresh-hashes','--engagements','--use','--report','--cnc'):
            self.assertIn(option,manual)
        self.assertNotIn('inventory|tcp-connect',manual)
    def test_all_defense_frames_have_working_option_examples(self):
        script='source "$FRAME"; defense_web_tls_frame; defense_linux_audit_frame; defense_web_check_frame; defense_project_frame'
        proc=subprocess.run(['bash','-c',script],env=dict(os.environ,FRAME=str(ROOT/'scripts/lib/arguments_frame')),capture_output=True,text=True,check=True)
        for short,long in (('-Dw','--web-tls'),('-Dl','--linux-audit'),('-Dc','--web-check'),('-Dp','--project')):
            self.assertIn(short,proc.stdout);self.assertIn(long,proc.stdout)
    def test_readme_describes_integrated_control_and_current_audit_fallback(self):
        readme=(ROOT/'README.md').read_text()
        self.assertIn('compatibility alias',readme)
        self.assertIn('Lynis',readme)
        self.assertIn('sudo cstk --refresh-hashes',readme)
        for stale in ('There is no public integrity-refresh command','has no Linux audit executable','through the local control API'):
            self.assertNotIn(stale,readme)

    def test_manual_renders(self):
        if not shutil.which('groff'): self.skipTest('groff not installed')
        proc=subprocess.run(['groff','-Tutf8','-man',str(ROOT/'scripts/lib/cstk.1')],capture_output=True,text=True,check=True)
        self.assertEqual(proc.stderr,'')
        self.assertIn('DEFENSE CLASS',proc.stdout)
