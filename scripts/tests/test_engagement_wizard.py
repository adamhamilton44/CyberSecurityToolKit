"""Guided completion uses temporary draft records, never real engagements."""
import copy
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'source/cstk_ai'
sys.path.insert(0,str(SOURCE))
import cstk_engagement as policy
import engagement_wizard as wizard
import test_engagement_manager as fixtures


class WizardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cstk-guided-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'Engagements'

    def create(self, config=None):
        config = copy.deepcopy(config or fixtures.valid_config())
        self.directory = policy.create_engagement(self.root,config)
        return policy.load_current_config(self.directory)[0]

    def run_wizard(self, answers):
        prompts=[]
        iterator=iter(answers)
        def read(label):
            prompts.append(label)
            try: return next(iterator)
            except StopIteration: raise AssertionError('Unexpected question: '+label)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            complete=wizard.resume_engagement(policy,self.root,'example-assessment',read)
        return complete,prompts,output.getvalue()

    def test_only_missing_evidence_is_asked_and_other_answers_are_preserved(self):
        config=fixtures.valid_config();config['authorization']['evidence']={'location':None,'sha256':None}
        before=self.create(config)
        # Locate the engine's immutable revision rather than relying on its filename.
        original=policy.revision_path(self.directory,1)
        original_bytes=original.read_bytes()
        complete,prompts,_=self.run_wizard(['approval://signed-roe','invalid','b'*64])
        after,revision,_=policy.load_current_config(self.directory)
        self.assertTrue(complete)
        self.assertEqual(len(prompts),3)
        self.assertEqual(original.read_bytes(),original_bytes)
        for key in before:
            if key not in ('authorization','revision','questionnaire'):
                self.assertEqual(before[key],after[key],key)
        self.assertEqual(after['authorization']['evidence'],{'location':'approval://signed-roe','sha256':'b'*64})
        self.assertEqual(policy.load_state(self.directory),'draft')
        self.assertGreater(revision,1)

    def test_stop_then_resume_asks_only_remaining_fingerprint(self):
        config=fixtures.valid_config();config['authorization']['evidence']={'location':None,'sha256':None}
        self.create(config)
        complete,_,_=self.run_wizard(['approval://saved',':later'])
        self.assertFalse(complete)
        self.assertEqual(policy.load_current_config(self.directory)[0]['authorization']['evidence']['location'],'approval://saved')
        complete,prompts,_=self.run_wizard(['a'*64])
        self.assertTrue(complete)
        self.assertEqual(len(prompts),1)
        self.assertIn('SHA-256',prompts[0])

    def test_complete_ready_record_is_not_changed_or_demoted(self):
        self.create()
        policy.transition(self.root,'example-assessment','ready')
        before=policy.load_current_config(self.directory)
        complete,prompts,_=self.run_wizard([])
        self.assertTrue(complete)
        self.assertEqual(prompts,[])
        self.assertEqual(policy.load_current_config(self.directory),before)
        self.assertEqual(policy.load_state(self.directory),'ready')

    def test_active_record_cannot_be_edited(self):
        self.create()
        policy.transition(self.root,'example-assessment','ready')
        policy.transition(self.root,'example-assessment','active')
        with self.assertRaises(policy.EngagementError): self.run_wizard([])

    def test_missing_contacts_targets_and_action_are_completed(self):
        config=fixtures.valid_config()
        config['contacts']=[c for c in config['contacts'] if c['role']=='technical']
        config['scope']['include']=[]
        config['actions']['allow'].remove('recon.passive')
        self.create(config)
        complete,_,_=self.run_wizard(['Main contact','phone one','Stop contact','phone two',
            'Incident contact','phone three','192.0.2.10,https://app.example.test/','3'])
        self.assertTrue(complete)
        saved=policy.load_current_config(self.directory)[0]
        self.assertIn('recon.passive',saved['actions']['deny'])
        self.assertEqual(policy.load_state(self.directory),'draft')

    def test_local_document_is_fingerprinted_without_manual_digest(self):
        document=Path(self.temp.name)/'approval.pdf';document.write_bytes(b'fictional approval fixture')
        config=fixtures.valid_config();config['authorization']['evidence']={'location':str(document),'sha256':None}
        self.create(config)
        complete,prompts,_=self.run_wizard(['yes'])
        self.assertTrue(complete)
        self.assertEqual(len(prompts),1)
        self.assertEqual(policy.load_current_config(self.directory)[0]['authorization']['evidence']['sha256'],hashlib.sha256(document.read_bytes()).hexdigest())
        with patch.dict('os.environ',{'HOME':str(Path(self.temp.name))}):
            self.assertEqual(wizard.document_sha256('~/approval.pdf'),hashlib.sha256(document.read_bytes()).hexdigest())
        link=document.with_suffix('.link');link.symlink_to(document)
        with self.assertRaises(OSError): wizard.document_sha256(link)

    def test_conflicting_revision_is_not_overwritten(self):
        config=fixtures.valid_config();config['authorization']['evidence']={'location':None,'sha256':None}
        self.create(config)
        def changed(_):
            updated=copy.deepcopy(policy.load_current_config(self.directory)[0]);updated['notes']='another operator saved this'
            policy.revise_engagement(self.root,'example-assessment',updated)
            return 'approval://must-not-overwrite'
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(policy.EngagementError):
            wizard.resume_engagement(policy,self.root,'example-assessment',changed)
        saved=policy.load_current_config(self.directory)[0]
        self.assertEqual(saved['notes'],'another operator saved this')
        self.assertIsNone(saved['authorization']['evidence']['location'])

    def test_remaining_permission_account_and_schedule_groups(self):
        config=fixtures.valid_config()
        config['authorization']['third_party_consent']='required_pending'
        config['technical_policy']['credentialed_testing']=True
        config['technical_policy']['credential_references']=[]
        config['constraints']['testing_windows']=[]
        config['constraints']['stop_conditions']=[]
        config['constraints']['allowed_source_ips']=[]
        config['traffic_identification']['source_ip_not_applicable_reason']=None
        self.create(config)
        complete,_,_=self.run_wizard(['yes','fixture-account','reader','vault://test-account',
            'mon,tue','25:00','18:00','UTC','mon,tue','09:00','18:00','UTC',
            'Stop if availability is affected','192.0.2.1'])
        self.assertTrue(complete)
        saved=policy.load_current_config(self.directory)[0]
        self.assertEqual(saved['constraints']['testing_windows'][0]['start'],'09:00')
        self.assertEqual(saved['technical_policy']['credential_references'][0]['secret_source'],'vault://test-account')
        self.assertEqual(policy.load_state(self.directory),'draft')

    def test_changed_questionnaire_requires_explicit_review(self):
        self.create()
        changed=Path(self.temp.name)/'changed-questions.md'
        changed.write_bytes(policy.safe_read(policy.QUESTIONNAIRE_PATH)+b'\nClarified question wording fixture.\n')
        with patch.object(policy,'QUESTIONNAIRE_PATH',changed):
            before=policy.load_current_config(self.directory)
            complete,_,_=self.run_wizard(['no'])
            self.assertFalse(complete)
            self.assertEqual(policy.load_current_config(self.directory),before)
            complete,_,_=self.run_wizard(['yes'])
            self.assertTrue(complete)
            self.assertEqual(policy.load_current_config(self.directory)[0]['questionnaire']['sha256'],policy.questionnaire_fingerprint()['sha256'])

    def test_g_menu_f_dispatches_resume_without_startup_or_network(self):
        source=(SOURCE.parents[2]/'cstk.sh').read_text()
        block=source[source.index('engagement_manager_menu() {'):source.index('open_engagement_reporting() {')]
        block=block.replace("[[ -t 0 && -t 1 ]] || { echo 'Engagement management needs an interactive terminal.' >&2; return 2; }", ':')
        script='clear() { :; }; show_engagement_status() { :; }; run_engagement_helper() { if [[ $1 == pick ]]; then echo testing-test; else echo "helper:$*"; fi; };\n'+block+'\nengagement_manager_menu'
        result=subprocess.run(['bash','-c',script],input='F\n\nX\n',capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Finish missing answers',result.stdout)
        self.assertIn('helper:finish testing-test',result.stdout)

    def test_number_and_choice_prompts_reask_invalid_values(self):
        self.assertEqual(set(policy.ACTION_LABELS),set(policy.ACTIONS))
        with patch('builtins.input',side_effect=['oops','-1','3']),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.number_prompt('Connections',integer=True,minimum=1),3)
        with patch('builtins.input',return_value='2'),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.choice('Access',('vpn','public_internet')),'public_internet')
        with patch('builtins.input',return_value='public internet'),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.choice('Access',('vpn','public_internet')),'public_internet')


if __name__=='__main__': unittest.main()
