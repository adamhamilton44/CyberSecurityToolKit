"""Interactive completion of an existing draft; no activation or tool execution."""
import copy
import hashlib
import os
from pathlib import Path
import stat


class Later(Exception):
    pass


def document_sha256(filename):
    """Fingerprint a bounded regular document without executing or uploading it."""
    fd = os.open(Path(filename).expanduser(), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 64 * 1024 * 1024:
            raise ValueError('Use a regular document up to 64 MiB, or enter its SHA-256 manually.')
        digest = hashlib.sha256()
        while block := os.read(fd, 65536):
            digest.update(block)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('The document changed while its fingerprint was calculated. Try again.')
        return digest.hexdigest()
    finally:
        os.close(fd)


def resume_engagement(policy, root, identifier, input_fn=None):
    read = input_fn or input
    directory = policy.resolve_engagement(root, identifier)
    if policy.load_state(directory) not in ('draft', 'ready', 'paused'):
        raise policy.EngagementError('Pause this engagement before editing its answers.')
    current, revision, digest = policy.load_current_config(directory)
    print(f"Finish missing answers: {policy.terminal_safe(current['name'])}")
    print('Saved answers are kept. Type :later at any question to stop.')
    print('Completed answers are saved as draft revisions; this does not activate testing.')

    def ask(label, default=None):
        while True:
            suffix = f' [{policy.terminal_safe(default)}]' if default else ''
            value = read(label + suffix + ': ').strip()
            if value == ':later':
                raise Later
            if value or default:
                return value or default
            print('Enter an answer, or type :later to finish another time.')

    def confirm(label):
        while True:
            value = ask(label + ' (yes/no)', 'no').lower()
            if value in ('yes','y'): return True
            if value in ('no','n'): return False
            print('Please answer yes or no.')

    def save(candidate):
        nonlocal current, revision, digest
        if candidate == current:
            return
        _, latest_revision, latest_digest = policy.load_current_config(directory)
        if (latest_revision, latest_digest) != (revision, digest):
            raise policy.EngagementError('Another session changed this engagement. Reopen it before continuing.')
        candidate.setdefault('revision', {})['change_reason'] = 'Completed missing answers in the guided questionnaire'
        policy.revise_engagement(root, identifier, candidate)
        current, revision, digest = policy.load_current_config(directory)
        print(f'Saved draft revision {revision}.')

    def update(section, key, value):
        candidate = copy.deepcopy(current)
        candidate[section][key] = value
        save(candidate)

    try:
        if current['questionnaire']['sha256'] != policy.questionnaire_fingerprint()['sha256']:
            print('The questionnaire changed since these answers were recorded. Review its current questions first:')
            for line in policy.safe_read(policy.QUESTIONNAIRE_PATH).decode('utf-8').splitlines():
                if line.startswith('* **'): print(policy.terminal_safe(line))
            if not confirm('Have you reviewed the current questions and checked the saved answers?'):
                raise Later
            candidate = copy.deepcopy(current)
            candidate['questionnaire'] = policy.questionnaire_fingerprint()
            save(candidate)
        evidence = current['authorization']['evidence']
        if not evidence.get('location') or not evidence.get('sha256'):
            print('\nWritten permission: name the document or approval record that permits this test.')
            print('Its SHA-256 is a fingerprint identifying that exact document, not a password.')
            if not evidence.get('location'):
                value = ask('Where is that approval saved? Enter a local file path or a document reference')
                candidate = copy.deepcopy(current)
                candidate['authorization']['evidence']['location'] = value
                save(candidate)
            if not current['authorization']['evidence'].get('sha256'):
                location = current['authorization']['evidence']['location']
                fingerprint = None
                if Path(location).expanduser().is_file() and not Path(location).expanduser().is_symlink():
                    if confirm('Calculate the fingerprint from this local document? The document stays on this computer'):
                        try: fingerprint = document_sha256(location)
                        except (OSError,ValueError) as error: print(str(error))
                while fingerprint is None:
                    value = ask('Document SHA-256 (64 hexadecimal characters; use sha256sum on the document)').lower()
                    if policy.SHA256_RE.fullmatch(value): fingerprint = value
                    else: print('A SHA-256 must contain exactly 64 hexadecimal characters (0-9, a-f).')
                candidate = copy.deepcopy(current)
                candidate['authorization']['evidence']['sha256'] = fingerprint
                save(candidate)

        auth = current['authorization']
        if auth['third_party_consent'] == 'required_pending' or (
            current['environment']['third_party_infrastructure'] and auth['third_party_consent'] != 'confirmed'
        ):
            if confirm('Do you now have the required written permission from the hosting provider?'):
                update('authorization','third_party_consent','confirmed')
            else: print('Provider permission remains pending. Testing will stay blocked.')

        for role, label in [('primary','main client contact'),('emergency','emergency stop contact'),
                            ('breach_escalation','contact to notify about a real security incident')]:
            if not any(c['role'] == role for c in current['contacts']):
                contact = {'role':role,'name':ask(f'Who is the {label}? Name and job title'),
                           'method':ask('How can they be reached? Phone number or approved contact method')}
                candidate = copy.deepcopy(current)
                candidate['contacts'].append(contact)
                save(candidate)

        if not current['scope']['include']:
            print('\nWhich targets are approved? Examples: 192.0.2.10, 192.0.2.0/28, app.example.test, https://app.example.test/')
            while True:
                value = ask('Approved targets, separated by commas')
                targets = []
                for item in (part.strip() for part in value.split(',')):
                    if '://' in item: kind = 'url'
                    elif '/' in item: kind = 'cidr'
                    else:
                        try: policy.ipaddress.ip_address(item); kind = 'ip'
                        except ValueError: kind = 'dns'
                    targets.append({'type':kind,'value':item,'note':None})
                errors = [policy.target_error(t,'Target') for t in targets]
                if not any(errors): break
                print('; '.join(e for e in errors if e))
            update('scope','include',targets)

        classified = set().union(*(set(values) for values in current['actions'].values()))
        for action in policy.ACTIONS:
            if action not in classified:
                while True:
                    answer = ask(f"Permission: {policy.ACTION_LABELS.get(action, action)}. 1 = allowed, 2 = ask before each run, 3 = forbidden",'3')
                    if answer in ('1','2','3'): break
                candidate = copy.deepcopy(current)
                candidate['actions'][{'1':'allow','2':'confirm_each_run','3':'deny'}[answer]].append(action)
                try: save(candidate)
                except policy.EngagementError as error:
                    print(str(error)); raise Later

        if current['technical_policy']['credentialed_testing'] and not current['technical_policy']['credential_references']:
            print('Record account identifiers only. Do not enter a password, token or private key.')
            reference = {'account_identifier':ask('Approved test account name'),
                         'role':ask('What access or role does that account have?'),
                         'secret_source':ask('Where is its secret stored? Enter an approved vault reference, not the secret')}
            update('technical_policy','credential_references',[reference])

        if not current['constraints']['testing_windows']:
            while True:
                window = {'days':[v.strip().lower() for v in ask('Which days can testing run? Use mon,tue,wed,thu,fri,sat,sun').split(',')],
                          'start':ask('Daily start time, using 24-hour HH:MM'),
                          'end':ask('Daily stop time, using 24-hour HH:MM'),
                          'timezone':ask('Time zone for these hours',current['authorization']['timezone'])}
                try: update('constraints','testing_windows',[window]); break
                except policy.EngagementError as error: print(str(error))
        if not current['constraints']['stop_conditions']:
            update('constraints','stop_conditions',[ask('What must make testing stop immediately?')])
        if not current['constraints']['allowed_source_ips'] and not current['traffic_identification']['source_ip_not_applicable_reason']:
            while True:
                value = ask('Testing source IPs/networks (comma-separated), or type not-applicable')
                if value.lower() == 'not-applicable':
                    update('traffic_identification','source_ip_not_applicable_reason',ask('Why do source IP restrictions not apply here?'))
                    break
                values = [v.strip() for v in value.split(',')]
                try:
                    for address in values: policy.ipaddress.ip_network(address,strict=False)
                    update('constraints','allowed_source_ips',values); break
                except ValueError: print('Use IP addresses or networks, for example 192.0.2.10 or 192.0.2.0/28.')
    except (Later,EOFError,KeyboardInterrupt):
        print('\nStopped. Completed answers are saved; use Finish missing answers to continue.')
    remaining = policy.validation_errors(current,activation=True)
    if remaining:
        print('\nStill needed before this engagement can be marked ready:')
        for error in remaining: print('- '+policy.terminal_safe(error))
        print('Use Finish missing answers again when the remaining details are available.')
    else:
        print('\nAll required answers are saved. Current state: '+policy.load_state(directory)+'.')
        print('Review the answers, then mark it ready. Activation remains a separate step.')
    return not remaining
