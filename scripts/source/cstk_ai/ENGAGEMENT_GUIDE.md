# Engagement setup: start here

An engagement is one client's approved assessment. Its saved scope says what
can be tested, when, from where, and using which techniques. Creating a draft
never starts a tool or grants permission to test.

## The normal workflow

Run `sudo cstk`, then **G**. The engagement screen groups setup first, followed
by OSINT, Payloads, Post Exploit, ETC and Defense in the main menu's order.
Numbers stay together and management letters appear beneath them.

1. **Create/resume:** start a new questionnaire. Single choices use numbered,
   readable labels; multiple choices accept numbers such as `1,3`. Press Enter
   for a marked default. You never need to type machine names with underscores.
2. **Select:** choose an already active engagement from a numbered list.
3. **Review/activate:** choose your saved draft from a list. Review written
   permission, dates, included/excluded targets and permitted techniques. Missing
   requirements are listed. Type `REVIEW`, then `ACTIVATE`, only when correct.
4. **Notes/reports:** choose an engagement and set up its separate encrypted
   notebook. Add notes, review evidence/findings and generate draft/final reports.
5. **Offline forms:** save a blank JSON form, edit it outside CSTK, then import it.

The practical first-time order is **1 → 3 → 2 → 4**. Then use the assessment
options. A client authorization that has expired cannot be activated. If review
finds errors, edit a separate JSON copy and use **R** to create a new revision.
Never change an existing `scope/revisions/` file directly.

Saving displays **SAVED**, the engagement name, its full ID, its short name
(also called a slug), its folder and the scope JSON path. The menus use numbered
lists so you do not need to remember or type any of those identifiers.

## Save and finish later

Answers are saved after every response in the invoking user's private folder:

```text
~/.local/share/cstk/Engagements/.drafts/
```

Type `:save` at a question, or press Ctrl+C, to pause. Reopen **G → 1 → Resume**,
or run `sudo cstk --engagement-resume`, and select the saved questionnaire.
CSTK restores earlier answers and asks the remaining questions. A completed
questionnaire also retains a `.form.json` file. If final validation fails, CSTK
shows the file to correct instead of claiming that an engagement was created.
An interrupted last keystroke or a failed disk write cannot be recovered; only
answers whose writes completed are guaranteed saved. No older screen output is
needed to resume a successfully checkpointed questionnaire.

These files are permission metadata in **plaintext**, stored in owner-only
folders (0700) and files (0600). Do not enter passwords, tokens, private keys or
sensitive findings. Encrypted notes are a separate feature. Backups can retain
copies of questionnaire metadata; updates and uninstall preserve Engagements.

## Fill out a JSON form offline

```bash
sudo cstk --engagement-template
```

CSTK prints the private file's full path. Open that file in a text editor, follow
its `_help` section, replace empty fields, and save whenever you wish. You can
exit CSTK while editing it. JSON requires double quotes and commas between
fields; it does not allow comments. The `_help` section supplies instructions,
valid options and fictional target examples; it is removed from the saved scope.
All testing actions initially remain denied. Move only explicitly authorized
actions into `allow` or `confirm_each_run`, without listing an action twice.

Import the edited form with **G → 5**, or:

```bash
sudo cstk --engagement-import /absolute/path/to/your-form.json
```

You can keep the exported form in `.drafts` or import another file you own. Use
CSTK to import it; merely dropping a JSON file in Engagements does not activate
it. Import keeps a private editable copy before validation and creates an
immutable **draft** only. Invalid JSON leaves the original file untouched;
structurally invalid forms are retained for correction. Existing engagement
records are not replaced. Export never overwrites an existing form.

## Useful question examples

- Authorization timestamps need the UTC offset, for example
  `2026-10-29T09:00:00-05:00`. Replace examples with your approved dates.
- Time zones use names such as `UTC` or `America/Chicago`. Daily testing windows
  use 24-hour times such as `08:00` and `18:30`.
- An IP address identifies one host; CIDR identifies a range, such as
  `192.0.2.0/28`. Those are fictional documentation addresses, not test targets.
- For guarded hostname HTTP requests, the hostname **and** its resolved IPs must
  be included under the `both_required` DNS policy. Explicit exclusions win.
- Contact methods and permission evidence identify the approved records. They
  are not a place to paste credentials. Activation requires the authorization
  evidence reference/location and its SHA-256 as well as valid dates.
- Anything omitted from allowed or approval-only actions stays denied.
  Conflicting technique selections resolve toward denial; the wizard does not
  silently grant a technique just to make validation pass.

## Tool availability

**6 OSINT** runs the existing guarded TCP check; **10 Defense** runs the guarded
HTTP request. Both retain current target, source-IP, DNS, redirect, rate, expiry
and testing-window checks and require encrypted reporting capture. **9 ETC**
opens the optional AI Analyst; sending information to a provider remains an
operator-controlled action.

Payload and Post Exploit entries explain that those tools do not yet have
scope-enforcing adapters. They start no tool. Reordering menus never makes
unsupported tools safe for an engagement or changes the approved scope.
Legacy C/U/B/N/W aliases remain accepted. Main-menu X still returns; advanced
inspect, validation, revision, pause and state changes remain under letters.
