# Sigma rules from Security Distractions

Sigma detection rules written from malware detonated in a home analysis lab, published so they
can be used and improved. Nothing else from that lab is in this repository: it holds the rules,
and only the rules.

Licensed under the [Detection Rule License (DRL) 1.1](LICENSE), the same licence SigmaHQ uses for
its rule set, so these can be dropped straight into an existing Sigma pipeline.

## The rules

| Rule | Logsource | Level | Fired in testing |
|---|---|---|---|
| [PyArmor obfuscated PyInstaller payload extraction](rules/file_event_win_pyarmor_runtime_in_pyinstaller_extraction.yml) | `file_event` | medium | yes |
| [Defender exclusion added via WMIC](rules/proc_creation_win_wmic_defender_exclusion_added.yml) | `process_creation` | high | yes |
| [Double extension executable from a user-writable path](rules/proc_creation_win_double_extension_exec_user_writable.yml) | `process_creation` | high | **no, see below** |

### PyArmor runtime inside a PyInstaller extraction

Correlates two facts in one file-creation event: PyInstaller unpacking to a `_MEI` prefixed
directory, and `pyarmor_runtime` appearing inside it. Together they mean the bundled Python
bytecode was deliberately obfuscated before packaging. That combination is common in commodity
Python malware and rare in software an organisation buys or builds.

There is no equivalent rule in SigmaHQ at the time of writing.

### Defender exclusion added via WMIC

Matches `wmic.exe` calling `MSFT_MpPreference` together with a specific exclusion property.
SigmaHQ's `proc_creation_win_wmic_namespace_defender.yml` (`51cbac1e`) covers the same ground via
the `/Namespace:\\root\Microsoft\Windows\Defender` argument; this one keys on the class name and
the exclusion property instead, so it also catches command lines that reach the class without the
`/Namespace:` form.

### Double extension executable from a user-writable path

**This rule has never fired.** It was written against a sample that ships as `composer.php.exe`,
but in the detonation the file executed under its SHA256 filename, so the condition was never met.
The logic is sound on inspection and the extension list is broader than SigmaHQ's, particularly
`.php.exe`, `.dat.exe` and `.lock.exe`. It is published as untested and should be treated that
way. SigmaHQ already has `proc_creation_win_susp_double_extension.yml` (`1cdd9a09`, stable)
covering the general case.

## Provenance

All three came from one detonation on 2026-08-17 of the sample referenced in each rule's
`references` field, observed with Sysmon and Elastic Defend telemetry. The `falsepositives`
sections are written from what was actually seen, not from imagination. The PyArmor rule will
fire on legitimately PyArmor-licensed commercial Python applications, and that is stated in the
rule rather than discovered by whoever deploys it.

## Testing them yourself

```sh
pip install sigma-cli
sigma check rules/
sigma convert -t lucene -p ecs_windows rules/
```

## Contributing

Corrections welcome, particularly false positives found in a real estate, which is the feedback
these are missing. Open an issue or a pull request.
