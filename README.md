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
| [.NET Framework utility started without arguments](rules/proc_creation_win_dotnet_framework_utility_no_arguments.yml) | `process_creation` | high | yes |
| [Outbound connection from a .NET Framework utility](rules/net_connection_win_dotnet_framework_utility_outbound.yml) | `network_connection` | medium | yes |

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

### .NET Framework utility started without arguments

Matches RegSvcs.exe, RegAsm.exe, InstallUtil.exe and both AddInProcess binaries started with a
command line consisting of nothing but the image itself. These utilities act on an assembly named
on the command line, so an empty argument list means the process is not doing the job the binary
exists for. .NET loaders use it as a hollowing container.

**SigmaHQ covers most of this already.** `proc_creation_win_regasm_no_flag_or_dll_execution.yml`
(`651f87f7`, experimental, level low) detects the same behaviour for RegAsm alone, and it was
written from Agent Tesla reporting, which is the same family this rule came from. If you already
run that rule, what this one adds is the other four binaries and a higher level, not the technique.

The debt runs the other way too. That rule matches four terminal command-line forms where the first
draft of this one matched two, and the single-quote variant here is taken directly from it.

### Outbound connection from a .NET Framework utility

Matches the same binaries opening a socket. Assembly registration is a local operation, so these
have no reason to reach the network.

SigmaHQ has `net_connection_win_regasm_network_activity.yml` (`0531e43a`, test, medium) for RegAsm,
and it **excludes RFC1918 destinations**. That exclusion is the reason this rule exists separately.
On an estate with forced proxy egress, the internal proxy is the only destination host telemetry
ever records, so filtering private ranges removes the exact event you want. In the detonation this
rule was written from, the hollowed process connected to the internal proxy and to nothing else,
and the SigmaHQ rule would not have fired on it. This one carries no destination condition at all,
which is noisier by design and correct behind a proxy.

## Provenance

The first three came from one detonation on 2026-08-17, and the two .NET Framework rules from an
Agent Tesla detonation on 2026-10-27, each of the sample referenced in the rule's `references`
field, observed with Sysmon and Elastic Defend telemetry. The `falsepositives` sections are written
from what was actually seen, not from imagination. The PyArmor rule will fire on legitimately
PyArmor-licensed commercial Python applications, and that is stated in the rule rather than
discovered by whoever deploys it.

The two .NET Framework rules were deployed to the lab SIEM and the sample was detonated again on
2026-10-29. Both fired. That is a true positive on the sample they were drafted from, which is the
weakest kind of confirmation available, and it says nothing about false positives on a populated
estate. Both remain `experimental` for that reason. A 90 day retrohunt across the lab returned 19
hits and no false positives, on an estate of two hosts of which one runs Windows, so the absence of
false positives there reflects the size of the estate rather than the quality of the rules.

## Testing them yourself

```sh
pip install sigma-cli
sigma check rules/
sigma convert -t lucene -p ecs_windows rules/
```

## Contributing

Corrections welcome, particularly false positives found in a real estate, which is the feedback
these are missing. Open an issue or a pull request.
