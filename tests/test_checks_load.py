import textwrap

import pytest

from posture.checks import CheckError, load_checks

VALID = """\
- id: LNX-SSH-001
  title: SSH root login is disabled
  platform: linux
  cis: {benchmark: CIS Ubuntu Linux 24.04 LTS, version: "1.0.0", control: "x"}
  severity: high
  attack: [T1110.001, T1078.003]
  rationale: Root is the account every password guesser tries first.
  check: {fact: ssh.permitrootlogin, op: in, value: ["no", prohibit-password]}
  remediation:
    text: Set PermitRootLogin no.
    script: echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/50-posture.conf
"""


def write(tmp_path, text, name="checks.yaml"):
    (tmp_path / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp_path


def test_valid_file_loads(tmp_path):
    [check] = load_checks(write(tmp_path, VALID))
    assert check.id == "LNX-SSH-001"
    assert check.check.value == ["no", "prohibit-password"]


def test_nested_files_load(tmp_path):
    (tmp_path / "linux").mkdir()
    write(tmp_path / "linux", VALID)
    assert len(load_checks(tmp_path)) == 1


@pytest.mark.parametrize(
    ("old", "new", "error"),
    [
        ("  severity: high", "  severity: high\n  sevrity: high", "sevrity"),
        ("  severity: high", "  severity: urgent", "severity"),
        ("[T1110.001, T1078.003]", "[T1110.1]", "attack"),
        ("[T1110.001, T1078.003]", "[]", "attack"),
        ("id: LNX-SSH-001", "id: lnx ssh 1", "id"),
        ("platform: linux", "platform: macos", "platform"),
        ("op: in, value:", "op: regex, value:", "regex needs a string"),
        ('value: ["no", prohibit-password]', "value: '(unclosed'", "op in needs a list"),
        ('op: in, value: ["no", prohibit-password]', "op: regex, value: '(unclosed'", "bad regex"),
        ('op: in, value: ["no", prohibit-password]', "op: gt, value: '5'", "needs a number"),
        ('op: in, value: ["no", prohibit-password]', "op: exists, value: 1", "takes no value"),
        ('op: in, value: ["no", prohibit-password]', "op: eq", "needs a value"),
        ('op: in, value: ["no", prohibit-password]', "op: like, value: x", "op"),
        ("{fact: ssh.permitrootlogin,", "{fakt: ssh.permitrootlogin,", "fakt"),
    ],
)
def test_invalid_check_rejected(tmp_path, old, new, error):
    assert old in VALID
    with pytest.raises(CheckError, match=error):
        load_checks(write(tmp_path, VALID.replace(old, new)))


def test_for_each_needs_key_and_where(tmp_path):
    bad = VALID.replace(
        '{fact: ssh.permitrootlogin, op: in, value: ["no", prohibit-password]}',
        "{for_each: ad.users, where: {fact: enabled, op: eq, value: true}}",
    )
    with pytest.raises(CheckError, match="key"):
        load_checks(write(tmp_path, bad))


def test_cis_null_needs_references(tmp_path):
    no_cis = VALID.replace("  cis: {benchmark", "  cis: null\n  x: {benchmark")
    no_cis = no_cis.replace(
        '  x: {benchmark: CIS Ubuntu Linux 24.04 LTS, version: "1.0.0", control: "x"}\n', ""
    )
    with pytest.raises(CheckError, match="needs references"):
        load_checks(write(tmp_path, no_cis))
    with_refs = no_cis + '  references: ["https://attack.mitre.org/techniques/T1110/001/"]\n'
    assert load_checks(write(tmp_path, with_refs))[0].cis is None


def test_cis_must_be_stated(tmp_path):
    no_cis = VALID.replace(
        '  cis: {benchmark: CIS Ubuntu Linux 24.04 LTS, version: "1.0.0", control: "x"}\n', ""
    )
    with pytest.raises(CheckError, match="cis"):
        load_checks(write(tmp_path, no_cis))


def test_duplicate_id_across_files(tmp_path):
    write(tmp_path, VALID, "a.yaml")
    write(tmp_path, VALID, "b.yaml")
    with pytest.raises(CheckError, match="duplicate check id LNX-SSH-001"):
        load_checks(tmp_path)


def test_not_a_list(tmp_path):
    with pytest.raises(CheckError, match="expected a list"):
        load_checks(write(tmp_path, "id: LNX-SSH-001\n"))


def test_unsafe_yaml_tag_rejected(tmp_path):
    with pytest.raises(CheckError):
        load_checks(write(tmp_path, "- !!python/object/apply:os.system ['echo pwned']\n"))


def test_missing_directory(tmp_path):
    with pytest.raises(CheckError, match="not a directory"):
        load_checks(tmp_path / "nope")
