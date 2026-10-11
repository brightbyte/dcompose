import pytest

from dockscreen import argscan


@pytest.mark.parametrize("args, values", [
    (["-f", "a.yml", "--file", "b.yml"], ["a.yml", "b.yml"]),
    (["--file=a.yml", "-fb.yml"], ["a.yml", "b.yml"]),
    (["--files", "x", "-f"], []),  # another option, and -f without a value
    ([], []),
])
def test_option_values(args, values):
    assert argscan.option_values(args, "--file", "-f") == values


@pytest.mark.parametrize("args, value", [
    (["--pull", "always", "web"], "always"),
    (["--pull=never"], "never"),
    (["--", "--pull", "always"], None),  # belongs to the command
    (["--pull"], None),
])
def test_option_value(args, value):
    assert argscan.option_value(args, "--pull") == value
