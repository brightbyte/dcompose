import os

from dockscreen import helptext, messages

OPTIONS = (helptext.Option("--long-option", "Some text that is long enough to need wrapping at a narrow "
                                           "width"),
           helptext.Option("--user", "Short", short="u", value="string"))


def test_tables_wrap_descriptions_under_their_own_column():
    lines = helptext.table([(o.left(), o.text) for o in OPTIONS], 60)
    column = len("  -u, --user string") + 3  # three spaces after the widest option, as docker does
    assert lines[0].startswith("      --long-option".ljust(column) + "Some text that is long enough")
    assert lines[1].startswith(" " * column) and lines[1][column] != " "
    assert lines[-1] == "  -u, --user string   Short"
    assert all(len(line) <= 60 for line in lines)


def test_without_a_width_nothing_is_wrapped():
    assert helptext.table([(o.left(), o.text) for o in OPTIONS], None)[0].endswith("at a narrow width")
    assert helptext.paragraph("a " * 100, None) == ["a " * 100]


def test_list_items_continue_under_their_text():
    lines = helptext.item("- " + "word " * 30, 40)
    assert lines[0].startswith("  - word") and all(line.startswith("    word") for line in lines[1:])


def test_a_topic_has_docker_like_parts_and_says_whose_help_follows():
    lines = helptext.topic(helptext.DOCKER["exec"], "Docker's own", None)
    assert lines[0] == "Usage:  dockscreen exec [OPTIONS] CONTAINER COMMAND [ARG...]"
    assert "Aliases:" in lines and "Options:" in lines
    assert lines[-2] == "Docker's own help follows:"
    assert helptext.topic(helptext.DOCKER["audit"], "Docker's own", None)[-1] != ""  # nothing follows audit


def test_help_without_a_terminal_is_wrapped_at_80_unlike_reports(monkeypatch, capsys):
    monkeypatch.delenv("COLUMNS")
    monkeypatch.setattr(messages.shutil, "get_terminal_size", lambda fallback: os.terminal_size(fallback))
    helptext.show(helptext.docker_overview)
    lines = capsys.readouterr().out.splitlines()
    assert max(len(line) for line in lines if not line.startswith("Usage:")) <= 80
    assert messages.report_width() is None  # reports: whole lines for grep
