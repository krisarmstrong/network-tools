from network_tools import __main__ as cli


def test_build_parser_has_commands():
    parser = cli.build_parser()
    assert "listen" in parser._subparsers._group_actions[0].choices
