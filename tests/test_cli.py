from click.testing import CliRunner

from envault.cli import cli


def test_cli_help():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "lock" in result.output
    assert "unlock" in result.output


def test_lock_unlock_roundtrip(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=abc123\n")
    vault_file = tmp_path / ".env.vault"
    unlocked_file = tmp_path / ".env.out"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["lock", str(env_file), "-o", str(vault_file), "-p", "test-pass", "--no-banner"],
    )
    assert result.exit_code == 0
    assert vault_file.exists()

    result = runner.invoke(
        cli,
        ["unlock", str(vault_file), "-o", str(unlocked_file), "-p", "test-pass", "--no-banner"],
    )
    assert result.exit_code == 0
    assert unlocked_file.read_text() == "API_KEY=abc123\n"
