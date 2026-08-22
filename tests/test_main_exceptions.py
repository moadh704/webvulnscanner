#!/usr/bin/env python
"""RED-GREEN test for main.py top-level exception handling."""
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_main_catches_phase_exception_and_exits_gracefully():
    """
    A RuntimeError during a scan phase must not bubble out as a raw
    traceback. main() should catch it, print an error, and exit with
    code 1 so the caller knows the scan failed but the process stays
    controlled.
    """
    tmpdir = tempfile.mkdtemp()
    old_argv = sys.argv
    old_cwd = os.getcwd()

    # Move into the repo root so config.py resolution works predictably.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(repo_root)

    try:
        sys.argv = [
            'main.py', '--src', tmpdir,
            '--mode', 'static', '--no-ai', '--quiet'
        ]

        # Force a crash inside the static scan phase.
        from static.scanner import StaticScanner
        original_run = StaticScanner.run
        StaticScanner.run = lambda self, src: (_ for _ in ()).throw(
            RuntimeError("injected scan failure")
        )

        from main import main
        try:
            main()
        except SystemExit as e:
            assert e.code == 1, (
                f"Expected exit code 1 after phase exception, got {e.code}"
            )
        finally:
            StaticScanner.run = original_run
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)
        shutil.rmtree(tmpdir)


if __name__ == '__main__':
    test_main_catches_phase_exception_and_exits_gracefully()
    print('ALL PASS')
