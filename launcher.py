"""One-file Windows entry point shared by supervisor and isolated child processes."""
import multiprocessing

if __name__ == '__main__':
    # PyInstaller requires this before imports or CLI dispatch on Windows.
    multiprocessing.freeze_support()
    from diagnostic_browser.bundle import configure_bundled_browser
    configure_bundled_browser()
    from diagnostic_browser.main import main
    raise SystemExit(main())
