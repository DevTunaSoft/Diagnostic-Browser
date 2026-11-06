"""Unit-test-only backend when native SQLCipher cannot be executed on this host."""
import os
os.environ['DIAGNOSTIC_BROWSER_TEST_PLAINTEXT'] = '1'
