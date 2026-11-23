"""Regression tests for the offline release RPM source resolver."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / 'source-handlers'))
import common
import rpm

SRPM = 'java-21-openjdk-21.0.12.1.1-1.2.el9.src.rpm'
PAYLOAD = b'fixture for checksum verification, not a vendor RPM'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def component(arch, srpm=SRPM, vendor='Red Hat, Inc.'):
    rows = [{'name': 'java-21-openjdk-headless', 'version': '21.0.12.1.1',
             'release': '1.2.el9', 'arch': arch, 'vendor': vendor,
             'sourcerpm': srpm, 'license': 'GPL-2.0-only WITH Classpath-exception-2.0'}]
    facts = {'os_release': {'etc/os-release': 'VERSION_ID="9.8"'}}
    registry = {}
    with patch.object(rpm, 'installed', return_value=rows):
        rpm.components(facts, 'fixture/image', 'arm64' if arch == 'aarch64' else 'amd64', None, registry)
    return registry[f'rpm:{srpm}']


class ArchivedRpmTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.cache = common.Cache(Path(directory.name))
        self.index = patch.object(rpm, 'find_srpm', return_value=(None, None)).start()
        self.containers = patch.object(rpm, 'srpm_from_source_container', return_value=None).start()
        self.addCleanup(patch.stopall)

    def test_archive_used_for_both_architectures_when_index_has_only_successor(self):
        for arch in ('aarch64', 'x86_64'):
            with self.subTest(arch=arch), patch('common._open', return_value=io.BytesIO(PAYLOAD)) as download:
                with patch.object(rpm, 'RED_HAT_ARCHIVED_SRPM', {SRPM: (DIGEST, len(PAYLOAD), 'RHSA-2026:55787')}):
                    [(path, relative, url, proof)] = rpm.fetch(component(arch), self.cache, None, 'src')
                self.assertEqual(path.read_bytes(), PAYLOAD)
                self.assertEqual(relative, f'src/rpm/java-21-openjdk/{SRPM}')
                self.assertIn(f'/{arch}/appstream/source/SRPMS/Packages/j/{SRPM}', url)
                self.assertIn('RHSA-2026:55787', proof)
                self.cache.blob('sha256', DIGEST).unlink()
                download.assert_called_once()
        self.containers.assert_not_called()

    def test_archive_rejects_incorrect_bytes(self):
        with patch('common._open', return_value=io.BytesIO(b'wrong')), patch.object(
                rpm, 'RED_HAT_ARCHIVED_SRPM', {SRPM: (DIGEST, len(PAYLOAD), 'RHSA-2026:55787')}):
            with self.assertRaisesRegex(common.VerificationError, '!= expected'):
                rpm.fetch(component('x86_64'), self.cache, None, 'src')
        self.assertFalse(self.cache.blob('sha256', DIGEST).exists())
        self.containers.assert_not_called()

    def test_unavailable_archive_can_still_use_source_container(self):
        result = (Path('verified.rpm'), 'https://example.invalid/verified', 'verified registry layer')
        self.containers.return_value = result
        with patch('common._open', side_effect=TimeoutError('unavailable')):
            [(path, _, url, proof)] = rpm.fetch(component('x86_64'), self.cache, None, 'src')
        self.assertEqual((path, url, proof), result)
        self.containers.assert_called_once()

    def test_unpinned_or_other_vendor_packages_fail_closed(self):
        for comp in (component('x86_64', srpm='other-1-1.el9.src.rpm'),
                     component('x86_64', vendor='Other vendor')):
            with self.subTest(comp=comp), patch('common._open') as download:
                with self.assertRaises(common.Unresolved):
                    rpm.fetch(comp, self.cache, None, 'src')
                download.assert_not_called()

    def test_index_keeps_precedence(self):
        url = 'https://example.invalid/indexed.src.rpm'
        self.index.return_value = (('sha256', DIGEST, len(PAYLOAD), url), ('9', 'x86_64', 'appstream'))
        with patch('common._open', return_value=io.BytesIO(PAYLOAD)) as download:
            [(_, _, used, proof)] = rpm.fetch(component('x86_64'), self.cache, None, 'src')
        self.assertEqual(used, url)
        self.assertIn('repodata', proof)
        download.assert_called_once()
        self.containers.assert_not_called()


if __name__ == '__main__':
    unittest.main()
