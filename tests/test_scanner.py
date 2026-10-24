import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch, Mock
import subprocess
import dns.exception
import legacy_domain_scanner as scan


class ScannerRegressionTests(unittest.TestCase):
    def test_domain_evidence_stays_separate_and_html_is_escaped(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'domains.txt'
            output = Path(directory) / 'report'
            source.write_text('one.example\ntwo.example\n')
            calls = []
            def recommend(evidence, model):
                calls.append((evidence['domain'], evidence['tls']['output']))
                return '<script>bad()</script>', None
            with patch.object(scan.shutil, 'which', return_value='/fake/sslscan'), \
                 patch.object(scan, 'perform_ssl_scan', side_effect=lambda d: {'output': d, 'error': None}), \
                 patch.object(scan, 'fetch_dns_and_mta_sts_records', return_value={}), \
                 patch.object(scan, 'generate_recommendations', side_effect=recommend), \
                 patch.dict('os.environ', {'OPENAI_API_KEY': 'synthetic-test-value'}):
                self.assertEqual(scan.main([str(source), '--output-dir', str(output), '--ai', '--model', 'test']), 0)
            self.assertEqual(calls, [('one.example', 'one.example'), ('two.example', 'two.example')])
            html = (output / 'domain_results.html').read_text()
            self.assertNotIn('<script>', html)
            self.assertIn('&lt;script&gt;', html)

    def test_default_run_never_calls_ai_and_failure_keeps_dns(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'domains.txt'
            output = Path(directory) / 'report'
            source.write_text('one.example\ntwo.example\n')
            with patch.object(scan.shutil, 'which', return_value='/fake'), \
                 patch.object(scan, 'perform_ssl_scan', return_value={'output': 'partial', 'error': 'failed'}), \
                 patch.object(scan, 'fetch_dns_and_mta_sts_records', return_value={'SPF': {'records': ['v=spf1 -all'], 'error': None}}) as dns, \
                 patch.object(scan, 'generate_recommendations') as ai:
                self.assertEqual(scan.main([str(source), '--output-dir', str(output)]), 1)
            ai.assert_not_called()
            self.assertEqual(dns.call_count, 2)
            self.assertIn('v=spf1 -all', (output / 'results.json').read_text())

    def test_api_error_returns_message_not_unbound_variable(self):
        import requests
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'synthetic'}), \
             patch.object(requests, 'post', side_effect=requests.Timeout()):
            text, error = scan.generate_recommendations({'domain': 'example.org'}, 'test')
        self.assertEqual(text, '')
        self.assertIn('retained', error)

    def test_timeout_is_failure_with_partial_evidence(self):
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('sslscan', 120, output=b'partial')):
            result = scan.perform_ssl_scan('example.org')
        self.assertEqual(result['output'], 'partial')
        self.assertIn('timed out', result['error'])

    def test_dns_timeout_is_unknown(self):
        with patch.object(scan.dns.resolver, 'Resolver') as factory:
            factory.return_value.resolve.side_effect = dns.exception.Timeout()
            result = scan.fetch_dns_and_mta_sts_records('example.org')
        self.assertTrue(all('unknown' in v['error'] for v in result.values()))
