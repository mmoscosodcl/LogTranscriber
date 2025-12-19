import unittest
import sys
import os
import jwt
from datetime import datetime, timedelta

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import parse_log_line, decode_token, generate_summary
import app

class TestLogParser(unittest.TestCase):
    def setUp(self):
        # Set secret for testing
        app.JWT_SECRET = 'testsecret'

    def test_parse_log_line_valid(self):
        # Generate a valid token
        secret = 'testsecret'
        payload = {'user_id': 123, 'exp': datetime.utcnow() + timedelta(hours=1)}
        token = jwt.encode(payload, secret, algorithm='HS256')
        
        # Note: jwt.encode returns bytes in Python 3 < 3.8 depending on version, but usually str in newer pyjwt
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        
        log_line = f'181.74.37.7 - - [09/Dec/2025:04:43:12 -0300] "GET /asignaturas_alumno/asignaturas?t={token} HTTP/1.1" 200 2880 "-" "Mozilla/5.0"'
        
        result = parse_log_line(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '181.74.37.7')
        self.assertEqual(result['t_raw'], token)
        self.assertEqual(result['t_decoded']['user_id'], 123)

    def test_parse_log_line_no_t(self):
        log_line = '181.74.37.7 - - [09/Dec/2025:04:43:12 -0300] "GET /other/path HTTP/1.1" 200 2880 "-" "Mozilla/5.0"'
        result = parse_log_line(log_line)
        self.assertIsNotNone(result)
        self.assertIsNone(result['t_raw'])

    def test_decode_token_invalid(self):
        result = decode_token("invalid.token.here")
        self.assertIn('error', result)

    def test_generate_summary(self):
        # Mock entries
        entries = [
            {
                "ip": "192.168.1.1",
                "date": "09/Dec/2025:04:43:12 -0300",
                "url": "/api/resource?t=token1",
                "t_decoded": {"run": "12345678"}
            },
            {
                "ip": "192.168.1.1",
                "date": "09/Dec/2025:04:45:00 -0300",
                "url": "/api/resource?t=token1",
                "t_decoded": {"run": "12345678"}
            },
            {
                "ip": "10.0.0.1",
                "date": "09/Dec/2025:05:00:00 -0300",
                "url": "/api/other?t=token2",
                "t_decoded": {"run": "87654321"}
            }
        ]

        summary = generate_summary(entries)

        # Check IP stats
        self.assertEqual(summary['ip_amount'], 2)
        self.assertIn("192.168.1.1", summary['ip'])
        self.assertIn("10.0.0.1", summary['ip'])

        # Check Date stats
        self.assertEqual(summary['date_start'], "09/Dec/2025:04:43:12 -0300")
        self.assertEqual(summary['date_end'], "09/Dec/2025:05:00:00 -0300")

        # Check URL stats
        self.assertEqual(summary['url_amount'], 2)
        self.assertIn("/api/resource?t=", summary['url'])
        self.assertEqual(summary['url']['/api/resource?t=']['count'], 1) # 1 unique run
        self.assertEqual(summary['url']['/api/resource?t=']['run'], ['12345678'])

        # Check User stats
        self.assertEqual(summary['users_amount'], 2)
        self.assertIn("12345678", summary['users'])
        self.assertIn("/api/resource?t=", summary['users']['12345678'])

if __name__ == '__main__':
    unittest.main()
