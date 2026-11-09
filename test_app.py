import os
import sqlite3
import tempfile
import unittest

_tmp = tempfile.mkdtemp()
os.environ['DB_PATH'] = os.path.join(_tmp, 'test.db')
os.environ['ADMIN_PASSWORD'] = 'test-pass'

import app as demo  # noqa: E402


class FlowTest(unittest.TestCase):
    def setUp(self):
        self.c = demo.app.test_client()
        with self.c.session_transaction() as s:
            s['_csrf'] = 'tok'

    def post(self, url, **data):
        data['_csrf'] = 'tok'
        return self.c.post(url, data=data)

    def db(self):
        con = sqlite3.connect(os.environ['DB_PATH'])
        con.row_factory = sqlite3.Row
        return con

    def test_full_flow(self):
        # apply
        r = self.post('/apply', full_name='Test User', organization='Org',
                      email='t@example.com', phone='123', member_type='individual')
        self.assertEqual(r.status_code, 302)
        # duplicate email rejected
        r = self.post('/apply', full_name='Test User', email='t@example.com', member_type='individual')
        self.assertEqual(r.status_code, 400)
        # admin pages need login
        self.assertEqual(self.c.get('/admin').status_code, 302)
        # login
        r = self.post('/admin/login', username='admin', password='wrong')
        self.assertEqual(r.status_code, 401)
        r = self.post('/admin/login', username='admin', password='test-pass')
        self.assertEqual(r.status_code, 302)
        with self.c.session_transaction() as s:
            s['_csrf'] = 'tok'
        # approve -> certificate issued
        mid = self.db().execute('SELECT id FROM members').fetchone()['id']
        self.assertEqual(self.post(f'/admin/members/{mid}/approve').status_code, 302)
        doc = self.db().execute('SELECT * FROM documents').fetchone()
        self.assertTrue(doc['doc_no'].startswith('BSREA-'))
        # NOC
        self.post(f'/admin/members/{mid}/noc', purpose='Tender', days='30')
        self.assertEqual(self.db().execute('SELECT COUNT(*) FROM documents').fetchone()[0], 2)
        # public verify = valid, no PII leaked
        page = self.c.get(f"/verify/{doc['token']}").get_data(as_text=True)
        self.assertIn('VALID', page)
        self.assertNotIn('t@example.com', page)
        self.assertNotIn('123', page.split('Holder')[1][:200])
        # QR image
        q = self.c.get(f"/qr/{doc['token']}.png")
        self.assertEqual(q.status_code, 200)
        self.assertTrue(q.data.startswith(b'\x89PNG'))
        # scan logged
        self.assertGreaterEqual(self.db().execute('SELECT COUNT(*) FROM verification_log').fetchone()[0], 1)
        # revoke -> shows revoked
        self.post(f"/admin/documents/{doc['id']}/revoke")
        self.assertIn('REVOKED', self.c.get(f"/verify/{doc['token']}").get_data(as_text=True))

    def test_unknown_and_injection(self):
        for code in ('nope', "' OR '1'='1", '1; DROP TABLE documents;--'):
            page = self.c.get('/verify', query_string={'code': code}, follow_redirects=True).get_data(as_text=True)
            self.assertIn('Not found', page)
        self.assertEqual(self.c.get('/qr/unknown.png').status_code, 404)

    def test_csrf_enforced(self):
        r = self.c.post('/apply', data={'full_name': 'x', 'email': 'a@b.co'})
        self.assertEqual(r.status_code, 400)

    def test_xss_escaped(self):
        self.post('/apply', full_name='<script>alert(1)</script>', email='x@example.com', member_type='individual')
        self.post('/admin/login', username='admin', password='test-pass')
        with self.c.session_transaction() as s:
            s['_csrf'] = 'tok'
        page = self.c.get('/admin').get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn('&lt;script&gt;', page)


if __name__ == '__main__':
    unittest.main(verbosity=2)
