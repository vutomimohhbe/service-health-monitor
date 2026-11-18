"""Functional checks using Flask's test client and isolated temporary SQLite DB.

Run from the project root with: python3 -m unittest discover -s tests -v
These checks do not replace running Docker on your own machine.
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as monitor
from werkzeug.security import generate_password_hash


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_db = monitor.DB_PATH
        monitor.DB_PATH = str(Path(self.temp.name) / "test.sqlite")
        monitor.init_db()
        monitor.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = monitor.app.test_client()
        with monitor.app.app_context():
            db = monitor.connect()
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       ("student", generate_password_hash("student-password-123")))
            self.student_id = db.execute("SELECT id FROM users WHERE username = 'student'").fetchone()[0]
            self.admin_id = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()[0]
            db.close()

    def tearDown(self):
        monitor.app.config.update(WTF_CSRF_ENABLED=True, TESTING=False)
        monitor.DB_PATH = self.previous_db
        self.temp.cleanup()

    def as_user(self, uid):
        with self.client.session_transaction() as sess:
            sess['uid'] = uid

    def post_log(self, i):
        return self.client.post('/logs', data={
            'service': f'Service {i}', 'status': 'Down',
            'description': f'Log {i} detail <script>alert(1)</script>'
        }, follow_redirects=True)

    def test_standard_account_cannot_access_admin(self):
        self.as_user(self.student_id)
        self.assertEqual(self.client.get('/admin').status_code, 403)
        self.assertEqual(self.client.post('/admin/users/1/lock').status_code, 403)

    def test_unauthenticated_metrics_are_protected(self):
        self.assertEqual(self.client.get('/api/metrics').status_code, 302)

    def test_submission_quota_is_enforced_and_encrypted(self):
        self.as_user(self.student_id)
        for i in range(monitor.MAX_LOGS):
            self.assertEqual(self.post_log(i).status_code, 200)
        self.post_log(99)
        db = sqlite3.connect(monitor.DB_PATH)
        count = db.execute('SELECT COUNT(*) FROM logs WHERE user_id = ?', (self.student_id,)).fetchone()[0]
        raw = db.execute('SELECT service, description FROM logs LIMIT 1').fetchone()
        db.close()
        self.assertEqual(count, monitor.MAX_LOGS)
        self.assertTrue(raw[0].startswith('enc:v1:'))
        self.assertTrue(raw[1].startswith('enc:v1:'))
        self.assertNotIn('<script>', raw[1])

    def test_submitted_xss_is_escaped_when_displayed(self):
        self.as_user(self.student_id)
        response = self.post_log(1)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>alert(1)</script>', response.data)

    def test_locked_user_cannot_submit(self):
        db = sqlite3.connect(monitor.DB_PATH)
        db.execute('UPDATE users SET locked = 1 WHERE id = ?', (self.student_id,))
        db.commit()
        db.close()
        self.as_user(self.student_id)
        self.post_log(1)
        db = sqlite3.connect(monitor.DB_PATH)
        count = db.execute('SELECT COUNT(*) FROM logs WHERE user_id = ?', (self.student_id,)).fetchone()[0]
        db.close()
        self.assertEqual(count, 0)

    def test_admin_moderation(self):
        self.as_user(self.student_id)
        self.post_log(1)
        self.as_user(self.admin_id)
        self.assertEqual(self.client.get('/admin').status_code, 200)
        self.client.post('/admin/logs/1/flag')
        db = sqlite3.connect(monitor.DB_PATH)
        self.assertEqual(db.execute('SELECT flagged FROM logs WHERE id = 1').fetchone()[0], 1)
        db.close()
        self.client.post('/admin/logs/1/delete')
        db = sqlite3.connect(monitor.DB_PATH)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM logs').fetchone()[0], 0)
        db.close()

    def test_csrf_missing_token_is_rejected(self):
        monitor.app.config['WTF_CSRF_ENABLED'] = True
        self.as_user(self.student_id)
        response = self.client.post('/logs', data={
            'service': 'test', 'status': 'Down', 'description': 'hello'})
        self.assertEqual(response.status_code, 400)

    def test_wrong_login_password_fails(self):
        self.client.post('/login', data={'username': 'student', 'password': 'wrong'})
        with self.client.session_transaction() as sess:
            self.assertNotIn('uid', sess)


if __name__ == '__main__':
    unittest.main()
