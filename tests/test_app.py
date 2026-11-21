"""Functional checks using Flask's test client and isolated temporary SQLite DB.

Run from the project root with: python3 -m unittest discover -s tests -v

"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as monitor
from werkzeug.security import check_password_hash, generate_password_hash


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

    def as_user(self, uid, client=None):
        client = client or self.client
        with client.session_transaction() as sess:
            sess['uid'] = uid
            sess['session_version'] = 0
            sess['last_activity'] = monitor.time.time()

    def post_log(self, i):
        return self.client.post('/logs', data={
            'service': f'Service {i}', 'status': 'Down',
            'description': f'Log {i} detail <script>alert(1)</script>'
        }, follow_redirects=True)

    def test_standard_account_cannot_access_admin(self):
        self.as_user(self.student_id)
        self.assertEqual(self.client.get('/admin').status_code, 403)
        self.assertEqual(self.client.get('/admin/security').status_code, 403)
        self.assertEqual(self.client.get('/admin/tickets.csv').status_code, 403)
        self.assertEqual(self.client.post('/admin/users/1/lock').status_code, 403)

    def test_unauthenticated_metrics_are_protected(self):
        self.assertEqual(self.client.get('/api/metrics').status_code, 302)
        self.assertEqual(self.client.get('/api/metrics/history').status_code, 302)
        self.assertEqual(self.client.get('/api/tickets/suggestions?service=Portal').status_code, 302)

    def test_metrics_api_records_rate_limited_history(self):
        self.as_user(self.student_id)
        metrics = {'cpu_percent': 23.4, 'mem_percent': 64.2, 'disk_percent': 42.8}
        with patch.object(monitor, 'collect_metrics', return_value=metrics):
            self.assertEqual(self.client.get('/api/metrics').json, metrics)
            self.assertEqual(self.client.get('/api/metrics').json, metrics)
        response = self.client.get('/api/metrics/history')
        self.assertEqual(response.status_code, 200)
        samples = response.json['samples']
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]['cpu_percent'], 23.4)
        self.assertEqual(samples[0]['mem_percent'], 64.2)
        self.assertEqual(samples[0]['disk_percent'], 42.8)

    def test_dashboard_renders_resource_history_chart(self):
        self.as_user(self.student_id)
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="resource-chart"', response.data)
        self.assertIn(b'Resource utilization', response.data)

    def test_existing_logs_migrate_to_tickets_without_losing_content(self):
        legacy_path = Path(self.temp.name) / "legacy.sqlite"
        db = sqlite3.connect(legacy_path)
        db.executescript("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                locked INTEGER NOT NULL DEFAULT 0,
                submission_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                service TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT NOT NULL,
                flagged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO users (id, username, password_hash) VALUES
                (7, 'legacyuser', 'not-used');
            INSERT INTO logs (id, user_id, service, status, description, created_at) VALUES
                (42, 7, 'Old service', 'Down', 'Existing report', '2025-01-02 03:04:05');
        """)
        db.commit()
        db.close()
        previous_db = monitor.DB_PATH
        monitor.DB_PATH = str(legacy_path)
        try:
            monitor.init_db()
            db = monitor.connect()
            ticket = db.execute("SELECT * FROM logs WHERE id = 42").fetchone()
            event = db.execute(
                "SELECT * FROM ticket_events WHERE log_id = 42").fetchone()
            self.assertEqual(ticket["ticket_ref"], "INC-0042")
            self.assertEqual(ticket["ticket_status"], "Open")
            self.assertEqual(ticket["priority"], "Medium")
            self.assertEqual(ticket["status"], "Down")
            self.assertEqual(monitor.decrypt_field(ticket["service"]), "Old service")
            self.assertEqual(monitor.decrypt_field(ticket["description"]), "Existing report")
            self.assertEqual(event["event_type"], "created")
            self.assertEqual(event["created_at"], "2025-01-02 03:04:05")
            monitor.init_db()
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM ticket_events WHERE log_id = 42").fetchone()[0],
                1)
            db.close()
        finally:
            monitor.DB_PATH = previous_db

    def test_ticket_workflow_assignment_notifications_and_timeline(self):
        self.as_user(self.student_id)
        self.post_log(1)
        self.assertEqual(
            self.client.post('/tickets/1/status', data={'ticket_status': 'Resolved'}).status_code,
            403)
        db = sqlite3.connect(monitor.DB_PATH)
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ("support", generate_password_hash("support-password-123")))
        support_id = db.execute(
            "SELECT id FROM users WHERE username = 'support'").fetchone()[0]
        db.commit()
        db.close()

        self.as_user(self.admin_id)
        self.client.post(f'/admin/users/{support_id}/support')
        self.as_user(support_id)
        self.assertEqual(self.client.get('/tickets/1').status_code, 403)
        self.as_user(self.admin_id)
        self.client.post('/tickets/1/assign', data={'assigned_to': support_id})
        self.as_user(support_id)
        self.assertEqual(self.client.get('/tickets/1').status_code, 200)
        queue = self.client.get('/tickets')
        self.assertEqual(queue.status_code, 200)
        self.assertIn(b'INC-0001', queue.data)
        self.assertEqual(
            self.client.post('/tickets/1/status', data={'ticket_status': 'In Progress'}).status_code,
            302)
        self.client.post('/tickets/1/priority', data={'priority': 'Critical'})
        response = self.client.post('/tickets/1/responses', data={
            'body': '<script>alert(1)</script> We are investigating this report.'})
        self.assertEqual(response.status_code, 302)

        db = sqlite3.connect(monitor.DB_PATH)
        db.row_factory = sqlite3.Row
        ticket = db.execute("SELECT * FROM logs WHERE id = 1").fetchone()
        stored_response = db.execute(
            "SELECT body FROM ticket_responses WHERE log_id = 1").fetchone()[0]
        event_count = db.execute(
            "SELECT COUNT(*) FROM ticket_events WHERE log_id = 1").fetchone()[0]
        db.close()
        self.assertEqual(ticket["ticket_ref"], "INC-0001")
        self.assertEqual(ticket["ticket_status"], "In Progress")
        self.assertEqual(ticket["priority"], "Critical")
        self.assertTrue(stored_response.startswith("enc:v1:"))
        self.assertNotIn("investigating", stored_response)
        self.assertEqual(event_count, 5)

        self.client.post('/tickets/1/status', data={'ticket_status': 'Resolved'})
        db = sqlite3.connect(monitor.DB_PATH)
        first_resolved_at = db.execute(
            "SELECT resolved_at FROM logs WHERE id = 1").fetchone()[0]
        db.close()
        self.client.post('/tickets/1/status', data={'ticket_status': 'Open'})
        db = sqlite3.connect(monitor.DB_PATH)
        reopened = db.execute(
            "SELECT ticket_status, resolved_at FROM logs WHERE id = 1").fetchone()
        db.close()
        self.assertEqual(reopened[0], "Open")
        self.assertEqual(reopened[1], first_resolved_at)

        self.as_user(self.admin_id)
        self.client.post('/admin/users/{}/support'.format(support_id))
        db = sqlite3.connect(monitor.DB_PATH)
        role = db.execute(
            "SELECT is_support FROM users WHERE id = ?", (support_id,)).fetchone()[0]
        db.close()
        self.assertEqual(role, 1)
        self.client.post('/tickets/1/assign', data={'assigned_to': ''})
        self.as_user(support_id)
        self.assertEqual(self.client.get('/tickets/1').status_code, 403)

        self.as_user(self.student_id)
        ticket_page = self.client.get('/tickets/1')
        self.assertEqual(ticket_page.status_code, 200)
        self.assertIn(b'&lt;script&gt;alert(1)&lt;/script&gt;', ticket_page.data)
        self.assertNotIn(b'<script>alert(1)</script>', ticket_page.data)
        self.assertIn(b'We are investigating this report.', ticket_page.data)
        self.assertNotIn(b'enc:v1:', ticket_page.data)
        notifications_response = self.client.get('/notifications')
        self.assertEqual(notifications_response.status_code, 200)
        self.assertIn(b'INC-0001', notifications_response.data)
        db = sqlite3.connect(monitor.DB_PATH)
        first_notification = db.execute(
            "SELECT id FROM notifications WHERE user_id = ? ORDER BY id LIMIT 1",
            (self.student_id,)).fetchone()[0]
        db.close()
        self.client.post(f'/notifications/{first_notification}/read')
        db = sqlite3.connect(monitor.DB_PATH)
        read_at = db.execute(
            "SELECT read_at FROM notifications WHERE id = ?", (first_notification,)).fetchone()[0]
        db.close()
        self.assertIsNotNone(read_at)

    def test_ticket_filters_csv_export_and_formula_safety(self):
        self.as_user(self.student_id)
        self.client.post('/tickets', data={
            'service': '=Critical portal', 'service_status': 'Down',
            'priority': 'High', 'description': '=1+1'})
        db = sqlite3.connect(monitor.DB_PATH)
        created_date = db.execute(
            "SELECT substr(created_at, 1, 10) FROM logs WHERE id = 1").fetchone()[0]
        db.close()
        self.as_user(self.admin_id)
        response = self.client.get('/admin', query_string={
            'user': 'student', 'service': 'critical', 'priority': 'High',
            'service_status': 'Down', 'ticket_status': 'Open',
            'from_date': created_date, 'to_date': created_date})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'INC-0001', response.data)
        legacy_filter = self.client.get('/admin?status=Down')
        self.assertIn(b'INC-0001', legacy_filter.data)
        exported = self.client.get('/admin/tickets.csv', query_string={
            'user': 'student', 'service': 'critical', 'priority': 'High',
            'service_status': 'Down', 'ticket_status': 'Open',
            'from_date': created_date, 'to_date': created_date})
        self.assertEqual(exported.status_code, 200)
        self.assertIn(b"'=Critical portal", exported.data)
        self.assertIn(b"'=1+1", exported.data)
        self.assertIn(b"text/csv", exported.content_type.encode())

    def test_duplicate_suggestions_match_only_open_same_service(self):
        self.as_user(self.student_id)
        for service in ("Department portal", " department   PORTAL "):
            self.client.post('/tickets', data={
                'service': service, 'service_status': 'Degraded',
                'priority': 'Medium', 'description': 'A different report'})
        db = sqlite3.connect(monitor.DB_PATH)
        db.execute("UPDATE logs SET ticket_status = 'Resolved' WHERE id = 1")
        db.commit()
        db.close()
        response = self.client.get('/api/tickets/suggestions?service=Department%20Portal')
        self.assertEqual(response.status_code, 200)
        suggestions = response.json['suggestions']
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]['reference'], 'INC-0002')

    def test_metric_samples_are_spaced_and_old_samples_pruned(self):
        now = 1_800_000_000
        metrics = {'cpu_percent': 23.4, 'mem_percent': 64.2, 'disk_percent': 42.8}
        with monitor.app.app_context():
            db = monitor.get_db()
            db.execute(
                'INSERT INTO metric_samples '
                '(sampled_at, cpu_percent, mem_percent, disk_percent) VALUES (?, ?, ?, ?)',
                (now - monitor.METRIC_HISTORY_SECONDS - 1, 1, 1, 1))
            monitor.record_metric_sample(now, metrics)
            monitor.record_metric_sample(now + 30, metrics)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM metric_samples').fetchone()[0], 1)
            monitor.record_metric_sample(now + 60, metrics)
            samples = db.execute(
                'SELECT sampled_at FROM metric_samples ORDER BY sampled_at').fetchall()
            self.assertEqual([row['sampled_at'] for row in samples], [now, now + 60])

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

    def test_locked_accounts_cannot_log_in_or_use_existing_sessions(self):
        db = sqlite3.connect(monitor.DB_PATH)
        db.execute('UPDATE users SET locked = 1 WHERE id = ?', (self.student_id,))
        db.commit()
        db.close()

        login_client = monitor.app.test_client()
        response = login_client.post('/login', data={
            'username': 'student', 'password': 'student-password-123'})
        self.assertEqual(response.status_code, 200)
        with login_client.session_transaction() as sess:
            self.assertNotIn('uid', sess)

        self.as_user(self.student_id)
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/login')
        with self.client.session_transaction() as sess:
            self.assertNotIn('uid', sess)

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
        response = self.client.post('/login', data={'username': 'student', 'password': 'wrong'})
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as sess:
            self.assertNotIn('uid', sess)
        db = sqlite3.connect(monitor.DB_PATH)
        event = db.execute(
            "SELECT event_type, attempted_username, details FROM security_events "
            "WHERE event_type = 'login_failed'").fetchone()
        db.close()
        self.assertEqual(event, ('login_failed', 'student', 'Invalid username or password.'))

    def test_login_throttle_persists_and_security_console_shows_attempts(self):
        with patch.object(monitor, 'check_password_hash', return_value=False):
            for _ in range(monitor.LOGIN_MAX_ATTEMPTS):
                response = self.client.post('/login', data={
                    'username': 'unknown', 'password': 'never-store-this-password'})
                self.assertEqual(response.status_code, 200)
            blocked = self.client.post('/login', data={
                'username': 'another-account', 'password': 'never-store-this-password'})
            self.assertEqual(blocked.status_code, 429)

        monitor.init_db()
        with patch.object(monitor, 'check_password_hash', return_value=False):
            persisted_block = self.client.post('/login', data={
                'username': 'unknown', 'password': 'never-store-this-password'})
        self.assertEqual(persisted_block.status_code, 429)

        self.as_user(self.admin_id)
        console = self.client.get('/admin/security')
        self.assertEqual(console.status_code, 200)
        self.assertIn(b'login failed', console.data)
        self.assertIn(b'login rate limited', console.data)
        self.assertIn(b'unknown', console.data)
        self.assertIn(b'127.0.0.1', console.data)

        db = sqlite3.connect(monitor.DB_PATH)
        failed_count = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'login_failed'").fetchone()[0]
        rate_limited_count = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'login_rate_limited'").fetchone()[0]
        stored_values = repr(db.execute(
            "SELECT details, attempted_username FROM security_events").fetchall())
        db.close()
        self.assertEqual(failed_count, monitor.LOGIN_MAX_ATTEMPTS)
        self.assertEqual(rate_limited_count, 1)
        self.assertNotIn('never-store-this-password', stored_values)

    def test_login_throttle_blocks_account_across_ips(self):
        with patch.object(monitor, 'check_password_hash', return_value=False):
            for attempt in range(monitor.LOGIN_MAX_ATTEMPTS):
                response = self.client.post('/login', data={
                    'username': 'student', 'password': 'wrong'},
                    environ_base={'REMOTE_ADDR': '192.0.2.{}'.format(attempt + 1)})
                self.assertEqual(response.status_code, 200)
            blocked = self.client.post('/login', data={
                'username': 'student', 'password': 'wrong'},
                environ_base={'REMOTE_ADDR': '198.51.100.10'})
        self.assertEqual(blocked.status_code, 429)

    def test_successful_login_clears_ip_failure_bucket(self):
        login_client = monitor.app.test_client()
        with patch.object(monitor, 'check_password_hash', return_value=False):
            for attempt in range(monitor.LOGIN_MAX_ATTEMPTS - 1):
                response = login_client.post('/login', data={
                    'username': 'unknown-{}'.format(attempt), 'password': 'wrong'})
                self.assertEqual(response.status_code, 200)

        success = login_client.post('/login', data={
            'username': 'student', 'password': 'student-password-123'})
        self.assertEqual(success.status_code, 302)
        with patch.object(monitor, 'check_password_hash', return_value=False):
            next_attempt = login_client.post('/login', data={
                'username': 'another-unknown', 'password': 'wrong'})
        self.assertEqual(next_attempt.status_code, 200)

        db = sqlite3.connect(monitor.DB_PATH)
        ip_failures = db.execute(
            "SELECT failed_count FROM login_attempts "
            "WHERE ip_address = '127.0.0.1' AND username = ''").fetchone()
        db.close()
        self.assertEqual(ip_failures, (1,))

    def test_password_change_invalidates_other_sessions(self):
        other_client = monitor.app.test_client()
        self.as_user(self.student_id)
        self.as_user(self.student_id, other_client)

        page = self.client.get('/account/password')
        self.assertEqual(page.status_code, 200)
        mismatch = self.client.post('/account/password', data={
            'current_password': 'student-password-123',
            'new_password': 'a-different-password',
            'confirm_password': 'not-the-same-password',
        })
        self.assertEqual(mismatch.status_code, 200)

        changed = self.client.post('/account/password', data={
            'current_password': 'student-password-123',
            'new_password': 'updated-student-password',
            'confirm_password': 'updated-student-password',
        })
        self.assertEqual(changed.status_code, 302)
        self.assertEqual(self.client.get('/dashboard').status_code, 200)
        self.assertEqual(other_client.get('/dashboard').status_code, 302)

        db = sqlite3.connect(monitor.DB_PATH)
        password_hash, version = db.execute(
            "SELECT password_hash, session_version FROM users WHERE id = ?",
            (self.student_id,)).fetchone()
        event = db.execute(
            "SELECT event_type FROM security_events WHERE actor_id = ? "
            "AND event_type = 'password_changed'", (self.student_id,)).fetchone()
        db.close()
        self.assertTrue(check_password_hash(password_hash, 'updated-student-password'))
        self.assertEqual(version, 1)
        self.assertEqual(event[0], 'password_changed')

        new_client = monitor.app.test_client()
        login = new_client.post('/login', data={
            'username': 'student', 'password': 'updated-student-password'})
        self.assertEqual(login.status_code, 302)

    def test_inactive_session_is_signed_out(self):
        self.as_user(self.student_id)
        with self.client.session_transaction() as sess:
            sess['last_activity'] = (
                monitor.time.time() - monitor.SESSION_IDLE_TIMEOUT_SECONDS - 1)
        response = self.client.get('/tickets')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/login')
        with self.client.session_transaction() as sess:
            self.assertNotIn('uid', sess)
        login_page = self.client.get('/login')
        self.assertIn(b'expired due to inactivity', login_page.data)

        login_client = monitor.app.test_client()
        self.as_user(self.student_id, login_client)
        with login_client.session_transaction() as sess:
            sess['last_activity'] = (
                monitor.time.time() - monitor.SESSION_IDLE_TIMEOUT_SECONDS - 1)
        expired_login_page = login_client.get('/login')
        self.assertEqual(expired_login_page.status_code, 200)
        self.assertIn(b'Log in', expired_login_page.data)
        with login_client.session_transaction() as sess:
            self.assertNotIn('uid', sess)

    def test_admin_audit_and_locked_accounts_are_visible(self):
        db = sqlite3.connect(monitor.DB_PATH)
        db.execute("UPDATE users SET locked = 1 WHERE id = ?", (self.student_id,))
        db.commit()
        db.close()
        self.as_user(self.admin_id)
        self.client.post('/admin/users/{}/lock'.format(self.student_id))
        db = sqlite3.connect(monitor.DB_PATH)
        audit = db.execute(
            "SELECT actor_id, action, target_type, target_id FROM admin_audit "
            "WHERE action = 'user.unlock'").fetchone()
        db.execute("UPDATE users SET locked = 1 WHERE id = ?", (self.student_id,))
        db.commit()
        db.close()

        console = self.client.get('/admin/security')
        self.assertEqual(console.status_code, 200)
        self.assertIn(b'student', console.data)
        self.assertEqual(audit, (self.admin_id, 'user.unlock', 'user', str(self.student_id)))


if __name__ == '__main__':
    unittest.main()
