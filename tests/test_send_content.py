"""Outbound detail regressions use synthetic retained MIME and real project authorization."""
import base64
from email.message import EmailMessage
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location('send_content_app', Path(__file__).parents[1] / 'api/app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SendContentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.patches = [patch.object(app, 'DB', Path(self.temp.name) / 'mail.db'),
                        patch.dict(app.os.environ, {'API_KEY_PEPPER': 'fixture-only'})]
        for item in self.patches:
            item.start()
        app._schema_initialized = False
        c = app.db()
        self.project = 'prj_send_content'
        c.execute('insert into projects(id,name,created_at) values(?,?,?)', (self.project, 'Fixture', time.time()))
        for name, scope, project in [('owner', 'mail.send', self.project), ('other', 'mail.send', 'prj_other'), ('reader', 'mail.read', self.project)]:
            if project != self.project:
                c.execute('insert into projects(id,name,created_at) values(?,?,?)', (project, project, time.time()))
            digest = hashlib.sha256((name + 'fixture-only').encode()).hexdigest()
            c.execute('insert into api_keys(name,key_hash,scopes,created_at) values(?,?,?,?)', (name, digest, scope, time.time()))
            key_id = c.execute('select last_insert_rowid()').fetchone()[0]
            c.execute('insert into api_key_grants values(?,?,?,?)', (key_id, project, scope, time.time()))
        message = EmailMessage()
        message['From'] = 'sender@example.test'
        message['To'] = 'one@outside.test, two@outside.test'
        message['Subject'] = '中文主题 <fixture>'
        message['Reply-To'] = 'reply@example.test'
        message['Message-ID'] = '<sent@example.test>'
        message['In-Reply-To'] = '<original@outside.test>'
        message['References'] = '<thread@outside.test> <original@outside.test>'
        message.set_content('中文正文\nsecond line')
        message.add_alternative('<p onclick="evil()">富文本</p><script>evil()</script>', subtype='html')
        message.add_attachment(b'fixture attachment', maintype='application', subtype='octet-stream', filename='附件.txt')
        self.raw = message.as_bytes()
        c.execute('''insert into outbound_outbox(request_id,project_id,sender,recipients_json,raw_message,status,next_attempt_at,created_at,updated_at)
                     values(?,?,?,?,?,'submitted_to_mta',?,?,?)''',
                  ('send_content_fixture', self.project, 'sender@example.test', '["one@outside.test","two@outside.test"]', self.raw, 0, time.time() - 10 * 86400, time.time()))
        c.commit()
        c.close()
        self.client = TestClient(app.app)
        self.path = '/api/v1/send/send_content_fixture'
        self.owner = {'X-API-Key': 'owner'}

    def tearDown(self):
        self.client.close()
        app._schema_initialized = False
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def test_detail_recovers_retained_unicode_body_headers_and_attachment_metadata(self):
        response = self.client.get(self.path + '/content', headers=self.owner)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertTrue(data['content_available'])
        self.assertEqual(data['subject'], '中文主题 <fixture>')
        self.assertEqual(data['sender'], 'sender@example.test')
        self.assertEqual(data['recipients'], ['one@outside.test', 'two@outside.test'])
        self.assertIn('中文正文', data['content']['text'])
        self.assertIn('富文本', data['content']['html'])
        self.assertNotIn('<script', data['content']['html'])
        self.assertNotIn('onclick', data['content']['html'])
        self.assertEqual(data['reply_to'], 'reply@example.test')
        self.assertEqual(data['references'], ['<thread@outside.test>', '<original@outside.test>'])
        self.assertEqual(data['attachments'], [{'filename': '附件.txt', 'content_type': 'application/octet-stream', 'size': 18}])
        self.assertNotIn('data_base64', str(data))

    def test_download_is_byte_exact_and_keeps_attachment(self):
        response = self.client.get(self.path + '/raw', headers=self.owner)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.raw)
        self.assertIn('attachment;', response.headers['content-disposition'])
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        self.assertEqual(response.headers['cache-control'], 'private, no-store')

    def test_content_and_raw_enforce_existing_send_scope_and_project_boundary(self):
        for suffix in ('/content', '/raw'):
            for headers in ({}, {'X-API-Key': 'other'}, {'X-API-Key': 'reader'}):
                response = self.client.get(self.path + suffix, headers=headers)
                self.assertEqual(response.status_code, 403, response.text)
                self.assertNotIn('中文正文', response.text)
            self.assertEqual(self.client.get('/api/v1/send/missing' + suffix, headers=self.owner).status_code, 404)

    def test_status_polling_and_list_never_include_body_or_attachments(self):
        for path in (self.path, '/api/v1/send?project_id=' + self.project):
            response = self.client.get(path, headers=self.owner)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn('中文正文', response.text)
            self.assertNotIn('data_base64', response.text)
            self.assertNotIn('content_available', response.text)

    def test_empty_legacy_content_is_explicit_and_not_reported_as_expiration(self):
        c = app.db()
        c.execute('update outbound_outbox set raw_message=?', (b'',))
        c.commit()
        c.close()
        data = self.client.get(self.path + '/content', headers=self.owner).json()
        self.assertFalse(data['content_available'])
        self.assertIsNone(data['content'])
        self.assertEqual(self.client.get(self.path + '/raw', headers=self.owner).status_code, 404)

    def test_inbound_retention_keeps_old_outbound_mime(self):
        app.cleanup_expired_messages(days=1)
        response = self.client.get(self.path + '/raw', headers=self.owner)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.raw)


if __name__ == '__main__':
    unittest.main()
