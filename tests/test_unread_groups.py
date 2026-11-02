"""未读会话的类型 / 免打扰分组。只用合成联系人，不读真实数据库。"""

import sqlite3
import tempfile
import unittest

from wechat_cli.commands.unread import build_unread_results, render_unread_text
from wechat_cli.core.contacts import get_contact_class_rows
from wechat_cli.core.session_kind import (
    ALERT_MUTED,
    ALERT_ON,
    SESSION_NORMAL,
    SESSION_OA,
    SESSION_WECOM,
    classify_session,
    group_unread,
)


class ClassifyTests(unittest.TestCase):
    def test_buckets(self):
        cases = [
            ("wxid_friend", {}, SESSION_NORMAL, False),
            ("room@chatroom", {"chat_room_notify": 1, "flag": 0x200}, SESSION_NORMAL, False),
            ("room@chatroom", {"chat_room_notify": 0}, SESSION_NORMAL, True),
            ("gh_news", {"flag": 0}, SESSION_OA, False),
            ("gh_news", {"flag": 0x200}, SESSION_OA, True),
            ("brandsessionholder", {"flag": 0x201}, SESSION_OA, True),
            ("brandservicesessionholder", {}, SESSION_OA, False),
            ("somebiz", {"verify_flag": 8, "local_type": 1}, SESSION_OA, False),
            ("wxid_plain", {"verify_flag": 0, "local_type": 3}, SESSION_NORMAL, False),
            ("colleague@openim", {"local_type": 5, "flag": 0x200}, SESSION_WECOM, True),
            ("kefu@kefu.openim", {"flag": 1}, SESSION_WECOM, False),
        ]
        for username, contact, kind, muted in cases:
            got_kind, got_alert, got_muted = classify_session(username, contact)
            self.assertEqual(got_kind, kind, username)
            self.assertEqual(got_muted, muted, username)
            self.assertEqual(got_alert, ALERT_MUTED if muted else ALERT_ON)

    def test_group_omits_empty_and_keeps_order(self):
        rows = [
            {"session_type": SESSION_WECOM, "alert": ALERT_ON, "chat": "corp"},
            {"session_type": SESSION_OA, "alert": ALERT_MUTED, "chat": "oa"},
            {"session_type": SESSION_NORMAL, "alert": ALERT_ON, "chat": "friend"},
            {"session_type": SESSION_NORMAL, "alert": ALERT_ON, "chat": "group"},
        ]
        sections = group_unread(rows, "type,mute")
        self.assertEqual(
            [section["title"] for section in sections],
            ["普通聊天 · 正常提醒", "公众号 · 免打扰", "企业微信 · 正常提醒"],
        )
        self.assertEqual(
            [item["chat"] for item in sections[0]["sessions"]],
            ["friend", "group"],
        )
        type_only = group_unread(rows, "type")
        self.assertEqual(
            [section["title"] for section in type_only],
            ["普通聊天", "公众号", "企业微信"],
        )


class RenderTests(unittest.TestCase):
    def test_text_sections_and_flat_list(self):
        rows = [
            (100, "alice", False, SESSION_NORMAL, ALERT_ON),
            (90, "订阅号", False, SESSION_OA, ALERT_MUTED),
        ]
        results = []
        for ts, chat, is_group, kind, alert in rows:
            results.append({
                "chat": chat,
                "username": chat,
                "is_group": is_group,
                "session_type": kind,
                "alert": alert,
                "muted": alert == ALERT_MUTED,
                "unread": 2,
                "last_message": "hi",
                "msg_type": "文本",
                "sender": "",
                "timestamp": ts,
                "time": "11-02 09:00",
            })
        text = render_unread_text(results, "type,mute")
        self.assertIn("## 普通聊天 · 正常提醒", text)
        self.assertIn("## 公众号 · 免打扰", text)
        self.assertNotIn("## 企业微信", text)
        self.assertLess(text.index("普通聊天"), text.index("公众号"))

        flat = render_unread_text(results, "none")
        self.assertNotIn("## ", flat)
        self.assertIn("[公众号]", flat)
        self.assertIn("[免打扰]", flat)

    def test_build_results_uses_contact_rows(self):
        rows = [(
            "gh_demo", 3, b"", 1_700_000_000, 1, "", "",
        )]
        built = build_unread_results(
            rows,
            {"gh_demo": "示例号"},
            {"gh_demo": {"flag": 0x200, "verify_flag": 8}},
        )
        self.assertEqual(built[0]["chat"], "示例号")
        self.assertEqual(built[0]["session_type"], SESSION_OA)
        self.assertTrue(built[0]["muted"])


class ContactQueryTests(unittest.TestCase):
    def test_reads_present_columns_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = tempfile.NamedTemporaryFile(suffix=".db", dir=tmp, delete=False).name
            conn = sqlite3.connect(path)
            conn.execute(
                "CREATE TABLE contact (username TEXT, verify_flag INT, flag INT)"
            )
            conn.execute(
                "INSERT INTO contact VALUES (?, ?, ?)",
                ("gh_demo", 8, 0x200),
            )
            conn.commit()
            conn.close()

            class Cache:
                def get(self, _key):
                    return path

            rows = get_contact_class_rows(Cache(), "", ["gh_demo", "missing"])
            self.assertEqual(rows["gh_demo"]["verify_flag"], 8)
            self.assertEqual(rows["gh_demo"]["flag"], 0x200)
            self.assertNotIn("chat_room_notify", rows["gh_demo"])
            self.assertNotIn("missing", rows)


if __name__ == "__main__":
    unittest.main()
