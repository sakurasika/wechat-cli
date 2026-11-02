"""未读会话的类型与免打扰分类。

依据微信 4.x contact 表（与 WeChat Linux 4.1 的实测一致）：

- 企业微信：username 以 ``@openim`` 结尾，或客服形态 ``*.openim``。
- 群：username 以 ``@chatroom`` 结尾，归入普通聊天。
- 公众号：``gh_`` 前缀、订阅号文件夹 ``brandsessionholder`` /
  ``brandservicesessionholder``，或 ``verify_flag != 0``。
  ``verify_flag != 0`` 与 ``biz_info`` 成员一一对应，不是个人好友的企业认证。
  不用 ``local_type == 3`` 单独判断公众号：那一档比公众号集合大得多。
- 免打扰：非群看 ``flag & 0x200``；群看 ``chat_room_notify == 0``
  （1 为正常提醒）。SessionTable 没有免打扰列。
"""

SESSION_NORMAL = "普通聊天"
SESSION_OA = "公众号"
SESSION_WECOM = "企业微信"

ALERT_ON = "正常提醒"
ALERT_MUTED = "免打扰"

# 订阅号 / 服务号折叠入口，本身不是 gh_ 账号。
_OA_FOLDERS = frozenset({
    "brandsessionholder",
    "brandservicesessionholder",
})

_MUTE_FLAG = 0x200

_SECTION_ORDER = (
    (SESSION_NORMAL, ALERT_ON),
    (SESSION_NORMAL, ALERT_MUTED),
    (SESSION_OA, ALERT_ON),
    (SESSION_OA, ALERT_MUTED),
    (SESSION_WECOM, ALERT_ON),
    (SESSION_WECOM, ALERT_MUTED),
)

_TYPE_ORDER = (SESSION_NORMAL, SESSION_OA, SESSION_WECOM)


def session_type(username, verify_flag=None):
    """返回 普通聊天 / 公众号 / 企业微信。"""
    name = (username or "").strip()
    lower = name.lower()
    if lower.endswith("@openim") or lower.endswith(".openim"):
        return SESSION_WECOM
    if "@chatroom" in lower:
        return SESSION_NORMAL
    if lower.startswith("gh_") or lower in _OA_FOLDERS:
        return SESSION_OA
    if verify_flag:
        return SESSION_OA
    return SESSION_NORMAL


def is_muted(username, flag=None, chat_room_notify=None):
    """未知字段按正常提醒，避免把未读塞进免打扰。"""
    name = (username or "").strip().lower()
    if "@chatroom" in name:
        return chat_room_notify == 0
    if flag is None:
        return False
    try:
        return (int(flag) & _MUTE_FLAG) != 0
    except (TypeError, ValueError):
        return False


def classify_session(username, contact=None):
    """返回 (session_type, alert, muted)。"""
    contact = contact or {}
    kind = session_type(username, verify_flag=contact.get("verify_flag"))
    muted = is_muted(
        username,
        flag=contact.get("flag"),
        chat_room_notify=contact.get("chat_room_notify"),
    )
    alert = ALERT_MUTED if muted else ALERT_ON
    return kind, alert, muted


def group_unread(results, group_by="type,mute"):
    """按固定顺序分组，空组省略。每项含 title 与 sessions。"""
    if group_by == "type":
        buckets = {key: [] for key in _TYPE_ORDER}
        for row in results:
            buckets[row["session_type"]].append(row)
        sections = []
        for key in _TYPE_ORDER:
            rows = buckets[key]
            if not rows:
                continue
            sections.append({
                "session_type": key,
                "alert": None,
                "title": key,
                "sessions": rows,
            })
        return sections

    buckets = {pair: [] for pair in _SECTION_ORDER}
    for row in results:
        buckets[(row["session_type"], row["alert"])].append(row)
    sections = []
    for kind, alert in _SECTION_ORDER:
        rows = buckets[(kind, alert)]
        if not rows:
            continue
        sections.append({
            "session_type": kind,
            "alert": alert,
            "title": f"{kind} · {alert}",
            "sessions": rows,
        })
    return sections
