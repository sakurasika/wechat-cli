"""unread 命令 — 查看未读会话"""

import os
import sqlite3
from contextlib import closing
from datetime import datetime

import click

from ..core.contacts import get_contact_class_rows, get_contact_names
from ..core.messages import decompress_content, format_msg_type
from ..core.session_kind import classify_session, group_unread
from ..output.formatter import output


def _format_entry(row, show_alert=False):
    entry = f"[{row['time']}] {row['chat']}"
    if row['is_group']:
        entry += " [群]"
    if row['session_type'] != '普通聊天':
        entry += f" [{row['session_type']}]"
    if show_alert or row['muted']:
        entry += f" [{row['alert']}]"
    entry += f" ({row['unread']}条未读)"
    entry += f"\n  {row['msg_type']}: "
    if row['sender']:
        entry += f"{row['sender']}: "
    entry += row['last_message']
    return entry


def render_unread_text(results, group_by):
    if not results:
        return "没有未读消息"
    if group_by == "none":
        lines = [_format_entry(row, show_alert=True) for row in results]
        return f"未读会话（{len(results)} 个）:\n\n" + "\n\n".join(lines)

    sections = group_unread(results, group_by)
    parts = [f"未读会话（{len(results)} 个）:"]
    show_alert = group_by == "type"
    for section in sections:
        block = [f"## {section['title']}"]
        block.extend(_format_entry(row, show_alert=show_alert) for row in section["sessions"])
        parts.append("\n\n".join(block))
    return "\n\n".join(parts)


def build_unread_results(rows, names, contact_rows):
    results = []
    for username, unread, summary, ts, msg_type, sender, sender_name in rows:
        display = names.get(username, username)
        is_group = '@chatroom' in (username or '')
        kind, alert, muted = classify_session(username, contact_rows.get(username))

        if isinstance(summary, bytes):
            summary = decompress_content(summary, 4) or '(压缩内容)'
        if isinstance(summary, str) and ':\n' in summary:
            summary = summary.split(':\n', 1)[1]

        sender_display = ''
        if is_group and sender:
            sender_display = names.get(sender, sender_name or sender)

        results.append({
            'chat': display,
            'username': username,
            'is_group': is_group,
            'session_type': kind,
            'alert': alert,
            'muted': muted,
            'unread': unread or 0,
            'last_message': str(summary or ''),
            'msg_type': format_msg_type(msg_type),
            'sender': sender_display,
            'timestamp': ts,
            'time': datetime.fromtimestamp(ts).strftime('%m-%d %H:%M') if ts else '',
        })
    return results


@click.command("unread")
@click.option("--limit", default=50, help="返回的会话数量（先截取再分组）")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "text"]), help="输出格式")
@click.option(
    "--group-by",
    default="type,mute",
    show_default=True,
    type=click.Choice(["type,mute", "type", "none"]),
    help="分组：type,mute 按会话类型和免打扰，type 仅按类型，none 平铺（兼容旧列表）",
)
@click.pass_context
def unread(ctx, limit, fmt, group_by):
    """查看未读会话，并按类型与免打扰分组

    \b
    类型：普通聊天（好友+群）、公众号、企业微信
    提醒：正常提醒、免打扰

    \b
    示例:
      wechat-cli unread                         # 按类型和免打扰分组
      wechat-cli unread --format text           # 文本分段：普通聊天 · 正常提醒 …
      wechat-cli unread --group-by type         # 只按类型
      wechat-cli unread --group-by none         # 平铺列表
      wechat-cli unread --limit 10
    """
    app = ctx.obj

    path = app.cache.get(os.path.join("session", "session.db"))
    if not path:
        click.echo("错误: 无法解密 session.db", err=True)
        ctx.exit(3)

    names = get_contact_names(app.cache, app.decrypted_dir)
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_msg_sender, last_sender_display_name
            FROM SessionTable
            WHERE unread_count > 0
            ORDER BY last_timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()

    contact_rows = get_contact_class_rows(
        app.cache, app.decrypted_dir, [row[0] for row in rows]
    )
    results = build_unread_results(rows, names, contact_rows)

    if fmt == "text":
        output(render_unread_text(results, group_by), "text")
        return

    if group_by == "none":
        output(results, "json")
        return

    sections = group_unread(results, group_by)
    output({
        "total": len(results),
        "group_by": group_by,
        "groups": [
            {
                "session_type": section["session_type"],
                "alert": section["alert"],
                "title": section["title"],
                "count": len(section["sessions"]),
                "sessions": section["sessions"],
            }
            for section in sections
        ],
    }, "json")
