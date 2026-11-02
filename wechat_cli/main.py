"""wechat-cli 入口"""

import sys


def _configure_stdio():
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_configure_stdio()

import click

from .core.context import AppContext

_VERSION = "0.2.6"


@click.group()
@click.version_option(version=_VERSION, prog_name="wechat-cli")
@click.option("--config", "config_path", default=None, envvar="WECHAT_CLI_CONFIG",
              help="config.json 路径（默认自动查找）")
@click.pass_context
def cli(ctx, config_path):
    """WeChat CLI — 查询微信消息、联系人等数据

    \b
    使用示例:
      wechat-cli init                                # 首次使用：提取密钥
      wechat-cli sessions                            # 最近会话列表
      wechat-cli sessions --limit 10                 # 最近 10 个会话
      wechat-cli history "张三" --limit 20          # 查看张三的最近 20 条消息
      wechat-cli history "AI交流群" --start-time "2026-04-01"  # 指定时间范围
      wechat-cli search "Claude" --chat "AI交流群"   # 在指定群里搜索关键词
      wechat-cli search "你好" --limit 50           # 全局搜索
      wechat-cli contacts --query "李"              # 搜索联系人
      wechat-cli new-messages                       # 获取增量新消息
    """
    # init/version 不需要 AppContext。子命令 --help 也不该先要求已经 init。
    if ctx.invoked_subcommand in ("init", "version"):
        return
    if "--help" in sys.argv[1:]:
        return

    try:
        ctx.obj = AppContext(config_path)
    except FileNotFoundError as e:
        click.echo(str(e), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"初始化失败: {e}", err=True)
        sys.exit(1)


# 注册子命令
from .commands.init import init
from .commands.sessions import sessions
from .commands.history import history
from .commands.search import search
from .commands.contacts import contacts
from .commands.new_messages import new_messages
from .commands.members import members
from .commands.export import export
from .commands.stats import stats
from .commands.unread import unread
from .commands.favorites import favorites

cli.add_command(init)
cli.add_command(sessions)
cli.add_command(history)
cli.add_command(search)
cli.add_command(contacts)
cli.add_command(new_messages)
cli.add_command(members)
cli.add_command(export)
cli.add_command(stats)
cli.add_command(unread)
cli.add_command(favorites)


if __name__ == "__main__":
    cli()
