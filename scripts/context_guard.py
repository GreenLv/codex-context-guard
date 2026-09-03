#!/usr/bin/env python3
"""Context Guard: local Codex hook runtime with no third-party dependencies."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 9
READ_ONLY_COMPATIBILITY_SCHEMAS = {7, 8}
STOP_PROTOCOL_VERSION = "2.1.0"
CLASSIFIER_VERSION = "2.4.0"
PROOF_PROTOCOL_VERSION = "1.0.0"
EXECUTION_PROTOCOL_VERSION = "2.0.0"
WORK_UNIT_PROTOCOL_VERSION = "1.0.0"
ADAPTER_MANIFEST_VERSION = "1.0.0"
CURRENT_RELEASE_READINESS_SCHEMA = "release-readiness/v3"
SUPPORTED_RELEASE_READINESS_SCHEMAS = frozenset(
    {"release-readiness/v2", CURRENT_RELEASE_READINESS_SCHEMA}
)
CLAUSE_DERIVATION_VERSION = "1.0.0"
ADAPTER_MANIFEST = {
    "version": ADAPTER_MANIFEST_VERSION,
    "adapters": {
        "file_read": "1.0.0",
        "thread_read": "1.0.0",
        "shell_read": "1.0.0",
        "visual_read": "1.0.0",
    },
}

PRIVATE_CONTROL_TOKEN_BYTES = 24
PRIVATE_CONTROL_TOKEN_LENGTH = (PRIVATE_CONTROL_TOKEN_BYTES * 8 + 5) // 6
DECISION_LOG_LIMIT = 32
RECOVERY_CHAR_LIMIT = 15000
RECOVERY_COMPLETION_RULE = (
    "## Completion rule\nDo not declare completion unless every non-superseded "
    "requirement and acceptance item passes with concrete evidence and open_items "
    "is empty."
)
EVIDENCE_LIMIT = 200
AGENT_RECORD_LIMIT = 64
PLAN_STEP_LIMIT = 32
SUBAGENT_CONTEXT_CHAR_LIMIT = 3000
RETENTION_DAYS = 30
SUCCESSOR_INPUT_FILENAME = "SUCCESSOR_INPUT.json"
SUCCESSOR_HANDOFF_FILENAME = "CONTEXT_HANDOFF.md"
SUCCESSOR_MANIFEST_FILENAME = "CONTEXT_MANIFEST.json"
MAX_SUCCESSOR_INPUT_BYTES = 64 * 1024
MAX_SUCCESSOR_CURRENT_READS = 12
MAX_SUCCESSOR_FULL_READ_BYTES = 96 * 1024
MAX_SUCCESSOR_TARGETED_LINES = 1200
MAX_SUCCESSOR_HASH_BYTES = 256 * 1024 * 1024
MAX_SUCCESSOR_AUDIT_FILES = 80
MAX_SUCCESSOR_AUDIT_BYTES = 256 * 1024 * 1024
TRANSCRIPT_TAIL_BYTES = 2 * 1024 * 1024
MAX_ASSET_BYTES = 64 * 1024 * 1024
MAX_PROOF_MANIFEST_BYTES = 64 * 1024
MAX_EXECUTION_STATE_BYTES = 64 * 1024
MAX_EXECUTION_DEPTH = 8
MAX_EXECUTION_STRING = 512
MAX_EXECUTION_RECORDS = 64
MAX_EXECUTION_TICKETS = 128
PROCESS_SESSION_LOCKS_GUARD = threading.Lock()
PROCESS_SESSION_LOCKS: dict[str, threading.Lock] = {}
STATE_REQUIRED_KEYS = {
    "schema_version",
    "session",
    "mode",
    "prompts",
    "requirements",
    "acceptance_items",
    "supersedes",
    "evidence",
    "evidence_sequence",
    "assets",
    "asset_sequence",
    "proofs",
    "proof_sequence",
    "work_state",
    "work_units",
    "work_unit_sequence",
    "agents",
    "open_items",
    "compactions",
    "completion_attempt",
    "completion_checkpoint",
    "continuation_attempts",
    "decision_log",
    "execution",
    "adapter_manifest",
    "classifier_metadata",
    "pending",
    "prompt_journal",
    "integrity",
    "content_hash",
}
ASSET_ID_RE = re.compile(r"M\d{4,}")
PROOF_ID_RE = re.compile(r"V\d{4,}")
EXECUTION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
# Windows drive-path lexically supported by subject capture (v1 set): drive
# absolute paths with either separator, including Markdown link targets. An
# ASCII colon inside the body is captured on purpose so alternate data
# streams classify as the unsupported ``ads`` form instead of silently
# truncating the locator; full-width CJK punctuation ends the match.
WINDOWS_DRIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_:\\/])(?:[A-Za-z]):[\\/][^\s<>\"|?*\[\]：；，。！？]*",
)
# UNC and device-path forms are captured only to classify them as
# unsupported; they never become bindable subjects.
WINDOWS_UNC_PATH_RE = re.compile(r"\\\\[^\s<>:\"|?*\[\]：；，。！？]*")
# Word-boundary-disciplined physical-identity capture signal. The English
# tokens use explicit ASCII boundaries (never Unicode \b); the Chinese tokens
# are exact phrases.
PHYSICAL_IDENTITY_SIGNAL_RE = re.compile(
    r"(?<![A-Za-z0-9_-])anti-junction(?![A-Za-z0-9_-])"
    r"|(?<![A-Za-z0-9_-])junction(?![A-Za-z0-9_-])"
    r"|(?<![A-Za-z0-9_-])reparse(?![A-Za-z0-9_-])"
    r"|(?<![A-Za-z0-9_-])physical identity(?![A-Za-z0-9_-])"
    r"|物理身份"
    r"|无\s*reparse",
    re.IGNORECASE,
)
# Opaque subjects for lexically unsupported Windows locator forms. The opaque
# string is the final subject id; it is never re-wrapped and never bindable.
UNSUPPORTED_SUBJECT_PREFIX = "codex:unsupported/"
UNSUPPORTED_LOCATOR_DOMAIN = "ccg.locator.v1\n"
UNSUPPORTED_REASON_TOKENS = (
    "unc",
    "device_path",
    "ads",
    "beyond_root",
    "reserved_name",
    "trailing_dots_spaces",
    "physical_identity",
)
WINDOWS_RESERVED_COMPONENT_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
THREAD_URI_PREFIX = "codex://threads/"
THREAD_ID_RE = re.compile(r"^[0-9a-f][0-9a-f-]{15,}", re.IGNORECASE)
# Exact, versioned thread-read tool names. Only these tools give a bare
# threadId argument its codex://threads/<uuid> subject semantics; no other
# tool output may bind a thread subject.
THREAD_READ_TOOL_ALIASES = {"read_thread"}
CONTRACT_STATES = {
    "absent", "candidate", "inactive", "active", "stale", "conflicted",
    "rejected", "superseded",
}
CONTRACT_TRANSITIONS = {
    "absent": {"candidate"},
    "candidate": {"inactive", "active", "conflicted", "rejected", "superseded"},
    "inactive": {"active", "conflicted", "rejected", "superseded"},
    "active": {"stale", "conflicted", "superseded"},
    "stale": {"candidate", "conflicted", "rejected", "superseded"},
    "conflicted": {"candidate", "inactive", "rejected", "superseded"},
    "rejected": {"candidate", "superseded"},
    "superseded": set(),
}
PHASE_STATES = {"pending", "passed", "failed", "waived", "stale", "conflicted", "superseded"}
PHASE_TRANSITIONS = {
    "pending": {"passed", "failed", "waived", "conflicted", "superseded"},
    "passed": {"stale", "conflicted", "superseded"},
    "failed": {"pending", "waived", "superseded"},
    "waived": {"stale", "superseded"},
    "stale": {"pending", "conflicted", "superseded"},
    "conflicted": {"pending", "waived", "superseded"},
    "superseded": set(),
}
TICKET_STATES = {"reserved", "in_flight", "consumed", "invalidated", "expired"}
TICKET_TRANSITIONS = {
    "reserved": {"in_flight", "invalidated", "expired"},
    "in_flight": {"reserved", "consumed", "invalidated", "expired"},
    "consumed": set(),
    "invalidated": set(),
    "expired": set(),
}
FORBIDDEN_EXECUTION_KEYS = {
    "command", "content", "cwd", "path", "prompt", "raw_prompt", "secret",
    "text", "token", "tool_input",
}
ABSOLUTE_PATH_RE = re.compile(
    r"(?<![\w:/\\])(?:/[\w.@+~\-\u0080-\uffff][^\s,;，；。!?！？'\"<>]*)"
)
URL_RE = re.compile(
    r"(?:https?://[^\s,;，；。!?！？'\"<>]+|codex://threads/[0-9a-f-]{20,})",
    re.IGNORECASE,
)
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}
IMAGE_REFERENCE_RE = re.compile(r"(?:截图|图片|图像|image|screenshot|visual)", re.IGNORECASE)
# Schema-8 clause polarity: a clause matching this pattern is negative
# (prohibition / non-goal) and never derives protection subjects, physical
# identity obligations, or surface escalation.
CLAUSE_NEGATION_RE = re.compile(
    r"\b(?:do\s+not|don't|must\s+not|should\s+not|no|without)\b|"
    r"(?:不要|不得|无需|不需要|暂不|不再|别|切勿|勿|不跑|不执行)",
    re.IGNORECASE,
)
VISUAL_MUTATION_RE = re.compile(
    r"(?:修改|修复|调整|更新|替换|编辑|生成|渲染|展示|显示|改成|"
    r"edit|fix|change|update|replace|generate|render|display)",
    re.IGNORECASE,
)
FULL_SCOPE_RE = re.compile(
    r"(?:全部|所有|完整|整个|全量|每(?:个|一)|\b(?:all|every|entire|whole|complete|full)\b)",
    re.IGNORECASE,
)
FULL_SCOPE_NEGATION_RE = re.compile(
    r"(?:\b(?:not|without)\s+(?:all|every|complete|full)\b|"
    r"(?:不要|无需|不需要|并非|不是|不必)\s*(?:全部|所有|完整|整个|全量)|"
    r"(?:仅|只)\s*(?:处理|核验|检查|修改|覆盖)?\s*(?:部分|选定|指定)|"
    r"\bno\s+(?:scope\s+|full\s+)?verification\s+is\s+requested\b)",
    re.IGNORECASE,
)
SCOPE_CARDINALITY_PATTERNS = (    re.compile(
        r"(?:全部|所有|全量|每(?:个|一))\s*(\d{1,5})\s*"
        r"(?:个|项|条|张|份|套|组)?\s*"
        r"[\u4e00-\u9fffA-Za-z_-]{0,8}?"
        r"(?:条目|项目|文件|截图|图片|测试|用例|记录|页面|对象|结果)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:all|every)\s+(?:the\s+)?(\d{1,5})\s+"
        r"(?:items?|entries|files?|screenshots?|images?|tests?|cases?|"
        r"records?|pages?|objects?|results?)\b",
        re.IGNORECASE,
    ),
)
COMPLETE_RATIO_RE = re.compile(r"(?<!\d)(\d{1,5})\s*/\s*\1(?!\d)")
# UI surface signals with lexical discipline (v0.9.5, CG-1a): English tokens
# use explicit ASCII boundaries via lookarounds (never Unicode \b), the
# standalone Chinese noun 列 is gone, and the ambiguous 页面/可见 words match
# only inside context phrases. Explicit UI requests must still produce an
# enforced UI obligation; proof strictness is not relaxed.
UI_SURFACE_RE = re.compile(
    r"(?<![A-Za-z0-9_])GUI(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])UI(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])(?:screen|browser|window)s?(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])visible(?![A-Za-z0-9_])"
    r"|界面|窗口|浏览器|网页|应用(?:界面|页面|窗口)"
    r"|(?:GUI|UI|界面|网页|应用)[\s]{0,2}页面"
    r"|可见(?!性)[^。；;.\n]{0,6}(?:结果|界面|窗口|浏览器)"
    r"|(?:界面|窗口|浏览器|结果)[^。；;.\n]{0,6}可见(?!性)",
    re.IGNORECASE,
)
CHECKPOINT_RE = re.compile(
    r"<!--\s*context-guard-checkpoint\s*(\{.*?\})\s*-->",
    re.IGNORECASE | re.DOTALL,
)
COMPLETION_RE = re.compile(
    r"\b(done|complete[dn]?|finished|implemented|resolved|fixed|shipped|"
    r"deployed|verified|committed|pushed|ready|all tests pass|"
    r"tests?\s+(?:all\s+)?pass(?:ed)?)\b|"
    r"(已完成|已经完成|全部完成|任务完成|实现完毕|验收通过|已经解决|"
    r"已修复|已经修复|修复完成|已处理|处理完毕|处理好了|已交付|可以交付|"
    r"已部署|已更新|已提交|已推送|已验证|修好了|搞定了|可以使用了|"
    r"(?:测试|校验|验证|检查|回归|技能).{0,12}(?:已)?(?:全部|全量|均)?通过)",
    re.IGNORECASE,
)
WHOLE_COMPLETION_RE = re.compile(
    r"^\s*(?:done|complete[dn]?|finished|resolved|fixed)\s*[.!。！]?\s*$|"
    r"^\s*(?:(?:the|this)\s+)?(?:task|request|plan|project|work)\s+"
    r"(?:(?:is|has\s+been)\s+)?(?:fully\s+|safely\s+)?"
    r"(?:done|complete[dn]?|finished|resolved|fixed)\s*[.!。！]?\s*$|"
    r"\b(?:I|we)\s+(?:now\s+)?(?:consider|declare|regard|confirm)\s+"
    r"(?:(?:the|this)\s+)?(?:task|request|plan|project|work)\s+"
    r"(?:fully\s+|safely\s+)?(?:done|complete[dn]?|finished|resolved|fixed)\b|"
    r"\b(?:(?:the|this|entire|whole|overall|full)\s+)?"
    r"(?:tasks?|requests?|plans?|projects?|work|items?)\s+"
    r"(?:(?:is|are)\s+|(?:has|have)\s+been\s+)"
    r"(?:fully\s+|safely\s+)?(?:done|complete[dn]?|finished|resolved|fixed)\b|"
    r"\b(?:everything|all\s+(?:requested\s+)?(?:work|tasks?|requirements?|items?)"
    r"|every\s+(?:single\s+)?(?:task|request|requirement|item|plan|project))"
    r"\s+(?:(?:is|are)\s+|(?:has|have)\s+been\s+)?"
    r"(?:done|complete[dn]?|finished|resolved|fixed|satisfied)\b|"
    r"(?:整个|整体|全部|所有|本次|当前)(?:任务|工作|需求|计划|项目)"
    r".{0,16}(?:已|已经|均已|全部)?(?:完成|结束|解决|修复)|"
    r"(?:任务|工作|需求|计划|项目).{0,12}(?:已|已经|均已|都|全部|整体)"
    r"(?:完成|结束|解决|修复)|"
    r"^\s*(?:已完成|全部完成|任务完成|搞定了)\s*[。！!]?\s*$",
    re.IGNORECASE | re.DOTALL,
)
FIRST_PERSON_COMPLETION_ASSERTION_RE = re.compile(
    r"\b(?:I|we)\s+(?:now\s+)?"
    r"(?:say|said|state|stated|declare|declared|consider|regard|confirm|"
    r"report|reported)\b.{0,64}$|"
    r"(?:我|我们)(?:现在)?(?:认为|确认|宣布|判定|声明).{0,40}$",
    re.IGNORECASE | re.DOTALL,
)
NONASSERTIVE_COMPLETION_CONTEXT_RE = re.compile(
    r"\b(?:may|might|could|would|should)\b.{0,64}"
    r"\b(?:call|claim|declare|describe|label|mark|present|report|say|treat)\b.{0,48}$|"
    r"\b(?:call(?:ing|s|ed)?|claim(?:ing|s|ed)?|declar(?:e|es|ed|ing)|"
    r"describ(?:e|es|ed|ing)|label(?:s|ed|ing)?|mark(?:s|ed|ing)?|"
    r"quot(?:e|es|ed|ing)|report(?:s|ed|ing)?|say(?:s|ing)?|said|"
    r"treat(?:s|ed|ing)?)\b.{0,64}$|"
    r"(?:可能|也许|或许|假如|假设|会|可能会).{0,32}"
    r"(?:称|声称|宣称|认为|描述|标记|写成|说成).{0,32}$|"
    r"(?:称|声称|宣称|认为|描述|标记|写着|写成|说成).{0,40}$",
    re.IGNORECASE | re.DOTALL,
)
COMPLETION_DISCUSSION_RE = re.compile(
    r"\b(?:article|case|docs?|documentation|example|hypothetical|phrase|"
    r"quotation?|quoted|scenario|text|wording)\b|"
    r"(?:文章|案例|文档|示例|反例|假设|场景|引文|引用|措辞|表述|说法|文案)",
    re.IGNORECASE,
)
QUOTED_COMPLETION_DISCUSSION_SUFFIX_RE = re.compile(
    r"^\s*(?:[”’」』\"`]\s*)?"
    r"(?:(?:这|此|同)?类|这种|这样的|上述)"
    r"(?:声明|说法|表述|措辞|文案|文本|字样|提示|消息)",
    re.IGNORECASE,
)
USER_PERSISTENCE_RE = re.compile(
    r"\b(?:(?:do\s+not|don't|never)\s+(?:stop|pause|yield|end)\s+"
    r"(?:working|on\s+(?:this|the)\s+(?:task|work)|while\s+.{0,24}remains?|"
    r"until\s+.{0,64}(?:done|complete[dn]?|finish(?:ed|es)?))|"
    r"(?:keep\s+(?:going|working)|continue\s+(?:working\s+)?)"
    r".{0,40}(?:until|through\s+to).{0,40}(?:done|complete[dn]?|finished))\b|"
    r"(?:不要|不得|别|切勿|不能).{0,12}(?:停止|停下|停|暂停|中止|结束)"
    r".{0,32}(?:直到|直至).{0,32}(?:完成|结束)|"
    r"(?:持续|继续|一直).{0,24}(?:执行|推进|工作)"
    r".{0,32}(?:直到|直至).{0,32}(?:完成|结束)|"
    r"(?:不要|不得|别|切勿).{0,24}(?:工作|任务|事项)"
    r".{0,24}(?:仍|还|尚).{0,8}(?:可执行|未完成).{0,16}(?:停止|结束)",
    re.IGNORECASE | re.DOTALL,
)
NON_COMPLETION_RE = re.compile(
    r"\b(not\s+(?:(?:yet|fully|safely)\s+)*(?:done|complete[dn]?|finished|implemented)|"
    r"unfinished|incomplete|remaining|still\s+need|could(?:n't| not)\s+complete|"
    r"(?:await(?:ing)?|wait(?:ing)?\s+for)\s+"
    r"(?:(?:your|user(?:'s)?)\s+)?(?:approval|authorization|confirmation|"
    r"decision|choice|input|response|acceptance)|"
    r"(?:blocked\s+(?:by|on)|waiting\s+for\s+(?:you|the\s+user)\s+to)\s+.{0,48}|"
    r"(?:need|require)\s+(?:you|the\s+user)\s+to\s+"
    r"(?:act|approve|authorize|confirm|decide|choose|log\s*in|sign\s*in|unlock|open|configure|"
    r"reply|respond)|"
    r"please\s+(?:act|approve|authorize|confirm|decide|choose|log\s*in|open|"
    r"configure|reply|respond)|"
    r"(?:after|once|when)\s+(?:you|the\s+user)\s+.{0,48}"
    r"(?:reply|respond|tell\s+me|let\s+me\s+know)|"
    r"(?:can(?:not|'t)|unable\s+to)\s+(?:safely\s+)?(?:continue|proceed|act)|"
    r"(?:need|require)\s+(?:your|user(?:'s)?)\s+(?:explicit\s+)?"
    r"(?:approval|authorization|confirmation|decision|choice|input|response|acceptance)|"
    r"(?:can(?:not|'t)|should(?:not|n't)|unable\s+to)\s+"
    r"(?:claim|declare|report|say).{0,40}\b(?:done|complete[dn]?|finished))\b|"
    r"(未(?:全部|完全|整体)?完成|尚未(?:全部|完全|整体)?(?:完成|结束)|"
    r"还未(?:全部|完全|整体)?完成|未实现|无法完成|未能完成|"
    r"(?:不能|无法|不可|不应|尚不能).{0,24}(?:宣告|声明|声称).{0,16}完成|"
    r"(?:原始|整个|整体|当前)?任务.{0,16}(?:仍|尚|还)(?:待|需)|"
    r"(?:尚未|还未).{0,20}(?:导入|下载|写入|执行|开始)|"
    r"(?:等待|待)(?:你|您|用户)?(?:的)?(?:明确)?"
    r"(?:验收|确认|授权|批准|审批|决定|选择|操作|回复|输入)|"
    r"(?:你|您|用户).{0,8}(?:需要|请).{0,8}"
    r"(?:验收|确认|授权|批准|审批|决定|选择|操作|登录|打开|配置|回复|输入)|"
    r"(?:必须|需要|须)(?:先)?(?:由)?(?:你|您|用户)(?:本人)?(?:先)?"
    r"(?:完成|操作|登录|打开|配置|批准|审批|确认|授权|决定|选择|回复|输入)|"
    r"(?:下一步|接下来).{0,8}(?:需要|请)(?:你|您|用户).{0,8}"
    r"(?:做|操作|登录|打开|配置|批准|审批|确认|回复)|"
    r"(?:配置|完成|操作|登录|打开|批准|审批).{0,12}"
    r"(?:后|之后|以后).{0,12}"
    r"(?:回复(?:我|我们)?(?=$|[\s，。,:：；;“”'\"「」『』])|"
    r"告诉(?:我|我们)|通知(?:我|我们))|"
    r"(?:必须|需要)(?:先)?(?:得到|获得|收到|等待).{0,16}"
    r"(?:验收|确认|授权|批准|审批|决定|选择|回复|输入)|"
    r"(?:无法|不能|不可|尚不能)(?:安全)?(?:继续|推进|执行|操作)|"
    r"仍待处理|仍需继续|还需要|(?:被|因).{0,32}(?:阻塞|卡住)|阻塞[：:])",
    re.IGNORECASE,
)
# A status-only reply can legitimately end a turn while work is externally
# pending or explicitly paused by policy. Keep this separate from user-action
# handoffs so both categories stay narrow and independently regression-tested.
EXPLICIT_HOLD_RE = re.compile(
    r"\b(?:"
    r"(?:submitted|filed|listed|applied).{0,32}"
    r"(?:pending|awaiting|waiting\s+for).{0,24}"
    r"(?:review|approval|response|decision|selection|listing|inclusion|result)|"
    r"(?:pr|pull\s+request|submission|listing).{0,24}"
    r"(?:remain(?:s|ed)?|is|are)?\s*(?:pending|awaiting|on\s+hold)|"
    r"(?:pending|awaiting|waiting\s+for)\s+"
    r"(?:(?:external|third[- ]party|platform|maintainer|reviewer)\s+)?"
    r"(?:review|approval|response|decision|selection|listing|inclusion|result)|"
    r"(?:remain(?:s|ed)?|still|currently|continue(?:s|d)?\s+to\s+be).{0,48}"
    r"(?:paused|on\s+hold|deferred|pending|awaiting)|"
    r"(?:not|no\s+longer)\s+"
    r"(?:proceeding|submitting|publishing|promoting|modifying)|"
    r"(?:no|without)\s+(?:new\s+)?"
    r"(?:publication|submission|repository\s+changes?|code\s+changes?|"
    r"writes?|mutations?|promotion|external\s+actions?)"
    r")\b|"
    r"(?:"
    r"(?:已提交|已申请|已投稿|已登记).{0,32}(?:等待|待)"
    r"(?:(?:外部|第三方|平台|维护者|审核方|对方)(?:的)?)?"
    r"(?:审核|审查|批准|回复|答复|决定|结果|选择|收录)|"
    r"(?:仍|继续|保持|目前|当前).{0,24}(?:等待|待)"
    r"(?:(?:外部|第三方|平台|维护者|审核方|对方)(?:的)?)?"
    r"(?:审核|审查|批准|回复|答复|决定|结果|选择|收录)|"
    r"(?:等待|待)(?:(?:外部|第三方|平台|维护者|审核方|对方)(?:的)?)"
    r"(?:审核|审查|批准|回复|答复|决定|结果|选择|收录)|"
    r"(?:仍|继续|目前|当前|暂时|暂不|按.{0,12}要求).{0,32}"
    r"(?:暂停|搁置|不(?:再)?(?:执行|提交|发布|推广|修改|写入|处理|推进|投稿))|"
    r"(?:没有|未)(?:进行|发生|执行|重复)?(?:任何|新的|新)?.{0,12}"
    r"(?:发布|投稿|提交|推广|写入|变更|外部操作)|"
    r"(?:没有|未)(?:进行|发生|执行|重复)?(?:任何|新的|新)?.{0,12}"
    r"(?:修改.{0,8}(?:仓库|代码|项目)|(?:仓库|代码|项目).{0,8}修改)"
    r")",
    re.IGNORECASE,
)
# A bounded user turn can legitimately complete a local review, test, or commit
# while explicitly leaving a more expansive phase for later authorization. The
# assistant wording alone is ambiguous: the same "next phase remains" sentence
# must still be gated after a broad "continue/finish/push" instruction. Keep the
# prompt and reply classifiers separate so the Stop decision is scope-aware.
BOUNDED_TURN_PROMPT_RE = re.compile(
    r"\b(?:review|audit|inspect|check|test|verify|commit|stage|report|explain)\b|"
    r"(?:审查|审核|检查|评估|测试|验证|本地提交|提交(?:改动|变更|代码)?|汇报|解释)",
    re.IGNORECASE,
)
EN_BROAD_EXECUTION_ACTION = (
    r"(?:continue|proceed|"
    r"(?:finish|complete|execute)\s+(?:(?:the|this)\s+)?"
    r"(?:entire|whole|remaining)|push|publish|deploy|promote|"
    r"create.{0,16}(?:repo(?:sitory)?|remote)|run.{0,8}ci)"
)
ZH_BROAD_EXECUTION_ACTION = (
    r"(?:继续|收尾|(?:完成|执行)(?:整个|整体|完整|全部|剩余)|"
    r"推送|发布|部署|推广|创建.{0,12}(?:远端|仓库)|"
    r"(?:运行|跑).{0,8}CI)"
)
BROAD_EXECUTION_PROMPT_RE = re.compile(
    rf"\b{EN_BROAD_EXECUTION_ACTION}\b|{ZH_BROAD_EXECUTION_ACTION}",
    re.IGNORECASE | re.DOTALL,
)
DEFERRED_ACTION_CLAUSE_RE = re.compile(
    r"\b(?:defer(?:red)?|paused|on\s+hold|out\s+of\s+scope|"
    r"outside\s+.{0,20}\bscope|denied)\b|"
    r"(?:留待|推迟|延后|暂停|搁置|超出.{0,12}范围|"
    r"不在.{0,12}范围|被拒绝)",
    re.IGNORECASE | re.DOTALL,
)
REMAINING_WORK_RE = re.compile(
    r"\b(?:next|later|subsequent|future)\s+(?:phase|step|turn)|"
    r"\b(?:remain(?:s|ing)?|still)\s+(?:need|require|pending)|"
    r"\b(?:defer(?:red)?|leave|left)\s+.{0,32}(?:later|next|future)|"
    r"\bnext\s+i\s+will\b|\bi\s+will\s+(?:next|then)\b|"
    r"(?:下一|后续)(?:个)?(?:阶段|步|轮)|(?:仍|还|尚)(?:需|需要|待)|"
    r"(?:留待|推迟到|延后到)(?:下一|后续)|"
    r"\bthen\s+continue\b|(?:然后|随后)继续|"
    r"(?:接下来|随后|与此同时).{0,16}(?:我会|我将|会|需要|仍需)|"
    r"后续.{0,12}(?:处理|执行|完成)",
    re.IGNORECASE | re.DOTALL,
)
USER_HANDOFF_RE = re.compile(
    r"\b(?:await(?:ing)?|wait(?:ing)?)\s+for\s+"
    r"(?:(?:your|user(?:'s)?)\s+)?(?:approval|authorization|confirmation|"
    r"decision|choice|input|response|acceptance)|"
    r"\b(?:need|require)\s+(?:you|the\s+user)\s+to\s+"
    r"(?:act|approve|authorize|confirm|decide|choose|log\s*in|open|configure|"
    r"reply|respond)|\bplease\s+(?:act|approve|authorize|confirm|decide|choose|"
    r"log\s*in|sign\s*in|unlock|open|configure|reply|respond)|"
    r"\bwait(?:ing)?\s+for\s+(?:(?:you|the\s+user)\s+)?to\s+"
    r"(?:act|approve|authorize|confirm|decide|choose|log\s*in|sign\s*in|unlock|configure|reply|respond)|"
    r"\b(?:cannot|can't|unable\s+to)\s+(?:safely\s+)?(?:continue|proceed)\s+"
    r"without\s+(?:your|user(?:'s)?)\s+(?:approval|authorization|confirmation|input)|"
    r"\b(?:when|once|after)\s+(?:that(?:'s|\s+is)?\s+)?done.{0,24}"
    r"(?:tell\s+me|let\s+me\s+know|reply|respond)|"
    r"(?:等待|待)(?:你|您|用户)?(?:的)?(?:明确)?"
    r"(?:验收|确认|授权|批准|审批|决定|选择|操作|回复|输入)|"
    r"(?:请|需要|必须|须)(?:先)?(?:由)?(?:你|您|用户)(?:本人)?(?:先)?"
    r".{0,48}(?:验收|确认|授权|批准|审批|决定|选择|操作|登录|重新登录|解锁|打开|配置|回复|输入)|"
    r"(?:你|您|用户).{0,12}(?:需要|请).{0,16}"
    r"(?:验收|确认|授权|批准|审批|决定|选择|操作|登录|重新登录|解锁|打开|配置|回复|输入)|"
    r"(?:等待|待).{0,16}(?:你|您|用户).{0,12}(?:批准|确认|授权|回复|操作)|"
    r"(?:请|需要你|下一步需要你).{0,48}(?:回复|告诉|通知|登录|重新登录|解锁|打开|配置|批准|确认)|"
    r"(?:完成|配置|批准|确认).{0,16}(?:后|之后).{0,16}(?:回复|告诉我|通知我)|"
    r"(?:等待|待).{0,16}(?:批次)?确认",
    re.IGNORECASE | re.DOTALL,
)
EXPLICIT_ASSISTANT_FUTURE_RE = re.compile(
    r"\bI\s+(?:will|need\s+to)\b|"
    r"\b(?:next|then|afterwards?)\s+I(?:'ll|\s+will)\b|"
    r"(?:我会|我将|我需|需要我|接下来我)|"
    r"(?:接下来|随后|然后|之后|下一步)(?:我)?(?:会|将)?"
    r".{0,8}(?:继续|修改|实现|更新|推送|发布|部署|运行|测试|验证|处理|执行|配置)",
    re.IGNORECASE,
)
USER_DEPENDENT_ASSISTANT_RE = re.compile(
    r"\b(?:after|once|when)\s+(?:you|the\s+user)\b|"
    r"\b(?:after|once|when)\s+(?:your|the\s+user(?:'s)?)\s+"
    r"(?:approval|authorization|confirmation|login|sign[- ]?in|reply|response)|"
    r"(?:等|待)(?:你|您|用户).{0,32}(?:后|之后)|"
    r"(?:你|您|用户).{0,24}(?:完成|确认|批准|授权|登录|重新登录|解锁|回复).{0,12}(?:后|之后)|"
    r"(?:完成|确认|批准|授权|登录|重新登录|解锁|回复).{0,12}(?:后|之后).{0,20}"
    r"(?:我会|我将|我需|需要我)|"
    r"(?:收到|得到|获得).{0,20}(?:后|之后).{0,20}"
    r"(?:我会|我将|我需|需要我)|"
    r"\b(?:when|once|after)\s+(?:that(?:'s|\s+is)?\s+)?done.{0,48}"
    r"(?:then|afterwards?)?\s*I(?:'ll|\s+will)\b|"
    r"\b(?:tell\s+me|let\s+me\s+know|reply|respond).{0,40}"
    r"(?:then|afterwards?)\s*I(?:'ll|\s+will)\b",
    re.IGNORECASE | re.DOTALL,
)
PARALLEL_ASSISTANT_RE = re.compile(
    r"\b(?:meanwhile|in\s+the\s+meantime|while\s+(?:you|the\s+user|we)?\s*wait)\b|"
    r"(?:与此同时|同时|等待期间|在等待.{0,16}期间)",
    re.IGNORECASE | re.DOTALL,
)
EXTERNAL_WAIT_RE = re.compile(
    r"\b(?:pending|awaiting|waiting\s+for)\s+"
    r"(?:(?:external|third[- ]party|platform|maintainer|reviewer)\s+)?"
    r"(?:review|approval|response|decision|selection|listing|inclusion|result)|"
    r"\b(?:pr|pull\s+request|submission|listing).{0,24}"
    r"(?:remain(?:s|ed)?|is|are)?\s*(?:pending|awaiting|on\s+hold)|"
    r"(?:等待|待)(?:(?:外部|第三方|平台|维护者|审核方|对方)(?:的)?)?"
    r"(?:审核|审查|批准|回复|答复|决定|结果|选择|收录)|"
    r"(?:PR|申请|投稿|提交).{0,20}(?:仍|继续|保持|目前|当前)?(?:等待|待)"
    r"(?:审核|审查|批准|回复|答复|决定|结果|选择|收录)",
    re.IGNORECASE | re.DOTALL,
)
POLICY_HOLD_RE = re.compile(
    r"\b(?:paused|on\s+hold|not\s+proceeding|do\s+not\s+proceed|"
    r"no\s+(?:new\s+)?(?:publication|submission|repository\s+changes?|"
    r"writes?|mutations?|promotion|external\s+actions?))\b|"
    r"(?:暂停|搁置|暂不|不再|没有|未).{0,28}"
    r"(?:发布|投稿|推广|写入|变更|外部操作|修改.{0,8}(?:仓库|代码|项目))",
    re.IGNORECASE | re.DOTALL,
)

# Categories are intentionally stable diagnostic identifiers. They describe the
# action, not the surrounding natural-language clause, so decision_log never
# needs to retain raw prompt or reply text.
ACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("local_review", re.compile(r"\b(?:review|audit|inspect|check)\b|(?:审查|审核|检查|评估)", re.I)),
    ("local_edit", re.compile(r"\b(?:edit|modify|implement|update\s+(?:the\s+)?(?:code|repository))\b|(?:实现|修改|更新)(?:.{0,10}(?:代码|仓库|项目))?", re.I)),
    ("local_commit", re.compile(r"\bcommit(?:ted|ting)?\b|(?:本地提交|提交(?:改动|变更|代码))", re.I)),
    ("remote_create", re.compile(r"\bcreat(?:e|ing).{0,18}(?:remote|repo(?:sitory)?)\b|创建.{0,12}(?:远端|仓库)", re.I)),
    ("remote_push", re.compile(r"\bpush(?:ed|ing)?\b|推送", re.I)),
    ("remote_publish", re.compile(r"\b(?:publish|deploy|promot|release|blog|community\s+post)\w*\b|(?:发布|部署|推广|博客|社区发帖|正式版本)", re.I)),
    ("remote_ci", re.compile(r"\b(?:run(?:ning)?\s+)?ci\b|(?:运行|跑).{0,8}CI", re.I)),
    ("review_followup", re.compile(r"\b(?:address|handle|process|check).{0,24}(?:review\s+(?:comment|feedback)|review\s+log)\b|(?:处理|检查).{0,16}(?:审查意见|审核意见|审核日志)", re.I)),
    ("test_verify", re.compile(r"\b(?:test|verify|validate|validation)\w*\b|(?:测试|验证|校验)", re.I)),
    ("artifact_work", re.compile(r"\b(?:import|download|configure|configuration)\w*\b|(?:导入|下载|配置|打开页面|处理PDF|PDF\s*阶段)", re.I)),
)
# A trailing test/verify signal certifies a concrete action rather than
# replacing it. Review/CI signals remain verification operations themselves,
# so combinations such as "check and verify" stay deliberately ambiguous.
PRIMARY_CLAUSE_ACTIONS = {
    "local_edit",
    "local_commit",
    "remote_create",
    "remote_push",
    "remote_publish",
    "artifact_work",
}
REPLY_ACTION_NEGATION_PREFIX_RE = re.compile(
    r"\b(?:do\s+not|don't|does\s+not|doesn't|will\s+not|won't|never|"
    r"without|avoid(?:s|ed|ing)?)\b.{0,48}$|"
    r"(?:不|不要|不会|不得|未|没有|并非|不是|避免|无需|不需要).{0,40}$",
    re.IGNORECASE | re.DOTALL,
)
ACTION_MENTION_SUFFIX_RE = re.compile(
    r"^\s*(?:article|case|docs?|documentation|example|guide|phrase|reference|"
    r"scenario|text|tutorial|wording|文章|案例|文档|示例|指南|教程|说法|表述)",
    re.IGNORECASE,
)
INTERNAL_CONTINUATION_PREFIX = "[Context Guard continuation]"
EVIDENCE_ID_RE = re.compile(r"^E\d{4,}$")
STAGE_REQUEST_MARKER = "CONTEXT_GUARD_STAGE_REQUEST"
DISPOSITION_REQUEST_MARKER = "CONTEXT_GUARD_DISPOSITION_REQUEST"
PROOF_REQUEST_MARKER = "CONTEXT_GUARD_PROOF_REQUEST"
DISPOSITION_REASONS = {
    "continue": "assistant_work_remains",
    "user_wait": "user_action_required",
    "external_wait": "external_dependency",
    "deferred": "denied_or_out_of_scope",
}
PRIVATE_METADATA_RE = re.compile(
    r"context-guard-checkpoint|checkpoint-status|stage-checkpoint|"
    r"stage-disposition|CONTEXT_GUARD_STAGE_REQUEST|"
    r"CONTEXT_GUARD_DISPOSITION_REQUEST|"
    r"CONTEXT_GUARD_DATA_DIR|CLAUDE_PLUGIN_DATA",
    re.IGNORECASE,
)

# Always-sensitive internal markers — their mere presence is a leak.
SENSITIVE_MARKER_RE = re.compile(
    r"context-guard-checkpoint|CONTEXT_GUARD_STAGE_REQUEST|"
    r"CONTEXT_GUARD_DISPOSITION_REQUEST|CONTEXT_GUARD_PROOF_REQUEST",
    re.IGNORECASE,
)

# Bare command names are ordinary documentation terms. They become private
# control material only when they participate in an invocation, binding, or
# serialized control structure.
CONTROL_COMMAND_PATTERN = (
    r"(?:checkpoint-status|stage-checkpoint|stage-disposition|register-proof)"
)
CONTROL_COMMAND_RE = re.compile(CONTROL_COMMAND_PATTERN, re.IGNORECASE)
CONTROL_INVOCATION_RE = re.compile(
    CONTROL_COMMAND_PATTERN
    + r"(?:[\s`'\"“”‘’：:,，]*)"
    + r"(?P<option>--[a-z][a-z0-9-]*)"
    + r"(?P<binding>[\s=]+(?P<value>[^\s`'\"“”‘’，,;；|&<>]{1,500}))?",
    re.IGNORECASE,
)
SECRET_OPTION_BINDING_RE = re.compile(
    r"--(?:data-dir|session-id|turn-id|token)(?:[\s=]+)\S+",
    re.IGNORECASE,
)
CONTROL_OPTION_BINDING_RE = re.compile(
    r"--(?:requirement|acceptance|manifest|disposition)(?:[\s=]+)\S+",
    re.IGNORECASE,
)
PRIVATE_ENV_ASSIGNMENT_RE = re.compile(
    r"(?:CLAUDE_PLUGIN_DATA|CONTEXT_GUARD_DATA_DIR)\s*=\s*\S+",
    re.IGNORECASE,
)
SERIALIZED_CONTROL_KEY_RE = re.compile(
    r"[\"'](?:command|token|data[_-]dir|session[_-]id|turn[_-]id|"
    r"requirements?|acceptance|manifest|disposition)[\"']\s*:",
    re.IGNORECASE,
)
SERIALIZED_SECRET_BINDING_RE = re.compile(
    r"(?P<key_quote>[\"'])"
    r"(?P<key>token|data[_-]dir|session[_-]id|turn[_-]id)"
    r"(?P=key_quote)\s*:\s*"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,\s}\]]+)",
    re.IGNORECASE,
)
SAFE_SERIALIZED_PLACEHOLDER_RE = re.compile(
    r"(?:<|\[)?(?:redacted|omitted)(?:>|\])?|\*{3,}",
    re.IGNORECASE,
)
PRIVATE_CONTROL_TOKEN_SHAPE_RE = re.compile(
    rf"[A-Za-z0-9_-]{{{PRIVATE_CONTROL_TOKEN_LENGTH}}}"
)
CONTROL_RUNTIME_RE = re.compile(
    r"(?:context_guard\.py|context-guard(?:/|\\)scripts(?:/|\\)context_guard\.py)"
    r"[^\r\n]{0,240}"
    + CONTROL_COMMAND_PATTERN,
    re.IGNORECASE,
)


def classify_private_metadata(text: str) -> tuple[str, list[str]]:
    """Classify final user-visible text without retaining sensitive values.

    The stable categories are ``sensitive_control``,
    ``ambiguous_control_fragment``, and ``explanatory_reference``. Only the
    latter is safe for a user-facing reply.
    """
    sensitive_reasons: list[str] = []
    ambiguous_reasons: list[str] = []

    if SENSITIVE_MARKER_RE.search(text):
        sensitive_reasons.append("internal_marker_or_serialized_control")
    if PRIVATE_ENV_ASSIGNMENT_RE.search(text):
        sensitive_reasons.append("environment_binding")
    serialized_secret_bindings = list(SERIALIZED_SECRET_BINDING_RE.finditer(text))
    sensitive_serialized_binding = False
    for binding in serialized_secret_bindings:
        raw_value = binding.group("value")
        quoted = (
            len(raw_value) >= 2
            and raw_value[0] == raw_value[-1]
            and raw_value[0] in "\"'"
        )
        value = raw_value[1:-1] if quoted else raw_value
        if SAFE_SERIALIZED_PLACEHOLDER_RE.fullmatch(value.strip()):
            continue
        if binding.group("key").lower() == "token" and quoted and any(
            character.isspace() for character in value
        ):
            collapsed = "".join(value.split())
            if not PRIVATE_CONTROL_TOKEN_SHAPE_RE.search(collapsed):
                # Human-readable quoted examples such as "alpha beta" cannot
                # contain the current URL-safe private token after whitespace
                # is removed, so they are safe to explain. Padding, wrapping,
                # or splitting a token-shaped value remains sensitive.
                continue
        sensitive_serialized_binding = True
        break
    if SECRET_OPTION_BINDING_RE.search(text) or sensitive_serialized_binding:
        sensitive_reasons.append("private_parameter_binding")
    if CONTROL_RUNTIME_RE.search(text):
        sensitive_reasons.append("full_command_invocation")

    invocations = list(CONTROL_INVOCATION_RE.finditer(text))
    for invocation in invocations[:8]:
        if invocation.group("binding") and invocation.group("value"):
            sensitive_reasons.append("full_command_invocation")
        else:
            ambiguous_reasons.append("incomplete_control_invocation")

    if CONTROL_COMMAND_RE.search(text) and CONTROL_OPTION_BINDING_RE.search(text):
        sensitive_reasons.append("private_parameter_binding")

    serialized_keys = SERIALIZED_CONTROL_KEY_RE.findall(text)
    if CONTROL_COMMAND_RE.search(text) and len(serialized_keys) >= 2:
        sensitive_reasons.append("internal_marker_or_serialized_control")
    elif len(serialized_keys) >= 3:
        ambiguous_reasons.append("serialized_control_fragment")

    if sensitive_reasons:
        return "sensitive_control", list(dict.fromkeys(sensitive_reasons))[:4]
    if ambiguous_reasons:
        return (
            "ambiguous_control_fragment",
            list(dict.fromkeys(ambiguous_reasons))[:4],
        )
    reasons = ["bare_control_reference"] if CONTROL_COMMAND_RE.search(text) else []
    return "explanatory_reference", reasons
FAILED_TOOL_RESPONSE_RE = re.compile(
    r"(?im)^\s*(?:script (?:failed|error)|command failed|"
    r"(?:script|command) completed with (?:errors?|failures?)|"
    r"fatal:|error:|\[fail\]|"
    r"traceback \(most recent call last\)|"
    r".*(?:operation not permitted|permission denied|command not found|"
    r"no such file or directory))"
)
AUTHORITATIVE_SUCCESS_TOOL_RESPONSE_RE = re.compile(
    r"(?im)^\s*(?:script completed|command completed)\s*$"
)
UPDATE_PLAN_SUCCESS_TOOL_RESPONSE_RE = re.compile(
    r"^\s*Plan updated\s*$", re.IGNORECASE
)
WEAK_SUCCESS_TOOL_RESPONSE_RE = re.compile(
    r"(?im)^\s*(?:\[ok\]|smoke_pass\b|pass\b|done!\s*$)"
)
SUPERSESSION_INTENT_RE = re.compile(
    r"(?:改为|改成|取消|不再|以此为准|替代|覆盖|修正|"
    r"\breplace\b|\bsupersede\b|\bcancel\b)",
    re.I,
)
SUPERSESSION_NEGATION_PREFIX_RE = re.compile(
    r"(?:不要|不得|不能|不应|无需|并非|不是|切勿|勿|别|"
    r"do\s+not|don't|must\s+not|should\s+not|never|without)\s*"
    r"(?:(?:再|擅自|直接|随意|轻易|ever|again|silently|automatically)\s*)*$",
    re.I,
)
EXPLICIT_PREVIOUS_REQUIREMENT_RE = re.compile(
    r"(?:上一条(?:需求|要求)?|前一条(?:需求|要求)?|"
    r"\b(?:previous|prior|last)\s+(?:requirement|instruction)\b)",
    re.I,
)
ATTRIBUTED_SUPERSESSION_LINE_RE = re.compile(
    r"^\s*(?:>|(?:assistant|system|developer)\s*:|assistant\s+said\s*:|"
    r"(?:助手|系统|开发者)\s*[：:]|你(?:之前)?说\s*[：:]|"
    r"\[(?:assistant|system|developer)(?:/[^\]]+)?\]).*$",
    re.I | re.M,
)
ATTRIBUTED_SUPERSESSION_BLOCK_RE = re.compile(
    r"<(?:assistant|quote|response|quoted-response|system|developer|"
    r"system-reminder|app-context|context-guard-recovery)\b[^>]*>.*?"
    r"</(?:assistant|quote|response|quoted-response|system|developer|"
    r"system-reminder|app-context|context-guard-recovery)>",
    re.I | re.S,
)
DATA_URL_RE = re.compile(
    r"^data:(?P<mime>[^;,]+)?(?P<parameters>(?:;[^,]*)*?),(?P<body>.*)$",
    re.IGNORECASE | re.DOTALL,
)
BASE64_TEXT_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")
BINARY_VALUE_KEYS = {
    "audio_url",
    "base64",
    "blob",
    "bytes",
    "encrypted_content",
    "image_url",
}
BINARY_CONTAINER_TYPES = {"audio", "binary", "blob", "image", "video"}
DELEGATION_RE = re.compile(
    r"^\s*<codex_delegation>.*?</codex_delegation>\s*$",
    re.I | re.S,
)
AGENT_RESULT_FIELDS = {
    "outcome": ("outcome", "结果", "结论"),
    "evidence": ("evidence", "证据"),
    "validation": ("validation", "verification", "校验", "验证", "测试"),
    "limitations": ("limitations", "limitation", "限制", "局限", "未覆盖"),
    "next": ("next", "next steps", "下一步", "后续"),
}
SECRET_PATTERNS = (
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{12,})\b"), "[REDACTED]"),
    (
        re.compile(r"(?i)\b(authorization\s*:\s*)(?:bearer\s+)?[^\s,;]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|secret|password)"
            r"(\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(r"([?&](?:token|key|secret|signature|auth)=)[^&#\s]+", re.I),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(https?://[^\s?#]+)\?[^\s#]*(?:#[^\s]*)?", re.I),
        r"\1?[QUERY_REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(--token\s+)(?:\"[^\"]+\"|'[^']+'|[^\s,;]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(--token=)(?:\"[^\"]+\"|'[^']+'|[^\s,;]+)"),
        r"\1[REDACTED]",
    ),
)
SURROGATE_RE = re.compile(r"[\uD800-\uDFFF]")


class StateIntegrityError(RuntimeError):
    """Raised when private session state cannot be trusted."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact_text(value: str) -> str:
    redacted = value
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def repair_unicode_scalars(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return SURROGATE_RE.subn("\ufffd", value)
    if isinstance(value, list):
        repaired_items: list[Any] = []
        repairs = 0
        for item in value:
            repaired, count = repair_unicode_scalars(item)
            repaired_items.append(repaired)
            repairs += count
        return repaired_items, repairs
    if isinstance(value, dict):
        repaired_items: dict[Any, Any] = {}
        repairs = 0
        for key, item in value.items():
            repaired_key, key_count = repair_unicode_scalars(key)
            repaired, count = repair_unicode_scalars(item)
            repaired_items[repaired_key] = repaired
            repairs += key_count + count
        return repaired_items, repairs
    return value, 0


def bounded(value: Any, limit: int = 1200) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = repr(value)
    text = redact_text(text.replace("\x00", ""))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated {len(text) - limit} chars]"


def binary_placeholder(value: str, *, mime: str | None = None) -> str:
    kind = mime or "base64"
    digest = sha256_text(value)
    return f"[binary omitted: type={kind}, chars={len(value)}, sha256={digest}]"


def sanitize_evidence_value(
    value: Any,
    *,
    key: str | None = None,
    binary_context: bool = False,
    depth: int = 0,
) -> Any:
    """Remove binary payloads before serializing bounded tool evidence."""
    if depth >= 8:
        return "[nested value omitted]"
    if isinstance(value, str):
        match = DATA_URL_RE.match(value)
        if match:
            return binary_placeholder(value, mime=match.group("mime") or "data-url")
        normalized_key = (key or "").lower()
        compact = re.sub(r"\s+", "", value)
        if (
            (
                normalized_key in BINARY_VALUE_KEYS
                or (binary_context and normalized_key in {"", "data"})
            )
            and len(compact) >= 512
            and BASE64_TEXT_RE.fullmatch(compact)
        ):
            return binary_placeholder(value)
        return value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        items = list(value.items())
        container_type = str(value.get("type") or value.get("kind") or "").lower()
        container_mime = str(
            value.get("mimeType")
            or value.get("mime_type")
            or value.get("mime")
            or ""
        ).lower()
        declares_binary = (
            container_type in BINARY_CONTAINER_TYPES
            or container_mime.startswith(("image/", "audio/", "video/"))
            or container_mime
            in {
                "application/octet-stream",
                "application/pdf",
                "application/zip",
            }
        )
        for raw_key, item in items[:64]:
            text_key = str(raw_key)
            result[text_key] = sanitize_evidence_value(
                item,
                key=text_key,
                binary_context=declares_binary,
                depth=depth + 1,
            )
        if len(items) > 64:
            result["_context_guard_omitted_keys"] = len(items) - 64
        return result
    if isinstance(value, (list, tuple)):
        items = list(value)
        result = [
            sanitize_evidence_value(
                item,
                binary_context=binary_context,
                depth=depth + 1,
            )
            for item in items[:64]
        ]
        if len(items) > 64:
            result.append(f"[omitted {len(items) - 64} items]")
        return result
    return value


def bounded_evidence(value: Any, limit: int) -> str:
    return bounded(sanitize_evidence_value(value), limit)


def console_write(value: Any, *, stream: Any = None) -> None:
    target = stream or sys.stdout
    text = str(value)
    try:
        target.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(target, "encoding", None) or "ascii"
        safe = text.encode(encoding, errors="backslashreplace").decode(encoding)
        target.write(safe + "\n")


def safe_session_id(value: Any) -> str:
    raw = str(value or "unknown-session")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:160]
    return safe or "unknown-session"


def data_root() -> Path:
    configured = (
        os.environ.get("CONTEXT_GUARD_DATA_DIR")
        or os.environ.get("PLUGIN_DATA")
        or os.environ.get("CLAUDE_PLUGIN_DATA")
    )
    return Path(configured).expanduser() if configured else Path.home() / ".codex" / "context-guard"


def secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def secure_file(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def atomic_write_text(path: Path, content: str) -> None:
    secure_directory(path.parent)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, prefix=f".{path.name}."
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temp_path)
        os.replace(temp_path, path)
        secure_file(path)
    except BaseException:
        with contextlib.suppress(OSError):
            temp_path.unlink()
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def state_content_hash(state: dict[str, Any]) -> str:
    hashable = dict(state)
    hashable.pop("content_hash", None)
    return sha256_text(canonical_json(hashable))


def prompt_record_hash(record: dict[str, Any]) -> str:
    hashable = dict(record)
    hashable.pop("record_sha256", None)
    return sha256_text(canonical_json(hashable))


def dormant_execution_state() -> dict[str, Any]:
    """Return the schema-7 execution ledger without activating enforcement."""
    return {
        "protocol_version": EXECUTION_PROTOCOL_VERSION,
        "instruction_sources": [],
        "contract": {
            "state": "absent",
            "revision": 0,
            "contract_id": None,
            "canonical_sha256": None,
            "adoption": None,
            "supersedes_revision": None,
            "phases": [],
            "gates": [],
            "authorization_candidates": [],
        },
        "coverage_manifest": {
            "host_lock": None,
            "adapters": [],
            "uncovered_write_surfaces": [],
            "unclassified_high_risk_policy": "deny_when_active",
            "non_active_contract_policy": "completion_only",
            "stale_conflicted_policy": "deny_covered_high_risk",
            "pre_tool_output_policy": "allow_deny_only",
        },
        "drift": [],
        "action_tickets": [],
        "denials": [],
        "unified_exec_sessions": [],
        "delegations": [],
    }


def contract_content_hash(contract: dict[str, Any]) -> str:
    normalized = dict(contract)
    normalized.pop("canonical_sha256", None)
    return sha256_text(canonical_json(normalized))


def _execution_id(value: Any, field: str) -> str:
    text = str(value or "")
    if not EXECUTION_ID_RE.fullmatch(text):
        raise StateIntegrityError(f"execution field {field} has an invalid identifier")
    return text


def _execution_sha(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise StateIntegrityError(f"execution field {field} has an invalid sha256")
    return text


def _execution_time(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    text = str(value or "")
    if parse_time(text) is None:
        raise StateIntegrityError(f"execution field {field} has an invalid timestamp")
    return text


def _validate_execution_value(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_EXECUTION_DEPTH:
        raise StateIntegrityError("execution state nesting limit exceeded")
    if isinstance(value, str):
        if len(value) > MAX_EXECUTION_STRING:
            raise StateIntegrityError("execution state string limit exceeded")
        if value.startswith(("/", "\\\\")) or WINDOWS_ABSOLUTE_PATH_RE.match(value):
            raise StateIntegrityError("execution state must not retain raw machine paths")
    elif isinstance(value, list):
        for item in value:
            _validate_execution_value(item, depth=depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_EXECUTION_KEYS:
                raise StateIntegrityError(f"execution state forbids raw field {key!r}")
            _validate_execution_value(item, depth=depth + 1)


def _require_record_keys(
    record: Any,
    *,
    field: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise StateIntegrityError(f"execution field {field} must contain objects")
    allowed = required | (optional or set())
    if not required.issubset(record) or not set(record).issubset(allowed):
        raise StateIntegrityError(f"execution field {field} has invalid record keys")
    return record


def _validate_phase_records(records: Any, field: str) -> None:
    if not isinstance(records, list) or len(records) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError(f"execution field {field} exceeds its record limit")
    seen: set[str] = set()
    for raw in records:
        record = _require_record_keys(
            raw,
            field=field,
            required={"id", "state", "depends_on", "evidence_ids", "resolution_sha256"},
        )
        record_id = _execution_id(record["id"], f"{field}.id")
        if record_id in seen or record.get("state") not in PHASE_STATES:
            raise StateIntegrityError(f"execution field {field} has a duplicate id or invalid state")
        seen.add(record_id)
        _execution_sha(record.get("resolution_sha256"), f"{field}.resolution_sha256", nullable=True)
        for list_field in ("depends_on", "evidence_ids"):
            values = record.get(list_field)
            if not isinstance(values, list) or len(values) > MAX_EXECUTION_RECORDS:
                raise StateIntegrityError(f"execution field {field}.{list_field} is invalid")
            for value in values:
                _execution_id(value, f"{field}.{list_field}")


def validate_execution_state(execution: Any) -> None:
    if not isinstance(execution, dict):
        raise StateIntegrityError("private execution state must be an object")
    if len(canonical_json(execution).encode("utf-8")) > MAX_EXECUTION_STATE_BYTES:
        raise StateIntegrityError("execution state byte limit exceeded")
    _validate_execution_value(execution)
    expected_top = {
        "protocol_version", "instruction_sources", "contract", "coverage_manifest", "drift",
        "action_tickets", "denials", "unified_exec_sessions", "delegations",
    }
    if set(execution) != expected_top or execution.get("protocol_version") != EXECUTION_PROTOCOL_VERSION:
        raise StateIntegrityError("private execution state has invalid top-level fields")

    sources = execution.get("instruction_sources")
    if not isinstance(sources, list) or len(sources) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError("execution instruction source limit exceeded")
    source_ids: set[str] = set()
    for raw in sources:
        record = _require_record_keys(
            raw,
            field="instruction_sources",
            required={"id", "kind", "origin_id", "revision", "sha256", "state"},
        )
        source_id = _execution_id(record["id"], "instruction_sources.id")
        _execution_id(record["kind"], "instruction_sources.kind")
        _execution_id(record["origin_id"], "instruction_sources.origin_id")
        _execution_sha(record["sha256"], "instruction_sources.sha256")
        if source_id in source_ids or not isinstance(record.get("revision"), int) or record["revision"] < 1:
            raise StateIntegrityError("execution instruction source is duplicated or has invalid revision")
        if record.get("state") not in {"active", "stale", "superseded"}:
            raise StateIntegrityError("execution instruction source has invalid state")
        source_ids.add(source_id)

    contract = execution.get("contract")
    contract_keys = {
        "state", "revision", "contract_id", "canonical_sha256", "adoption",
        "supersedes_revision", "phases", "gates", "authorization_candidates",
    }
    if not isinstance(contract, dict) or set(contract) != contract_keys:
        raise StateIntegrityError("execution contract has invalid fields")
    contract_state = contract.get("state")
    revision = contract.get("revision")
    if contract_state not in CONTRACT_STATES or not isinstance(revision, int) or revision < 0:
        raise StateIntegrityError("execution contract state or revision is invalid")
    if contract_state == "absent":
        dormant_fields = (
            revision == 0
            and contract.get("contract_id") is None
            and contract.get("canonical_sha256") is None
            and contract.get("adoption") is None
            and contract.get("supersedes_revision") is None
            and not contract.get("phases")
            and not contract.get("gates")
            and not contract.get("authorization_candidates")
        )
        if not dormant_fields:
            raise StateIntegrityError("absent execution contract must be dormant")
    else:
        if revision < 1:
            raise StateIntegrityError("non-absent execution contract needs a revision")
        _execution_id(contract.get("contract_id"), "contract.contract_id")
        stored_contract_hash = _execution_sha(
            contract.get("canonical_sha256"), "contract.canonical_sha256"
        )
        if stored_contract_hash != contract_content_hash(contract):
            raise StateIntegrityError("execution contract canonical hash mismatch")
    adoption = contract.get("adoption")
    if adoption is not None:
        adoption = _require_record_keys(
            adoption,
            field="contract.adoption",
            required={"prompt_id", "prompt_sha256", "contract_sha256", "revision", "adopted_at"},
        )
        _execution_id(adoption["prompt_id"], "contract.adoption.prompt_id")
        _execution_sha(adoption["prompt_sha256"], "contract.adoption.prompt_sha256")
        _execution_sha(adoption["contract_sha256"], "contract.adoption.contract_sha256")
        _execution_time(adoption["adopted_at"], "contract.adoption.adopted_at")
        if adoption.get("revision") != revision:
            raise StateIntegrityError("execution adoption revision mismatch")
    if contract_state == "active" and adoption is None:
        raise StateIntegrityError("active execution contract requires adoption")
    supersedes_revision = contract.get("supersedes_revision")
    if supersedes_revision is not None and (
        not isinstance(supersedes_revision, int) or supersedes_revision < 1 or supersedes_revision >= revision
    ):
        raise StateIntegrityError("execution contract supersedes revision is invalid")
    _validate_phase_records(contract.get("phases"), "contract.phases")
    _validate_phase_records(contract.get("gates"), "contract.gates")

    candidates = contract.get("authorization_candidates")
    if not isinstance(candidates, list) or len(candidates) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError("execution authorization candidate limit exceeded")
    candidate_ids: set[str] = set()
    for raw in candidates:
        record = _require_record_keys(
            raw,
            field="authorization_candidates",
            required={
                "id", "prompt_id", "prompt_sha256", "semantic_action_id",
                "canonical_target_id", "write_surface_id", "binding", "state", "activation",
            },
            optional={"ticket_binding"},
        )
        candidate_id = _execution_id(record["id"], "authorization_candidates.id")
        for key in ("prompt_id", "semantic_action_id", "canonical_target_id", "write_surface_id"):
            _execution_id(record[key], f"authorization_candidates.{key}")
        _execution_sha(record["prompt_sha256"], "authorization_candidates.prompt_sha256")
        if candidate_id in candidate_ids or record.get("binding") not in {"deterministic", "natural_language"}:
            raise StateIntegrityError("execution authorization candidate is duplicated or invalid")
        if record.get("state") not in {"candidate", "active", "rejected", "superseded"}:
            raise StateIntegrityError("execution authorization candidate state is invalid")
        activation = record.get("activation")
        if activation is not None:
            activation = _require_record_keys(
                activation,
                field="authorization_candidates.activation",
                required={"prompt_id", "prompt_sha256", "activated_at"},
            )
            _execution_id(activation["prompt_id"], "authorization_candidates.activation.prompt_id")
            _execution_sha(activation["prompt_sha256"], "authorization_candidates.activation.prompt_sha256")
            _execution_time(activation["activated_at"], "authorization_candidates.activation.activated_at")
        if record.get("state") == "active" and (
            record.get("binding") != "deterministic" or activation is None
        ):
            raise StateIntegrityError("authorization activation requires deterministic binding and record")
        if record.get("state") != "active" and activation is not None:
            raise StateIntegrityError("inactive authorization candidate cannot retain activation")
        ticket_binding = record.get("ticket_binding")
        if ticket_binding is not None:
            ticket_binding = _require_record_keys(
                ticket_binding,
                field="authorization_candidates.ticket_binding",
                required={
                    "ticket_schema", "repository_id", "candidate_commit",
                    "release_version", "closure_sha256", "readiness_sha256",
                    "closure_status", "readiness_schema", "readiness_kind",
                    "readiness_status", "action_ticket_eligible",
                    "input_sha256", "expires_at",
                },
            )
            if ticket_binding.get("ticket_schema") != "action-ticket/v1":
                raise StateIntegrityError("authorization ticket binding schema is invalid")
            if (
                ticket_binding.get("closure_status") != "passed"
                or ticket_binding.get("readiness_schema")
                not in SUPPORTED_RELEASE_READINESS_SCHEMAS
                or ticket_binding.get("readiness_kind") != "publication"
                or ticket_binding.get("readiness_status") != "passed"
                or ticket_binding.get("action_ticket_eligible") is not True
            ):
                raise StateIntegrityError(
                    "action ticket requires passed candidate closure and publication readiness"
                )
            for key in ("repository_id", "release_version"):
                _execution_id(
                    ticket_binding.get(key),
                    f"authorization_candidates.ticket_binding.{key}",
                )
            if not re.fullmatch(
                r"[0-9a-f]{40}", str(ticket_binding.get("candidate_commit") or "")
            ):
                raise StateIntegrityError(
                    "authorization ticket binding requires an exact candidate commit"
                )
            for key in ("closure_sha256", "readiness_sha256", "input_sha256"):
                _execution_sha(ticket_binding.get(key), f"authorization_candidates.ticket_binding.{key}")
            _execution_time(ticket_binding.get("expires_at"), "authorization_candidates.ticket_binding.expires_at")
            if record.get("binding") != "deterministic":
                raise StateIntegrityError("only deterministic authorization may carry an action ticket")
        candidate_ids.add(candidate_id)

    coverage = execution.get("coverage_manifest")
    coverage_keys = {
        "host_lock", "adapters", "uncovered_write_surfaces", "unclassified_high_risk_policy",
        "non_active_contract_policy", "stale_conflicted_policy", "pre_tool_output_policy",
    }
    if not isinstance(coverage, dict) or set(coverage) != coverage_keys:
        raise StateIntegrityError("execution coverage manifest has invalid fields")
    if coverage.get("unclassified_high_risk_policy") != "deny_when_active":
        raise StateIntegrityError("execution unclassified high-risk policy must fail closed")
    if coverage.get("non_active_contract_policy") != "completion_only":
        raise StateIntegrityError("non-active execution contracts must remain completion-only")
    if coverage.get("stale_conflicted_policy") != "deny_covered_high_risk":
        raise StateIntegrityError("stale/conflicted execution policy must fail closed")
    if coverage.get("pre_tool_output_policy") != "allow_deny_only":
        raise StateIntegrityError("execution PreToolUse output policy is invalid")
    host_lock = coverage.get("host_lock")
    if host_lock is not None:
        host_lock = _require_record_keys(
            host_lock,
            field="coverage_manifest.host_lock",
            required={"cli_version", "desktop_version", "snapshot_id", "sha256"},
        )
        for key in ("cli_version", "desktop_version", "snapshot_id"):
            _execution_id(host_lock[key], f"coverage_manifest.host_lock.{key}")
        _execution_sha(host_lock["sha256"], "coverage_manifest.host_lock.sha256")
    adapters = coverage.get("adapters")
    if not isinstance(adapters, list) or len(adapters) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError("execution adapter limit exceeded")
    adapter_ids: set[str] = set()
    for raw in adapters:
        record = _require_record_keys(
            raw,
            field="coverage_manifest.adapters",
            required={"id", "tool_name", "revision", "input_schema_sha256", "host_lock_sha256", "status"},
        )
        adapter_id = _execution_id(record["id"], "coverage_manifest.adapters.id")
        _execution_id(record["tool_name"], "coverage_manifest.adapters.tool_name")
        _execution_sha(record["input_schema_sha256"], "coverage_manifest.adapters.input_schema_sha256")
        _execution_sha(record["host_lock_sha256"], "coverage_manifest.adapters.host_lock_sha256")
        if adapter_id in adapter_ids or not isinstance(record.get("revision"), int) or record["revision"] < 1:
            raise StateIntegrityError("execution adapter is duplicated or invalid")
        if record.get("status") not in {"eligible", "unverified", "uncovered"}:
            raise StateIntegrityError("execution adapter status is invalid")
        adapter_ids.add(adapter_id)
    uncovered = coverage.get("uncovered_write_surfaces")
    if not isinstance(uncovered, list) or len(uncovered) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError("execution uncovered surface limit exceeded")
    uncovered_ids: set[str] = set()
    for raw in uncovered:
        record = _require_record_keys(
            raw,
            field="coverage_manifest.uncovered_write_surfaces",
            required={"id", "reason_code", "status"},
        )
        surface_id = _execution_id(record["id"], "uncovered_write_surfaces.id")
        _execution_id(record["reason_code"], "uncovered_write_surfaces.reason_code")
        if surface_id in uncovered_ids or record.get("status") != "uncovered":
            raise StateIntegrityError("execution uncovered surface is duplicated or invalid")
        uncovered_ids.add(surface_id)

    drift = execution.get("drift")
    if not isinstance(drift, list) or len(drift) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError("execution drift record limit exceeded")
    drift_ids: set[str] = set()
    for raw in drift:
        record = _require_record_keys(
            raw,
            field="drift",
            required={
                "id", "source_id", "baseline_sha256", "observed_sha256",
                "affected_ids", "state", "detected_at", "resolution_sha256",
            },
        )
        drift_id = _execution_id(record["id"], "drift.id")
        _execution_id(record["source_id"], "drift.source_id")
        _execution_sha(record["baseline_sha256"], "drift.baseline_sha256")
        _execution_sha(record["observed_sha256"], "drift.observed_sha256")
        _execution_sha(record["resolution_sha256"], "drift.resolution_sha256", nullable=True)
        _execution_time(record["detected_at"], "drift.detected_at")
        affected = record.get("affected_ids")
        if not isinstance(affected, list) or not affected or len(affected) > MAX_EXECUTION_RECORDS:
            raise StateIntegrityError("execution drift affected ids are invalid")
        for affected_id in affected:
            _execution_id(affected_id, "drift.affected_ids")
        if drift_id in drift_ids or record.get("state") not in {"detected", "resolved", "superseded"}:
            raise StateIntegrityError("execution drift record is duplicated or invalid")
        if record.get("state") == "resolved" and record.get("resolution_sha256") is None:
            raise StateIntegrityError("resolved execution drift requires a resolution digest")
        drift_ids.add(drift_id)

    tickets = execution.get("action_tickets")
    if not isinstance(tickets, list) or len(tickets) > MAX_EXECUTION_TICKETS:
        raise StateIntegrityError("execution ticket limit exceeded")
    ticket_ids: set[str] = set()
    for raw in tickets:
        record = _require_record_keys(
            raw,
            field="action_tickets",
            required={
                "id", "session_id", "turn_id", "actor_id", "tool_use_id",
                "authorization_prompt_id", "authorization_prompt_sha256",
                "contract_revision", "semantic_action_id", "canonical_target_id",
                "write_surface_id", "input_sha256", "state", "reserved_at",
                "expires_at", "settled_at", "ticket_schema", "repository_id",
                "candidate_commit", "release_version", "contract_sha256",
                "closure_sha256", "readiness_sha256", "attempt_count",
                "closure_status", "readiness_schema", "readiness_kind",
                "readiness_status", "action_ticket_eligible",
            },
        )
        ticket_id = _execution_id(record["id"], "action_tickets.id")
        ids = [
            _execution_id(record[key], f"action_tickets.{key}")
            for key in (
                "session_id", "turn_id", "actor_id", "tool_use_id", "semantic_action_id",
                "canonical_target_id", "write_surface_id", "authorization_prompt_id",
            )
        ]
        _execution_sha(
            record["authorization_prompt_sha256"],
            "action_tickets.authorization_prompt_sha256",
        )
        if record.get("ticket_schema") != "action-ticket/v1":
            raise StateIntegrityError("execution ticket schema is invalid")
        readiness_passed = (
            record.get("closure_status") == "passed"
            and record.get("readiness_schema")
            in SUPPORTED_RELEASE_READINESS_SCHEMAS
            and record.get("readiness_kind") == "publication"
            and record.get("readiness_status") == "passed"
            and record.get("action_ticket_eligible") is True
        )
        legacy_terminal = (
            record.get("state") in {"consumed", "invalidated", "expired"}
            and record.get("closure_status") == "legacy_unverified"
            and record.get("readiness_schema") == "legacy"
            and record.get("readiness_kind") == "legacy"
            and record.get("readiness_status") == "legacy_unverified"
            and record.get("action_ticket_eligible") is False
        )
        if not readiness_passed and not legacy_terminal:
            raise StateIntegrityError(
                "execution ticket requires passed candidate closure and publication readiness"
            )
        for key in ("repository_id", "release_version"):
            _execution_id(record[key], f"action_tickets.{key}")
        if not legacy_terminal and not re.fullmatch(
            r"[0-9a-f]{40}", str(record.get("candidate_commit") or "")
        ):
            raise StateIntegrityError(
                "execution ticket requires an exact candidate commit"
            )
        for key in ("input_sha256", "contract_sha256", "closure_sha256", "readiness_sha256"):
            _execution_sha(record[key], f"action_tickets.{key}")
        reserved_at = _execution_time(record["reserved_at"], "action_tickets.reserved_at")
        expires_at = _execution_time(record["expires_at"], "action_tickets.expires_at")
        settled_at = _execution_time(
            record["settled_at"], "action_tickets.settled_at", nullable=True
        )
        ticket_revision = record.get("contract_revision")
        if (
            ticket_id in ticket_ids
            or not isinstance(ticket_revision, int)
            or ticket_revision < 1
            or record.get("state") not in TICKET_STATES
            or not isinstance(record.get("attempt_count"), int)
            or record["attempt_count"] < 0
        ):
            raise StateIntegrityError("execution ticket identity, namespace, revision, or state is invalid")
        if parse_time(expires_at) <= parse_time(reserved_at):
            raise StateIntegrityError("execution ticket lease must expire after reservation")
        if record["state"] in {"reserved", "in_flight"} and record.get("settled_at") is not None:
            raise StateIntegrityError("active execution ticket cannot be settled")
        if record["state"] in {"consumed", "invalidated", "expired"} and record.get("settled_at") is None:
            raise StateIntegrityError("settled execution ticket needs a settlement timestamp")
        if record["state"] == "reserved" and record.get("tool_use_id") != "unclaimed":
            raise StateIntegrityError("reserved execution ticket must be unclaimed")
        if record["state"] == "in_flight" and record.get("tool_use_id") == "unclaimed":
            raise StateIntegrityError("in-flight execution ticket must bind a tool use")
        if settled_at is not None and parse_time(settled_at) < parse_time(reserved_at):
            raise StateIntegrityError("execution ticket cannot settle before reservation")
        ticket_ids.add(ticket_id)

    bounded_collections = {
        "denials": MAX_EXECUTION_TICKETS,
        "unified_exec_sessions": MAX_EXECUTION_RECORDS,
        "delegations": MAX_EXECUTION_RECORDS,
    }
    for field, limit in bounded_collections.items():
        values = execution.get(field)
        if not isinstance(values, list) or len(values) > limit:
            raise StateIntegrityError(f"execution field {field} exceeds its record limit")
        ids: set[str] = set()
        denial_keys: set[tuple[str, int, str, str]] = set()
        for raw in values:
            if field == "denials":
                required = {
                    "id", "deny_key", "reason_code", "contract_revision",
                    "semantic_action_id", "canonical_target_id", "retry_count", "last_seen_at",
                    "decision_id", "activation_prompt_id", "activation_prompt_sha256",
                }
            elif field == "unified_exec_sessions":
                required = {
                    "id", "session_id", "turn_id", "actor_id", "tool_use_id",
                    "contract_revision", "creation_input_sha256", "stdin_coverage", "state",
                }
            else:
                required = {
                    "id", "parent_session_id", "parent_actor_id", "child_agent_id",
                    "child_turn_id", "contract_revision", "contract_view_sha256", "relay_state",
                }
            record = _require_record_keys(raw, field=field, required=required)
            record_id = _execution_id(record["id"], f"{field}.id")
            if record_id in ids:
                raise StateIntegrityError(f"execution field {field} has duplicate ids")
            ids.add(record_id)
            for key, value in record.items():
                if key.endswith("_sha256"):
                    _execution_sha(
                        value,
                        f"{field}.{key}",
                        nullable=field == "denials" and key == "activation_prompt_sha256",
                    )
                elif key.endswith("_id") or key in {"deny_key", "reason_code"}:
                    if value is not None:
                        _execution_id(value, f"{field}.{key}")
            revision_value = record.get("contract_revision")
            if not isinstance(revision_value, int) or revision_value < 1:
                raise StateIntegrityError(f"execution field {field} has invalid contract revision")
            if field == "denials":
                if not isinstance(record.get("retry_count"), int) or not 0 <= record["retry_count"] <= 8:
                    raise StateIntegrityError("execution denial retry count is invalid")
                _execution_time(record["last_seen_at"], "denials.last_seen_at")
                for key in ("decision_id", "activation_prompt_id"):
                    if record.get(key) is not None:
                        _execution_id(record[key], f"denials.{key}")
                _execution_sha(
                    record.get("activation_prompt_sha256"),
                    "denials.activation_prompt_sha256",
                    nullable=True,
                )
                if record.get("reason_code") == "user_decision_required" and record.get("decision_id") is None:
                    raise StateIntegrityError("user-decision denial requires decision id")
                activation_fields = (
                    record.get("activation_prompt_id"),
                    record.get("activation_prompt_sha256"),
                )
                if (activation_fields[0] is None) != (activation_fields[1] is None):
                    raise StateIntegrityError("execution denial activation binding is incomplete")
                denial_identity = (
                    str(record["deny_key"]),
                    int(record["contract_revision"]),
                    str(record["semantic_action_id"]),
                    str(record["canonical_target_id"]),
                )
                if denial_identity in denial_keys:
                    raise StateIntegrityError("execution denial identity is duplicated")
                denial_keys.add(denial_identity)
            elif field == "unified_exec_sessions":
                if record.get("stdin_coverage") not in {"none", "creation_only"} or record.get("state") not in {"active", "closed", "expired_unsettled"}:
                    raise StateIntegrityError("execution unified-exec coverage or state is invalid")
            elif record.get("relay_state") not in {"pending", "relayed", "resolved", "failed"}:
                raise StateIntegrityError("execution delegation relay state is invalid")


def transition_execution_contract(
    execution: dict[str, Any],
    next_state: str,
    *,
    revision: int | None = None,
    contract_id: str | None = None,
    adoption: dict[str, Any] | None = None,
    supersedes_revision: int | None = None,
) -> None:
    validate_execution_state(execution)
    contract = execution["contract"]
    current = str(contract["state"])
    if next_state not in CONTRACT_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid execution contract transition: {current} -> {next_state}")
    if next_state == "candidate" and current in {"absent", "stale", "conflicted", "rejected"}:
        previous_revision = int(contract["revision"])
        if revision is None or revision <= previous_revision or contract_id is None:
            raise ValueError("candidate transition requires a newer revision and contract id")
        contract["revision"] = revision
        contract["contract_id"] = contract_id
        contract["adoption"] = None
        contract["supersedes_revision"] = (
            supersedes_revision if supersedes_revision is not None else (previous_revision or None)
        )
    elif revision is not None or contract_id is not None or supersedes_revision is not None:
        raise ValueError("revision metadata is only valid for a candidate transition")
    if next_state == "active":
        if adoption is None:
            raise ValueError("active transition requires an adoption record")
        contract["adoption"] = adoption
    elif adoption is not None:
        raise ValueError("adoption is only valid for an active transition")
    contract["state"] = next_state
    contract["canonical_sha256"] = contract_content_hash(contract)
    validate_execution_state(execution)


def execution_contract_mode(execution: dict[str, Any]) -> str:
    """Return the Phase-3 mode without granting authority to inactive state."""
    validate_execution_state(execution)
    contract = execution["contract"]
    if contract["state"] != "active":
        return "completion_only"
    if any(
        item.get("state") == "active"
        for item in contract["authorization_candidates"]
        if isinstance(item, dict)
    ):
        return "active_contract"
    return "active_without_write_authority"


def _bounded_contract_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("execution contract manifest must be a regular file")
    if path.stat().st_size > MAX_EXECUTION_STATE_BYTES:
        raise ValueError("execution contract manifest exceeds 64 KiB")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"execution contract manifest is unreadable: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ValueError("execution contract manifest must contain one object")
    return value


def _manifest_records(
    value: Any,
    *,
    field: str,
    required: set[str],
    limit: int = MAX_EXECUTION_RECORDS,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"execution contract manifest field {field} is invalid")
    records: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError(f"execution contract manifest field {field} has invalid keys")
        records.append(dict(raw))
    return records


def adopt_execution_contract(
    state: dict[str, Any],
    prompt: dict[str, Any],
    manifest_argument: str | None,
) -> str:
    """Explicitly adopt a bounded project manifest from one root-user prompt."""
    if not manifest_argument or not manifest_argument.strip():
        raise ValueError("context-guard adopt requires a project-relative JSON manifest")
    project_root = Path(str(state.get("session", {}).get("cwd") or ".")).resolve()
    manifest_path = (project_root / manifest_argument.strip()).resolve()
    try:
        manifest_path.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("execution contract manifest must stay inside the project") from exc
    manifest = _bounded_contract_manifest(manifest_path)
    allowed = {
        "protocol_version", "contract_id", "revision", "instruction_sources",
        "phases", "gates", "authorization_candidates", "coverage_manifest",
    }
    if set(manifest) != allowed or manifest.get("protocol_version") != EXECUTION_PROTOCOL_VERSION:
        raise ValueError("execution contract manifest has invalid top-level fields")
    contract_id = _execution_id(manifest.get("contract_id"), "manifest.contract_id")
    revision = manifest.get("revision")
    if not isinstance(revision, int) or revision < 1:
        raise ValueError("execution contract manifest revision must be positive")
    execution = state["execution"]
    current_revision = int(execution["contract"]["revision"])
    if revision <= current_revision:
        raise ValueError("execution contract manifest must advance the current revision")

    sources = _manifest_records(
        manifest.get("instruction_sources"),
        field="instruction_sources",
        required={"id", "kind", "origin_id", "revision", "sha256"},
    )
    manifest_sha256 = sha256_text(canonical_json(manifest))
    normalized_sources = [
        {**item, "state": "active"}
        for item in sources
    ]
    normalized_sources.append(
        {
            "id": f"manifest-{contract_id}",
            "kind": "contract_manifest",
            "origin_id": contract_id,
            "revision": revision,
            "sha256": manifest_sha256,
            "state": "active",
        }
    )

    def phase_records(field: str) -> list[dict[str, Any]]:
        records = _manifest_records(
            manifest.get(field), field=field, required={"id", "depends_on"}
        )
        return [
            {
                "id": item["id"],
                "state": "pending",
                "depends_on": item["depends_on"],
                "evidence_ids": [],
                "resolution_sha256": None,
            }
            for item in records
        ]

    raw_candidates = manifest.get("authorization_candidates")
    if not isinstance(raw_candidates, list) or len(raw_candidates) > MAX_EXECUTION_RECORDS:
        raise ValueError("execution contract manifest field authorization_candidates is invalid")
    candidate_keys = {
        "id", "prompt_id", "prompt_sha256", "semantic_action_id",
        "canonical_target_id", "write_surface_id", "binding",
    }
    candidates: list[dict[str, Any]] = []
    for raw_candidate in raw_candidates:
        if (
            not isinstance(raw_candidate, dict)
            or not candidate_keys.issubset(raw_candidate)
            or set(raw_candidate).difference(candidate_keys | {"ticket_binding"})
        ):
            raise ValueError(
                "execution contract manifest field authorization_candidates has invalid keys"
            )
        candidates.append(dict(raw_candidate))
    normalized_candidates: list[dict[str, Any]] = []
    for item in candidates:
        binding = item.get("binding")
        if binding not in {"deterministic", "natural_language"}:
            raise ValueError("authorization candidate binding is invalid")
        active = binding == "deterministic"
        ticket_binding = item.get("ticket_binding")
        if ticket_binding is not None:
            source_prompt = next(
                (
                    candidate_prompt
                    for candidate_prompt in state.get("prompts", [])
                    if isinstance(candidate_prompt, dict)
                    and candidate_prompt.get("id") == item.get("prompt_id")
                    and candidate_prompt.get("sha256") == item.get("prompt_sha256")
                    and candidate_prompt.get("origin", "human") == "human"
                    and candidate_prompt.get("authority", "user") == "user"
                ),
                None,
            )
            if source_prompt is None:
                raise ValueError("action ticket authorization must bind an existing root-user prompt")
            if not isinstance(ticket_binding, dict):
                raise ValueError("action ticket binding must be an object")
        normalized_candidates.append(
            {
                **item,
                "state": "active" if active else "candidate",
                "activation": (
                    {
                        "prompt_id": prompt["id"],
                        "prompt_sha256": prompt["sha256"],
                        "activated_at": utc_now(),
                    }
                    if active
                    else None
                ),
            }
        )

    coverage = manifest.get("coverage_manifest")
    if not isinstance(coverage, dict):
        raise ValueError("execution contract coverage manifest is missing")
    expected_coverage = {
        "host_lock", "adapters", "uncovered_write_surfaces",
        "unclassified_high_risk_policy", "non_active_contract_policy",
        "stale_conflicted_policy", "pre_tool_output_policy",
    }
    if set(coverage) != expected_coverage:
        raise ValueError("execution contract coverage manifest has invalid fields")

    candidate_execution = dormant_execution_state()
    transition_execution_contract(
        candidate_execution,
        "candidate",
        revision=revision,
        contract_id=contract_id,
        supersedes_revision=current_revision or None,
    )
    candidate_execution["instruction_sources"] = normalized_sources
    candidate_execution["contract"]["phases"] = phase_records("phases")
    candidate_execution["contract"]["gates"] = phase_records("gates")
    candidate_execution["contract"]["authorization_candidates"] = normalized_candidates
    candidate_execution["coverage_manifest"] = json.loads(canonical_json(coverage))
    candidate_execution["contract"]["canonical_sha256"] = contract_content_hash(
        candidate_execution["contract"]
    )
    validate_execution_state(candidate_execution)

    plan_sources = [
        item for item in normalized_sources if item.get("kind") == "plan_snapshot"
    ]
    if len(plan_sources) > 1:
        raise ValueError("execution contract may bind at most one plan snapshot")
    current_plan = state.get("work_state", {}).get("plan_snapshot")
    current_plan_sha = (
        current_plan.get("semantic_sha256")
        if isinstance(current_plan, dict)
        else None
    )
    if plan_sources and current_plan_sha != plan_sources[0]["sha256"]:
        for item in candidate_execution["contract"]["authorization_candidates"]:
            item["state"] = "candidate"
            item["activation"] = None
        candidate_execution["contract"]["canonical_sha256"] = contract_content_hash(
            candidate_execution["contract"]
        )
        transition_execution_contract(candidate_execution, "conflicted")
        state["execution"] = candidate_execution
        return "Execution contract recorded as conflicted because the current plan does not match its bound digest."

    candidate_hash = candidate_execution["contract"]["canonical_sha256"]
    adoption = {
        "prompt_id": prompt["id"],
        "prompt_sha256": prompt["sha256"],
        "contract_sha256": candidate_hash,
        "revision": revision,
        "adopted_at": utc_now(),
    }
    transition_execution_contract(candidate_execution, "active", adoption=adoption)
    contract_sha256 = str(candidate_execution["contract"]["canonical_sha256"])
    for item in normalized_candidates:
        binding = item.get("ticket_binding")
        if item.get("state") != "active" or not isinstance(binding, dict):
            continue
        reserved_at = utc_now()
        expires_at = str(binding.get("expires_at") or "")
        if parse_time(expires_at) is None or parse_time(expires_at) <= parse_time(reserved_at):
            raise ValueError("action ticket expiry must be in the future")
        candidate_execution["action_tickets"].append(
            {
                "id": f"ticket-{item['id']}",
                "ticket_schema": "action-ticket/v1",
                "session_id": str(state["session"]["id"]),
                "turn_id": str(item["prompt_id"]),
                "actor_id": "root-user",
                "authorization_prompt_id": str(item["prompt_id"]),
                "authorization_prompt_sha256": str(item["prompt_sha256"]),
                "tool_use_id": "unclaimed",
                "contract_revision": revision,
                "semantic_action_id": item["semantic_action_id"],
                "canonical_target_id": item["canonical_target_id"],
                "write_surface_id": item["write_surface_id"],
                "repository_id": binding["repository_id"],
                "candidate_commit": binding["candidate_commit"],
                "release_version": binding["release_version"],
                "contract_sha256": contract_sha256,
                "closure_sha256": binding["closure_sha256"],
                "readiness_sha256": binding["readiness_sha256"],
                "closure_status": binding["closure_status"],
                "readiness_schema": binding["readiness_schema"],
                "readiness_kind": binding["readiness_kind"],
                "readiness_status": binding["readiness_status"],
                "action_ticket_eligible": binding["action_ticket_eligible"],
                "input_sha256": binding["input_sha256"],
                "state": "reserved",
                "attempt_count": 0,
                "reserved_at": reserved_at,
                "expires_at": expires_at,
                "settled_at": None,
            }
        )
    validate_execution_state(candidate_execution)
    state["execution"] = candidate_execution
    return (
        f"Execution contract {contract_id} revision {revision} adopted explicitly; "
        f"mode={execution_contract_mode(candidate_execution)}."
    )


def transition_execution_phase(
    execution: dict[str, Any],
    collection: str,
    record_id: str,
    next_state: str,
    *,
    resolution_sha256: str | None = None,
) -> None:
    validate_execution_state(execution)
    if collection not in {"phases", "gates"}:
        raise ValueError("execution phase collection must be phases or gates")
    record = next(
        (
            item
            for item in execution["contract"][collection]
            if isinstance(item, dict) and item.get("id") == record_id
        ),
        None,
    )
    if record is None:
        raise ValueError(f"unknown execution {collection} id: {record_id}")
    current = str(record.get("state") or "")
    if next_state not in PHASE_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid execution phase transition: {current} -> {next_state}")
    if current in {"stale", "conflicted"} and next_state == "pending":
        _execution_sha(resolution_sha256, "execution phase resolution_sha256")
        record["resolution_sha256"] = resolution_sha256
    elif resolution_sha256 is not None:
        raise ValueError("resolution digest is only valid when reopening stale/conflicted state")
    record["state"] = next_state
    execution["contract"]["canonical_sha256"] = contract_content_hash(
        execution["contract"]
    )
    validate_execution_state(execution)


def transition_execution_ticket(
    execution: dict[str, Any], ticket_id: str, next_state: str, *, settled_at: str
) -> None:
    validate_execution_state(execution)
    ticket = next(
        (
            item
            for item in execution["action_tickets"]
            if isinstance(item, dict) and item.get("id") == ticket_id
        ),
        None,
    )
    if ticket is None:
        raise ValueError(f"unknown execution ticket id: {ticket_id}")
    current = str(ticket.get("state") or "")
    if next_state not in TICKET_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid execution ticket transition: {current} -> {next_state}")
    _execution_time(settled_at, "action_tickets.settled_at")
    ticket["state"] = next_state
    if next_state == "reserved":
        ticket["tool_use_id"] = "unclaimed"
        ticket["settled_at"] = None
    else:
        ticket["settled_at"] = settled_at
    validate_execution_state(execution)


def expire_execution_tickets(execution: dict[str, Any], *, observed_at: str) -> list[str]:
    """Settle expired reservations without claiming that no side effect occurred."""
    validate_execution_state(execution)
    now = parse_time(observed_at)
    if now is None:
        raise ValueError("observed_at must be an ISO-8601 timestamp")
    expired: list[str] = []
    for ticket in execution["action_tickets"]:
        expires_at = parse_time(ticket.get("expires_at"))
        if ticket.get("state") in {"reserved", "in_flight"} and expires_at is not None and expires_at <= now:
            ticket["state"] = "expired"
            ticket["settled_at"] = observed_at
            expired.append(str(ticket["id"]))
    validate_execution_state(execution)
    return expired


def validate_pre_tool_decision(decision: Any) -> None:
    """Validate the synchronous PreToolUse allow/deny output subset."""
    if not isinstance(decision, dict) or set(decision) != {"hookSpecificOutput"}:
        raise ValueError("PreToolUse decision must contain only hookSpecificOutput")
    output = decision.get("hookSpecificOutput")
    if not isinstance(output, dict):
        raise ValueError("PreToolUse hookSpecificOutput must be an object")
    allowed = {"hookEventName", "permissionDecision", "permissionDecisionReason"}
    if not set(output).issubset(allowed) or output.get("hookEventName") != "PreToolUse":
        raise ValueError("unsupported PreToolUse output field")
    permission = output.get("permissionDecision")
    if permission not in {"allow", "deny"}:
        raise ValueError("Phase-4 PreToolUse decision must be allow or deny")
    reason = output.get("permissionDecisionReason")
    if permission == "deny" and (not isinstance(reason, str) or not reason or len(reason) > 512):
        raise ValueError("PreToolUse deny requires a bounded reason")
    if permission == "allow" and reason is not None and (
        not isinstance(reason, str) or len(reason) > 512
    ):
        raise ValueError("PreToolUse allow reason is invalid")


SHELL_TOOL_NAMES = {
    "bash", "shell", "exec_command", "mcp_exec_command", "unified_exec",
}
APPLY_PATCH_TOOL_NAMES = {"apply_patch", "mcp_apply_patch"}


def normalized_tool_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def pre_tool_input_sha256(tool_name: str, tool_input: Any) -> str:
    return sha256_text(
        canonical_json({"tool_name": tool_name, "tool_input": tool_input})
    )


def repository_identity(cwd: Any) -> str:
    try:
        resolved = str(Path(str(cwd or os.getcwd())).expanduser().resolve())
    except (OSError, RuntimeError, ValueError):
        resolved = str(cwd or "unresolved")
    return "repo-" + sha256_text(resolved)


def repository_commit(cwd: Any) -> str:
    root = str(cwd or os.getcwd())
    try:
        result = subprocess.run(
            ["git", "-C", root, "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
        status = subprocess.run(
            ["git", "-C", root, "status", "--porcelain=v1", "--untracked-files=all"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unresolved"
    value = result.stdout.strip().lower()
    clean = status.returncode == 0 and not status.stdout.strip()
    return (
        value
        if clean and result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", value)
        else "unresolved"
    )


def _shell_command(tool_input: Any) -> str | None:
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        for key in ("cmd", "command"):
            value = tool_input.get(key)
            if isinstance(value, str):
                return value
    return None


def _unquote_command_token(token: str) -> str:
    """Remove quote pairs retained by non-POSIX ``shlex`` tokenization."""
    while len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        token = token[1:-1]
    return token


def _command_basename(token: str) -> str:
    """Return a shell executable basename for either path separator style."""
    name = _unquote_command_token(token).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe")


def _command_tokens(command: str, *, posix: bool | None = None) -> list[str]:
    try:
        lexer = shlex.shlex(
            command,
            posix=os.name != "nt" if posix is None else posix,
            punctuation_chars=";&|()",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        return [_unquote_command_token(token) for token in lexer]
    except ValueError:
        return []


SHELL_CONTROL_TOKENS = {";", "&&", "||", "|", "&", "(", ")"}
SHELL_WRAPPERS = {"bash", "dash", "ksh", "pwsh", "powershell", "sh", "zsh"}


def _subcommands(tokens: list[str], executable: str) -> list[tuple[str, list[str]]]:
    """Return every executable invocation instead of trusting the first one."""
    invocations: list[tuple[str, list[str]]] = []
    indices = [
        index
        for index, token in enumerate(tokens)
        if _command_basename(token) == executable
    ]
    for position, start in enumerate(indices):
        end = indices[position + 1] if position + 1 < len(indices) else len(tokens)
        segment = tokens[start + 1 : end]
        boundary = next(
            (index for index, token in enumerate(segment) if token in SHELL_CONTROL_TOKENS),
            len(segment),
        )
        segment = segment[:boundary]
        index = 0
        while index < len(segment) and segment[index].startswith("-"):
            option = segment[index]
            index += 2 if option in {"-C", "-c", "--git-dir", "--work-tree"} else 1
        if index < len(segment):
            invocations.append((segment[index].lower(), segment[index + 1 :]))
    return invocations


def _expanded_command_tokens(
    command: str, *, depth: int = 0, posix: bool | None = None
) -> list[str]:
    """Tokenize a command and boundedly inspect explicit shell ``-c`` wrappers."""
    tokens = _command_tokens(command, posix=posix)
    if depth >= 3:
        return tokens
    expanded = list(tokens)
    for index, token in enumerate(tokens):
        wrapper = _command_basename(token)
        if wrapper not in SHELL_WRAPPERS:
            continue
        for option_index in range(index + 1, min(len(tokens), index + 5)):
            option = tokens[option_index].lower()
            if option in SHELL_CONTROL_TOKENS:
                break
            is_command_option = (
                option in {"-c", "--command", "-command"}
                or (option.startswith("-") and "c" in option[1:] and wrapper not in {"pwsh", "powershell"})
            )
            if is_command_option and option_index + 1 < len(tokens):
                expanded.extend(
                    _expanded_command_tokens(
                        tokens[option_index + 1], depth=depth + 1, posix=posix
                    )
                )
                break
    return expanded


def _first_version_token(values: list[str]) -> str | None:
    for value in values:
        candidate = value.removeprefix("refs/tags/")
        if re.fullmatch(r"v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:[-+][A-Za-z0-9._-]+)?", candidate):
            return candidate
    return None


def current_branch(cwd: Any) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd or os.getcwd()), "branch", "--show-current"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    value = result.stdout.strip()
    return value if result.returncode == 0 and EXECUTION_ID_RE.fullmatch(value) else "unknown"


def classify_pre_tool_action(payload: dict[str, Any]) -> dict[str, str] | None:
    tool_name = str(payload.get("tool_name") or "")
    normalized = normalized_tool_name(tool_name)
    tool_input = payload.get("tool_input")
    input_sha = pre_tool_input_sha256(tool_name, tool_input)
    action: dict[str, str] | None = None
    if normalized in SHELL_TOOL_NAMES or normalized.endswith("_exec_command"):
        command = _shell_command(tool_input)
        if command is None:
            return None
        tokens = _expanded_command_tokens(command)
        actions: list[dict[str, str]] = []
        for git_command, git_args in _subcommands(tokens, "git"):
            if git_command == "tag" and not any(
                value in {"-d", "--delete", "-l", "--list", "-v", "--verify", "--contains", "--points-at"}
                for value in git_args
            ):
                positional_tags = [value for value in git_args if not value.startswith("-")]
                if positional_tags:
                    tag = _first_version_token(git_args) or "unknown"
                    actions.append({
                        "tier": "A", "semantic_action_id": "release_tag_mutation",
                        "canonical_target_id": f"tag:{tag}", "write_surface_id": "git_release_tag",
                    })
            elif git_command == "push":
                version = _first_version_token(git_args)
                if version is not None or "--tags" in git_args or any("refs/tags/" in value for value in git_args):
                    tag = version or "all"
                    actions.append({
                        "tier": "A", "semantic_action_id": "release_tag_push",
                        "canonical_target_id": f"tag:{tag}", "write_surface_id": "git_remote_tag",
                    })
                else:
                    positional = [value for value in git_args if not value.startswith("-")]
                    remote = positional[0] if positional else "unknown"
                    refspec = positional[1] if len(positional) > 1 else current_branch(payload.get("cwd"))
                    ref = refspec.rsplit(":", 1)[-1]
                    semantic = "remote_push"
                    if any(value in {"--force", "--force-with-lease", "-f"} or value.startswith("+") for value in git_args):
                        semantic = "force_push"
                    elif "--delete" in git_args or any(value.startswith(":") for value in git_args):
                        semantic = "remote_branch_delete"
                    actions.append({
                        "tier": "B", "semantic_action_id": semantic,
                        "canonical_target_id": f"remote:{remote}:{ref.lstrip(':')}",
                        "write_surface_id": "git_remote_branch",
                    })
        for gh_command, gh_args in _subcommands(tokens, "gh"):
            if gh_command != "release" or not gh_args:
                continue
            verb = gh_args[0].lower()
            if verb in {"create", "edit", "delete", "upload"}:
                target = _first_version_token(gh_args[1:]) or next(
                    (value for value in gh_args[1:] if not value.startswith("-")),
                    "unknown",
                )
                actions.append({
                    "tier": "A", "semantic_action_id": f"github_release_{verb}",
                    "canonical_target_id": f"release:{target}",
                    "write_surface_id": "github_release",
                })
        lowered = [
            token if token in SHELL_CONTROL_TOKENS else _command_basename(token)
            for token in tokens
        ]
        registry_pairs = {
            ("npm", "publish"), ("npm", "unpublish"),
            ("cargo", "publish"), ("cargo", "yank"),
            ("gem", "push"), ("gem", "yank"),
            ("docker", "push"), ("twine", "upload"),
        }
        for left, right in zip(lowered, lowered[1:]):
            if (left, right) in registry_pairs:
                semantic = f"{left}_{right}"
                actions.append({
                    "tier": "A", "semantic_action_id": f"registry_{semantic}",
                    "canonical_target_id": f"registry:{semantic}",
                    "write_surface_id": "package_registry",
                    "release_version": "unresolved",
                })
        if len(actions) == 1:
            action = actions[0]
        elif len(actions) > 1:
            action = {
                "tier": "A" if any(item["tier"] == "A" for item in actions) else "B",
                "semantic_action_id": "compound_remote_mutation",
                "canonical_target_id": f"compound:{sha256_text(canonical_json(actions))}",
                "write_surface_id": "multiple_remote_surfaces",
                "release_version": "unresolved",
            }
    if action is None:
        joined = normalized
        mcp_actions = {
            "create_release": "github_release_create",
            "update_release": "github_release_edit",
            "delete_release": "github_release_delete",
            "publish_package": "registry_publish_package",
            "yank_package": "registry_yank_package",
        }
        for marker, semantic in mcp_actions.items():
            if joined == marker or joined.endswith("_" + marker):
                action = {
                    "tier": "A", "semantic_action_id": semantic,
                    "canonical_target_id": f"tool-target:{sha256_text(canonical_json(tool_input))}",
                    "write_surface_id": "remote_release_api",
                    "release_version": "unresolved",
                }
                break
    if action is None:
        return None
    if "release_version" not in action:
        target_value = action["canonical_target_id"].split(":", 1)[-1]
        action["release_version"] = target_value if target_value != "unknown" else "unresolved"
    return {
        **action,
        "input_sha256": input_sha,
        "repository_id": repository_identity(payload.get("cwd")),
        "candidate_commit": repository_commit(payload.get("cwd")),
    }


def _pre_tool_decision(permission: str, reason: str | None = None) -> dict[str, Any]:
    output: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": permission,
    }
    if reason:
        output["permissionDecisionReason"] = bounded(reason, 500)
    decision = {"hookSpecificOutput": output}
    validate_pre_tool_decision(decision)
    return decision


def _prompt_authorizes_b_action(prompt_text_value: str, action: dict[str, str]) -> bool:
    text = authoritative_supersession_text(prompt_text_value)
    text = re.sub(r"[,，](?=\s*(?:and\b|并(?:且|将)?))", " ", text, flags=re.I)
    patterns = {
        "remote_push": re.compile(r"\bpush\b|推送", re.I),
        "force_push": re.compile(r"\bforce[- ]?push\b|强制推送", re.I),
        "remote_branch_delete": re.compile(r"(?:delete|remove).{0,24}(?:remote\s+branch)|删除.{0,12}远程分支", re.I),
    }
    pattern = patterns.get(action["semantic_action_id"])
    if pattern is None:
        return False
    raw_target_parts = action["canonical_target_id"].split(":")[1:]
    if not raw_target_parts or any(
        part in {"", "unknown", "HEAD"} for part in raw_target_parts
    ):
        return False
    target_parts = raw_target_parts
    for clause in re.split(r"[\n!?。！？;；,，]|\.(?=\s|$)", text):
        if not pattern.search(clause) or CLAUSE_NEGATION_RE.search(clause):
            continue
        if target_parts and all(re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(part)}(?![A-Za-z0-9_.-])", clause) for part in target_parts):
            return True
    return False


def _active_work_unit_kind(state: dict[str, Any]) -> str | None:
    active = state.get("work_state", {}).get("active_work_unit_id")
    for unit in state.get("work_units", []):
        if isinstance(unit, dict) and unit.get("id") == active:
            return str(unit.get("kind") or "")
    return None


def _matching_action_ticket(
    state: dict[str, Any], action: dict[str, str]
) -> dict[str, Any] | None:
    if not re.fullmatch(r"[0-9a-f]{40}", action.get("candidate_commit", "")):
        return None
    execution = state.get("execution", {})
    contract = execution.get("contract", {}) if isinstance(execution, dict) else {}
    if contract.get("state") != "active":
        return None
    now = utc_now()
    expire_execution_tickets(execution, observed_at=now)
    for ticket in execution.get("action_tickets", []):
        if not isinstance(ticket, dict) or ticket.get("state") != "reserved":
            continue
        if (
            ticket.get("repository_id") == action["repository_id"]
            and (
                ticket.get("candidate_commit") != action["candidate_commit"]
                or ticket.get("contract_revision") != contract.get("revision")
                or ticket.get("contract_sha256") != contract.get("canonical_sha256")
            )
        ):
            ticket["state"] = "invalidated"
            ticket["settled_at"] = now
            continue
        exact = (
            ticket.get("ticket_schema") == "action-ticket/v1"
            and ticket.get("contract_revision") == contract.get("revision")
            and ticket.get("contract_sha256") == contract.get("canonical_sha256")
            and ticket.get("semantic_action_id") == action["semantic_action_id"]
            and ticket.get("canonical_target_id") == action["canonical_target_id"]
            and ticket.get("write_surface_id") == action["write_surface_id"]
            and ticket.get("repository_id") == action["repository_id"]
            and ticket.get("candidate_commit") == action["candidate_commit"]
            and (
                action["release_version"] == "unresolved"
                or ticket.get("release_version") == action["release_version"]
            )
            and ticket.get("input_sha256") == action["input_sha256"]
        )
        if exact:
            return ticket
    return None


def handle_pre_tool(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state.get("mode", {}).get("manual_off"):
        return {}
    require_usable_state(state)
    normalized = normalized_tool_name(payload.get("tool_name"))
    if _active_work_unit_kind(state) == "cleanup" and (
        normalized in APPLY_PATCH_TOOL_NAMES or normalized.endswith("_apply_patch")
    ):
        return _pre_tool_decision(
            "deny",
            "The active work unit is cleanup-only; product edits require a separate root-user authorization.",
        )
    effective_payload = dict(payload)
    effective_payload.setdefault("cwd", state.get("session", {}).get("cwd"))
    action = classify_pre_tool_action(effective_payload)
    if action is None:
        return {}
    if action["tier"] == "B":
        prompt_value = latest_requirement_text(session_dir, state)
        if _prompt_authorizes_b_action(prompt_value, action):
            return _pre_tool_decision("allow", "Exact root-user remote target authorization matched.")
        return _pre_tool_decision(
            "deny",
            "Shared remote mutation requires an explicit root-user action and exact remote/ref target.",
        )
    ticket = _matching_action_ticket(state, action)
    if ticket is None:
        save_state(session_dir, state)
        return _pre_tool_decision(
            "deny",
            "Release/public identity mutation requires an exact unexpired action-ticket/v1 bound to the active candidate.",
        )
    tool_use_id = str(payload.get("tool_use_id") or payload.get("toolUseId") or "")
    if not EXECUTION_ID_RE.fullmatch(tool_use_id):
        return _pre_tool_decision("deny", "High-risk tool use has no valid tool-use identity.")
    ticket["state"] = "in_flight"
    ticket["tool_use_id"] = tool_use_id
    ticket["attempt_count"] += 1
    save_state(session_dir, state)
    return _pre_tool_decision("allow", "Exact one-shot action ticket matched this release mutation.")


def settle_pre_tool_ticket(state: dict[str, Any], payload: dict[str, Any], outcome: str) -> None:
    tool_use_id = str(payload.get("tool_use_id") or payload.get("toolUseId") or "")
    if not tool_use_id:
        return
    execution = state.get("execution")
    if not isinstance(execution, dict):
        return
    for ticket in execution.get("action_tickets", []):
        if not isinstance(ticket, dict) or ticket.get("state") != "in_flight":
            continue
        if ticket.get("tool_use_id") != tool_use_id:
            continue
        if outcome == "success":
            ticket["state"] = "consumed"
            ticket["settled_at"] = utc_now()
        elif outcome == "failed":
            ticket["state"] = "reserved"
            ticket["tool_use_id"] = "unclaimed"
            ticket["settled_at"] = None
        else:
            # An ambiguous result may already have produced the external side
            # effect. Never make that uncertainty replayable.
            ticket["state"] = "invalidated"
            ticket["settled_at"] = utc_now()
        validate_execution_state(execution)
        return


def benchmark_pre_action_authorization(event: dict[str, Any]) -> str:
    if event.get("risk_tier") != "A":
        return "allow_neutral"
    if (
        event.get("execution_contract_state") == "active"
        and event.get("action_ticket_state") == "valid"
        and event.get("input_matches") is True
    ):
        return "allow_exact_ticket"
    return "deny_high_risk_action_without_ticket"


def benchmark_supersession_attribution(event: dict[str, Any]) -> str:
    if event.get("supersession_phrase_origin") in {"quoted", "quoted_or_annotated", "attributed"}:
        return "preserve_prior_requirement"
    return "supersede_explicit_target" if event.get("explicit_target_count") == 1 else "preserve_prior_requirement"


def benchmark_scope_transition_authority(event: dict[str, Any]) -> str:
    if event.get("authorized_work_unit") == "merge_cleanup" and event.get("attempted_transition") == "new_product_repair" and not event.get("separate_authorization"):
        return "deny_unapproved_scope_transition"
    return "allow_neutral"


def execution_state_is_dormant(execution: Any) -> bool:
    return isinstance(execution, dict) and canonical_json(execution) == canonical_json(dormant_execution_state())


def project_state_to_schema6(state: dict[str, Any]) -> dict[str, Any]:
    """Return a lossless schema-6 projection only for a dormant execution ledger."""
    if state.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("schema-6 projection requires current private state")
    validate_state_integrity(state)
    if not execution_state_is_dormant(state.get("execution")):
        raise ValueError("cannot project non-dormant execution state to schema 6")
    projected = json.loads(canonical_json(state))
    projected.pop("execution", None)
    projected["schema_version"] = 6
    projected["content_hash"] = state_content_hash(projected)
    return projected


def validate_work_units(state: dict[str, Any]) -> None:
    units = state.get("work_units")
    sequence = state.get("work_unit_sequence")
    if not isinstance(units, list) or len(units) > MAX_EXECUTION_RECORDS:
        raise StateIntegrityError("private work-unit ledger exceeds its record limit")
    if not isinstance(sequence, int) or sequence < 0:
        raise StateIntegrityError("private work-unit sequence is invalid")
    ids: set[str] = set()
    for raw in units:
        record = _require_record_keys(
            raw,
            field="work_units",
            required={
                "id", "protocol_version", "prompt_id", "parent_id", "kind",
                "status", "created_at", "closed_at", "scope_sha256",
            },
        )
        unit_id = str(record.get("id") or "")
        if not re.fullmatch(r"WU\d{4,}", unit_id) or unit_id in ids:
            raise StateIntegrityError("private work-unit identity is invalid")
        if record.get("protocol_version") != WORK_UNIT_PROTOCOL_VERSION:
            raise StateIntegrityError("private work-unit protocol is invalid")
        _execution_id(record.get("prompt_id"), "work_units.prompt_id")
        parent = record.get("parent_id")
        if parent is not None and parent not in ids:
            raise StateIntegrityError("private work-unit parent must precede its child")
        if record.get("kind") not in {"legacy", "general", "planning", "implementation", "cleanup", "release"}:
            raise StateIntegrityError("private work-unit kind is invalid")
        if record.get("status") not in {"active", "passed", "superseded"}:
            raise StateIntegrityError("private work-unit status is invalid")
        _execution_time(record.get("created_at"), "work_units.created_at")
        _execution_time(record.get("closed_at"), "work_units.closed_at", nullable=True)
        _execution_sha(record.get("scope_sha256"), "work_units.scope_sha256")
        if record.get("status") == "passed" and record.get("closed_at") is None:
            raise StateIntegrityError("passed work unit requires closed_at")
        ids.add(unit_id)
    active = state.get("work_state", {}).get("active_work_unit_id")
    if active is not None and active not in ids:
        raise StateIntegrityError("active work-unit id is unknown")
    if sequence < len(ids):
        raise StateIntegrityError("private work-unit sequence trails its records")


def validate_state_integrity(state: dict[str, Any]) -> None:
    version = state.get("schema_version")
    if version not in {1, 2, 3, 4, 5, 6, *READ_ONLY_COMPATIBILITY_SCHEMAS, SCHEMA_VERSION}:
        raise StateIntegrityError(f"unsupported private state schema {version!r}")
    stored_hash = state.get("content_hash")
    if not isinstance(stored_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", stored_hash):
        raise StateIntegrityError("private state has no valid content hash")
    expected_hash = state_content_hash(state)
    if not hmac.compare_digest(stored_hash, expected_hash):
        raise StateIntegrityError("private state content hash mismatch")
    if version == 1:
        required = STATE_REQUIRED_KEYS - {
            "integrity",
            "evidence_sequence",
            "completion_attempt",
            "work_state",
            "work_units",
            "work_unit_sequence",
            "agents",
            "execution",
        }
    elif version == 2:
        required = STATE_REQUIRED_KEYS - {
            "integrity", "work_state", "work_units", "work_unit_sequence", "agents", "execution"
        }
    elif version == 3:
        required = STATE_REQUIRED_KEYS - {
            "decision_log", "execution", "work_units", "work_unit_sequence"
        }
    elif version == 5:
        required = STATE_REQUIRED_KEYS - {
            "assets",
            "asset_sequence",
            "proofs",
            "proof_sequence",
            "execution",
            "work_units",
            "work_unit_sequence",
        }
    elif version in {4, 6, *READ_ONLY_COMPATIBILITY_SCHEMAS}:
        required = STATE_REQUIRED_KEYS - {
            "execution", "adapter_manifest", "classifier_metadata", "pending",
            "prompt_journal", "work_units", "work_unit_sequence",
        }
    else:
        required = STATE_REQUIRED_KEYS
    missing = sorted(required - set(state))
    if missing:
        raise StateIntegrityError(
            "private state is missing required fields: " + ", ".join(missing)
        )
    for key in (
        "session",
        "mode",
    ):
        if not isinstance(state.get(key), dict):
            raise StateIntegrityError(f"private state field {key} must be an object")
    if version >= 3 and not isinstance(state.get("work_state"), dict):
        raise StateIntegrityError("private state field work_state must be an object")
    for key in (
        "prompts",
        "requirements",
        "acceptance_items",
        "supersedes",
        "evidence",
        "assets",
        "proofs",
        "agents",
        "open_items",
        "compactions",
        "decision_log",
        "work_units",
    ):
        if key in state and not isinstance(state.get(key), list):
            raise StateIntegrityError(f"private state field {key} must be a list")
    if version == SCHEMA_VERSION:
        validate_execution_state(state.get("execution"))
        validate_work_units(state)
        work_unit_ids = {
            str(item.get("id"))
            for item in state.get("work_units", [])
            if isinstance(item, dict)
        }
        asset_ids: set[str] = set()
        for asset in state.get("assets", []):
            if (
                not isinstance(asset, dict)
                or not ASSET_ID_RE.fullmatch(str(asset.get("id") or ""))
                or asset.get("id") in asset_ids
                or not isinstance(asset.get("prompt_ids"), list)
                or any(
                    not isinstance(prompt_id, str)
                    for prompt_id in asset.get("prompt_ids", [])
                )
                or not re.fullmatch(r"[0-9a-f]{64}", str(asset.get("locator_sha256") or ""))
                or ";base64," in str(asset.get("source_ref") or "")
            ):
                raise StateIntegrityError("private asset ledger is invalid")
            asset_ids.add(str(asset["id"]))
        for collection in ("requirements", "acceptance_items"):
            for item in state.get(collection, []):
                contract = item.get("verification_contract") if isinstance(item, dict) else None
                if (
                    not isinstance(item, dict)
                    or item.get("work_unit_id") not in work_unit_ids
                    or
                    not isinstance(contract, dict)
                    or contract.get("protocol_version") != PROOF_PROTOCOL_VERSION
                    or contract.get("mode") not in {"enforced", "legacy_fallback"}
                    or not isinstance(contract.get("obligations"), list)
                ):
                    raise StateIntegrityError("private verification contract is invalid")
                if contract.get("mode") == "legacy_fallback" and contract.get("obligations"):
                    raise StateIntegrityError("legacy fallback cannot retain enforced obligations")
        proof_ids: set[str] = set()
        for proof in state.get("proofs", []):
            if (
                not isinstance(proof, dict)
                or not PROOF_ID_RE.fullmatch(str(proof.get("id") or ""))
                or proof.get("id") in proof_ids
                or proof.get("protocol_version") != PROOF_PROTOCOL_VERSION
            ):
                raise StateIntegrityError("private proof ledger is invalid")
            normalized = dict(proof)
            normalized.pop("id", None)
            normalized.pop("created_at", None)
            stored_proof_hash = normalized.pop("sha256", None)
            if stored_proof_hash != sha256_text(canonical_json(normalized)):
                raise StateIntegrityError("private proof hash mismatch")
            proof_ids.add(str(proof["id"]))


def preserve_corrupt_state(path: Path) -> Path | None:
    if not path.exists() or not path.is_file():
        return None
    timestamp = f"{int(time.time() * 1000)}-{os.getpid()}"
    backup = path.with_name(f"state.corrupt.{timestamp}.json")
    try:
        shutil.copy2(path, backup)
        secure_file(backup)
        return backup
    except OSError:
        return None


def process_session_lock(lock_path: Path) -> threading.Lock:
    key = os.path.normcase(os.path.abspath(lock_path))
    with PROCESS_SESSION_LOCKS_GUARD:
        return PROCESS_SESSION_LOCKS.setdefault(key, threading.Lock())


@contextlib.contextmanager
def filesystem_session_lock(lock_path: Path, timeout: float) -> Iterator[None]:
    deadline = time.monotonic() + timeout
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(
                str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            os.write(descriptor, f"{os.getpid()} {time.time()}".encode("ascii"))
        except (FileExistsError, PermissionError) as exc:
            # Windows can report an existing, still-open O_EXCL lock as
            # ERROR_ACCESS_DENIED instead of ERROR_FILE_EXISTS. The holder may
            # delete the lock before this thread can observe it, so absence is
            # not enough to reject the Windows contention case.
            if (
                isinstance(exc, PermissionError)
                and os.name != "nt"
                and not lock_path.exists()
            ):
                raise
            try:
                if time.time() - lock_path.stat().st_mtime > 30:
                    lock_path.unlink()
                    continue
            except FileNotFoundError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for {lock_path}")
            time.sleep(0.025)
    try:
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            lock_path.unlink()


@contextlib.contextmanager
def session_lock(session_dir: Path, timeout: float = 5.0) -> Iterator[None]:
    secure_directory(session_dir)
    lock_path = session_dir / ".lock"
    with process_session_lock(lock_path):
        with filesystem_session_lock(lock_path, timeout):
            yield


def session_dir_for(payload: dict[str, Any]) -> Path:
    return data_root() / "sessions" / safe_session_id(payload.get("session_id"))


def new_state(payload: dict[str, Any]) -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "session": {
            "id": str(payload.get("session_id") or "unknown-session"),
            "cwd": str(payload.get("cwd") or os.getcwd()),
            "model": payload.get("model"),
            "permission_mode": payload.get("permission_mode"),
            "transcript_path": payload.get("transcript_path"),
            "created_at": now,
            "updated_at": now,
            "ended_at": None,
            "asset_reconciliation": {
                "pending_prompt_ids": [],
                "post_tool_attempted_prompt_ids": [],
            },
        },
        "mode": {
            "active": False,
            "manual_off": False,
            "complexity_score": 0,
            "activation_reasons": [],
        },
        "prompts": [],
        "requirements": [],
        "acceptance_items": [],
        "supersedes": [],
        "evidence": [],
        "evidence_sequence": 0,
        "assets": [],
        "asset_sequence": 0,
        "proofs": [],
        "proof_sequence": 0,
        "work_state": {
            "plan_snapshot": None,
            "active_work_unit_id": None,
        },
        "work_units": [],
        "work_unit_sequence": 0,
        "agents": [],
        "open_items": [],
        "compactions": [],
        "completion_attempt": None,
        "completion_checkpoint": None,
        "continuation_attempts": 0,
        "decision_log": [],
        "execution": dormant_execution_state(),
        "adapter_manifest": json.loads(canonical_json(ADAPTER_MANIFEST)),
        "classifier_metadata": {
            "version": CLASSIFIER_VERSION,
            "clause_derivation_version": CLAUSE_DERIVATION_VERSION,
            "fail_closed": True,
        },
        "pending": {"operations": [], "recovery": None, "clear_token": None},
        "prompt_journal": {"version": 1, "entries": []},
        "integrity": {
            "status": "ok",
            "issue": None,
            "recovered_at": None,
            "backup_file": None,
        },
        "content_hash": "",
    }


def migrate_execution_state(execution: Any) -> dict[str, Any]:
    if not isinstance(execution, dict):
        return dormant_execution_state()
    protocol = execution.get("protocol_version")
    if protocol == EXECUTION_PROTOCOL_VERSION:
        return execution
    if protocol != "1.0.0":
        raise StateIntegrityError("unsupported execution protocol during schema migration")
    migrated = json.loads(canonical_json(execution))
    migrated["protocol_version"] = EXECUTION_PROTOCOL_VERSION
    contract = migrated.get("contract", {})
    for candidate in contract.get("authorization_candidates", []):
        if isinstance(candidate, dict):
            candidate.setdefault("ticket_binding", None)
    contract_sha = str(contract.get("canonical_sha256") or ("0" * 64))
    state_map = {
        "reserved": "invalidated",
        "consumed": "consumed",
        "failed": "invalidated",
        "expired_unsettled": "expired",
    }
    migrated_tickets: list[dict[str, Any]] = []
    for ticket in migrated.get("action_tickets", []):
        if not isinstance(ticket, dict):
            continue
        item = dict(ticket)
        item.update(
            {
                "ticket_schema": "action-ticket/v1",
                "repository_id": "legacy-unbound",
                "candidate_commit": "legacy-unbound",
                "release_version": "legacy-unbound",
                "authorization_prompt_id": str(item.get("turn_id") or "legacy-turn"),
                "authorization_prompt_sha256": "0" * 64,
                "contract_sha256": contract_sha,
                "closure_sha256": "0" * 64,
                "readiness_sha256": "0" * 64,
                "closure_status": "legacy_unverified",
                "readiness_schema": "legacy",
                "readiness_kind": "legacy",
                "readiness_status": "legacy_unverified",
                "action_ticket_eligible": False,
                "attempt_count": 0,
                "state": state_map.get(str(ticket.get("state")), "invalidated"),
            }
        )
        if item["state"] in {"invalidated", "expired"} and item.get("settled_at") is None:
            item["settled_at"] = utc_now()
        migrated_tickets.append(item)
    migrated["action_tickets"] = migrated_tickets
    if isinstance(contract, dict):
        contract["canonical_sha256"] = contract_content_hash(contract)
    return migrated


def migrate_state(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    version = state.get("schema_version")
    if version == 1:
        evidence_sequence = 0
        for item in state.get("evidence", []):
            match = re.fullmatch(r"E(\d+)", str(item.get("id") or ""))
            if match:
                evidence_sequence = max(evidence_sequence, int(match.group(1)))
        for collection in ("requirements", "acceptance_items"):
            for item in state.get(collection, []):
                evidence = item.get("evidence", [])
                if item.get("status") == "pass" and (
                    not isinstance(evidence, list)
                    or not evidence
                    or any(
                        not isinstance(value, str)
                        or not EVIDENCE_ID_RE.fullmatch(value)
                        for value in evidence
                    )
                ):
                    item["status"] = "pending"
                    item["evidence"] = []
        state["evidence_sequence"] = evidence_sequence
    elif version not in {2, 3, 4, 5, 6, *READ_ONLY_COMPATIBILITY_SCHEMAS, SCHEMA_VERSION}:
        raise StateIntegrityError(f"unsupported private state schema {version!r}")
    if version in {1, 2}:
        state["work_state"] = {"plan_snapshot": None}
        state["agents"] = []
    if version in {1, 2, 3}:
        state["decision_log"] = []
    elif version == 4:
        migrated_decisions: list[dict[str, Any]] = []
        for raw_item in state.get("decision_log", []):
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            outcome = str(item.get("outcome") or "fail_closed_integrity")
            item.setdefault("protocol_version", None)
            item.setdefault(
                "decision_source",
                "checkpoint"
                if outcome == "consume_checkpoint"
                else (
                    "integrity"
                    if outcome == "fail_closed_integrity"
                    else "legacy_classifier"
                ),
            )
            item.setdefault("declared_disposition", None)
            item.setdefault("observed_outcome", outcome)
            migrated_decisions.append(item)
        state["decision_log"] = migrated_decisions[-DECISION_LOG_LIMIT:]
    if version in {1, 2, 3, 4, 5, 6, *READ_ONLY_COMPATIBILITY_SCHEMAS}:
        # Turn tokens and partially staged controls are intentionally ephemeral.
        # Preserve the durable ledger/history while requiring a fresh protocol
        # token after a schema upgrade.
        state["completion_attempt"] = None
        state["schema_version"] = SCHEMA_VERSION
    if version in {1, 2, 3, 4, 5}:
        state["assets"] = []
        state["asset_sequence"] = 0
        state["proofs"] = []
        state["proof_sequence"] = 0
        for collection in ("requirements", "acceptance_items"):
            for item in state.get(collection, []):
                item["verification_contract"] = {
                    "protocol_version": PROOF_PROTOCOL_VERSION,
                    "mode": "legacy_fallback",
                    "reason": "migrated_schema5_or_earlier",
                    "obligations": [],
                }
    if not isinstance(state.get("integrity"), dict):
        state["integrity"] = {
            "status": "ok",
            "issue": None,
            "recovered_at": None,
            "backup_file": None,
        }
    state.setdefault("evidence_sequence", 0)
    state.setdefault("assets", [])
    state.setdefault("asset_sequence", 0)
    state.setdefault("proofs", [])
    state.setdefault("proof_sequence", 0)
    work_state = state.setdefault(
        "work_state", {"plan_snapshot": None, "active_work_unit_id": None}
    )
    if isinstance(work_state, dict):
        work_state.setdefault("plan_snapshot", None)
        work_state.setdefault("active_work_unit_id", None)
    state.setdefault("work_units", [])
    state.setdefault("work_unit_sequence", 0)
    if version in {1, 2, 3, 4, 5, 6, *READ_ONLY_COMPATIBILITY_SCHEMAS}:
        if state["requirements"] or state["acceptance_items"]:
            state["work_unit_sequence"] = 1
            state["work_units"] = [
                {
                    "id": "WU0001",
                    "protocol_version": WORK_UNIT_PROTOCOL_VERSION,
                    "prompt_id": state["prompts"][-1]["id"] if state["prompts"] else "P0001",
                    "parent_id": None,
                    "kind": "legacy",
                    "status": "active",
                    "created_at": state.get("session", {}).get("created_at") or utc_now(),
                    "closed_at": None,
                    "scope_sha256": sha256_text("legacy-migrated-work-unit"),
                }
            ]
            work_state["active_work_unit_id"] = "WU0001"
            for collection in ("requirements", "acceptance_items"):
                for item in state[collection]:
                    if isinstance(item, dict):
                        item.setdefault("work_unit_id", "WU0001")
    state.setdefault("agents", [])
    state.setdefault("completion_attempt", None)
    attempt = state.get("completion_attempt")
    if isinstance(attempt, dict):
        if attempt.get("protocol_version") not in {None, STOP_PROTOCOL_VERSION}:
            # A turn-bound control from an older protocol cannot be interpreted
            # under new Stop semantics. Preserve the durable ledger and require
            # the next UserPromptSubmit event to establish a fresh attempt.
            state["completion_attempt"] = None
        else:
            attempt.setdefault("protocol_version", STOP_PROTOCOL_VERSION)
            attempt.setdefault("staged_control", None)
            attempt.setdefault("staged_at", None)
    state.setdefault("continuation_attempts", 0)
    state.setdefault("decision_log", [])
    state["execution"] = migrate_execution_state(state.get("execution"))
    state.setdefault("adapter_manifest", json.loads(canonical_json(ADAPTER_MANIFEST)))
    state.setdefault("classifier_metadata", {
        "version": CLASSIFIER_VERSION,
        "clause_derivation_version": CLAUSE_DERIVATION_VERSION,
        "fail_closed": True,
    })
    state.setdefault("pending", {"operations": [], "recovery": None, "clear_token": None})
    state.setdefault("prompt_journal", {"version": 1, "entries": []})
    session = state.setdefault("session", {})
    reconciliation = session.setdefault("asset_reconciliation", {})
    if isinstance(reconciliation, dict):
        reconciliation.setdefault(
            "pending_prompt_ids",
            [
                str(item["id"])
                for item in state.get("prompts", [])
                if isinstance(item, dict)
                and item.get("origin", "human") == "human"
                and isinstance(item.get("id"), str)
            ],
        )
        reconciliation.setdefault("post_tool_attempted_prompt_ids", [])
    return state


def load_state(session_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    state_path = session_dir / "state.json"
    if not state_path.exists():
        prompt_dir = session_dir / "prompts"
        if prompt_dir.is_dir() and any(prompt_dir.glob("P*.json")):
            state = rebuild_state_from_prompts(
                session_dir,
                payload,
                issue="private state file is missing",
                backup_file=None,
            )
        else:
            state = new_state(payload)
    else:
        issue: str | None = None
        try:
            with state_path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict):
                raise StateIntegrityError("private state root must be an object")
            validate_state_integrity(loaded)
            state = migrate_state(loaded, payload)
            integrity = state.get("integrity")
            if isinstance(integrity, dict) and integrity.get("status") == "failed":
                state = rebuild_state_from_prompts(
                    session_dir,
                    payload,
                    issue=(
                        "retrying prior private-state recovery failure: "
                        + bounded(integrity.get("issue"), 800)
                    ),
                    backup_file=integrity.get("backup_file"),
                )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            StateIntegrityError,
            TypeError,
            ValueError,
        ) as exc:
            issue = f"{type(exc).__name__}: {exc}"
            backup = preserve_corrupt_state(state_path)
            state = rebuild_state_from_prompts(
                session_dir,
                payload,
                issue=issue,
                backup_file=backup.name if backup is not None else None,
            )
    session = state.setdefault("session", {})
    for key in ("cwd", "model", "permission_mode", "transcript_path"):
        if payload.get(key) is not None:
            session[key] = payload[key]
    state["open_items"] = open_item_ids(state)
    return state


def pending_operation(state: dict[str, Any], operation: str, *, subject_id: str | None = None, requested_surface: str | None = None) -> dict[str, Any]:
    """Return a deterministic pending operation record without granting authority.

    Ambiguous operations are recorded too: they are exactly the records that
    need explicit resolution or an explicit clear, never silent drops.
    """
    if not operation:
        operation = "unspecified"
    record = {
        "operation": operation,
        "subjectId": subject_id,
        "requestedSurface": requested_surface,
        "state": "pending",
    }
    pending = state.setdefault("pending", {"operations": [], "recovery": None, "clear_token": None})
    operations = pending.setdefault("operations", [])
    operations[:] = [item for item in operations if item != record]
    operations.append(record)
    operations[:] = operations[-64:]
    return record


def clear_pending(state: dict[str, Any], *, operation: str | None = None) -> int:
    """Clear only pending records; completed evidence and requirements are immutable."""
    pending = state.setdefault("pending", {"operations": [], "recovery": None, "clear_token": None})
    operations = pending.setdefault("operations", [])
    before = len(operations)
    if operation is None:
        operations.clear()
    else:
        operations[:] = [item for item in operations if item.get("operation") != operation]
    return before - len(operations)


def save_state(session_dir: Path, state: dict[str, Any]) -> None:
    state["open_items"] = open_item_ids(state)
    state["session"]["updated_at"] = utc_now()
    state["content_hash"] = state_content_hash(state)
    atomic_write_json(session_dir / "state.json", state)


def prompt_text(payload: dict[str, Any]) -> str:
    for key in ("prompt", "user_prompt", "message"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return ""


def recursive_strings(value: Any, *, depth: int = 0) -> Iterator[str]:
    """Yield bounded string leaves without retaining multimodal bytes."""
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from recursive_strings(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value[:64]:
            yield from recursive_strings(item, depth=depth + 1)


def image_dimensions(raw: bytes, media_type: str) -> tuple[int | None, int | None]:
    try:
        if media_type == "image/png" and raw.startswith(b"\x89PNG\r\n\x1a\n"):
            return int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")
        if media_type == "image/gif" and raw[:6] in {b"GIF87a", b"GIF89a"}:
            return int.from_bytes(raw[6:8], "little"), int.from_bytes(raw[8:10], "little")
        if media_type == "image/jpeg" and raw.startswith(b"\xff\xd8"):
            offset = 2
            while offset + 9 < len(raw):
                if raw[offset] != 0xFF:
                    offset += 1
                    continue
                marker = raw[offset + 1]
                offset += 2
                if marker in {0xD8, 0xD9}:
                    continue
                length = int.from_bytes(raw[offset : offset + 2], "big")
                if length < 2 or offset + length > len(raw):
                    break
                if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                    return (
                        int.from_bytes(raw[offset + 5 : offset + 7], "big"),
                        int.from_bytes(raw[offset + 3 : offset + 5], "big"),
                    )
                offset += length
    except (IndexError, ValueError):
        pass
    return None, None


def asset_candidate(value: str) -> tuple[str, str, bytes | None, bool] | None:
    """Return kind, locator, bounded bytes, availability for an image reference."""
    stripped = value.strip()
    if stripped.startswith("data:image/") and ";base64," in stripped:
        header, encoded = stripped.split(",", 1)
        if len(encoded) > (MAX_ASSET_BYTES * 4 // 3 + 8):
            return "data_url", header.split(";", 1)[0][5:], None, False
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            return "data_url", header.split(";", 1)[0][5:], None, False
        if len(raw) > MAX_ASSET_BYTES:
            return "data_url", header.split(";", 1)[0][5:], None, False
        return "data_url", header.split(";", 1)[0][5:], raw, True
    raw_path = stripped[7:] if stripped.startswith("file://") else stripped
    path = Path(raw_path).expanduser()
    if path.suffix.lower() not in IMAGE_SUFFIXES:
        return None
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ASSET_BYTES:
            return "local_file", raw_path, None, False
        raw = path.read_bytes()
    except OSError:
        return "local_file", raw_path, None, False
    return "local_file", raw_path, raw, True


def add_asset(
    state: dict[str, Any], prompt_id: str | None, candidate: tuple[str, str, bytes | None, bool], source: str
) -> str:
    kind, locator, raw, available = candidate
    media_type = (
        locator if kind == "data_url" else (mimetypes.guess_type(locator)[0] or "application/octet-stream")
    )
    digest = hashlib.sha256(raw).hexdigest() if raw is not None else None
    for item in state.get("assets", []):
        if digest and item.get("sha256") == digest:
            if prompt_id and prompt_id not in item.get("prompt_ids", []):
                item.setdefault("prompt_ids", []).append(prompt_id)
            return str(item["id"])
        if not digest and item.get("locator_sha256") == sha256_text(locator):
            if prompt_id and prompt_id not in item.get("prompt_ids", []):
                item.setdefault("prompt_ids", []).append(prompt_id)
            return str(item["id"])
    width, height = image_dimensions(raw or b"", media_type)
    state["asset_sequence"] = int(state.get("asset_sequence", 0)) + 1
    asset_id = f"M{state['asset_sequence']:04d}"
    source_ref = (
        f"data:{media_type}"
        if kind == "data_url"
        else Path(locator).name
    )
    state["assets"].append(
        {
            "id": asset_id,
            "prompt_ids": [prompt_id] if prompt_id else [],
            "created_at": utc_now(),
            "source": source,
            "source_kind": kind,
            "source_ref": bounded(source_ref, 180),
            "locator_sha256": sha256_text(locator),
            "sha256": digest,
            "bytes": len(raw) if raw is not None else None,
            "media_type": media_type,
            "width": width,
            "height": height,
            "available": available,
        }
    )
    return asset_id


def discover_assets(
    state: dict[str, Any], value: Any, *, prompt_id: str | None, source: str
) -> list[str]:
    found: list[str] = []
    for text in recursive_strings(value):
        candidate = (
            asset_candidate(text)
            if text.startswith("data:image/")
            or text.startswith("file://")
            or not any(character.isspace() for character in text)
            else None
        )
        if candidate is not None:
            found.append(add_asset(state, prompt_id, candidate, source))
        for match in ABSOLUTE_PATH_RE.findall(text):
            candidate = asset_candidate(match.rstrip(")]}>"))
            if candidate is not None:
                found.append(add_asset(state, prompt_id, candidate, source))
    return list(dict.fromkeys(found))


def unsupported_locator_digest(raw_locator: str) -> str:
    return sha256_text(UNSUPPORTED_LOCATOR_DOMAIN + raw_locator)


def unsupported_subject(reason_token: str, raw_locator: str) -> str:
    """Build the final opaque subject id for an unsupported locator form."""
    if reason_token not in UNSUPPORTED_REASON_TOKENS:
        raise ValueError(f"unsupported reason token {reason_token!r}")
    return f"{UNSUPPORTED_SUBJECT_PREFIX}{reason_token}/{unsupported_locator_digest(raw_locator)}"


def canonical_windows_locator(raw: str) -> tuple[str | None, str | None]:
    """Lexically canonicalize one Windows drive locator.

    Returns ``(canonical_text, None)`` for the supported v1 set, or
    ``(None, reason_token)`` for a deterministic unsupported form. Case is
    never folded: spellings that differ in component case stay distinct
    subjects. Junction/reparse questions are physical properties that prompt
    text cannot answer, so the lexical layer never resolves them.
    """
    text = raw.rstrip(")]}>.,")
    body = text
    if body[:2].upper() in {"\\\\", "//"}:
        if body[:4].upper() in {"\\\\.\\", "\\\\?\\", "//./", "//?/"}:
            return None, "device_path"
        return None, "unc"
    match = re.fullmatch(r"([A-Za-z]):[\\/](.*)", body)
    if match is None:
        return None, "physical_identity"
    drive = match.group(1).upper()
    rest = match.group(2)
    if ":" in rest:
        # A second colon beyond the drive separator is an alternate data
        # stream or otherwise not a plain filesystem locator.
        return None, "ads"
    raw_components = re.split(r"[\\/]+", rest)
    if raw_components and raw_components[-1] == "":
        raw_components = raw_components[:-1]
    for component in raw_components:
        if component in {".", ".."}:
            continue
        if component != component.rstrip(" "):
            return None, "trailing_dots_spaces"
        if component.endswith("."):
            return None, "trailing_dots_spaces"
        if component.upper() in WINDOWS_RESERVED_COMPONENT_NAMES:
            return None, "reserved_name"
    resolved: list[str] = []
    for component in raw_components:
        if component == ".":
            continue
        if component == "..":
            if not resolved:
                return None, "beyond_root"
            resolved.pop()
            continue
        resolved.append(component)
    if not resolved:
        return f"{drive}:\\", None
    return f"{drive}:\\" + "\\".join(resolved), None


def canonical_thread_uri(text: str) -> str | None:
    """Return the normalized ``codex://threads/<uuid>`` text for a locator."""
    candidate = text.strip().rstrip(")]}>.,")
    if not candidate.lower().startswith(THREAD_URI_PREFIX):
        return None
    identifier = candidate[len(THREAD_URI_PREFIX):]
    if not THREAD_ID_RE.fullmatch(identifier):
        return None
    return THREAD_URI_PREFIX + identifier.lower()


def thread_subject_item(uri_text: str) -> dict[str, str]:
    normalized = canonical_thread_uri(uri_text)
    if normalized is None:
        raise ValueError(f"invalid thread locator {uri_text!r}")
    return {
        "id": f"subject:{sha256_text(normalized)[:20]}",
        "kind": "thread",
        "display": normalized,
        "locator_sha256": sha256_text(normalized),
    }


def thread_subject_id_from_thread_id(value: str) -> str | None:
    stripped = str(value).strip().strip("\"'")
    if not THREAD_ID_RE.fullmatch(stripped):
        return None
    normalized = THREAD_URI_PREFIX + stripped.lower()
    return f"subject:{sha256_text(normalized)[:20]}"


def windows_locator_display(locator: str) -> str:
    return re.split(r"[\\/]+", locator.rstrip(")]}>.,:"))[-1] or locator[:60]


def prompt_subjects(text: str, include_threads: bool = True) -> list[dict[str, str]]:
    subjects: list[dict[str, str]] = []
    for value in WINDOWS_UNC_PATH_RE.findall(text):
        canonical, unsupported = canonical_windows_locator(value)
        reason = unsupported or "unc"
        subjects.append(
            {
                "id": unsupported_subject(reason, value),
                "kind": "path",
                "display": windows_locator_display(value),
                "locator_sha256": unsupported_locator_digest(value),
            }
        )
    for value in WINDOWS_DRIVE_PATH_RE.findall(text):
        canonical, unsupported = canonical_windows_locator(value)
        if unsupported is not None:
            subjects.append(
                {
                    "id": unsupported_subject(unsupported, value),
                    "kind": "path",
                    "display": windows_locator_display(value),
                    "locator_sha256": unsupported_locator_digest(value),
                }
            )
            continue
        subjects.append(
            {
                "id": f"subject:{sha256_text(canonical)[:20]}",
                "kind": "path",
                "display": windows_locator_display(canonical),
                "locator_sha256": sha256_text(canonical),
            }
        )
    for kind, pattern in (("path", ABSOLUTE_PATH_RE), ("url", URL_RE)):
        for value in pattern.findall(text):
            cleaned = value.rstrip(")]}>.,")
            if kind == "url":
                normalized_thread = canonical_thread_uri(cleaned)
                if normalized_thread is not None:
                    if include_threads:
                        subjects.append(thread_subject_item(normalized_thread))
                    continue
            if (
                kind == "path"
                and "/" not in cleaned[1:]
                and not Path(cleaned).suffix
            ):
                # A bare slash-delimited prose fragment (for example
                # "公共/macOS" after lossy decoding) is not an inspectable
                # absolute-path subject. Real artifact paths normally contain
                # another path separator or a filename suffix.
                continue
            if kind == "path" and Path(cleaned).suffix.lower() in IMAGE_SUFFIXES:
                continue
            subjects.append(
                {
                    "id": f"subject:{sha256_text(cleaned)[:20]}",
                    "kind": kind,
                    "display": Path(cleaned).name if kind == "path" else cleaned[:120],
                    "locator_sha256": sha256_text(cleaned),
                }
            )
    return list({item["id"]: item for item in subjects}.values())


def windows_drive_subject_ids(text: str) -> list[str]:
    """Return opaque/canonical subject ids for the drive paths in ``text``."""
    result: list[str] = []
    for value in WINDOWS_DRIVE_PATH_RE.findall(text):
        canonical, unsupported = canonical_windows_locator(value)
        if unsupported is not None:
            result.append(unsupported_subject(unsupported, value))
        else:
            result.append(f"subject:{sha256_text(canonical)[:20]}")
    return list(dict.fromkeys(result))


def discovered_subject_ids(value: Any, include_threads: bool = True) -> list[str]:
    result: list[str] = []
    for text in recursive_strings(value):
        result.extend(
            item["id"]
            for item in prompt_subjects(text, include_threads=include_threads)
        )
    return list(dict.fromkeys(result))


def deterministic_scope_spec(
    text: str,
    subjects: list[dict[str, str]],
    assets: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return prompt-derived scope facts, never a caller-asserted count."""
    counts: set[int] = set()
    for pattern in SCOPE_CARDINALITY_PATTERNS:
        counts.update(
            int(match.group(1))
            for match in pattern.finditer(text)
            if 0 < int(match.group(1)) <= 10000
        )
    counts.update(
        int(match.group(1))
        for match in COMPLETE_RATIO_RE.finditer(text)
        if 0 < int(match.group(1)) <= 10000
    )
    if len(counts) > 1:
        return None
    expected_ids = sorted(
        {
            str(item["id"])
            for item in [*subjects, *assets]
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
    )
    if counts:
        expected_count = counts.pop()
        return {
            "expected_scope_count": expected_count,
            "expected_scope_sha256": (
                sha256_text(canonical_json(expected_ids))
                if len(expected_ids) >= 2 and len(expected_ids) == expected_count
                else None
            ),
        }
    if len(expected_ids) >= 2:
        return {
            "expected_scope_count": len(expected_ids),
            "expected_scope_sha256": sha256_text(canonical_json(expected_ids)),
        }
    return None


def visual_mutation_requested(text: str) -> bool:
    """Return true only for an affirmative visual-mutation clause."""
    negation = re.compile(
        r"\b(?:do\s+not|don't|must\s+not|should\s+not|no|without)\b|"
        r"(?:不要|不得|无需|不需要|暂不|不再|别|切勿|勿)",
        re.IGNORECASE,
    )
    for clause in _protected_prompt_clauses(text):
        if not VISUAL_MUTATION_RE.search(clause):
            continue
        if negation.search(clause) or DEFERRED_ACTION_CLAUSE_RE.search(clause):
            continue
        return True
    return False


def verification_contract(
    item_id: str,
    text: str,
    state: dict[str, Any],
    asset_ids: list[str],
    clauses: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive the enforced contract from the schema-8 clause model.

    The clause-derived ``(operation, subjectId, requestedSurface)`` triple is
    the source of the subject set, the readback surface, and the operation
    stamped on each subject_readback obligation. Negated clauses never derive
    protection subjects or physical-identity obligations, and the derivation
    version is sealed into the contract so certification can detect drift.
    """
    if clauses is None:
        clauses = clause_metadata(text)
    positive_clauses = _positive_clause_texts(clauses)
    positive_text = "\n".join(positive_clauses)
    contract_operation = "unspecified"
    primary_clause = _primary_positive_clause(clauses)
    if primary_clause is not None:
        operation = primary_clause.get("operation")
        if isinstance(operation, str) and operation not in {
            "",
            "unspecified",
            "ambiguous",
        }:
            contract_operation = operation
    assets = [item for item in state.get("assets", []) if item.get("id") in asset_ids]
    subjects = prompt_subjects(positive_text) if positive_text else []
    if IMAGE_REFERENCE_RE.search(positive_text) and not assets:
        return {
            "protocol_version": PROOF_PROTOCOL_VERSION,
            "mode": "legacy_fallback",
            "reason": "asset_reference_unresolved",
            "obligations": [],
        }
    if assets and any(not item.get("available") for item in assets):
        return {
            "protocol_version": PROOF_PROTOCOL_VERSION,
            "mode": "legacy_fallback",
            "reason": "asset_unavailable",
            "obligations": [],
        }
    full_scope_requested = bool(
        FULL_SCOPE_RE.search(positive_text)
        and not FULL_SCOPE_NEGATION_RE.search(positive_text)
    )
    scope_spec = (
        deterministic_scope_spec(positive_text or text, subjects, assets)
        if full_scope_requested
        else None
    )
    if full_scope_requested and scope_spec is None:
        return {
            "protocol_version": PROOF_PROTOCOL_VERSION,
            "mode": "legacy_fallback",
            "reason": "scope_not_constructible",
            "obligations": [],
        }
    obligations: list[dict[str, Any]] = []

    def add(
        kind: str,
        surface: str,
        subject_ids: list[str],
        scope: dict[str, Any] | None = None,
    ) -> None:
        obligation = {
            "id": f"O-{item_id}-{len(obligations) + 1:03d}",
            "kind": kind,
            "surface": surface,
            "subject_ids": list(dict.fromkeys(subject_ids)),
        }
        if scope is not None:
            obligation.update(scope)
        obligations.append(obligation)

    for asset in assets:
        add("input_asset_inspection", "visual", [str(asset["id"])])
    visual_signal = bool(assets or IMAGE_REFERENCE_RE.search(positive_text))
    if visual_signal and visual_mutation_requested(positive_text or text):
        add("result_visual_readback", "ui", [str(item["id"]) for item in assets])
    if subjects:
        readback_surface = "ui" if UI_SURFACE_RE.search(positive_text) else "artifact"
        readback = {
            "id": f"O-{item_id}-{len(obligations) + 1:03d}",
            "kind": "subject_readback",
            "surface": readback_surface,
            "subject_ids": [item["id"] for item in subjects],
            "operation": contract_operation,
            "requested_surface": readback_surface,
        }
        obligations.append(readback)
    # Restricted physical-identity capture: the schema-8 clause model replaced
    # the 0.9.5 lexical rule. The unbindable subject_readback derives only when
    # some non-negated clause carries the physical-identity signal outside
    # quoted spans; the drive-path subjects then come from every positive
    # clause, so paths named in negated clauses are never captured.
    if any(
        _signal_outside_quotes(clause)
        and PHYSICAL_IDENTITY_SIGNAL_RE.search(clause)
        for clause in positive_clauses
    ):
        physical_subjects = [
            unsupported_subject("physical_identity", locator)
            for locator in WINDOWS_DRIVE_PATH_RE.findall(positive_text)
        ]
        if physical_subjects:
            add("subject_readback", "artifact", physical_subjects)
    if scope_spec is not None:
        add(
            "scope_coverage",
            "scope",
            [item["id"] for item in subjects],
            scope_spec,
        )
    if not obligations:
        return {
            "protocol_version": PROOF_PROTOCOL_VERSION,
            "mode": "legacy_fallback",
            "reason": "no_deterministic_contract",
            "obligations": [],
        }
    return {
        "protocol_version": PROOF_PROTOCOL_VERSION,
        "mode": "enforced",
        "reason": "deterministic_prompt_contract",
        "clause_derivation_version": CLAUSE_DERIVATION_VERSION,
        "clause_operation": contract_operation,
        "obligations": obligations,
    }


def assistant_text(payload: dict[str, Any]) -> str:
    for key in ("last_assistant_message", "assistant_response", "response"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return ""


def latest_transcript_turn_id(
    state: dict[str, Any], payload: dict[str, Any]
) -> str | None:
    """Return the latest real turn id recorded by Codex, if available."""
    session = state.get("session")
    stored_path = (
        session.get("transcript_path") if isinstance(session, dict) else None
    )
    raw_path = payload.get("transcript_path") or stored_path
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    transcript = Path(raw_path).expanduser()
    try:
        with transcript.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - TRANSCRIPT_TAIL_BYTES)
            handle.seek(start)
            tail = handle.read()
    except OSError:
        return None
    if start:
        _, separator, tail = tail.partition(b"\n")
        if not separator:
            return None
    for raw_line in reversed(tail.splitlines()):
        try:
            record = json.loads(raw_line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict) or record.get("type") != "turn_context":
            continue
        record_payload = record.get("payload")
        if not isinstance(record_payload, dict):
            continue
        turn_id = record_payload.get("turn_id")
        if isinstance(turn_id, str) and turn_id.strip():
            return turn_id.strip()
    return None


def transcript_tail_records(state: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, Any]]:
    session = state.get("session")
    stored_path = session.get("transcript_path") if isinstance(session, dict) else None
    raw_path = payload.get("transcript_path") or stored_path
    if not isinstance(raw_path, str) or not raw_path.strip():
        return []
    transcript = Path(raw_path).expanduser()
    try:
        with transcript.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - TRANSCRIPT_TAIL_BYTES)
            handle.seek(start)
            tail = handle.read()
    except OSError:
        return []
    if start:
        _, separator, tail = tail.partition(b"\n")
        if not separator:
            return []
    records: list[dict[str, Any]] = []
    for raw_line in tail.splitlines():
        try:
            record = json.loads(raw_line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records[-512:]


def transcript_is_readable(state: dict[str, Any], payload: dict[str, Any]) -> bool:
    session = state.get("session")
    stored_path = session.get("transcript_path") if isinstance(session, dict) else None
    raw_path = payload.get("transcript_path") or stored_path
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False
    transcript = Path(raw_path).expanduser()
    try:
        return not transcript.is_symlink() and transcript.is_file()
    except OSError:
        return False


def reconciliation_tracker(state: dict[str, Any]) -> dict[str, list[str]]:
    session = state.setdefault("session", {})
    raw = session.setdefault("asset_reconciliation", {})
    if not isinstance(raw, dict):
        raw = {}
        session["asset_reconciliation"] = raw
    for key in ("pending_prompt_ids", "post_tool_attempted_prompt_ids"):
        value = raw.setdefault(key, [])
        if not isinstance(value, list):
            raw[key] = []
    return raw  # type: ignore[return-value]


def reconcile_transcript_assets(
    state: dict[str, Any],
    payload: dict[str, Any],
    *,
    trigger: str,
) -> None:
    """Supplement late assets once per prompt, plus forced lifecycle recovery."""
    tracker = reconciliation_tracker(state)
    pending = list(dict.fromkeys(str(value) for value in tracker["pending_prompt_ids"]))
    if not pending:
        return
    attempted = set(str(value) for value in tracker["post_tool_attempted_prompt_ids"])
    candidate_ids = set(pending)
    if trigger == "post_tool":
        candidate_ids.difference_update(attempted)
        if not candidate_ids:
            return
        if not transcript_is_readable(state, payload):
            return
        attempted.update(candidate_ids)
        tracker["post_tool_attempted_prompt_ids"] = sorted(attempted)
    human_prompts = [
        item
        for item in state.get("prompts", [])
        if item.get("origin", "human") == "human" and item.get("id") in candidate_ids
    ]
    if not human_prompts:
        return
    matched_prompt_ids: set[str] = set()
    for record in transcript_tail_records(state, payload):
        record_payload = record.get("payload")
        if not isinstance(record_payload, dict):
            continue
        record_type = record.get("type")
        if record_type == "response_item":
            if record_payload.get("role") != "user":
                continue
        elif record_type == "event_msg":
            if record_payload.get("type") != "user_message":
                continue
        else:
            continue
        text_values = [
            value for value in recursive_strings(record_payload) if len(value) < 20000
        ]
        prompt_meta = next(
            (
                item
                for item in reversed(human_prompts)
                if any(sha256_text(value) == item.get("sha256") for value in text_values)
            ),
            None,
        )
        if prompt_meta is None:
            continue
        matched_prompt_ids.add(str(prompt_meta["id"]))
        before = set(
            item["id"]
            for item in state.get("assets", [])
            if prompt_meta.get("id") in item.get("prompt_ids", [])
        )
        discover_assets(
            state,
            record_payload,
            prompt_id=str(prompt_meta.get("id")),
            source="transcript_tail",
        )
        after = [
            item["id"]
            for item in state.get("assets", [])
            if prompt_meta.get("id") in item.get("prompt_ids", [])
        ]
        if set(after) == before:
            continue
        for collection in ("requirements", "acceptance_items"):
            for item in state.get(collection, []):
                if item.get("prompt_id") != prompt_meta.get("id"):
                    continue
                contract = item.get("verification_contract")
                if not isinstance(contract, dict) or contract.get("mode") != "legacy_fallback":
                    continue
                upgraded = verification_contract(item["id"], item.get("text", ""), state, after)
                if upgraded.get("mode") == "enforced":
                    item["verification_contract"] = upgraded
    if matched_prompt_ids:
        tracker["pending_prompt_ids"] = [
            prompt_id for prompt_id in pending if prompt_id not in matched_prompt_ids
        ]
        tracker["post_tool_attempted_prompt_ids"] = [
            prompt_id
            for prompt_id in tracker["post_tool_attempted_prompt_ids"]
            if prompt_id not in matched_prompt_ids
        ]


def _protected_prompt_clauses(text: str) -> list[str]:
    protected = re.sub(
        r"\b(?:do\s+not|don't|must\s+not|should\s+not)\s+skip\s+",
        "",
        text,
        flags=re.IGNORECASE,
    )
    protected = re.sub(r"(?:不要|不得|不能)\s*(?:跳过|遗漏)", "", protected)
    protected = re.sub(r"(?:不能|不可)\s*不\s*", "", protected)
    protected = re.sub(
        r"\b(?:do\s+not|don't|never)\s+(?:stop|pause|yield|end)\b",
        "",
        protected,
        flags=re.IGNORECASE,
    )
    return [
        clause.strip()
        for clause in re.split(r"[\n。！？!?；;，,]+", protected)
        if clause.strip()
    ]


def prompt_action_scope(prompt_text: str) -> dict[str, Any]:
    authorized: set[str] = set()
    denied: set[str] = set()
    positive_clauses: list[str] = []
    negation = re.compile(
        r"\b(?:do\s+not|don't|must\s+not|should\s+not|no|without)\b|"
        r"(?:不要|不得|无需|不需要|暂不|不再|别|切勿|勿|不跑|不执行)",
        re.IGNORECASE,
    )
    for clause in _protected_prompt_clauses(prompt_text):
        negative = bool(negation.search(clause))
        if not negative:
            positive_clauses.append(clause)
        for category, pattern in ACTION_PATTERNS:
            if pattern.search(clause):
                (denied if negative else authorized).add(category)
    positive_text = "\n".join(positive_clauses)
    broad = bool(
        BROAD_EXECUTION_PROMPT_RE.search(positive_text)
        or re.search(
            r"\bimplement\s+(?:(?:the|this)\s+)?(?:proposed\s+)?plan\b|"
            r"(?:实施|实现|执行|完成).{0,12}(?:既定|上述|这个|该|完整|发布)?计划",
            positive_text,
            re.IGNORECASE,
        )
    )
    bounded = bool(BOUNDED_TURN_PROMPT_RE.search(prompt_text)) and not broad
    return {
        "authorized": authorized,
        "denied": denied,
        "broad": broad,
        "bounded": bounded,
    }


def _reply_clauses(text: str) -> list[str]:
    sentinel = "\u241f"

    def protect_acronym(match: re.Match[str]) -> str:
        return match.group(0).replace(".", sentinel)

    protected = re.sub(
        r"\b(?:[A-Za-z]\.){2,}[A-Za-z]?", protect_acronym, text
    )
    protected = re.sub(r"(?<=\d)\.(?=\d)", sentinel, protected)
    raw_clauses = [
        clause.replace(sentinel, ".").strip()
        for clause in re.split(r"[\n。！？!?；;.]|(?:—{1,2})", protected)
        if clause.replace(sentinel, ".").strip()
    ]
    clauses: list[str] = []
    for clause in raw_clauses:
        if (
            clauses
            and USER_HANDOFF_RE.search(clauses[-1])
            and EXPLICIT_ASSISTANT_FUTURE_RE.search(clause)
            and re.search(
                r"\b(?:then|afterwards?|next)\b|(?:随后|然后|之后|接下来)",
                clause,
                re.IGNORECASE,
            )
        ):
            clauses[-1] += "; " + clause
        else:
            clauses.append(clause)
    return clauses


def _completion_context_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    left = max(
        (text.rfind(separator, 0, start) for separator in "\n.。！？!?；;"),
        default=-1,
    )
    right_candidates = [
        index
        for separator in "\n.。！？!?；;"
        for index in [text.find(separator, end)]
        if index >= 0
    ]
    right = min(right_candidates, default=len(text))
    return left + 1, right


def _inside_bounded_quotation(
    text: str, start: int, end: int, lower: int, upper: int
) -> bool:
    for opening, closing in (("“", "”"), ("‘", "’"), ("「", "」"), ("『", "』")):
        opening_index = text.rfind(opening, lower, start)
        closing_index = text.find(closing, end, upper)
        if opening_index >= 0 and closing_index >= 0:
            return True
    for delimiter in ('"', "`"):
        if text[lower:start].count(delimiter) % 2 == 1 and text.find(
            delimiter, end, upper
        ) >= 0:
            return True
    return False


def _completion_match_is_nonassertive(
    text: str, match: re.Match[str]
) -> bool:
    lower, upper = _completion_context_bounds(text, match.start(), match.end())
    prefix = text[lower : match.start()]
    if FIRST_PERSON_COMPLETION_ASSERTION_RE.search(prefix):
        return False
    if NONASSERTIVE_COMPLETION_CONTEXT_RE.search(prefix):
        return True
    framing = text[max(0, lower - 160) : upper]
    if _inside_bounded_quotation(text, match.start(), match.end(), lower, upper):
        quoted_tail = text[match.end() : upper]
        if (
            COMPLETION_DISCUSSION_RE.search(framing)
            or QUOTED_COMPLETION_DISCUSSION_SUFFIX_RE.search(quoted_tail)
        ):
            return True
    line_start = text.rfind("\n", 0, match.start()) + 1
    return bool(
        text[line_start : match.start()].lstrip().startswith(">")
        and COMPLETION_DISCUSSION_RE.search(text[max(0, line_start - 160) : line_start])
    )


def _reply_action_match(
    pattern: re.Pattern[str], text: str
) -> re.Match[str] | None:
    for match in pattern.finditer(text):
        prefix = text[max(0, match.start() - 64) : match.start()]
        future_matches = list(EXPLICIT_ASSISTANT_FUTURE_RE.finditer(prefix))
        if future_matches:
            prefix = prefix[future_matches[-1].start() :]
        suffix = text[match.end() : match.end() + 32]
        if REPLY_ACTION_NEGATION_PREFIX_RE.search(prefix):
            continue
        if (
            match.group(0).casefold() == "configuration"
            and ACTION_MENTION_SUFFIX_RE.search(suffix)
        ):
            continue
        return match
    return None


def _action_authorization(category: str, scope: dict[str, Any]) -> str:
    if category in scope["denied"]:
        return "denied"
    if category in scope["authorized"] or scope["broad"]:
        return "authorized"
    if scope["bounded"]:
        return "out_of_scope"
    # Ambiguous task scopes fail toward continuation, not silent completion.
    return "authorized"


def deferred_action_bindings(
    reply_text: str, scope: dict[str, Any]
) -> list[str]:
    """Return specific reply actions that the prompt denies or leaves out of scope."""
    bound: list[str] = []
    for clause in _reply_clauses(reply_text):
        if not DEFERRED_ACTION_CLAUSE_RE.search(clause):
            continue
        candidates = [clause]
        if COMPLETION_RE.search(clause):
            candidates = [
                item.strip()
                for item in re.split(
                    r"\s*(?:,|，|\b(?:and|but|while|whereas)\b|但|但是|而|然而|同时)\s*",
                    clause,
                    flags=re.IGNORECASE,
                )
                if item.strip()
            ]
        for candidate in candidates:
            if (
                not DEFERRED_ACTION_CLAUSE_RE.search(candidate)
                or COMPLETION_RE.search(candidate)
            ):
                continue
            for category, pattern in ACTION_PATTERNS:
                if not pattern.search(candidate):
                    continue
                if _action_authorization(category, scope) in {
                    "denied",
                    "out_of_scope",
                }:
                    bound.append(category)
    return list(dict.fromkeys(bound))


def remaining_action_facts(text: str, prompt_text: str) -> list[dict[str, str]]:
    scope = prompt_action_scope(prompt_text)
    actions: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    explicit_assistant_facts: set[tuple[str, str, str]] = set()
    for clause in _reply_clauses(text):
        user_handoff = bool(USER_HANDOFF_RE.search(clause))
        if user_handoff:
            fact = ("user_action", "user", "user_only")
            if fact not in seen:
                actions.append(
                    {"category": fact[0], "owner": fact[1], "authorization": fact[2]}
                )
                seen.add(fact)
        if EXTERNAL_WAIT_RE.search(clause):
            fact = ("external_wait", "external", "external_dependency")
            if fact not in seen:
                actions.append(
                    {"category": fact[0], "owner": fact[1], "authorization": fact[2]}
                )
                seen.add(fact)
            # A single clause can still contain an explicit assistant future
            # after an external status, so do not return early here.
        assistant_match = EXPLICIT_ASSISTANT_FUTURE_RE.search(clause)
        assistant_future = assistant_match is not None
        assistant_clause = (
            clause[assistant_match.start() :] if assistant_match is not None else clause
        )
        user_dependent_future = bool(
            assistant_future
            and USER_DEPENDENT_ASSISTANT_RE.search(clause)
            and not PARALLEL_ASSISTANT_RE.search(clause)
        )
        if user_dependent_future and not user_handoff:
            fact = ("user_action", "user", "user_only")
            if fact not in seen:
                actions.append(
                    {"category": fact[0], "owner": fact[1], "authorization": fact[2]}
                )
                seen.add(fact)
            user_handoff = True
        # A pure user handoff owns every action in the clause. An explicit
        # assistant future becomes actionable only when it is independent of
        # the requested user action; a conditional "after you ... I will ..."
        # remains blocked on the user and may end safely.
        if user_handoff and (not assistant_future or user_dependent_future):
            continue
        remaining_marker = bool(REMAINING_WORK_RE.search(clause))
        remaining = bool(
            remaining_marker
            or NON_COMPLETION_RE.search(clause)
            or re.search(r"\b(?:next|then)\s+i\s+(?:will|need\s+to)\b", clause, re.I)
            or assistant_future
        )
        if not remaining:
            continue
        matched = False
        for category, pattern in ACTION_PATTERNS:
            if _reply_action_match(pattern, assistant_clause) is None:
                continue
            # Review words inside a pure external-wait clause belong to the
            # reviewer unless the assistant explicitly claims a future action.
            if (
                EXTERNAL_WAIT_RE.search(clause)
                and not assistant_future
            ):
                continue
            authorization = _action_authorization(category, scope)
            fact = (category, "assistant", authorization)
            if fact not in seen:
                actions.append(
                    {"category": fact[0], "owner": fact[1], "authorization": fact[2]}
                )
                seen.add(fact)
            if assistant_future:
                explicit_assistant_facts.add(fact)
            matched = True
        if not matched and remaining_marker and not EXTERNAL_WAIT_RE.search(clause):
            authorization = _action_authorization("generic_work", scope)
            fact = ("generic_work", "assistant", authorization)
            if fact not in seen:
                actions.append(
                    {"category": fact[0], "owner": fact[1], "authorization": fact[2]}
                )
                seen.add(fact)
            if assistant_future:
                explicit_assistant_facts.add(fact)
    if any(item["owner"] == "user" for item in actions):
        actions = [
            item
            for item in actions
            if item["owner"] != "assistant"
            or (
                item["category"],
                item["owner"],
                item["authorization"],
            )
            in explicit_assistant_facts
        ]
    return actions


def classify_stop_decision(
    text: str, prompt_text: str = "", *, prompt_integrity: bool = True
) -> dict[str, Any]:
    if not prompt_integrity:
        outcome = "fail_closed_integrity"
        reasons = ["prompt_integrity_unavailable"]
        actions: list[dict[str, str]] = []
    else:
        actions = remaining_action_facts(text, prompt_text)
        assistant_actions = [
            item for item in actions if item["owner"] == "assistant"
        ]
        authorized = [
            item
            for item in assistant_actions
            if item["authorization"] == "authorized"
        ]
        if authorized:
            outcome = "gate_authorized_remaining_work"
            reasons = ["assistant_actionable_work_remains"]
            if any(item["owner"] == "external" for item in actions):
                reasons.append("mixed_external_and_assistant_work")
        elif assistant_actions:
            outcome = "allow_out_of_scope_deferred"
            reasons = ["remaining_work_denied_or_out_of_scope"]
        elif any(item["owner"] == "user" for item in actions):
            outcome = "allow_user_handoff"
            reasons = ["remaining_action_owned_by_user"]
        elif any(item["owner"] == "external" for item in actions):
            outcome = "allow_external_wait"
            reasons = ["remaining_action_is_external_dependency"]
        elif POLICY_HOLD_RE.search(text) or EXPLICIT_HOLD_RE.search(text):
            outcome = "allow_external_wait"
            reasons = ["explicit_policy_or_external_hold"]
        elif NON_COMPLETION_RE.search(text):
            outcome = "allow_neutral"
            reasons = ["explicit_non_completion_without_actionable_detail"]
        elif COMPLETION_RE.search(text):
            outcome = "gate_completion_claim"
            reasons = ["completion_language_detected"]
        else:
            outcome = "allow_neutral"
            reasons = ["no_completion_or_remaining_work_claim"]
    return {
        "classifier_version": CLASSIFIER_VERSION,
        "outcome": outcome,
        "reason_codes": reasons,
        "prompt_sha256": sha256_text(prompt_text),
        "reply_sha256": sha256_text(text),
        "actions": actions,
    }


def reports_non_completion(text: str, prompt_text: str = "") -> bool:
    return classify_stop_decision(text, prompt_text)["outcome"] in {
        "allow_user_handoff",
        "allow_external_wait",
        "allow_out_of_scope_deferred",
    }


def claims_completion(text: str, prompt_text: str = "") -> bool:
    del prompt_text
    return claims_whole_completion(text)


def claims_whole_completion(text: str) -> bool:
    """Return true only for an affirmative whole-task completion declaration."""
    for match in WHOLE_COMPLETION_RE.finditer(text):
        nearby = text[max(0, match.start() - 32) : match.end()]
        prefix = text[max(0, match.start() - 24) : match.start()]
        if re.search(
            r"\b(?:not|never|cannot|can't|unable\s+to|must\s+not|"
            r"should\s+not)\b.{0,28}$|"
            r"\bwhether\b.{0,32}$|"
            r"(?:未|尚未|还未|没有|并非|不是|不能|无法|不可|不应)"
            r".{0,28}(?:完成|结束|解决|修复)$",
            nearby,
            re.IGNORECASE | re.DOTALL,
        ) or re.search(
            r"(?:他|她|它|其|有人|据|报道)[^。！？\n]{0,8}(?:说|称|表示|写道)$|"
            r"(?:假设|假如|如果|若是|倘若|预计|推测|若)\s*$",
            prefix,
        ):
            continue
        tail = text[match.end() : min(len(text), match.end() + 64)]
        if re.search(
            r"^\s*[?？]|"
            r"^\s*(?:[,，]\s*)?(?:and\s+|but\s+)?(?:the\s+answer|our\s+answer|"
            r"my\s+answer|the\s+reply)\s+is\s+(?:no|not|negative)\b|"
            r"(?:but|however)[^。.！？!?\n]{0,40}\bnot\b",
            tail,
            re.IGNORECASE,
        ):
            continue
        if _completion_match_is_nonassertive(text, match):
            continue
        return True
    return False


def latest_requirement_text(session_dir: Path, state: dict[str, Any]) -> str:
    for item in reversed(state.get("requirements", [])):
        if not isinstance(item, dict):
            continue
        prompt_id = item.get("prompt_id")
        metadata = next(
            (
                prompt
                for prompt in state.get("prompts", [])
                if isinstance(prompt, dict) and prompt.get("id") == prompt_id
            ),
            None,
        )
        if isinstance(metadata, dict):
            expected_file = f"prompts/{prompt_id}.json"
            if metadata.get("file") != expected_file:
                return ""
            record_path = session_dir / expected_file
            if record_path.is_symlink() or not record_path.is_file():
                return ""
            record = read_json(record_path, {})
            text = record.get("text") if isinstance(record, dict) else None
            digest = sha256_text(text) if isinstance(text, str) else None
            if (
                isinstance(text, str)
                and text.strip()
                and record.get("id") == prompt_id
                and record.get("sha256") == digest
                and metadata.get("sha256") == digest
                and record.get("record_sha256") == prompt_record_hash(record)
                and metadata.get("record_sha256") == record.get("record_sha256")
            ):
                return text
            return ""
        text = item.get("text")
        if isinstance(text, str) and text.strip():
            return text
    return ""


def score_complexity(text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    lines = [line for line in text.splitlines() if line.strip()]
    bullets = sum(bool(re.match(r"\s*(?:[-*+]|\d+[.)])\s+", line)) for line in lines)
    if len(text) >= 1200:
        score += 3
        reasons.append("long_prompt")
    elif len(text) >= 500:
        score += 2
        reasons.append("medium_prompt")
    if len(lines) >= 12:
        score += 2
        reasons.append("many_lines")
    if bullets >= 4:
        score += 2
        reasons.append("checklist")
    if re.search(
        r"(implement|build|refactor|migrate|install|deploy|测试|实现|构建|迁移|安装|部署)",
        text,
        re.I,
    ):
        score += 2
        reasons.append("implementation")
    if re.search(
        r"(verify|validate|acceptance|doctor|smoke test|验收|验证|不得|必须|不要|边界)",
        text,
        re.I,
    ):
        score += 2
        reasons.append("hard_constraints")
    if re.search(r"(?:^|\s)(?:/|[A-Za-z]:\\)[^\s]+|[\w.-]+\.(?:py|md|toml|json|sh|ps1)\b", text):
        score += 1
        reasons.append("artifacts")
    return score, reasons


def extract_acceptance(text: str) -> list[str]:
    items: list[str] = []
    for raw_line in text.splitlines():
        line = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s+", "", raw_line).strip()
        if not line or len(line) < 6 or len(line) > 500:
            continue
        if re.search(
            r"(must|should|verify|validate|test|accept|do not|不得|必须|确认|验证|测试|验收|门禁|不进入|不保存)",
            line,
            re.I,
        ):
            items.append(line)
    return list(dict.fromkeys(items))[:32]


def is_control_prompt(text: str) -> bool:
    stripped = text.strip()
    return bool(
        stripped.startswith(INTERNAL_CONTINUATION_PREFIX)
        or re.fullmatch(
            r"\$?context-guard(?:\s+(?:on|off|status|diagnose|export|rollover|adopt)(?:\s+.+)?)?",
            stripped,
            re.I,
        )
    )


def control_action(text: str) -> tuple[str | None, str | None]:
    stripped = text.strip()
    match = re.fullmatch(
        r"\$?context-guard(?:\s+(on|off|status|diagnose|export|rollover|adopt)(?:\s+(.+))?)?",
        stripped,
        re.I,
    )
    if not match:
        return None, None
    return (match.group(1) or "on").lower(), match.group(2)


def classify_prompt_origin(
    state: dict[str, Any], payload: dict[str, Any], text: str
) -> tuple[str, str, str | None]:
    if text.lstrip().startswith(INTERNAL_CONTINUATION_PREFIX):
        return "internal", "internal", None
    payload_agent_id = payload.get("agent_id")
    if isinstance(payload_agent_id, str) and payload_agent_id.strip():
        return "subagent_delegation", "delegated", payload_agent_id.strip()
    turn_id = str(payload.get("turn_id") or "")
    for agent in reversed(state.get("agents", [])):
        if (
            isinstance(agent, dict)
            and turn_id
            and turn_id == str(agent.get("start_turn_id") or "")
        ):
            return (
                "subagent_delegation",
                "delegated",
                str(agent.get("agent_id") or "") or None,
            )
    if DELEGATION_RE.search(text):
        running_agents = [
            agent
            for agent in state.get("agents", [])
            if isinstance(agent, dict) and agent.get("status") == "running"
        ]
        if running_agents:
            actor_id = str(running_agents[-1].get("agent_id") or "") or None
            return "subagent_delegation", "delegated", actor_id
    return "human", "user", None


def append_prompt(
    session_dir: Path,
    state: dict[str, Any],
    text: str,
    unicode_repairs: int = 0,
    *,
    origin: str = "human",
    authority: str = "user",
    actor_id: str | None = None,
) -> dict[str, Any]:
    sequences = [
        int(match.group(1))
        for path in (session_dir / "prompts").glob("P*.json")
        if (match := re.fullmatch(r"P(\d{4,})\.json", path.name))
    ]
    sequences.extend(
        int(match.group(1))
        for item in state["prompts"]
        if (match := re.fullmatch(r"P(\d{4,})", str(item.get("id") or "")))
    )
    prompt_id = f"P{max(sequences, default=0) + 1:04d}"
    path = session_dir / "prompts" / f"{prompt_id}.json"
    record = {
        "id": prompt_id,
        "created_at": utc_now(),
        "sha256": sha256_text(text),
        "text": text,
        "unicode_repairs": unicode_repairs,
        "origin": origin,
        "authority": authority,
        "actor_id": actor_id,
    }
    record["record_sha256"] = prompt_record_hash(record)
    if path.exists():
        raise RuntimeError(f"immutable prompt already exists: {path}")
    atomic_write_json(path, record)
    metadata = {
        "id": prompt_id,
        "created_at": record["created_at"],
        "sha256": record["sha256"],
        "chars": len(text),
        "file": f"prompts/{prompt_id}.json",
        "unicode_repairs": unicode_repairs,
        "origin": origin,
        "authority": authority,
        "actor_id": actor_id,
        "record_sha256": record["record_sha256"],
    }
    state["prompts"].append(metadata)
    journal = state.setdefault("prompt_journal", {"version": 1, "entries": []})
    entries = journal.setdefault("entries", []) if isinstance(journal, dict) else []
    if isinstance(entries, list):
        entries.append({
            "id": prompt_id,
            "sha256": record["sha256"],
            "record_sha256": record["record_sha256"],
            "origin": origin,
            "authority": authority,
        })
        journal["entries"] = entries[-128:]
    if origin == "human":
        tracker = reconciliation_tracker(state)
        tracker["pending_prompt_ids"] = list(
            dict.fromkeys([*tracker["pending_prompt_ids"], prompt_id])
        )
        tracker["post_tool_attempted_prompt_ids"] = [
            value
            for value in tracker["post_tool_attempted_prompt_ids"]
            if value != prompt_id
        ]
    return metadata


def clause_metadata(text: str) -> dict[str, Any]:
    """Derive bounded, diagnostic bindings from each protected prompt clause."""
    clauses: list[dict[str, Any]] = []
    for clause in _protected_prompt_clauses(text):
        operations = [category for category, pattern in ACTION_PATTERNS if pattern.search(clause)]
        primary_actions = [
            operation for operation in operations if operation in PRIMARY_CLAUSE_ACTIONS
        ]
        if len(primary_actions) == 1 and set(operations).issubset(
            {primary_actions[0], "test_verify"}
        ):
            operation = primary_actions[0]
        else:
            operation = (
                operations[0]
                if len(operations) == 1
                else ("ambiguous" if operations else "unspecified")
            )
        subjects = [item["id"] for item in prompt_subjects(clause, include_threads=True)]
        lowered = clause.casefold()
        if re.search(r"视觉|图片|图像|image|visual|截图|ui|界面|页面", lowered):
            surface = "visual" if re.search(r"视觉|图片|图像|image|visual|截图", lowered) else "ui"
        elif re.search(r"全部|所有|范围|scope|each|every", lowered):
            surface = "scope"
        else:
            surface = "artifact"
        clauses.append({
            "clause": bounded(clause, 400),
            "operation": operation,
            "subjectId": subjects,
            "requestedSurface": surface,
        })
    return {"version": CLAUSE_DERIVATION_VERSION, "clauses": clauses}


def primary_clause_operation(text: str) -> str:
    """Return the same affirmative operation selected by the contract.

    Empty or wholly negated prompts stay ``unspecified``; denied operations
    therefore never become evidence stamps for affirmative work.
    """
    clause = _primary_positive_clause(clause_metadata(text))
    if clause is None:
        return "unspecified"
    operation = clause.get("operation")
    return operation if isinstance(operation, str) and operation else "unspecified"


def _positive_clause_texts(metadata: dict[str, Any]) -> list[str]:
    """Return the non-negated clause texts from precomputed clause metadata."""
    return [
        str(clause.get("clause"))
        for clause in _positive_clause_records(metadata)
    ]


def _positive_clause_records(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only affirmative clause records for contract and pending state."""
    return [
        clause
        for clause in metadata.get("clauses") or []
        if isinstance(clause, dict)
        and not CLAUSE_NEGATION_RE.search(str(clause.get("clause") or ""))
    ]


def _primary_positive_clause(metadata: dict[str, Any]) -> dict[str, Any] | None:
    """Select the first concrete affirmative clause, then a safe fallback."""
    clauses = _positive_clause_records(metadata)
    for clause in clauses:
        if clause.get("operation") not in {None, "", "unspecified", "ambiguous"}:
            return clause
    return clauses[0] if clauses else None


_QUOTED_SPAN_RE = re.compile(
    r'"[^"]*"|\'[^\']*\'|“[^”]*”|‘[^’]*’|「[^」]*」|『[^』]*』|`[^`]*`'
)


def _signal_outside_quotes(clause: str) -> bool:
    """True when the physical-identity signal appears outside quoted spans, so
    quoted prose such as “不要提 anti-junction” stays a negated mention."""
    stripped = _QUOTED_SPAN_RE.sub(" ", clause)
    return bool(PHYSICAL_IDENTITY_SIGNAL_RE.search(stripped))


def append_requirement(
    state: dict[str, Any], prompt: dict[str, Any], text: str,
    asset_ids: list[str] | None = None, *, work_unit_id: str | None = None,
) -> str:
    requirement_id = f"R{len(state['requirements']) + 1:03d}"
    # One clause derivation feeds both the requirement record and the enforced
    # contract, so the stored triple cannot drift from what certification uses.
    metadata = clause_metadata(text)
    contract = verification_contract(requirement_id, text, state, asset_ids or [], clauses=metadata)
    positive_subjects = sorted(
        {
            item["id"]
            for item in prompt_subjects("\n".join(_positive_clause_texts(metadata)), include_threads=True)
        }
    )
    positive_clause_records = _positive_clause_records(metadata)
    state["requirements"].append(
        {
            "id": requirement_id,
            "prompt_id": prompt["id"],
            "work_unit_id": work_unit_id,
            "text": bounded(text, 900),
            "sha256": prompt["sha256"],
            "status": "pending",
            "evidence": [],
            "operation": contract.get("clause_operation", "unspecified"),
            "subjectId": positive_subjects,
            "requestedSurface": sorted(
                {clause["requestedSurface"] for clause in positive_clause_records}
            ),
            "clause_metadata": metadata,
            "verification_contract": contract,
        }
    )
    primary = _primary_positive_clause(metadata)
    if primary is not None:
        pending_operation(
            state,
            str(primary.get("operation") or "unspecified"),
            subject_id=(primary.get("subjectId") or [None])[0],
            requested_surface=primary.get("requestedSurface"),
        )
    return requirement_id


def append_acceptance(
    state: dict[str, Any], prompt_id: str, text: str,
    asset_ids: list[str] | None = None, *, work_unit_id: str | None = None,
) -> None:
    existing = {item["text"] for item in state["acceptance_items"]}
    for candidate in extract_acceptance(text):
        if candidate in existing:
            continue
        acceptance_id = f"A{len(state['acceptance_items']) + 1:03d}"
        state["acceptance_items"].append(
            {
                "id": acceptance_id,
                "prompt_id": prompt_id,
                "work_unit_id": work_unit_id,
                "text": candidate,
                "status": "pending",
                "evidence": [],
                "verification_contract": verification_contract(
                    acceptance_id, candidate, state, asset_ids or []
                ),
            }
        )
        existing.add(candidate)


def work_unit_kind(text: str) -> str:
    """Classify only the root user's stated unit; this never expands scope."""
    authoritative = authoritative_supersession_text(text)
    cleanup = bool(re.search(r"\b(?:cleanup|clean up|tidy|prune)\b|(?:清理|收尾|整理)", authoritative, re.I))
    product_change = bool(
        re.search(r"\b(?:implement|fix|repair|build|change)\b|(?:实现|修复|改动|开发)", authoritative, re.I)
    )
    if cleanup and not product_change:
        return "cleanup"
    if re.search(r"\b(?:release|publish|tag)\b|(?:发布|发版|打\s*tag)", authoritative, re.I):
        return "release"
    if product_change:
        return "implementation"
    if re.search(r"\b(?:plan|design|spec)\b|(?:计划|设计|方案)", authoritative, re.I):
        return "planning"
    return "general"


def append_work_unit(state: dict[str, Any], prompt: dict[str, Any], text: str) -> str:
    state["work_unit_sequence"] = int(state.get("work_unit_sequence", 0)) + 1
    unit_id = f"WU{state['work_unit_sequence']:04d}"
    parent_id = state.get("work_state", {}).get("active_work_unit_id")
    kind = work_unit_kind(text)
    scope = {
        "prompt_sha256": prompt["sha256"],
        "parent_id": parent_id,
        "kind": kind,
    }
    state.setdefault("work_units", []).append(
        {
            "id": unit_id,
            "protocol_version": WORK_UNIT_PROTOCOL_VERSION,
            "prompt_id": prompt["id"],
            "parent_id": parent_id,
            "kind": kind,
            "status": "active",
            "created_at": utc_now(),
            "closed_at": None,
            "scope_sha256": sha256_text(canonical_json(scope)),
        }
    )
    state.setdefault("work_state", {})["active_work_unit_id"] = unit_id
    return unit_id


def work_unit_relations(state: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    """Return current unit, its descendants, and its ancestor constraints."""
    active = state.get("work_state", {}).get("active_work_unit_id")
    if not isinstance(active, str):
        return set(), set(), set()
    units = {
        str(item.get("id")): item
        for item in state.get("work_units", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if active not in units:
        return set(), set(), set()
    descendants = {active}
    changed = True
    while changed:
        changed = False
        for unit_id, item in units.items():
            if item.get("parent_id") in descendants and unit_id not in descendants:
                descendants.add(unit_id)
                changed = True
    ancestors: set[str] = set()
    parent = units[active].get("parent_id")
    while isinstance(parent, str) and parent in units and parent not in ancestors:
        ancestors.add(parent)
        parent = units[parent].get("parent_id")
    return {active}, descendants, ancestors


def checkpoint_scope_item_ids(state: dict[str, Any]) -> tuple[set[str], set[str]]:
    _current, descendants, ancestors = work_unit_relations(state)
    if not descendants:
        all_ids = {
            str(item["id"])
            for collection in ("requirements", "acceptance_items")
            for item in state.get(collection, [])
            if isinstance(item, dict) and item.get("status") != "superseded"
        }
        return all_ids, set()
    scoped = {
        str(item["id"])
        for collection in ("requirements", "acceptance_items")
        for item in state.get(collection, [])
        if isinstance(item, dict)
        and item.get("status") != "superseded"
        and item.get("work_unit_id") in descendants
    }
    ancestor_constraints = {
        str(item["id"])
        for collection in ("requirements", "acceptance_items")
        for item in state.get(collection, [])
        if isinstance(item, dict)
        and item.get("status") != "superseded"
        and item.get("work_unit_id") in ancestors
    }
    return scoped, ancestor_constraints


def has_positive_supersession_intent(text: str) -> bool:
    text = authoritative_supersession_text(text)
    positive = False
    negated = False
    for match in SUPERSESSION_INTENT_RE.finditer(text):
        clause_prefix = re.split(r"[\n.!?。！？,，;；]", text[: match.start()])[-1]
        if SUPERSESSION_NEGATION_PREFIX_RE.search(clause_prefix[-80:]):
            negated = True
            continue
        positive = True
    return positive and not negated


def authoritative_supersession_text(text: str) -> str:
    """Remove quoted, attributed, and code material before authority parsing."""
    stripped = re.sub(r"```.*?```", " ", text, flags=re.S)
    stripped = re.sub(r"`[^`\n]*`", " ", stripped)
    stripped = ATTRIBUTED_SUPERSESSION_BLOCK_RE.sub(" ", stripped)
    stripped = ATTRIBUTED_SUPERSESSION_LINE_RE.sub(" ", stripped)
    stripped = _QUOTED_SPAN_RE.sub(" ", stripped)
    return stripped


def supersession_target(
    text: str, known_ids: set[str], new_requirement_id: str
) -> str | None:
    authoritative = authoritative_supersession_text(text)
    if not has_positive_supersession_intent(authoritative):
        return None
    explicit = list(
        dict.fromkeys(
            item.upper()
            for item in re.findall(r"\bR\d{3}\b", authoritative, re.I)
            if item.upper() in known_ids and item.upper() != new_requirement_id
        )
    )
    if len(explicit) == 1:
        return explicit[0]
    if explicit or not EXPLICIT_PREVIOUS_REQUIREMENT_RE.search(authoritative):
        return None
    candidates = sorted(
        (item for item in known_ids if item != new_requirement_id),
        key=lambda item: int(item[1:]),
    )
    return candidates[-1] if candidates else None


def record_supersession(
    state: dict[str, Any], text: str, new_requirement_id: str
) -> str | None:
    if len(state["requirements"]) < 2:
        return None
    known_ids = {item["id"] for item in state["requirements"]}
    target = supersession_target(text, known_ids, new_requirement_id)
    if target is None:
        return (
            "ambiguous"
            if has_positive_supersession_intent(text)
            else None
        )
    if target == new_requirement_id:
        return "ambiguous"
    if target not in known_ids:
        return "ambiguous"
    state["supersedes"].append(
        {
            "old_id": target,
            "new_id": new_requirement_id,
            "created_at": utc_now(),
            "reason": bounded(authoritative_supersession_text(text), 400),
        }
    )
    for item in state["requirements"]:
        if item["id"] == target:
            item["status"] = "superseded"
    return "superseded"


def prompt_records_from_disk(session_dir: Path) -> list[dict[str, Any]]:
    prompt_dir = session_dir / "prompts"
    if not prompt_dir.is_dir():
        return []
    records: list[tuple[int, dict[str, Any]]] = []
    for path in sorted(prompt_dir.glob("P*.json")):
        match = re.fullmatch(r"P(\d{4,})\.json", path.name)
        if match is None or path.is_symlink() or not path.is_file():
            raise StateIntegrityError(f"invalid immutable prompt file {path.name}")
        try:
            with path.open("r", encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StateIntegrityError(
                f"cannot read immutable prompt file {path.name}: {exc}"
            ) from exc
        prompt_id = path.stem
        if not isinstance(record, dict) or record.get("id") != prompt_id:
            raise StateIntegrityError(f"immutable prompt identity mismatch in {path.name}")
        text = record.get("text")
        digest = record.get("sha256")
        if not isinstance(text, str) or digest != sha256_text(text):
            raise StateIntegrityError(f"immutable prompt hash mismatch in {path.name}")
        if not isinstance(record.get("created_at"), str):
            raise StateIntegrityError(f"immutable prompt timestamp is invalid in {path.name}")
        unicode_repairs = record.get("unicode_repairs", 0)
        if (
            isinstance(unicode_repairs, bool)
            or not isinstance(unicode_repairs, int)
            or unicode_repairs < 0
        ):
            raise StateIntegrityError(
                f"immutable prompt Unicode repair count is invalid in {path.name}"
            )
        record_digest = record.get("record_sha256")
        if record_digest is not None and record_digest != prompt_record_hash(record):
            raise StateIntegrityError(
                f"immutable prompt record hash mismatch in {path.name}"
            )
        records.append((int(match.group(1)), record))
    if len({sequence for sequence, _ in records}) != len(records):
        raise StateIntegrityError("immutable prompt sequence contains duplicates")
    return [record for _, record in sorted(records, key=lambda item: item[0])]


def replay_prompt_record(
    state: dict[str, Any], record: dict[str, Any]
) -> None:
    text = record["text"]
    origin = record.get("origin")
    if origin not in {"human", "subagent_delegation", "internal"}:
        if text.lstrip().startswith(INTERNAL_CONTINUATION_PREFIX):
            origin = "internal"
        else:
            origin = "human"
    authority = record.get("authority")
    if authority not in {"user", "delegated", "internal"}:
        authority = {
            "human": "user",
            "subagent_delegation": "delegated",
            "internal": "internal",
        }[origin]
    metadata = {
        "id": record["id"],
        "created_at": record["created_at"],
        "sha256": record["sha256"],
        "chars": len(text),
        "file": f"prompts/{record['id']}.json",
        "unicode_repairs": record.get("unicode_repairs", 0),
        "origin": origin,
        "authority": authority,
        "actor_id": record.get("actor_id"),
        "record_sha256": record.get("record_sha256"),
    }
    state["prompts"].append(metadata)
    if origin != "human":
        return
    action, _ = control_action(text)
    if action == "on":
        state["mode"]["active"] = True
        state["mode"]["manual_off"] = False
        state["mode"]["activation_reasons"] = list(
            dict.fromkeys(state["mode"]["activation_reasons"] + ["explicit"])
        )
    elif action == "off":
        state["mode"]["active"] = False
        state["mode"]["manual_off"] = True
    if is_control_prompt(text):
        return
    work_unit_id = append_work_unit(state, metadata, text)
    requirement_id = append_requirement(
        state, metadata, text, [], work_unit_id=work_unit_id
    )
    append_acceptance(
        state, metadata["id"], text, [], work_unit_id=work_unit_id
    )
    record_supersession(state, text, requirement_id)
    score, reasons = score_complexity(text)
    goal_requested = bool(re.search(r"^\s*/goal\b", text, re.I | re.MULTILINE))
    if goal_requested:
        reasons.append("goal")
    state["mode"]["complexity_score"] = max(
        state["mode"]["complexity_score"], score
    )
    state["mode"]["activation_reasons"] = list(
        dict.fromkeys(state["mode"]["activation_reasons"] + reasons)
    )
    if not state["mode"]["manual_off"] and (
        score >= 4
        or "$context-guard" in text.lower()
        or goal_requested
        or len(state["acceptance_items"]) >= 2
        or len(state["requirements"]) >= 3
    ):
        state["mode"]["active"] = True


def rebuild_state_from_prompts(
    session_dir: Path,
    payload: dict[str, Any],
    *,
    issue: str,
    backup_file: str | None,
) -> dict[str, Any]:
    rebuilt = new_state(payload)
    try:
        records = prompt_records_from_disk(session_dir)
        if not records:
            raise StateIntegrityError("no immutable prompt records are available")
        for record in records:
            replay_prompt_record(rebuilt, record)
        rebuilt["session"]["created_at"] = records[0]["created_at"]
        rebuilt["open_items"] = open_item_ids(rebuilt)
        rebuilt["integrity"] = {
            "status": "recovered_from_prompts",
            "issue": bounded(issue, 800),
            "recovered_at": utc_now(),
            "backup_file": backup_file,
        }
    except (OSError, StateIntegrityError, TypeError, ValueError) as exc:
        rebuilt["mode"]["active"] = True
        rebuilt["mode"]["manual_off"] = False
        rebuilt["open_items"] = ["STATE_INTEGRITY"]
        rebuilt["integrity"] = {
            "status": "failed",
            "issue": bounded(f"{issue}; prompt recovery failed: {exc}", 1200),
            "recovered_at": None,
            "backup_file": backup_file,
        }
    return rebuilt


def require_usable_state(state: dict[str, Any]) -> None:
    integrity = state.get("integrity")
    status = integrity.get("status") if isinstance(integrity, dict) else None
    if status not in {"ok", "recovered_from_prompts"}:
        issue = integrity.get("issue") if isinstance(integrity, dict) else None
        raise StateIntegrityError(
            "private state integrity is unavailable"
            + (f": {bounded(issue, 800)}" if issue else "")
        )


def open_item_ids(state: dict[str, Any]) -> list[str]:
    result = []
    for collection in ("requirements", "acceptance_items"):
        for item in state[collection]:
            if item.get("status") not in {"pass", "superseded"}:
                result.append(item["id"])
    return result


def trim_evidence(state: dict[str, Any]) -> None:
    referenced = {
        evidence_id
        for collection in ("requirements", "acceptance_items")
        for item in state[collection]
        for evidence_id in item.get("evidence", [])
        if isinstance(evidence_id, str)
    }
    recent_unreferenced = [
        item
        for item in state["evidence"]
        if item.get("id") not in referenced
    ][-EVIDENCE_LIMIT:]
    keep_ids = referenced | {
        item["id"]
        for item in recent_unreferenced
        if isinstance(item.get("id"), str)
    }
    state["evidence"] = [
        item for item in state["evidence"] if item.get("id") in keep_ids
    ]


def append_decision_log(
    state: dict[str, Any], decision: dict[str, Any], turn_id: str
) -> None:
    record = {
        "created_at": utc_now(),
        "turn_id": bounded(turn_id or "unknown-turn", 160),
        "protocol_version": decision.get("protocol_version"),
        "decision_source": decision.get("decision_source", "nlp_diagnostic"),
        "declared_disposition": decision.get("declared_disposition"),
        "observed_outcome": decision.get(
            "observed_outcome", decision.get("outcome", "allow_neutral")
        ),
        "classifier_version": decision.get("classifier_version", CLASSIFIER_VERSION),
        "outcome": decision.get("outcome", "fail_closed_integrity"),
        "reason_codes": [
            bounded(value, 120)
            for value in decision.get("reason_codes", [])[:8]
            if isinstance(value, str)
        ],
        "prompt_sha256": decision.get("prompt_sha256", sha256_text("")),
        "reply_sha256": decision.get("reply_sha256", sha256_text("")),
        "actions": [
            {
                "category": bounded(item.get("category", "unknown"), 80),
                "owner": bounded(item.get("owner", "unknown"), 40),
                "authorization": bounded(
                    item.get("authorization", "unknown"), 40
                ),
            }
            for item in decision.get("actions", [])[:16]
            if isinstance(item, dict)
        ],
    }
    state.setdefault("decision_log", []).append(record)
    state["decision_log"] = state["decision_log"][-DECISION_LOG_LIMIT:]


def status_context(state: dict[str, Any]) -> str:
    integrity = state.get("integrity", {})
    decisions = state.get("decision_log", [])
    last_decision = (
        decisions[-1].get("outcome", "none")
        if decisions and isinstance(decisions[-1], dict)
        else "none"
    )
    execution = state.get("execution", dormant_execution_state())
    execution_state = execution.get("contract", {}).get("state", "absent")
    execution_mode = execution_contract_mode(execution)
    drift_count = sum(
        item.get("state") == "detected"
        for item in execution.get("drift", [])
        if isinstance(item, dict)
    )
    return (
        "Context Guard status: "
        f"active={state['mode']['active']}, "
        f"integrity={integrity.get('status', 'unknown')}, "
        f"stop_protocol={STOP_PROTOCOL_VERSION}, "
        f"classifier={CLASSIFIER_VERSION}, "
        f"proof_protocol={PROOF_PROTOCOL_VERSION}, "
        f"plan_mirror={plan_mirror_health(state)}, "
        f"execution_contract={execution_state}, "
        f"execution_mode={execution_mode}, "
        f"execution_drift={drift_count}, "
        f"last_decision={last_decision}, "
        f"requirements={len(state['requirements'])}, "
        f"acceptance={len(state['acceptance_items'])}, "
        f"open={len(open_item_ids(state))}, "
        f"agents={len(state.get('agents', []))}, "
        f"compactions={len(state['compactions'])}, "
        f"continuations={state['continuation_attempts']}."
    )


def diagnose_context(state: dict[str, Any], limit: int = 5) -> str:
    decisions = [
        item
        for item in state.get("decision_log", [])[-max(1, min(limit, 10)) :]
        if isinstance(item, dict)
    ]
    mirror = plan_mirror_health(state)
    execution = state.get("execution", dormant_execution_state())
    contract = execution.get("contract", {})
    coverage = execution.get("coverage_manifest", {})
    execution_summary = (
        f"execution={contract.get('state', 'absent')}/r{contract.get('revision', 0)}, "
        f"mode={execution_contract_mode(execution)}, "
        f"eligible_adapters={sum(item.get('status') == 'eligible' for item in coverage.get('adapters', []) if isinstance(item, dict))}, "
        f"uncovered={len(coverage.get('uncovered_write_surfaces', []))}, "
        f"drift={sum(item.get('state') == 'detected' for item in execution.get('drift', []) if isinstance(item, dict))}"
    )
    if not decisions:
        return (
            f"Context Guard classifier {CLASSIFIER_VERSION}, plan mirror {mirror}: "
            f"{execution_summary}; no Stop decisions recorded."
        )
    summaries = []
    for item in decisions:
        reasons = ",".join(str(value) for value in item.get("reason_codes", [])[:4])
        summaries.append(
            f"{item.get('outcome', 'unknown')}"
            f"<{item.get('decision_source', 'unknown')}>"
            f"[{bounded(reasons, 240)}]"
        )
    return (
        f"Context Guard Stop protocol {STOP_PROTOCOL_VERSION}, classifier "
        f"{CLASSIFIER_VERSION}, plan mirror {mirror}, {execution_summary}, recent decisions: "
        + "; ".join(summaries)
        + ". Raw prompts and replies are not included."
    )
def trim_agent_records(state: dict[str, Any]) -> None:
    agents = [item for item in state.get("agents", []) if isinstance(item, dict)]
    active = [item for item in agents if item.get("status") == "running"]
    completed = [item for item in agents if item.get("status") != "running"]
    keep = active + completed[-AGENT_RECORD_LIMIT:]
    state["agents"] = keep[-(AGENT_RECORD_LIMIT + len(active)) :]


def agent_record(state: dict[str, Any], agent_id: str) -> dict[str, Any] | None:
    for item in reversed(state.get("agents", [])):
        if isinstance(item, dict) and item.get("agent_id") == agent_id:
            return item
    return None


def tool_actor(state: dict[str, Any], payload: dict[str, Any]) -> tuple[str, str | None]:
    del state
    payload_agent_id = payload.get("agent_id")
    if isinstance(payload_agent_id, str) and payload_agent_id.strip():
        return "subagent", payload_agent_id.strip()
    return "runtime_unattributed", None


# Registered read adapters (CG-CODEX-001): the only evidence surfaces whose
# *input* binds an artifact readback subject. A path that is merely echoed in
# a tool response, command output, or unrelated payload text stays inert for
# readback derivation — the same rule the thread-read adapter already enforces
# for thread subjects (exact name membership, never a name substring).
FILE_READ_TOOL_ALIASES = {
    "read",
    "read_file",
    "readfile",
    "read_text_file",
    "view",
    "view_file",
    "open_file",
    "cat_file",
    "show_file",
}
FILE_READ_TOOL_SUFFIXES = ("_read_file", "_read_text_file")
# Read-shaped shell commands: their path arguments are read targets. Anything
# else (echo, grep, ls, redirects, in-place edits) is not a readback.
READ_COMMAND_NAMES = {"cat", "head", "tail", "nl", "stat", "wc", "file", "sha256sum", "shasum", "md5"}
READ_COMMAND_REDIRECT_RE = re.compile(r"(?:^|[>\s])>{1,2}\s*\S|\btee\b")


def read_input_subject_ids(tool_name: str, tool_input: Any) -> list[str]:
    """Subject ids actually read by this tool call's input, [] when ambiguous.

    Only registered read adapters contribute. Shell reads bind from read-shaped
    command segments; every other tool response text is inert. Ambiguous forms
    (redirections, in-place edits, non-``-n`` sed) fail closed to no binding.
    """
    normalized = re.sub(r"[^a-z0-9]+", "_", str(tool_name).lower()).strip("_")
    if tool_is_shell_execution(tool_name):
        if not isinstance(tool_input, dict):
            return []
        command = tool_input.get("command")
        if not isinstance(command, str) or not command:
            return []
        return _read_command_subject_ids(command)
    is_registered = normalized in FILE_READ_TOOL_ALIASES or normalized.endswith(
        FILE_READ_TOOL_SUFFIXES
    )
    if not is_registered or not isinstance(tool_input, dict):
        return []
    subjects: list[str] = []
    for key in ("file_path", "path", "filename", "file", "notebook_path", "target_file"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            subjects.extend(
                item["id"]
                for item in prompt_subjects(value, include_threads=False)
                if item.get("kind") == "path"
            )
    return list(dict.fromkeys(subjects))


def _read_command_subject_ids(command: str) -> list[str]:
    subjects: list[str] = []
    for segment in re.split(r"&&|\|\||;|\n", command):
        segment = segment.strip()
        if not segment or READ_COMMAND_REDIRECT_RE.search(segment):
            # A redirect makes the read shape ambiguous: fail closed.
            continue
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        name = re.sub(r"[^a-z0-9]+", "_", Path(tokens[0]).name.lower()).strip("_")
        if name == "sed":
            if "-n" not in tokens or any(
                token == "-i" or token.startswith("--in-place") for token in tokens
            ):
                continue
        elif name not in READ_COMMAND_NAMES:
            continue
        skip_value = False
        for token in tokens[1:]:
            if skip_value:
                skip_value = False
                continue
            if token.startswith("-"):
                # head -n / tail -n / wc -l style flag values are not paths.
                skip_value = token in {"-n", "-c", "-m", "-l", "-w", "-b"}
                continue
            subjects.extend(
                item["id"]
                for item in prompt_subjects(token, include_threads=False)
                if item.get("kind") == "path"
            )
    return list(dict.fromkeys(subjects))


def evidence_capabilities(tool_name: str, payload: dict[str, Any] | None = None) -> list[str]:
    """Capability trust root (v0.9.5, CG-3a).

    Fixed priority: host envelope metadata → exact versioned registered tool
    allowlist (name membership, never a name substring) → default ``artifact``.
    Tool response bodies, stdout, and recursive JSON content can never upgrade
    a capability; a plain text mention of a capability name is inert.
    """
    del payload  # envelope metadata is evaluated by host_tool_surface_disposition
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
    capabilities = {"artifact"}
    if _is_registered_visual_tool(tool_name):
        capabilities.add("visual")
        capabilities.add("ui")
    elif normalized in REGISTERED_UI_TOOL_ALIASES:
        capabilities.add("ui")
    if tool_is_shell_execution(tool_name):
        capabilities.add("scope")
    return sorted(capabilities)


REGISTERED_UI_TOOL_ALIASES = {
    "computer_use",
    "computeruse",
    "browser_use",
    "browseruse",
}

# Frozen field-equality contract for reading ``codex/toolSurface`` metadata
# from a host envelope: every equality must hold on a completed event, else
# the capability stays ``artifact``.
HOST_TOOL_SURFACE_REQUIRED_EQUALITIES = (
    ("hook.session_id", "event.thread_id"),
    ("hook.turn_id", "event.turn_id"),
    ("hook.tool_use_id", "event.item.id"),
)


def host_tool_surface_disposition(
    state: dict[str, Any], payload: dict[str, Any], requested_surface: str = "ui"
) -> tuple[bool, str | None]:
    """Return ``(upgraded, transient_disposition)`` for one tool event.

    ``codex/toolSurface`` structured metadata is read only from the host
    envelope (the hook payload's top-level key). A tool response that embeds
    the same key is not the host envelope and is ignored. Missing, duplicate,
    out-of-order, or uncorrelatable metadata keeps the ``artifact`` capability
    and reports the transient ``unavailable`` adapter disposition for
    diagnostics only; the disposition never persists and is never a
    capability member.
    """
    metadata = payload.get("codex/toolSurface")
    if metadata is None:
        return False, "unavailable" if _is_ui_surface_candidate_tool(str(payload.get("tool_name") or "")) else None
    if not isinstance(metadata, dict):
        return False, "unavailable" if _is_ui_surface_candidate_tool(str(payload.get("tool_name") or "")) else None
    events = metadata.get("events") if isinstance(metadata.get("events"), list) else [metadata.get("event")]
    events = [event for event in events if isinstance(event, dict)]
    if len(events) != 1:
        return False, "unavailable"
    event = events[0]
    hook = metadata.get("hook") if isinstance(metadata.get("hook"), dict) else {}
    item = event.get("item") if isinstance(event.get("item"), dict) else {}
    if str(item.get("status") or "") != "completed":
        return False, "unavailable"
    hook_values = (
        hook.get("session_id"),
        hook.get("turn_id"),
        hook.get("tool_use_id"),
    )
    event_values = (
        event.get("thread_id"),
        event.get("turn_id"),
        item.get("id"),
    )
    for left, right in zip(hook_values, event_values):
        if not isinstance(left, str) or not isinstance(right, str) or left != right:
            return False, "unavailable"
    if hook.get("session_id") != str(state["session"]["id"]):
        return False, "unavailable"
    if str(hook.get("turn_id") or "") != str(payload.get("turn_id") or ""):
        return False, "unavailable"
    surface = metadata.get("surface")
    if surface == requested_surface:
        return True, None
    return False, "unavailable"


def _is_ui_surface_candidate_tool(tool_name: str) -> bool:
    """True when the exact tool name is a registered UI-surface candidate."""
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
    return normalized in REGISTERED_UI_TOOL_ALIASES


def private_metadata_free_text(value: str) -> str:
    lines = [
        line
        for line in value.splitlines()
        if not PRIVATE_METADATA_RE.search(line)
    ]
    return redact_text("\n".join(lines))


def agent_result_envelope(text: str) -> dict[str, Any]:
    found: dict[str, bool] = {}
    for field, aliases in AGENT_RESULT_FIELDS.items():
        found[field] = any(
            re.search(rf"(?im)^\s*(?:[-*]\s*)?{re.escape(alias)}\s*[:：]", text)
            for alias in aliases
        )
    found["complete"] = all(
        found[field] for field in ("outcome", "evidence", "validation", "limitations")
    )
    return found


def subagent_contract_context(state: dict[str, Any]) -> str:
    lines = [
        "Context Guard delegated-task contract:",
        "- The root user's requirements remain authoritative; this subagent may not add, cancel, or supersede them.",
        "- Work only on the delegated scope supplied by the parent agent.",
        "- Return a concise result using labels Outcome, Evidence, Validation, Limitations, and Next.",
        "- Do not claim that the root task is complete.",
        "Root open items:",
    ]
    for collection in ("requirements", "acceptance_items"):
        for item in state.get(collection, []):
            if item.get("status") in {"pass", "superseded"}:
                continue
            lines.append(
                f"- {item.get('id')}: {bounded(item.get('text', ''), 320)}"
            )
    text = private_metadata_free_text("\n".join(lines))
    if len(text) > SUBAGENT_CONTEXT_CHAR_LIMIT:
        text = (
            text[: SUBAGENT_CONTEXT_CHAR_LIMIT - 80]
            + "\n…[subagent contract clipped to budget]"
        )
    return text


def read_prompt_record(session_dir: Path, metadata: dict[str, Any]) -> dict[str, Any] | None:
    relative = metadata.get("file")
    if not isinstance(relative, str):
        return None
    candidate = (session_dir / relative).resolve()
    try:
        candidate.relative_to(session_dir.resolve())
    except ValueError:
        return None
    value = read_json(candidate)
    if not isinstance(value, dict):
        return None
    text = value.get("text")
    digest = value.get("sha256")
    if (
        value.get("id") != metadata.get("id")
        or not isinstance(text, str)
        or digest != sha256_text(text)
        or digest != metadata.get("sha256")
        or (
            value.get("record_sha256") is not None
            and value.get("record_sha256") != prompt_record_hash(value)
        )
    ):
        return None
    return value


def format_items(title: str, items: list[dict[str, Any]], include_evidence: bool = False) -> str:
    lines = [f"## {title}"]
    if not items:
        lines.append("- None")
    for item in items:
        line = f"- {item['id']} [{item.get('status', 'pending')}]: {bounded(item.get('text', ''), 600)}"
        if include_evidence and item.get("evidence"):
            line += f" | evidence: {bounded(item['evidence'], 500)}"
        contract = item.get("verification_contract")
        if isinstance(contract, dict) and contract.get("mode") == "enforced":
            obligations = contract.get("obligations", [])
            line += (
                f" | proof={contract.get('mode')}"
                f"/{contract.get('reason', 'unknown')}"
            )
            if obligations:
                line += " obligations=" + ",".join(
                    str(value.get("id"))
                    for value in obligations
                    if isinstance(value, dict)
                )
        lines.append(line)
    return "\n".join(lines)


def clip_preserving_suffix(
    text: str,
    limit: int,
    suffix: str,
    marker: str,
) -> str:
    """Bound text while reserving a non-negotiable recovery suffix."""
    if len(text) <= limit:
        return text
    if limit <= len(suffix):
        return suffix[-limit:] if limit > 0 else ""
    prefix = text[: -len(suffix)].rstrip() if text.endswith(suffix) else text
    budget = max(0, limit - len(suffix) - len(marker) - 4)
    return prefix[:budget].rstrip() + "\n\n" + marker + "\n\n" + suffix


def recovery_packet(session_dir: Path, state: dict[str, Any]) -> str:
    integrity = state.get("integrity", {})
    sections: list[str] = [
        "# CONTEXT-GUARD RECOVERY PACKET",
        "This packet restores task boundaries after compaction. The private raw prompt ledger remains the fact source.",
        (
            "Integrity status: "
            f"{integrity.get('status', 'unknown')}. "
            "If recovery occurred, all reconstructed items require fresh evidence."
        ),
        format_items("Hard boundaries and requirements", state["requirements"], True),
        format_items("Acceptance criteria", state["acceptance_items"], True),
    ]
    if state["supersedes"]:
        lines = ["## Latest user revisions"]
        for item in state["supersedes"][-12:]:
            lines.append(
                f"- {item['new_id']} supersedes {item['old_id']}: {bounded(item['reason'], 400)}"
            )
        sections.append("\n".join(lines))
    open_ids = open_item_ids(state)
    sections.append("## Unfinished items\n- " + (", ".join(open_ids) if open_ids else "None"))
    if state.get("assets"):
        lines = ["## Multimodal asset contract"]
        for item in state["assets"][-16:]:
            lines.append(
                f"- {item['id']} prompts={','.join(item.get('prompt_ids', [])) or 'none'} "
                f"type={item.get('media_type')} size={item.get('width')}x{item.get('height')} "
                f"available={item.get('available')} sha256={item.get('sha256') or 'unavailable'} "
                f"source={item.get('source_ref')}"
            )
        sections.append("\n".join(lines))
    unresolved = unresolved_proof_obligations(state)
    if unresolved:
        sections.append(
            "## Unresolved verification obligations\n- "
            + "\n- ".join(
                f"{item_id}: {','.join(obligation_ids)}"
                for item_id, obligation_ids in unresolved.items()
            )
        )
    decisions = state.get("decision_log", [])
    if (
        decisions
        and isinstance(decisions[-1], dict)
        and decisions[-1].get("outcome") == "fail_closed_integrity"
    ):
        reason_codes = decisions[-1].get("reason_codes", [])
        sections.append(
            "## Latest fail-closed decision\n- "
            + bounded(", ".join(str(item) for item in reason_codes), 320)
        )
    plan_snapshot = state.get("work_state", {}).get("plan_snapshot")
    if isinstance(plan_snapshot, dict) and plan_snapshot.get("steps"):
        lines = [
            "## Latest Codex plan mirror",
            "This is a read-only recovery copy of the latest observed update_plan state; Codex remains the plan owner.",
            f"- sha256: {plan_snapshot.get('sha256', 'unknown')}",
        ]
        if plan_snapshot.get("explanation"):
            lines.append(
                f"- explanation: {bounded(plan_snapshot.get('explanation'), 500)}"
            )
        for item in plan_snapshot.get("steps", [])[:PLAN_STEP_LIMIT]:
            if isinstance(item, dict):
                lines.append(
                    f"- [{item.get('status', 'pending')}] {bounded(item.get('step', ''), 420)}"
                )
        sections.append("\n".join(lines))
    execution = state.get("execution")
    if isinstance(execution, dict) and not execution_state_is_dormant(execution):
        contract = execution.get("contract", {})
        lines = [
            "## Execution contract recovery state",
            f"- state: {contract.get('state', 'unknown')}",
            f"- revision: {contract.get('revision', 0)}",
            f"- mode: {execution_contract_mode(execution)}",
        ]
        unfinished = [
            str(item.get("id"))
            for collection in ("phases", "gates")
            for item in contract.get(collection, [])
            if isinstance(item, dict)
            and item.get("state") not in {"passed", "waived", "superseded"}
        ]
        detected = [
            str(item.get("id"))
            for item in execution.get("drift", [])
            if isinstance(item, dict) and item.get("state") == "detected"
        ]
        lines.append("- unfinished: " + (", ".join(unfinished[:32]) or "none"))
        lines.append("- detected drift: " + (", ".join(detected[:32]) or "none"))
        lines.append(
            "- coverage: eligible="
            + str(sum(
                item.get("status") == "eligible"
                for item in execution.get("coverage_manifest", {}).get("adapters", [])
                if isinstance(item, dict)
            ))
            + ", uncovered="
            + str(len(execution.get("coverage_manifest", {}).get("uncovered_write_surfaces", [])))
        )
        sections.append("\n".join(lines))
    agent_items = [
        item
        for item in state.get("agents", [])
        if isinstance(item, dict)
    ]
    if agent_items:
        running = [item for item in agent_items if item.get("status") == "running"]
        recent = [item for item in agent_items if item.get("status") != "running"][-4:]
        lines = ["## Bounded subagent coordination state"]
        for item in running + recent:
            line = (
                f"- {item.get('agent_id', 'unknown')} "
                f"[{item.get('status', 'unknown')}] type={item.get('agent_type', 'unknown')}"
            )
            if item.get("result_summary"):
                line += f": {bounded(item.get('result_summary'), 500)}"
            envelope = item.get("result_envelope")
            if isinstance(envelope, dict):
                line += f" | envelope_complete={bool(envelope.get('complete'))}"
            lines.append(line)
        sections.append("\n".join(lines))
    if state["evidence"]:
        lines = ["## Recently verified or attempted evidence"]
        for item in state["evidence"][-12:]:
            lines.append(
                f"- {item['id']} [{item['outcome']}]: {bounded(item['summary'], 500)}"
            )
        sections.append("\n".join(lines))
    human_prompts = [
        metadata
        for metadata in state["prompts"]
        if metadata.get("origin", "human") == "human"
    ]
    prompt_records = [
        read_prompt_record(session_dir, metadata)
        for metadata in (human_prompts[:1] + human_prompts[-3:])
    ]
    prompt_records = [item for item in prompt_records if item]
    if prompt_records:
        lines = ["## Original prompt excerpts and latest updates"]
        seen: set[str] = set()
        for record in prompt_records:
            if record["id"] in seen:
                continue
            seen.add(record["id"])
            lines.append(f"- {record['id']}: {bounded(record.get('text', ''), 1800)}")
        sections.append("\n".join(lines))
    sections.append(RECOVERY_COMPLETION_RULE)
    text = redact_text("\n\n".join(sections))
    return clip_preserving_suffix(
        text,
        RECOVERY_CHAR_LIMIT,
        RECOVERY_COMPLETION_RULE,
        "…[recovery packet clipped to budget; completion rule preserved]",
    )


def write_recovery(session_dir: Path, state: dict[str, Any], trigger: str) -> str:
    packet = recovery_packet(session_dir, state)
    record = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "trigger": trigger,
        "state_hash": state["content_hash"],
        "packet_sha256": sha256_text(packet),
        "packet": packet,
    }
    atomic_write_json(session_dir / "recovery.json", record)
    atomic_write_text(session_dir / "recovery.md", packet + "\n")
    return packet


def hook_output(event: str, additional_context: str | None = None, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = dict(extra)
    if additional_context:
        result["hookSpecificOutput"] = {
            "hookEventName": event,
            "additionalContext": additional_context,
        }
    return result


def shell_join(arguments: list[str], windows: bool | None = None) -> str:
    use_windows = os.name == "nt" if windows is None else windows
    return subprocess.list2cmdline(arguments) if use_windows else shlex.join(arguments)


def begin_completion_attempt(
    state: dict[str, Any], payload: dict[str, Any], fallback_turn_id: str
) -> tuple[str, str]:
    turn_id = str(payload.get("turn_id") or fallback_turn_id)
    token = secrets.token_urlsafe(PRIVATE_CONTROL_TOKEN_BYTES)
    state["completion_attempt"] = {
        "protocol_version": STOP_PROTOCOL_VERSION,
        "turn_id": turn_id,
        "token_sha256": sha256_text(token),
        "created_at": utc_now(),
        "staged_control": None,
        "staged_at": None,
    }
    return turn_id, token


def completion_command_context(
    state: dict[str, Any], turn_id: str, token: str
) -> str:
    common = [
        "--data-dir",
        str(data_root().resolve()),
        "--session-id",
        str(state["session"]["id"]),
        "--turn-id",
        turn_id,
        f"--token={token}",
    ]
    script = str(Path(__file__).resolve())
    status_command = shell_join(
        [sys.executable, script, "checkpoint-status", *common]
    )
    stage_command = shell_join(
        [sys.executable, script, "stage-checkpoint", *common]
    )
    disposition_command = shell_join(
        [sys.executable, script, "stage-disposition", *common]
    )
    proof_command = shell_join(
        [sys.executable, script, "register-proof", *common, "--manifest", "/path/to/proof.json"]
    )
    scoped_ids, ancestor_ids = checkpoint_scope_item_ids(state)
    requirement_ids = [
        item["id"]
        for item in state["requirements"]
        if item.get("status") != "superseded" and item["id"] in scoped_ids
    ]
    acceptance_ids = [
        item["id"]
        for item in state["acceptance_items"]
        if item.get("status") != "superseded" and item["id"] in scoped_ids
    ]
    return (
        "Context Guard is active. Keep completion metadata private: never append "
        "a context-guard checkpoint, HTML comment, JSON block, token, or private "
        "command to the user-facing response. Before claiming full completion, "
        "inspect the private ledger with this exact command:\n"
        f"{status_command}\n"
        "Then stage a turn-bound private checkpoint with this command plus one "
        "`--requirement ID=E####[,E####]` flag for each pending requirement and "
        "one `--acceptance ID=E####[,E####]` flag for each pending acceptance item:\n"
        f"{stage_command}\n"
        "For an incomplete terminal response, stage exactly one typed boundary "
        "instead: append `--disposition user_wait`, `external_wait`, or `deferred` "
        "to this exact command base (the reason is derived). Continue authorized "
        "assistant work by calling tools before ending the turn; the legacy "
        "`continue` value is advisory only and cannot force a Stop continuation:\n"
        f"{disposition_command}\n"
        "A different already-staged control can be replaced only with `--replace`. "
        "Only successful evidence IDs printed by checkpoint-status are valid. "
        "For an enforced verification contract, register each immutable proof "
        "manifest before staging the checkpoint with this command:\n"
        f"{proof_command}\n"
        "Previously passed items in the current work-unit closure are carried "
        "forward automatically; ancestor requirements remain constraints. "
        f"Tracked requirements: {','.join(requirement_ids) or 'none'}; "
        f"acceptance: {','.join(acceptance_ids) or 'none'}; "
        f"ancestor constraints: {','.join(sorted(ancestor_ids)) or 'none'}."
    )


def completion_attempt_for(
    state: dict[str, Any], turn_id: str, token: str
) -> dict[str, Any]:
    attempt = state.get("completion_attempt")
    if not isinstance(attempt, dict):
        raise RuntimeError("no active private completion attempt")
    if attempt.get("protocol_version") != STOP_PROTOCOL_VERSION:
        raise RuntimeError("completion attempt uses an unsupported Stop protocol")
    if str(attempt.get("turn_id")) != str(turn_id):
        raise RuntimeError("completion attempt belongs to a different turn")
    expected = str(attempt.get("token_sha256") or "")
    if not expected or not hmac.compare_digest(expected, sha256_text(token)):
        raise RuntimeError("invalid private completion token")
    if "staged_control" not in attempt:
        raise RuntimeError("completion attempt has no staged-control slot")
    return attempt


def parse_evidence_assignments(
    values: list[str], label: str
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for raw in values:
        item_id, separator, evidence_text = raw.partition("=")
        item_id = item_id.strip().upper()
        if not separator or not item_id:
            raise ValueError(f"{label} must use ID=E####[,E####] syntax")
        if item_id in result:
            raise ValueError(f"duplicate {label} assignment for {item_id}")
        evidence_ids = [
            value.strip().upper()
            for value in evidence_text.split(",")
            if value.strip()
        ]
        if not evidence_ids or any(
            not EVIDENCE_ID_RE.fullmatch(value) for value in evidence_ids
        ):
            raise ValueError(f"{label} {item_id} has invalid evidence IDs")
        result[item_id] = list(dict.fromkeys(evidence_ids))
    return result


def normalized_scope(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 10000:
        raise ValueError(f"{label} must be a non-empty bounded string list")
    normalized: list[str] = []
    for raw in value:
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 500:
            raise ValueError(f"{label} contains an invalid identifier")
        normalized.append(raw.strip())
    return sorted(set(normalized))


def proof_item(state: dict[str, Any], item_id: str) -> dict[str, Any]:
    for collection in ("requirements", "acceptance_items"):
        for item in state.get(collection, []):
            if item.get("id") == item_id and item.get("status") != "superseded":
                return item
    raise ValueError(f"proof references unknown item {item_id}")


def proof_obligation(item: dict[str, Any], obligation_id: str) -> dict[str, Any]:
    contract = item.get("verification_contract")
    if not isinstance(contract, dict) or contract.get("mode") != "enforced":
        raise ValueError(f"{item['id']} has no enforced verification contract")
    for obligation in contract.get("obligations", []):
        if isinstance(obligation, dict) and obligation.get("id") == obligation_id:
            return obligation
    raise ValueError(f"proof references unknown obligation {obligation_id}")


def visual_fact_id(asset_id: str, text: str) -> str:
    return f"F-{asset_id}-{sha256_text(text)[:16]}"


def normalize_proof_manifest(state: dict[str, Any], data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("proof manifest must be an object")
    allowed = {
        "protocol_version",
        "item_id",
        "obligation_id",
        "evidence_ids",
        "surface",
        "subject_ids",
        "visual_facts",
        "readback_asset_id",
        "resolved_fact_ids",
        "expected_scope",
        "observed_scope",
    }
    unknown = set(data).difference(allowed)
    if unknown:
        raise ValueError("proof manifest has unknown fields: " + ", ".join(sorted(unknown)))
    if data.get("protocol_version") != PROOF_PROTOCOL_VERSION:
        raise ValueError(f"proof protocol must be {PROOF_PROTOCOL_VERSION}")
    item_id = str(data.get("item_id") or "").upper()
    obligation_id = str(data.get("obligation_id") or "")
    item = proof_item(state, item_id)
    obligation = proof_obligation(item, obligation_id)
    surface = str(data.get("surface") or "")
    if surface != obligation.get("surface"):
        raise ValueError(
            f"{obligation_id} requires surface {obligation.get('surface')}, got {surface or 'none'}"
        )
    evidence_ids = data.get("evidence_ids")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or len(evidence_ids) > 20
        or any(not isinstance(value, str) or not EVIDENCE_ID_RE.fullmatch(value) for value in evidence_ids)
    ):
        raise ValueError("evidence_ids must be a non-empty E#### list")
    evidence_by_id = {item["id"]: item for item in state.get("evidence", [])}
    prompt_created_at = next(
        (
            prompt.get("created_at")
            for prompt in state.get("prompts", [])
            if prompt.get("id") == item.get("prompt_id")
        ),
        None,
    )
    for evidence_id in evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None or evidence.get("outcome") != "success":
            raise ValueError(f"proof requires successful existing evidence {evidence_id}")
        # The adapter manifest constrains only evidence selected by this proof.
        # Unselected history is irrelevant, while a missing stamp remains
        # eligible under the read-only schema-7 compatibility rule.
        stamped = evidence.get("adapter_manifest_version")
        if stamped is not None and stamped != ADAPTER_MANIFEST_VERSION:
            raise ValueError(
                f"evidence {evidence_id} was read under adapter manifest "
                f"{stamped!r}, not {ADAPTER_MANIFEST_VERSION!r}"
            )
        if (
            isinstance(prompt_created_at, str)
            and isinstance(evidence.get("created_at"), str)
            and evidence["created_at"] < prompt_created_at
        ):
            raise ValueError(f"proof evidence {evidence_id} predates {item_id}")
    evidence_capability_set = {
        capability
        for evidence_id in evidence_ids
        for capability in evidence_by_id[evidence_id].get("capabilities", [])
    }
    if surface not in evidence_capability_set:
        raise ValueError(f"proof evidence lacks required {surface} capability")
    subject_ids = data.get("subject_ids")
    if (
        not isinstance(subject_ids, list)
        or len(subject_ids) > 64
        or any(not isinstance(value, str) or not value for value in subject_ids)
    ):
        raise ValueError("subject_ids must be a bounded string list")
    required_subjects = set(obligation.get("subject_ids", []))
    unsupported_required = sorted(
        subject for subject in required_subjects
        if str(subject).startswith(UNSUPPORTED_SUBJECT_PREFIX)
    )
    if unsupported_required:
        # The codex:unsupported/ namespace is explicitly unbindable: no
        # evidence adapter may satisfy it, and tool output that echoes an
        # opaque id cannot fake a binding.
        raise ValueError(
            "obligation subjects in the unsupported namespace are not bindable: "
            + ", ".join(unsupported_required)
        )
    if not required_subjects.issubset(set(subject_ids)):
        missing = sorted(required_subjects.difference(subject_ids))
        raise ValueError("proof omits required subjects: " + ", ".join(missing))
    kind = str(obligation.get("kind"))
    evidence_assets = {
        asset_id
        for evidence_id in evidence_ids
        for asset_id in evidence_by_id[evidence_id].get("asset_ids", [])
    }
    evidence_subjects = {
        subject_id
        for evidence_id in evidence_ids
        for subject_id in evidence_by_id[evidence_id].get("subject_ids", [])
    }
    if kind == "input_asset_inspection" and not required_subjects.issubset(evidence_assets):
        raise ValueError("input asset proof evidence does not reference every required asset")
    if kind == "subject_readback" and str(surface) == "artifact":
        # CG-CODEX-001: an artifact readback — explicit or derived — binds
        # only through registered read adapters' actual read *inputs*. A path
        # echoed in tool output or any other payload text is not a readback;
        # the manifest may neither expand the subjects, nor rely on evidence
        # whose reads are a superset of the required subjects.
        evidence_readbacks = {
            subject_id
            for evidence_id in evidence_ids
            for subject_id in evidence_by_id[evidence_id].get("readback_subjects", [])
        }
        if set(subject_ids) != required_subjects:
            raise ValueError(
                "artifact readback proof must bind exactly the required subjects"
            )
        if evidence_readbacks != required_subjects:
            raise ValueError(
                "artifact readback proof evidence does not read exactly the "
                "required subjects through a registered read adapter"
            )
    elif kind == "subject_readback" and not required_subjects.issubset(evidence_subjects):
        raise ValueError("subject proof evidence does not reference every required subject")
    # The clause-derived operation binds certification: evidence stamped under
    # a different concrete operation cannot satisfy this obligation. Records
    # without a concrete operation on either side stay unconstrained.
    required_operation = obligation.get("operation")
    if isinstance(required_operation, str) and required_operation not in {"", "unspecified", "ambiguous"}:
        for evidence_id in evidence_ids:
            stamped_operation = evidence_by_id[evidence_id].get("operation")
            if (
                isinstance(stamped_operation, str)
                and stamped_operation not in {"", "unspecified", "ambiguous"}
                and stamped_operation != required_operation
            ):
                raise ValueError(
                    f"proof evidence {evidence_id} records operation "
                    f"{stamped_operation!r}, not required operation {required_operation!r}"
                )
    visual_facts: list[dict[str, str]] = []
    raw_facts = data.get("visual_facts", [])
    if raw_facts is not None:
        if not isinstance(raw_facts, list) or len(raw_facts) > 32:
            raise ValueError("visual_facts must be a bounded list")
        for index, raw_fact in enumerate(raw_facts):
            if not isinstance(raw_fact, dict) or set(raw_fact) != {"asset_id", "text"}:
                raise ValueError(f"visual_facts[{index}] must contain asset_id and text")
            asset_id = str(raw_fact.get("asset_id") or "")
            text = private_metadata_free_text(str(raw_fact.get("text") or "").strip())
            if asset_id not in required_subjects or not text or len(text) > 500:
                raise ValueError(f"visual_facts[{index}] is not bound to a required asset")
            visual_facts.append(
                {"id": visual_fact_id(asset_id, text), "asset_id": asset_id, "text": text}
            )
    if kind == "input_asset_inspection" and not visual_facts:
        raise ValueError("input asset inspection requires at least one visual fact")
    readback_asset_id = data.get("readback_asset_id")
    if readback_asset_id is not None:
        readback_asset_id = str(readback_asset_id)
        assets = {asset["id"]: asset for asset in state.get("assets", [])}
        readback = assets.get(readback_asset_id)
        if readback is None or not readback.get("available") or not readback.get("sha256"):
            raise ValueError("readback_asset_id must reference an available hashed asset")
        input_hashes = {
            assets[asset_id].get("sha256")
            for asset_id in required_subjects
            if asset_id in assets
        }
        if readback.get("sha256") in input_hashes:
            raise ValueError("result readback must differ from every input asset")
    if kind == "result_visual_readback" and not readback_asset_id:
        raise ValueError("result visual readback requires readback_asset_id")
    if kind == "result_visual_readback" and readback_asset_id not in evidence_assets:
        raise ValueError("result proof evidence does not reference the readback asset")
    resolved_fact_ids = data.get("resolved_fact_ids", [])
    if not isinstance(resolved_fact_ids, list) or any(
        not isinstance(value, str) for value in resolved_fact_ids
    ):
        raise ValueError("resolved_fact_ids must be a string list")
    if kind == "result_visual_readback":
        known_fact_ids = {
            fact["id"]
            for proof in state.get("proofs", [])
            if proof.get("item_id") == item_id
            for fact in proof.get("visual_facts", [])
            if isinstance(fact, dict) and isinstance(fact.get("id"), str)
        }
        if not known_fact_ids or not known_fact_ids.issubset(set(resolved_fact_ids)):
            raise ValueError("result readback must resolve every immutable visual fact")
    expected_scope: list[str] = []
    observed_scope: list[str] = []
    if kind == "scope_coverage":
        expected_scope = normalized_scope(data.get("expected_scope"), "expected_scope")
        observed_scope = normalized_scope(data.get("observed_scope"), "observed_scope")
        required_count = obligation.get("expected_scope_count")
        if not isinstance(required_count, int) or required_count <= 0:
            raise ValueError("scope obligation has no prompt-derived expected count")
        if len(expected_scope) != required_count:
            raise ValueError(
                f"scope proof expected set has {len(expected_scope)} identifiers; "
                f"the prompt-derived contract requires {required_count}"
            )
        required_sha256 = obligation.get("expected_scope_sha256")
        if required_sha256 is not None and not hmac.compare_digest(
            str(required_sha256), sha256_text(canonical_json(expected_scope))
        ):
            raise ValueError("scope proof expected set differs from the prompt-derived scope")
        missing = sorted(set(expected_scope).difference(observed_scope))
        if missing:
            raise ValueError(
                f"scope proof covers {len(observed_scope)}/{len(expected_scope)}; "
                f"missing {len(missing)} identifiers"
            )
    return {
        "protocol_version": PROOF_PROTOCOL_VERSION,
        "item_id": item_id,
        "obligation_id": obligation_id,
        "kind": kind,
        "surface": surface,
        "subject_ids": sorted(set(subject_ids)),
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
        "visual_facts": visual_facts,
        "readback_asset_id": readback_asset_id,
        "resolved_fact_ids": sorted(set(resolved_fact_ids)),
        "expected_scope_count": len(expected_scope),
        "expected_scope_sha256": sha256_text(canonical_json(expected_scope)) if expected_scope else None,
        "observed_scope_count": len(observed_scope),
        "observed_scope_sha256": sha256_text(canonical_json(observed_scope)) if observed_scope else None,
    }


def normalized_proof_file(state: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    raw = read_bounded_regular_file(manifest_path, MAX_PROOF_MANIFEST_BYTES, "proof manifest")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"proof manifest is invalid UTF-8 JSON: {exc}") from exc
    return normalize_proof_manifest(state, data)


def append_normalized_proof(state: dict[str, Any], normalized: dict[str, Any]) -> dict[str, Any]:
    digest = sha256_text(canonical_json(normalized))
    for proof in state.get("proofs", []):
        if proof.get("sha256") == digest:
            return proof
    state["proof_sequence"] = int(state.get("proof_sequence", 0)) + 1
    proof = {
        "id": f"V{state['proof_sequence']:04d}",
        "created_at": utc_now(),
        **normalized,
        "sha256": digest,
    }
    state["proofs"].append(proof)
    return proof


def validate_proof_request(
    root: Path, session_id: str, turn_id: str, token: str, manifest_path: Path
) -> str:
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    completion_attempt_for(state, turn_id, token)
    normalized = normalized_proof_file(state, manifest_path)
    return sha256_text(canonical_json(normalized))


def fulfilled_obligation_ids(state: dict[str, Any], item_id: str) -> set[str]:
    proofs = [proof for proof in state.get("proofs", []) if proof.get("item_id") == item_id]
    fact_ids = {
        fact["id"]
        for proof in proofs
        for fact in proof.get("visual_facts", [])
        if isinstance(fact, dict) and isinstance(fact.get("id"), str)
    }
    fulfilled: set[str] = set()
    item = proof_item(state, item_id)
    for obligation in item.get("verification_contract", {}).get("obligations", []):
        obligation_id = obligation.get("id")
        candidates = [proof for proof in proofs if proof.get("obligation_id") == obligation_id]
        if obligation.get("kind") == "result_visual_readback":
            candidates = [
                proof
                for proof in candidates
                if fact_ids.issubset(set(proof.get("resolved_fact_ids", [])))
            ]
        if candidates:
            fulfilled.add(str(obligation_id))
    return fulfilled


def unresolved_proof_obligations(state: dict[str, Any]) -> dict[str, list[str]]:
    unresolved: dict[str, list[str]] = {}
    for collection in ("requirements", "acceptance_items"):
        for item in state.get(collection, []):
            contract = item.get("verification_contract")
            if item.get("status") == "superseded" or not isinstance(contract, dict):
                continue
            if contract.get("mode") != "enforced":
                continue
            fulfilled = fulfilled_obligation_ids(state, item["id"])
            missing = [
                str(obligation.get("id"))
                for obligation in contract.get("obligations", [])
                if obligation.get("id") not in fulfilled
            ]
            if missing:
                unresolved[item["id"]] = missing
    return unresolved


def _proof_capable_evidence(
    state: dict[str, Any], item: dict[str, Any], capability: str
) -> list[dict[str, Any]]:
    """Successful, item-current evidence carrying one capability, in ledger order."""
    prompt_created_at = next(
        (
            prompt.get("created_at")
            for prompt in state.get("prompts", [])
            if prompt.get("id") == item.get("prompt_id")
        ),
        None,
    )
    eligible: list[dict[str, Any]] = []
    for evidence in state.get("evidence", []):
        if evidence.get("outcome") != "success":
            continue
        if capability not in evidence.get("capabilities", []):
            continue
        if (
            isinstance(prompt_created_at, str)
            and isinstance(evidence.get("created_at"), str)
            and evidence["created_at"] < prompt_created_at
        ):
            # Evidence predating the item's prompt is stale for this item.
            continue
        eligible.append(evidence)
    return eligible


def _minimal_subject_cover(
    evidence_list: list[dict[str, Any]],
    required_subjects: set[str],
    *,
    field: str = "subject_ids",
) -> tuple[list[str], bool]:
    """Deterministic first-fit cover in ledger order; no caller input.

    With ``field="readback_subjects"`` (readback derivation) evidence whose
    binding is a *superset* of the required subjects is skipped: a read that
    covers more than the obligation's subjects is not a unique derivation and
    fails closed instead of covering it.
    """
    cover: list[str] = []
    covered: set[str] = set()
    for evidence in evidence_list:
        if required_subjects <= covered:
            break
        binding = set(evidence.get(field, []))
        if field != "subject_ids" and binding - required_subjects:
            # Superset binding: the read covers more than the obligation's
            # subjects, so it is not a unique derivation — skip it and let
            # the obligation stay unresolved (fail closed).
            continue
        subjects = binding & required_subjects
        if subjects - covered:
            cover.append(str(evidence["id"]))
            covered |= subjects
    return cover, required_subjects <= covered


def derive_ordinary_proofs(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive ordinary non-visual proofs from the ledger and bound evidence.

    Only ``subject_readback`` obligations on the ``artifact`` surface and
    exactly verifiable ``scope_coverage`` obligations are derived. Every
    binding — item, obligation, surface, and subjects — comes from the
    obligation and the private ledger; the caller cannot pass or expand a
    subject or scope. Visual, qualitative, UI-surface, unsupported-namespace,
    and not-uniquely-derivable obligations are left to the explicit
    ``register-proof`` path. Derivation never mutates state.
    """
    derived: list[dict[str, Any]] = []
    for collection in ("requirements", "acceptance_items"):
        for item in state.get(collection, []):
            if item.get("status") == "superseded":
                continue
            contract = item.get("verification_contract")
            if not isinstance(contract, dict) or contract.get("mode") != "enforced":
                continue
            fulfilled = fulfilled_obligation_ids(state, item["id"])
            for obligation in contract.get("obligations", []):
                if not isinstance(obligation, dict):
                    continue
                obligation_id = str(obligation.get("id"))
                if not obligation_id or obligation_id in fulfilled:
                    continue
                kind = str(obligation.get("kind"))
                surface = str(obligation.get("surface"))
                required = sorted(
                    {
                        str(subject)
                        for subject in obligation.get("subject_ids", [])
                        if isinstance(subject, str) and subject
                    }
                )
                if not required or any(
                    subject.startswith(UNSUPPORTED_SUBJECT_PREFIX)
                    for subject in required
                ):
                    continue
                manifest: dict[str, Any]
                if kind == "subject_readback" and surface == "artifact":
                    # CG-CODEX-001: a readback is derived only from evidence
                    # whose *input* actually read the required subjects via a
                    # registered read adapter. A path echoed by any successful
                    # tool response never binds a readback subject; evidence
                    # reading beyond the required subjects is a superset and
                    # fails closed.
                    eligible = _proof_capable_evidence(state, item, "artifact")
                    cover, complete = _minimal_subject_cover(
                        eligible, set(required), field="readback_subjects"
                    )
                    if not complete or not cover:
                        continue
                    manifest = {
                        "protocol_version": PROOF_PROTOCOL_VERSION,
                        "item_id": item["id"],
                        "obligation_id": obligation_id,
                        "evidence_ids": cover,
                        "surface": surface,
                        "subject_ids": required,
                    }
                elif kind == "scope_coverage":
                    required_count = obligation.get("expected_scope_count")
                    required_sha256 = obligation.get("expected_scope_sha256")
                    if (
                        not isinstance(required_count, int)
                        or required_count <= 0
                        or not isinstance(required_sha256, str)
                    ):
                        # Without a prompt-derived count and digest the exact
                        # equality cannot be verified, so derivation fails
                        # closed instead of guessing the set.
                        continue
                    eligible = _proof_capable_evidence(state, item, "scope")
                    observed: set[str] = set()
                    for evidence in eligible:
                        observed |= {
                            str(subject)
                            for subject in evidence.get("subject_ids", [])
                        }
                    observed_sorted = sorted(observed)
                    if len(observed_sorted) != required_count:
                        continue
                    if not hmac.compare_digest(
                        required_sha256,
                        sha256_text(canonical_json(observed_sorted)),
                    ):
                        continue
                    cover, complete = _minimal_subject_cover(eligible, observed)
                    if not complete or not cover:
                        continue
                    manifest = {
                        "protocol_version": PROOF_PROTOCOL_VERSION,
                        "item_id": item["id"],
                        "obligation_id": obligation_id,
                        "evidence_ids": cover,
                        "surface": surface,
                        "subject_ids": required,
                        "expected_scope": observed_sorted,
                        "observed_scope": observed_sorted,
                    }
                else:
                    continue
                derived.append(normalize_proof_manifest(state, manifest))
    return derived


def checkpoint_status_snapshot_full(state: dict[str, Any], turn_id: str) -> dict[str, Any]:
    successful = [
        {
            "id": item["id"],
            "tool": item["tool"],
            "summary": bounded(item["summary"], 350),
        }
        for item in state["evidence"]
        if item.get("outcome") == "success"
    ]
    unresolved = unresolved_proof_obligations(state)

    def item_snapshot(item: dict[str, Any]) -> dict[str, Any]:
        contract = item.get("verification_contract")
        mode = contract.get("mode") if isinstance(contract, dict) else "legacy_fallback"
        obligations = contract.get("obligations", []) if isinstance(contract, dict) else []
        fulfilled = fulfilled_obligation_ids(state, item["id"]) if mode == "enforced" else set()
        return {
            "id": item["id"],
            "status": item.get("status", "pending"),
            "text": bounded(item.get("text", ""), 350),
            "evidence": item.get("evidence", []),
            "verification": {
                "protocol_version": PROOF_PROTOCOL_VERSION,
                "mode": mode,
                "reason": contract.get("reason") if isinstance(contract, dict) else "missing_contract",
                "obligations": [
                    {
                        "id": obligation.get("id"),
                        "kind": obligation.get("kind"),
                        "surface": obligation.get("surface"),
                        "subject_ids": obligation.get("subject_ids", []),
                        "expected_scope_count": obligation.get("expected_scope_count"),
                        "expected_scope_sha256": obligation.get("expected_scope_sha256"),
                        "fulfilled": obligation.get("id") in fulfilled,
                    }
                    for obligation in obligations
                    if isinstance(obligation, dict)
                ],
                "unresolved": unresolved.get(item["id"], []),
            },
        }

    return {
        "turn_id": turn_id,
        "proof_protocol_version": PROOF_PROTOCOL_VERSION,
        "requirements": [
            item_snapshot(item)
            for item in state["requirements"]
            if item.get("status") != "superseded"
        ],
        "acceptance": [
            item_snapshot(item)
            for item in state["acceptance_items"]
            if item.get("status") != "superseded"
        ],
        "successful_evidence_count": len(successful),
        "recent_successful_evidence": successful[-30:],
        "assets": [
            {
                key: item.get(key)
                for key in (
                    "id",
                    "prompt_ids",
                    "source_kind",
                    "source_ref",
                    "sha256",
                    "bytes",
                    "media_type",
                    "width",
                    "height",
                    "available",
                )
            }
            for item in state.get("assets", [])[-32:]
        ],
        "proofs": [
            {
                key: item.get(key)
                for key in (
                    "id",
                    "item_id",
                    "obligation_id",
                    "kind",
                    "surface",
                    "evidence_ids",
                    "readback_asset_id",
                    "expected_scope_count",
                    "observed_scope_count",
                )
            }
            for item in state.get("proofs", [])[-64:]
        ],
    }


def checkpoint_status_snapshot(
    state: dict[str, Any], turn_id: str, *, full: bool = False,
    item_id: str | None = None, after_revision: str | None = None,
) -> dict[str, Any]:
    """Return a bounded work-unit view; full/item modes are explicit audits."""
    revision = str(state.get("content_hash") or state_content_hash(state))
    active = state.get("work_state", {}).get("active_work_unit_id")
    if after_revision is not None and hmac.compare_digest(after_revision, revision):
        return {
            "unchanged": True,
            "revision": revision,
            "active_work_unit_id": active,
        }
    detailed = checkpoint_status_snapshot_full(state, turn_id)
    detailed.update(
        {
            "revision": revision,
            "work_unit_protocol_version": WORK_UNIT_PROTOCOL_VERSION,
            "active_work_unit_id": active,
        }
    )
    if item_id is not None:
        normalized = item_id.upper()
        matches = [
            item
            for key in ("requirements", "acceptance")
            for item in detailed[key]
            if item.get("id") == normalized
        ]
        if not matches:
            raise ValueError(f"unknown checkpoint item {normalized}")
        return {
            "turn_id": turn_id,
            "revision": revision,
            "active_work_unit_id": active,
            "item": matches[0],
        }
    if full:
        detailed["mode"] = "full"
        return detailed

    scoped_ids, ancestor_ids = checkpoint_scope_item_ids(state)
    items = [
        item
        for collection in ("requirements", "acceptance_items")
        for item in state.get(collection, [])
        if isinstance(item, dict)
        and item.get("status") != "superseded"
        and item.get("id") in scoped_ids
    ]
    successful = [
        {
            "id": item["id"],
            "tool": bounded(item.get("tool", "unknown"), 80),
            "summary": bounded(item.get("summary", ""), 160),
        }
        for item in state.get("evidence", [])
        if isinstance(item, dict) and item.get("outcome") == "success"
    ][-8:]
    counts = {
        "requirements": sum(str(item.get("id", "")).startswith("R") for item in items),
        "acceptance": sum(str(item.get("id", "")).startswith("A") for item in items),
        "pending": sum(item.get("status") not in {"pass", "superseded"} for item in items),
        "passed": sum(item.get("status") == "pass" for item in items),
        "ancestor_constraints": len(ancestor_ids),
    }
    return {
        "turn_id": turn_id,
        "revision": revision,
        "mode": "current_work_unit",
        "work_unit_protocol_version": WORK_UNIT_PROTOCOL_VERSION,
        "active_work_unit_id": active,
        "counts": counts,
        "item_ids_sha256": sha256_text(
            canonical_json(sorted(str(item["id"]) for item in items))
        ),
        "items": [
            {
                "id": item["id"],
                "status": item.get("status", "pending"),
                "summary": bounded(item.get("text", ""), 180),
            }
            for item in items[:12]
        ],
        "items_truncated": len(items) > 12,
        "ancestor_constraint_ids": sorted(ancestor_ids),
        "successful_evidence_count": sum(
            item.get("outcome") == "success"
            for item in state.get("evidence", [])
            if isinstance(item, dict)
        ),
        "recent_successful_evidence": successful,
    }


def private_checkpoint(
    state: dict[str, Any],
    requirement_assignments: dict[str, list[str]],
    acceptance_assignments: dict[str, list[str]],
) -> dict[str, Any]:
    scoped_ids, ancestor_ids = checkpoint_scope_item_ids(state)
    _current, scope_units, _ancestors = work_unit_relations(state)
    checkpoint: dict[str, Any] = {
        "status": "complete",
        "work_unit_id": state.get("work_state", {}).get("active_work_unit_id"),
        "scope_unit_ids": sorted(scope_units),
        "ancestor_constraints": sorted(ancestor_ids),
        "requirements": {},
        "acceptance": {},
        "open_items": [],
    }
    supplied = {
        "requirements": requirement_assignments,
        "acceptance_items": acceptance_assignments,
    }
    output_keys = {
        "requirements": "requirements",
        "acceptance_items": "acceptance",
    }
    for collection in ("requirements", "acceptance_items"):
        constrained_ids = scoped_ids | ancestor_ids
        known_ids = {
            item["id"]
            for item in state[collection]
            if item.get("status") != "superseded" and item["id"] in constrained_ids
        }
        unknown = set(supplied[collection]).difference(known_ids)
        if unknown:
            raise ValueError(
                f"unknown {collection} IDs: {','.join(sorted(unknown))}"
            )
        output = checkpoint[output_keys[collection]]
        for item in state[collection]:
            if item.get("status") == "superseded" or item["id"] not in constrained_ids:
                continue
            evidence_ids = supplied[collection].get(item["id"])
            if evidence_ids is None and item.get("status") == "pass":
                evidence_ids = list(item.get("evidence", []))
            if evidence_ids is not None:
                output[item["id"]] = {
                    "status": "pass",
                    "evidence": evidence_ids,
                }
    return checkpoint


def checkpoint_status(
    root: Path, session_id: str, turn_id: str, token: str, *,
    full: bool = False, item_id: str | None = None,
    after_revision: str | None = None,
) -> dict[str, Any]:
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    completion_attempt_for(state, turn_id, token)
    return checkpoint_status_snapshot(
        state, turn_id, full=full, item_id=item_id,
        after_revision=after_revision,
    )


def clear_pending_request(
    root: Path, session_id: str, turn_id: str, token: str
) -> int:
    """Runtime entry for clear-pending: verify the turn, then clear only the
    pending operation ledger. Requirements, evidence, and checkpoints are
    immutable here, and the state is persisted in the same transaction."""
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    completion_attempt_for(state, turn_id, token)
    cleared = clear_pending(state)
    save_state(session_dir, state)
    return cleared


def validate_checkpoint_request(
    root: Path,
    session_id: str,
    turn_id: str,
    token: str,
    requirement_values: list[str],
    acceptance_values: list[str],
    replace: bool = False,
) -> str:
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    attempt = completion_attempt_for(state, turn_id, token)
    requirements = parse_evidence_assignments(
        requirement_values, "requirement"
    )
    acceptance = parse_evidence_assignments(
        acceptance_values, "acceptance"
    )
    # Precheck mirrors the staging transaction in memory: ordinary proofs are
    # derived before validation, and the mutation is never persisted here.
    proof_mark = len(state.get("proofs", []))
    sequence_mark = int(state.get("proof_sequence", 0))
    for normalized in derive_ordinary_proofs(state):
        append_normalized_proof(state, normalized)
    checkpoint = private_checkpoint(state, requirements, acceptance)
    issues = checkpoint_issues(state, checkpoint)
    del state["proofs"][proof_mark:]
    state["proof_sequence"] = sequence_mark
    if issues:
        raise ValueError("; ".join(issues))
    control = checkpoint_control(checkpoint)
    validate_control_transition(attempt, control, replace=replace)
    return control_request_sha256(session_id, turn_id, control, replace=replace)


def checkpoint_control(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "checkpoint", "checkpoint": checkpoint}


def disposition_control(disposition: str) -> dict[str, str]:
    reason = DISPOSITION_REASONS.get(disposition)
    if reason is None:
        raise ValueError(
            "disposition must be continue, user_wait, external_wait, or deferred"
        )
    return {
        "kind": "disposition",
        "disposition": disposition,
        "reason": reason,
    }


def validate_staged_control(control: Any) -> dict[str, Any]:
    if not isinstance(control, dict):
        raise ValueError("staged control must be an object")
    if control.get("kind") == "checkpoint":
        if set(control) != {"kind", "checkpoint"} or not isinstance(
            control.get("checkpoint"), dict
        ):
            raise ValueError("invalid staged checkpoint control")
        return control
    if control.get("kind") == "disposition":
        if set(control) != {"kind", "disposition", "reason"}:
            raise ValueError("invalid staged disposition control")
        expected = DISPOSITION_REASONS.get(str(control.get("disposition") or ""))
        if expected is None or control.get("reason") != expected:
            raise ValueError("invalid staged disposition reason")
        return control
    raise ValueError("staged control has an unknown kind")


def control_request_sha256(
    session_id: str,
    turn_id: str,
    control: dict[str, Any],
    *,
    replace: bool,
) -> str:
    request = {
        "protocol_version": STOP_PROTOCOL_VERSION,
        "session_id": session_id,
        "turn_id": turn_id,
        "control": control,
        "replace": bool(replace),
    }
    return sha256_text(canonical_json(request))


def validate_control_transition(
    attempt: dict[str, Any], control: dict[str, Any], *, replace: bool
) -> bool:
    validate_staged_control(control)
    existing = attempt.get("staged_control")
    if existing is None:
        return False
    validate_staged_control(existing)
    if hmac.compare_digest(canonical_json(existing), canonical_json(control)):
        return True
    if not replace:
        raise ValueError(
            "a different private control is already staged; use --replace"
        )
    return False


def stage_control(
    attempt: dict[str, Any], control: dict[str, Any], *, replace: bool
) -> bool:
    idempotent = validate_control_transition(attempt, control, replace=replace)
    if not idempotent:
        attempt["staged_control"] = control
        attempt["staged_at"] = utc_now()
    return idempotent


def validate_disposition_request(
    root: Path,
    session_id: str,
    turn_id: str,
    token: str,
    disposition: str,
    replace: bool = False,
) -> str:
    session_dir = root / "sessions" / safe_session_id(session_id)
    state = load_state(session_dir, {"session_id": session_id})
    require_usable_state(state)
    attempt = completion_attempt_for(state, turn_id, token)
    control = disposition_control(disposition)
    validate_control_transition(attempt, control, replace=replace)
    return control_request_sha256(session_id, turn_id, control, replace=replace)


def stage_private_checkpoint(
    root: Path,
    session_id: str,
    turn_id: str,
    token: str,
    requirement_values: list[str],
    acceptance_values: list[str],
    replace: bool = False,
) -> dict[str, Any]:
    session_dir = root / "sessions" / safe_session_id(session_id)
    with session_lock(session_dir):
        state = load_state(session_dir, {"session_id": session_id})
        require_usable_state(state)
        attempt = completion_attempt_for(state, turn_id, token)
        requirements = parse_evidence_assignments(
            requirement_values, "requirement"
        )
        acceptance = parse_evidence_assignments(
            acceptance_values, "acceptance"
        )
        # One idempotent transaction: derived ordinary proofs and the staged
        # checkpoint are written together or not at all. A failed staging
        # never leaves half a proof behind and never advances state.
        proof_mark = len(state.get("proofs", []))
        sequence_mark = int(state.get("proof_sequence", 0))
        try:
            for normalized in derive_ordinary_proofs(state):
                append_normalized_proof(state, normalized)
            checkpoint = private_checkpoint(state, requirements, acceptance)
            issues = checkpoint_issues(state, checkpoint)
            if issues:
                raise ValueError("; ".join(issues))
            control = checkpoint_control(checkpoint)
            idempotent = stage_control(attempt, control, replace=replace)
        except Exception:
            del state["proofs"][proof_mark:]
            state["proof_sequence"] = sequence_mark
            raise
        receipt = {
            "turn_id": turn_id,
            "checkpoint_sha256": sha256_text(canonical_json(checkpoint)),
            "request_sha256": control_request_sha256(
                session_id, turn_id, control, replace=replace
            ),
            "idempotent": idempotent,
        }
        save_state(session_dir, state)
        return receipt


def stage_private_disposition(
    root: Path,
    session_id: str,
    turn_id: str,
    token: str,
    disposition: str,
    replace: bool = False,
) -> dict[str, Any]:
    session_dir = root / "sessions" / safe_session_id(session_id)
    with session_lock(session_dir):
        state = load_state(session_dir, {"session_id": session_id})
        require_usable_state(state)
        attempt = completion_attempt_for(state, turn_id, token)
        control = disposition_control(disposition)
        idempotent = stage_control(attempt, control, replace=replace)
        receipt = {
            "turn_id": turn_id,
            "disposition": disposition,
            "reason": control["reason"],
            "request_sha256": control_request_sha256(
                session_id, turn_id, control, replace=replace
            ),
            "idempotent": idempotent,
        }
        save_state(session_dir, state)
        return receipt


def handle_user_prompt(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    text = prompt_text(payload)
    origin, authority, actor_id = classify_prompt_origin(state, payload, text)
    prompt = append_prompt(
        session_dir,
        state,
        text,
        int(payload.get("_context_guard_unicode_repairs") or 0),
        origin=origin,
        authority=authority,
        actor_id=actor_id,
    )
    asset_ids = discover_assets(
        state, payload, prompt_id=prompt["id"], source="hook_payload"
    )
    if origin == "subagent_delegation":
        save_state(session_dir, state)
        return {}
    action, argument = control_action(text)
    context: str | None = None
    export_requested = False
    if action == "on":
        state["mode"]["active"] = True
        state["mode"]["manual_off"] = False
        state["mode"]["activation_reasons"] = list(
            dict.fromkeys(state["mode"]["activation_reasons"] + ["explicit"])
        )
        context = status_context(state)
    elif action == "off":
        state["mode"]["active"] = False
        state["mode"]["manual_off"] = True
        state["completion_attempt"] = None
        context = "Context Guard full protection disabled; immutable prompt journaling remains active."
    elif action == "status":
        context = status_context(state)
    elif action == "diagnose":
        context = diagnose_context(state)
    elif action == "adopt":
        try:
            context = adopt_execution_contract(state, prompt, argument)
        except (OSError, StateIntegrityError, ValueError) as exc:
            context = "Execution contract adoption rejected: " + bounded(str(exc), 400)
    elif action == "export":
        export_requested = True
    elif action == "rollover":
        export_requested = False
    if not is_control_prompt(text):
        state["continuation_attempts"] = 0
        work_unit_id = append_work_unit(state, prompt, text)
        requirement_id = append_requirement(
            state, prompt, text, asset_ids, work_unit_id=work_unit_id
        )
        acceptance_count = len(state["acceptance_items"])
        append_acceptance(
            state, prompt["id"], text, asset_ids, work_unit_id=work_unit_id
        )
        new_acceptance_ids = [
            item["id"] for item in state["acceptance_items"][acceptance_count:]
        ]
        supersession_result = record_supersession(state, text, requirement_id)
        score, reasons = score_complexity(text)
        goal_requested = bool(
            re.search(r"^\s*/goal\b", text, re.I | re.MULTILINE)
            or payload.get("goal_id")
            or payload.get("goal")
        )
        if goal_requested:
            reasons.append("goal")
        state["mode"]["complexity_score"] = max(state["mode"]["complexity_score"], score)
        state["mode"]["activation_reasons"] = list(
            dict.fromkeys(state["mode"]["activation_reasons"] + reasons)
        )
        if not state["mode"]["manual_off"] and (
            score >= 4
            or "$context-guard" in text.lower()
            or goal_requested
            or len(state["acceptance_items"]) >= 2
            or len(state["requirements"]) >= 3
        ):
            state["mode"]["active"] = True
        if state["mode"]["active"]:
            acceptance_note = (
                ", ".join(new_acceptance_ids) if new_acceptance_ids else "none"
            )
            context = (
                f"Context Guard is active. This turn added requirement {requirement_id} "
                f"and acceptance IDs {acceptance_note}. Preserve these IDs."
            )
            if supersession_result == "ambiguous":
                context += (
                    " Supersession target is ambiguous; prior requirements remain "
                    "active. Ask the root user to identify one exact requirement ID."
                )
    needs_private_completion = (
        state["mode"]["active"]
        and not state["mode"]["manual_off"]
        and state.get("integrity", {}).get("status") != "failed"
        and action not in {"on", "off", "status", "export", "rollover", "adopt"}
    )
    if needs_private_completion:
        turn_id, token = begin_completion_attempt(state, payload, prompt["id"])
        private_context = completion_command_context(state, turn_id, token)
        context = f"{context}\n\n{private_context}" if context else private_context
    save_state(session_dir, state)
    if export_requested:
        require_usable_state(state)
        path = export_handoff(session_dir, state, argument)
        context = f"Context Guard exported a redacted handoff to {path}."
    elif action == "rollover":
        require_usable_state(state)
        pack = export_successor_pack(session_dir, state, argument)
        context = (
            "Context Guard exported a bounded successor pack to "
            f"{pack}. It did not create, activate, retire, or authorize any task."
        )
    elif state.get("integrity", {}).get("status") == "failed":
        context = (
            "Context Guard detected unrecoverable private-state corruption. "
            "Prompt journaling continues, but compaction and completion remain "
            "blocked until the private ledger is repaired or protection is "
            "explicitly disabled."
        )
    return hook_output("UserPromptSubmit", context)


def response_text_values(value: Any, *, depth: int = 0) -> list[str]:
    if depth >= 6:
        return []
    if isinstance(value, str):
        if DATA_URL_RE.match(value):
            return []
        return [value[:12000]]
    if isinstance(value, dict):
        values: list[str] = []
        for item in list(value.values())[:64]:
            values.extend(response_text_values(item, depth=depth + 1))
            if sum(len(text) for text in values) >= 24000:
                break
        return values
    if isinstance(value, (list, tuple)):
        values = []
        for item in list(value)[:64]:
            values.extend(response_text_values(item, depth=depth + 1))
            if sum(len(text) for text in values) >= 24000:
                break
        return values
    return []


def normalized_exit_code(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value)
    return None


def has_hard_tool_failure(diagnostic: str) -> bool:
    """Failures outrank success, except an explicitly labeled warning line."""
    return any(
        not re.match(r"\s*warning:", match.group(0), re.IGNORECASE)
        for match in FAILED_TOOL_RESPONSE_RE.finditer(diagnostic)
    )


REGISTERED_VISUAL_TOOL_ALIASES = {
    "view_image",
    "functions_view_image",
    "tools_view_image",
}


def _visual_image_content_blocks(response: Any) -> list[str]:
    """Normalize only the registered first-party visual receipt shapes."""
    if isinstance(response, list):
        raw_blocks = response
    elif isinstance(response, dict) and isinstance(response.get("content"), list):
        raw_blocks = response["content"]
    elif isinstance(response, dict) and response.get("type") == "input_image":
        raw_blocks = [response]
    else:
        raw_blocks = []
    blocks: list[str] = []
    for value in raw_blocks[:16]:
        if not isinstance(value, dict) or value.get("type") != "input_image":
            continue
        image_url = value.get("image_url")
        if isinstance(image_url, str):
            blocks.append(image_url)
        if len(blocks) >= 8:
            break
    return blocks


def _is_registered_visual_tool(tool_name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(tool_name).lower()).strip("_")
    return normalized in REGISTERED_VISUAL_TOOL_ALIASES


def _is_image_data_url(value: Any) -> bool:
    match = DATA_URL_RE.match(value) if isinstance(value, str) else None
    return bool(
        match is not None
        and (match.group("mime") or "").lower().startswith("image/")
        and (match.group("body") or "").strip()
    )


def tool_outcome_details(payload: dict[str, Any]) -> tuple[str, str]:
    response = payload.get("tool_response")
    diagnostic = "\n".join(response_text_values(response))
    if isinstance(response, dict):
        if (
            response.get("is_error") is True
            or response.get("isError") is True
            or bool(response.get("error"))
            or response.get("success") is False
        ):
            return "failed", "structured_error"
        raw_exit_code = response.get("exit_code", response.get("exitCode"))
        exit_code = normalized_exit_code(raw_exit_code)
        if raw_exit_code is not None and exit_code is None:
            return "failed", "invalid_exit_code"
        if has_hard_tool_failure(diagnostic):
            return "failed", "failure_marker"
        if exit_code is not None:
            return (
                ("success", "structured_exit_code")
                if exit_code == 0
                else ("failed", "structured_exit_code")
            )
        if (
            response.get("is_error") is False
            or response.get("isError") is False
            or response.get("success") is True
        ):
            return "success", "structured_status"
    if has_hard_tool_failure(diagnostic):
        return "failed", "failure_marker"
    if _is_registered_visual_tool(str(payload.get("tool_name") or "")):
        # Top-level data URL object form.
        if isinstance(response, dict):
            image_url = response.get("image_url")
            if _is_image_data_url(image_url):
                return "success", "structured_visual_result"
        # Structured content-block form (e.g., input_image arrays).
        visual_blocks = _visual_image_content_blocks(response)
        if visual_blocks:
            has_valid = any(_is_image_data_url(block) for block in visual_blocks)
            if has_valid:
                return "success", "structured_visual_result"
    if (
        tool_is_update_plan(str(payload.get("tool_name") or ""))
        and UPDATE_PLAN_SUCCESS_TOOL_RESPONSE_RE.fullmatch(diagnostic)
    ):
        return "success", "first_party_plan_receipt"
    if AUTHORITATIVE_SUCCESS_TOOL_RESPONSE_RE.search(diagnostic):
        return "success", "authoritative_success_marker"
    if FAILED_TOOL_RESPONSE_RE.search(diagnostic):
        return "failed", "failure_marker"
    if WEAK_SUCCESS_TOOL_RESPONSE_RE.search(diagnostic):
        return "unknown", "weak_success_marker"
    return "unknown", "unstructured_text"


def tool_outcome(payload: dict[str, Any]) -> str:
    return tool_outcome_details(payload)[0]


def tool_is_update_plan(tool_name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
    return normalized == "update_plan" or normalized.endswith("_update_plan")


def plan_semantic_sha256(steps: list[dict[str, str]], explanation: str | None = None) -> str:
    semantic: dict[str, Any] = {"steps": steps}
    if isinstance(explanation, str) and explanation.strip():
        semantic["explanation"] = bounded(explanation, 800)
    return sha256_text(canonical_json(semantic))


def observe_plan_drift(state: dict[str, Any], observed_sha256: str) -> None:
    """Record adopted-plan drift without changing the Codex-owned plan."""
    execution = state.get("execution")
    if not isinstance(execution, dict):
        return
    validate_execution_state(execution)
    contract = execution["contract"]
    if contract["state"] not in {"active", "stale"}:
        return
    sources = [
        item
        for item in execution["instruction_sources"]
        if isinstance(item, dict)
        and item.get("kind") == "plan_snapshot"
        and item.get("state") in {"active", "stale"}
    ]
    if len(sources) != 1:
        return
    source = sources[0]
    baseline_sha256 = str(source["sha256"])
    if hmac.compare_digest(baseline_sha256, observed_sha256):
        return
    if any(
        item.get("source_id") == source["id"]
        and item.get("observed_sha256") == observed_sha256
        and item.get("state") == "detected"
        for item in execution["drift"]
        if isinstance(item, dict)
    ):
        return
    affected_ids = [
        str(item["id"])
        for collection in ("phases", "gates")
        for item in contract[collection]
        if isinstance(item, dict) and item.get("state") != "superseded"
    ] or [str(contract["contract_id"])]
    execution["drift"].append(
        {
            "id": f"drift-{len(execution['drift']) + 1}",
            "source_id": source["id"],
            "baseline_sha256": baseline_sha256,
            "observed_sha256": observed_sha256,
            "affected_ids": affected_ids,
            "state": "detected",
            "detected_at": utc_now(),
            "resolution_sha256": None,
        }
    )
    source["state"] = "stale"
    if contract["state"] == "active":
        transition_execution_contract(execution, "stale")
    for collection in ("phases", "gates"):
        for item in contract[collection]:
            if item.get("state") == "passed":
                item["state"] = "stale"
    contract["canonical_sha256"] = contract_content_hash(contract)
    validate_execution_state(execution)


def capture_plan_snapshot(
    state: dict[str, Any], payload: dict[str, Any], outcome: str
) -> None:
    if outcome != "success" or not tool_is_update_plan(
        str(payload.get("tool_name") or "")
    ):
        return
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("plan"), list):
        return
    steps: list[dict[str, str]] = []
    for raw_item in tool_input["plan"][:PLAN_STEP_LIMIT]:
        if not isinstance(raw_item, dict):
            continue
        step = bounded(raw_item.get("step", ""), 500).strip()
        status = str(raw_item.get("status") or "pending")
        if not step or status not in {"pending", "in_progress", "completed"}:
            continue
        steps.append({"step": step, "status": status})
    if not steps:
        return
    explanation = tool_input.get("explanation")
    normalized_explanation = (
        bounded(explanation, 800)
        if isinstance(explanation, str) and explanation.strip()
        else None
    )
    snapshot: dict[str, Any] = {
        "source": "update_plan",
        "updated_at": utc_now(),
        "turn_id": str(payload.get("turn_id") or ""),
        "tool_use_id": str(payload.get("tool_use_id") or ""),
        "steps": steps,
    }
    if normalized_explanation is not None:
        snapshot["explanation"] = normalized_explanation
    snapshot["semantic_sha256"] = plan_semantic_sha256(
        steps, normalized_explanation
    )
    snapshot["sha256"] = sha256_text(canonical_json(snapshot))
    state.setdefault("work_state", {})["plan_snapshot"] = snapshot
    observe_plan_drift(state, snapshot["semantic_sha256"])


def plan_mirror_health(state: dict[str, Any]) -> str:
    snapshot = state.get("work_state", {}).get("plan_snapshot")
    if snapshot is None:
        return "missing"
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("steps"), list):
        return "degraded"
    steps = snapshot.get("steps")
    if not steps or any(
        not isinstance(item, dict)
        or not isinstance(item.get("step"), str)
        or item.get("status") not in {"pending", "in_progress", "completed"}
        for item in steps
    ):
        return "degraded"
    expected_hash = snapshot.get("sha256")
    unhashed = dict(snapshot)
    unhashed.pop("sha256", None)
    if not isinstance(expected_hash, str) or expected_hash != sha256_text(
        canonical_json(unhashed)
    ):
        return "degraded"
    return "healthy"


def shell_control_operator_present(command: str) -> bool:
    """Return whether a shell operator occurs outside a quoted literal."""
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
            elif character == "`":
                return True
            elif character == "$" and command[index : index + 2] == "$(":
                return True
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in {";", "&", "|", "`", "\n", "\r"}:
            return True
        elif character == "$" and command[index : index + 2] == "$(":
            return True
        index += 1
    return False


def tool_is_shell_execution(tool_name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
    return (
        normalized in {"bash", "shell", "exec_command"}
        or normalized.endswith("_exec_command")
    )


def private_control_command_intent(payload: dict[str, Any]) -> bool:
    """Recognize execution of this runtime, never mere control-name text."""
    if not tool_is_shell_execution(str(payload.get("tool_name") or "")):
        return False
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return False
    control_commands = (
        "checkpoint-status",
        "clear-pending",
        "register-proof",
        "stage-checkpoint",
        "stage-disposition",
    )
    candidate = command.lstrip()
    script_path = str(Path(__file__).resolve())
    for control_command in control_commands:
        prefix = shell_join([sys.executable, script_path, control_command])
        if candidate == prefix or candidate.startswith(prefix + " "):
            return True
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return script_path in command and any(
            control_command in command for control_command in control_commands
        )
    tokens = [
        token[1:-1]
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}
        else token
        for token in tokens
    ]
    plain_search = bool(
        tokens
        and Path(tokens[0]).name.lower() in {"rg", "grep"}
        and not shell_control_operator_present(command)
    )
    if plain_search:
        return False
    expected_script = Path(__file__).resolve()
    for index in range(max(0, len(tokens) - 2)):
        if tokens[index + 2] not in control_commands:
            continue
        script = Path(tokens[index + 1]).expanduser()
        try:
            if script.is_absolute() and script.resolve() == expected_script:
                return True
        except (OSError, RuntimeError):
            continue
    return False


def is_exact_checkpoint_status_command(
    state: dict[str, Any], payload: dict[str, Any]
) -> bool:
    if not tool_is_shell_execution(str(payload.get("tool_name") or "")):
        return False
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or "checkpoint-status" not in command:
        return False
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return False
    tokens = [
        token[1:-1]
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}
        else token
        for token in tokens
    ]
    if len(tokens) < 3 or tokens[2] != "checkpoint-status":
        return False
    executable = Path(tokens[0]).expanduser()
    script = Path(tokens[1]).expanduser()
    if (
        not executable.is_absolute()
        or executable.resolve() != Path(sys.executable).resolve()
        or not script.is_absolute()
        or script.resolve() != Path(__file__).resolve()
    ):
        return False
    values = {name: [] for name in ("--data-dir", "--session-id", "--turn-id", "--token")}
    position = 3
    while position < len(tokens):
        raw_option = tokens[position]
        if raw_option.startswith("--") and "=" in raw_option:
            option, value = raw_option.split("=", 1)
            position += 1
        else:
            if raw_option not in values or position + 1 >= len(tokens):
                return False
            option = raw_option
            value = tokens[position + 1]
            position += 2
        if option not in values or not value:
            return False
        values[option].append(value)
    if any(len(value) != 1 for value in values.values()):
        return False
    if Path(values["--data-dir"][0]).expanduser().resolve() != data_root().resolve():
        return False
    session_id = values["--session-id"][0]
    turn_id = values["--turn-id"][0]
    if (
        session_id != str(state["session"]["id"])
        or turn_id != str(payload.get("turn_id") or "")
    ):
        return False
    completion_attempt_for(state, turn_id, values["--token"][0])
    return True


def parse_proof_request_from_tool(
    state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any] | None:
    if not tool_is_shell_execution(str(payload.get("tool_name") or "")):
        return None
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or "register-proof" not in command:
        return None
    if shell_control_operator_present(command):
        raise ValueError("private proof request must be one exact command")
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"invalid private proof command: {exc}") from exc
    tokens = [
        token[1:-1]
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}
        else token
        for token in tokens
    ]
    if len(tokens) < 3 or tokens[2] != "register-proof":
        raise ValueError("private proof request must be one exact command")
    try:
        if (
            Path(tokens[0]).expanduser().resolve() != Path(sys.executable).resolve()
            or Path(tokens[1]).expanduser().resolve() != Path(__file__).resolve()
        ):
            raise ValueError("private proof request uses a different runtime")
    except (OSError, RuntimeError):
        raise ValueError("private proof request path could not be resolved") from None
    values = {
        name: []
        for name in ("--data-dir", "--session-id", "--turn-id", "--token", "--manifest")
    }
    position = 3
    while position < len(tokens):
        raw = tokens[position]
        if raw.startswith("--") and "=" in raw:
            option, value = raw.split("=", 1)
            position += 1
        elif raw in values and position + 1 < len(tokens):
            option, value = raw, tokens[position + 1]
            position += 2
        else:
            raise ValueError(f"invalid private proof option {raw!r}")
        if option not in values or not value:
            raise ValueError(f"invalid private proof option {raw!r}")
        values[option].append(value)
    if any(len(value) != 1 for value in values.values()):
        raise ValueError("private proof request requires each option exactly once")
    if Path(values["--data-dir"][0]).expanduser().resolve() != data_root().resolve():
        raise ValueError("private proof request targets a different data directory")
    if values["--session-id"][0] != str(state["session"]["id"]):
        raise ValueError("private proof request targets a different session")
    turn_id = values["--turn-id"][0]
    if turn_id != str(payload.get("turn_id") or ""):
        raise ValueError("private proof request targets a different turn")
    completion_attempt_for(state, turn_id, values["--token"][0])
    manifest_path = Path(values["--manifest"][0]).expanduser().resolve()
    normalized = normalized_proof_file(state, manifest_path)
    expected_sha256 = sha256_text(canonical_json(normalized))
    response_values = response_text_values(payload.get("tool_response"))
    found: list[str] = []
    for value in response_values:
        for line in value.splitlines():
            match = re.fullmatch(
                rf"\s*{re.escape(PROOF_REQUEST_MARKER)} ([0-9a-f]{{64}})\s*",
                line,
            )
            if match is not None:
                found.append(match.group(1))
    if len(found) != 1:
        raise ValueError("private proof request requires one exact hash marker")
    if not hmac.compare_digest(found[0], expected_sha256):
        raise ValueError("private proof request marker does not match the manifest")
    return normalized


def parse_stage_request_from_tool(
    state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any] | None:
    if not tool_is_shell_execution(str(payload.get("tool_name") or "")):
        return None
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return None
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        if "stage-checkpoint" not in command and "stage-disposition" not in command:
            return None
        raise ValueError(f"invalid private stage command: {exc}") from exc
    tokens = [
        token[1:-1]
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}
        else token
        for token in tokens
    ]
    private_commands = {"stage-checkpoint", "stage-disposition"}
    present_commands = [token for token in tokens if token in private_commands]
    if not present_commands:
        return None
    if len(present_commands) != 1 or len(tokens) < 3:
        raise ValueError("private stage request command is ambiguous")
    private_command = present_commands[0]
    if tokens[2] != private_command:
        raise ValueError("private stage request must be one exact command")
    executable = Path(tokens[0]).expanduser()
    script = Path(tokens[1]).expanduser()
    if (
        not executable.is_absolute()
        or executable.resolve() != Path(sys.executable).resolve()
    ):
        raise ValueError("private stage request uses a different Python runtime")
    if not script.is_absolute() or script.resolve() != Path(__file__).resolve():
        raise ValueError("private stage request uses a different runtime script")

    common_options = {
        "--data-dir": [],
        "--session-id": [],
        "--turn-id": [],
        "--token": [],
    }
    command_options: dict[str, list[str]] = (
        {"--requirement": [], "--acceptance": []}
        if private_command == "stage-checkpoint"
        else {"--disposition": []}
    )
    option_values = {**common_options, **command_options}
    replace = False
    remainder = tokens[3:]
    position = 0
    while position < len(remainder):
        raw_option = remainder[position]
        if raw_option == "--replace":
            if replace:
                raise ValueError("private stage request repeats --replace")
            replace = True
            position += 1
            continue
        if raw_option.startswith("--") and "=" in raw_option:
            option, value = raw_option.split("=", 1)
            position += 1
        else:
            option = raw_option
            if option not in option_values or position + 1 >= len(remainder):
                raise ValueError(f"invalid private stage option {option!r}")
            value = remainder[position + 1]
            position += 2
        if option not in option_values or not value:
            raise ValueError(f"invalid private stage option {raw_option!r}")
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        option_values[option].append(value)
    for option in ("--data-dir", "--session-id", "--turn-id", "--token"):
        if len(option_values[option]) != 1:
            raise ValueError(f"private stage request requires exactly one {option}")
    if private_command == "stage-disposition" and len(
        option_values["--disposition"]
    ) != 1:
        raise ValueError("private stage request requires exactly one --disposition")
    expected_root = data_root().expanduser().resolve()
    requested_root = Path(option_values["--data-dir"][0]).expanduser().resolve()
    if requested_root != expected_root:
        raise ValueError("private stage request targets a different data directory")
    session_id = option_values["--session-id"][0]
    if session_id != str(state["session"]["id"]):
        raise ValueError("private stage request targets a different session")
    turn_id = option_values["--turn-id"][0]
    if turn_id != str(payload.get("turn_id") or ""):
        raise ValueError("private stage request targets a different turn")
    token = option_values["--token"][0]
    attempt = completion_attempt_for(state, turn_id, token)
    if private_command == "stage-checkpoint":
        requirements = parse_evidence_assignments(
            option_values["--requirement"], "requirement"
        )
        acceptance = parse_evidence_assignments(
            option_values["--acceptance"], "acceptance"
        )
        # Dry-run the derivation transaction: ordinary proofs are derived and
        # validated, then rolled back because parsing never mutates state.
        # The authoritative staging path re-appends the same normalized
        # proofs and writes them together with the staged control.
        proof_mark = len(state.get("proofs", []))
        sequence_mark = int(state.get("proof_sequence", 0))
        derived_proofs = derive_ordinary_proofs(state)
        try:
            for normalized in derived_proofs:
                append_normalized_proof(state, normalized)
            checkpoint = private_checkpoint(state, requirements, acceptance)
            issues = checkpoint_issues(state, checkpoint)
        finally:
            del state["proofs"][proof_mark:]
            state["proof_sequence"] = sequence_mark
        if issues:
            raise ValueError("; ".join(issues))
        control = checkpoint_control(checkpoint)
        expected_marker = STAGE_REQUEST_MARKER
    else:
        control = disposition_control(option_values["--disposition"][0])
        expected_marker = DISPOSITION_REQUEST_MARKER
    validate_control_transition(attempt, control, replace=replace)
    expected_sha256 = control_request_sha256(
        session_id, turn_id, control, replace=replace
    )

    response_values = response_text_values(payload.get("tool_response"))
    all_response_text = "\n".join(response_values)
    marker_names = (STAGE_REQUEST_MARKER, DISPOSITION_REQUEST_MARKER)
    found: list[tuple[str, str]] = []
    for value in response_values:
        for line in value.splitlines():
            match = re.fullmatch(
                rf"\s*({'|'.join(map(re.escape, marker_names))}) "
                r"([0-9a-f]{64})\s*",
                line,
            )
            if match is not None:
                found.append((match.group(1), match.group(2)))
    if len(found) != 1:
        raise ValueError("private stage request requires one exact hash marker")
    marker_name, marker_sha256 = found[0]
    if any(name in all_response_text for name in marker_names) and (
        marker_name != expected_marker
        or not hmac.compare_digest(marker_sha256, expected_sha256)
    ):
        raise ValueError("private stage request marker does not match the command")
    return {
        "turn_id": turn_id,
        "token": token,
        "control": control,
        "replace": replace,
        "derived_proofs": derived_proofs if private_command == "stage-checkpoint" else [],
    }


def handle_post_tool(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    outcome, outcome_basis = tool_outcome_details(payload)
    settle_pre_tool_ticket(state, payload, outcome)
    if state["mode"]["active"]:
        require_usable_state(state)
        # Codex may persist attachment metadata only after UserPromptSubmit.
        # Reconcile the bounded transcript before recording the first tool so
        # an available prompt asset cannot remain an accidental fallback.
        reconcile_transcript_assets(state, payload, trigger="post_tool")
        tool_name = str(payload.get("tool_name") or "unknown-tool")
        control_intent = private_control_command_intent(payload)
        if control_intent:
            try:
                proof_request = parse_proof_request_from_tool(state, payload)
                if proof_request is not None:
                    if outcome != "success":
                        raise ValueError(
                            "private proof request tool result was not successful"
                        )
                    proof = append_normalized_proof(state, proof_request)
                    save_state(session_dir, state)
                    return hook_output(
                        "PostToolUse",
                        "Context Guard privately registered immutable proof "
                        f"{proof['id']}. Continue with the remaining obligations.",
                    )
                stage_request = parse_stage_request_from_tool(state, payload)
                if stage_request is not None:
                    if outcome != "success":
                        raise ValueError(
                            "private stage request tool result was not successful"
                        )
                    attempt = completion_attempt_for(
                        state, stage_request["turn_id"], stage_request["token"]
                    )
                    proof_mark = len(state.get("proofs", []))
                    sequence_mark = int(state.get("proof_sequence", 0))
                    try:
                        for normalized in stage_request.get("derived_proofs", []):
                            append_normalized_proof(state, normalized)
                        idempotent = stage_control(
                            attempt,
                            stage_request["control"],
                            replace=stage_request["replace"],
                        )
                    except Exception:
                        del state["proofs"][proof_mark:]
                        state["proof_sequence"] = sequence_mark
                        raise
                    save_state(session_dir, state)
                    suffix = " (idempotent)" if idempotent else ""
                    return hook_output(
                        "PostToolUse",
                        "Context Guard privately staged the turn-bound control"
                        f"{suffix}. Send a normal user-facing response without "
                        "private control metadata.",
                    )
                if is_exact_checkpoint_status_command(state, payload):
                    save_state(session_dir, state)
                    return {}
                save_state(session_dir, state)
                return {
                    "decision": "block",
                    "reason": (
                        f"{INTERNAL_CONTINUATION_PREFIX} Malformed private "
                        "control command rejected; it was not recorded as evidence."
                    ),
                }
            except (OSError, RuntimeError, ValueError) as exc:
                save_state(session_dir, state)
                return {
                    "decision": "block",
                    "reason": (
                        f"{INTERNAL_CONTINUATION_PREFIX} Private control staging "
                        f"failed: {bounded(exc, 800)}"
                    ),
                }
        tool_input = bounded_evidence(payload.get("tool_input"), 700)
        tool_response = bounded_evidence(payload.get("tool_response"), 900)
        evidence_asset_ids = discover_assets(
            state, payload, prompt_id=None, source="tool_event"
        )
        evidence_origin, evidence_actor_id = tool_actor(state, payload)
        capabilities = set(evidence_capabilities(tool_name))
        upgraded, _transient = host_tool_surface_disposition(state, payload)
        if upgraded:
            capabilities.add("ui")
        normalized_tool = re.sub(r"[^a-z0-9]+", "_", tool_name.lower()).strip("_")
        is_thread_reader = normalized_tool in THREAD_READ_TOOL_ALIASES
        # Navigation/open tools and arbitrary output text produce at most
        # navigation facts: a codex://threads/ URI echoed by any other tool
        # can never satisfy a thread-subject readback (same thread, wrong
        # tool stays rejected). Only the registered thread-read adapter binds
        # thread subjects, from its bare threadId argument or its own URI.
        evidence_subject_ids = discovered_subject_ids(
            payload, include_threads=is_thread_reader
        )
        if is_thread_reader:
            tool_input_raw = payload.get("tool_input")
            thread_values: list[Any] = []
            if isinstance(tool_input_raw, dict):
                for key in ("threadId", "thread_id", "thread-id"):
                    value = tool_input_raw.get(key)
                    if isinstance(value, str):
                        thread_values.append(value)
            for value in thread_values:
                subject_id = thread_subject_id_from_thread_id(value)
                if subject_id is not None:
                    evidence_subject_ids.append(subject_id)
        state["evidence_sequence"] += 1
        # CG-CODEX-001: a readback subject is bound only by a registered read
        # adapter's *input*; response echoes and payload mentions stay inert.
        readback_subjects = read_input_subject_ids(tool_name, payload.get("tool_input"))
        evidence = {
            "id": f"E{state['evidence_sequence']:04d}",
            "adapter_manifest_version": ADAPTER_MANIFEST_VERSION,
            "operation": primary_clause_operation(latest_requirement_text(session_dir, state)),
            "subjectId": list(dict.fromkeys(readback_subjects or evidence_subject_ids)),
            "requestedSurface": "ui" if "ui" in capabilities else ("visual" if "visual" in capabilities else "artifact"),
            "created_at": utc_now(),
            "tool": tool_name,
            "origin": evidence_origin,
            "actor_id": evidence_actor_id,
            "outcome": outcome,
            "outcome_basis": outcome_basis,
            "summary": f"input={tool_input}; response={tool_response}",
            "unicode_repairs": int(
                payload.get("_context_guard_unicode_repairs") or 0
            ),
            "asset_ids": evidence_asset_ids,
            "subject_ids": list(dict.fromkeys(evidence_subject_ids)),
            "readback_subjects": readback_subjects,
            "capabilities": sorted(capabilities),
        }
        state["evidence"].append(evidence)
        capture_plan_snapshot(state, payload, outcome)
        trim_evidence(state)
        save_state(session_dir, state)
    else:
        save_state(session_dir, state)
    return {}


def handle_pre_compact(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["manual_off"]:
        return {"continue": True}
    require_usable_state(state)
    reconcile_transcript_assets(state, payload, trigger="pre_compact")
    state["mode"]["active"] = True
    state["mode"]["activation_reasons"] = list(
        dict.fromkeys(state["mode"]["activation_reasons"] + ["first_compaction"])
    )
    state["compactions"].append(
        {
            "created_at": utc_now(),
            "trigger": payload.get("trigger") or payload.get("source") or "unknown",
        }
    )
    pending = state.setdefault("pending", {"operations": [], "recovery": None, "clear_token": None})
    pending["recovery"] = {"state": "pending", "trigger": "PreCompact", "sequence": len(state["compactions"])}
    save_state(session_dir, state)
    write_recovery(session_dir, state, "PreCompact")
    pending["recovery"]["state"] = "ready"
    save_state(session_dir, state)
    return {"continue": True}


def handle_session_start(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    source = str(payload.get("source") or "")
    if source not in {"compact", "resume"} or not state["mode"]["active"]:
        return {}
    require_usable_state(state)
    reconcile_transcript_assets(state, payload, trigger="session_start")
    existing_attempt = state.get("completion_attempt")
    transcript_turn_id = latest_transcript_turn_id(state, payload)
    fallback_turn_id = transcript_turn_id
    if fallback_turn_id is None and isinstance(existing_attempt, dict):
        existing_turn_id = existing_attempt.get("turn_id")
        if existing_turn_id:
            fallback_turn_id = str(existing_turn_id)
    if fallback_turn_id is None:
        fallback_turn_id = f"{source}-{len(state['prompts'])}"
    turn_id, token = begin_completion_attempt(state, payload, fallback_turn_id)
    save_state(session_dir, state)
    packet = write_recovery(session_dir, state, f"SessionStart:{source}")
    pending = state.setdefault("pending", {"operations": [], "recovery": None, "clear_token": None})
    if isinstance(pending.get("recovery"), dict):
        pending["recovery"]["state"] = "consumed"
    save_state(session_dir, state)
    private_context = completion_command_context(state, turn_id, token)
    combined = f"{packet}\n\n{private_context}"
    if len(combined) > RECOVERY_CHAR_LIMIT:
        packet_budget = max(0, RECOVERY_CHAR_LIMIT - len(private_context) - 80)
        packet = clip_preserving_suffix(
            packet,
            packet_budget,
            RECOVERY_COMPLETION_RULE,
            "…[recovery packet clipped to preserve private completion commands]",
        )
        combined = (
            packet
            + "\n\n"
            + private_context
        )
    return hook_output("SessionStart", combined)


def handle_subagent_start(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["active"]:
        require_usable_state(state)
    agent_id = str(
        payload.get("agent_id")
        or f"unknown-agent-{payload.get('turn_id') or len(state.get('agents', [])) + 1}"
    )
    record = agent_record(state, agent_id)
    if record is None:
        record = {"agent_id": agent_id}
        state.setdefault("agents", []).append(record)
    record.update(
        {
            "agent_type": str(payload.get("agent_type") or "unknown"),
            "status": "running",
            "started_at": utc_now(),
            "stopped_at": None,
            "start_turn_id": str(payload.get("turn_id") or ""),
            "permission_mode": str(payload.get("permission_mode") or ""),
            "authority": "delegated",
            "requirement_ids": [
                item["id"]
                for item in state.get("requirements", [])
                if item.get("status") != "superseded"
            ],
            "acceptance_ids": [
                item["id"]
                for item in state.get("acceptance_items", [])
                if item.get("status") != "superseded"
            ],
        }
    )
    trim_agent_records(state)
    save_state(session_dir, state)
    if state["mode"]["active"]:
        return hook_output("SubagentStart", subagent_contract_context(state))
    return {}


def handle_subagent_stop(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if state["mode"]["active"]:
        require_usable_state(state)
    agent_id = str(
        payload.get("agent_id")
        or f"unknown-agent-{payload.get('turn_id') or len(state.get('agents', [])) + 1}"
    )
    record = agent_record(state, agent_id)
    if record is None:
        record = {
            "agent_id": agent_id,
            "started_at": None,
            "start_turn_id": "",
            "authority": "delegated",
            "requirement_ids": [],
            "acceptance_ids": [],
        }
        state.setdefault("agents", []).append(record)
    message = str(payload.get("last_assistant_message") or "")
    safe_message = private_metadata_free_text(message)
    record.update(
        {
            "agent_type": str(
                payload.get("agent_type") or record.get("agent_type") or "unknown"
            ),
            "status": "stopped",
            "stopped_at": utc_now(),
            "stop_turn_id": str(payload.get("turn_id") or ""),
            "result_summary": bounded_evidence(safe_message, 1800),
            "result_sha256": sha256_text(message),
            "result_envelope": agent_result_envelope(safe_message),
            "transcript_available": bool(payload.get("agent_transcript_path")),
        }
    )
    trim_agent_records(state)
    save_state(session_dir, state)
    return {}


def obligation_binding_diagnostic(
    state: dict[str, Any], item_id: str, obligation_id: str
) -> str:
    """Bounded transient diagnostic for one unresolved obligation (CG-5a).

    Reports the obligation's required surface, the capabilities available on
    current successful evidence, and whether the required subjects are
    covered. A UI obligation whose only related tool events are registered
    UI-surface candidates without trusted envelope metadata additionally
    reports the transient ``adapter_disposition=unavailable``. The output
    exists only in the current diagnostic message: it is never persisted and
    contains only rule facts, never prompt text.
    """
    item = proof_item(state, item_id)
    obligation = proof_obligation(item, obligation_id)
    kind = str(obligation.get("kind"))
    surface = str(obligation.get("surface"))
    required = sorted(
        {
            str(subject)
            for subject in obligation.get("subject_ids", [])
            if isinstance(subject, str) and subject
        }
    )
    if any(subject.startswith(UNSUPPORTED_SUBJECT_PREFIX) for subject in required):
        return f"required_surface={surface};subject_binding=unbindable"
    capability = "scope" if kind == "scope_coverage" else surface
    eligible = _proof_capable_evidence(state, item, capability)
    covered: set[str] = set()
    available: set[str] = set()
    for evidence in eligible:
        covered |= {
            str(subject) for subject in evidence.get("subject_ids", [])
        }
        available |= {
            str(capability) for capability in evidence.get("capabilities", [])
        }
    if kind == "scope_coverage":
        binding = "covered" if eligible else "missing"
    else:
        binding = "matched" if set(required) <= covered else "missing"
    parts = [
        f"required_surface={surface}",
        f"available_capabilities={','.join(sorted(available)) or 'none'}",
        f"subject_binding={binding}",
    ]
    if (
        surface == "ui"
        and binding == "missing"
        and any(
            _is_ui_surface_candidate_tool(str(evidence.get("tool") or ""))
            for evidence in state.get("evidence", [])
        )
    ):
        parts.append("adapter_disposition=unavailable")
    return ";".join(parts)


def checkpoint_issues(
    state: dict[str, Any], checkpoint: dict[str, Any]
) -> list[str]:
    issues: list[str] = []
    top_status = checkpoint.get("status")
    if top_status != "complete":
        issues.append(f"top-level status must be complete, got {top_status!r}")
    scoped_ids, ancestor_ids = checkpoint_scope_item_ids(state)
    _current, scope_units, _ancestors = work_unit_relations(state)
    if checkpoint.get("work_unit_id") != state.get("work_state", {}).get("active_work_unit_id"):
        issues.append("checkpoint work-unit identity is stale")
    if checkpoint.get("scope_unit_ids") != sorted(scope_units):
        issues.append("checkpoint work-unit closure is stale")
    if checkpoint.get("ancestor_constraints") != sorted(ancestor_ids):
        issues.append("checkpoint ancestor constraints are stale")
    evidence_by_id = {
        item["id"]: item
        for item in state["evidence"]
        if isinstance(item.get("id"), str)
    }
    for collection, key in (
        ("requirements", "requirements"),
        ("acceptance_items", "acceptance"),
    ):
        reported = checkpoint.get(key)
        if not isinstance(reported, dict):
            issues.append(f"missing {key} status map")
            continue
        constrained_ids = scoped_ids | ancestor_ids
        expected_ids = {
            item["id"]
            for item in state[collection]
            if item.get("status") != "superseded" and item["id"] in constrained_ids
        }
        unknown_ids = set(reported).difference(expected_ids)
        if unknown_ids:
            issues.append(
                f"unknown {key} IDs: {','.join(sorted(unknown_ids))}"
            )
        for item in state[collection]:
            item_id = item["id"]
            if item.get("status") == "superseded" or item_id not in constrained_ids:
                continue
            value = reported.get(item_id)
            if not isinstance(value, dict):
                issues.append(f"{item_id} is missing")
                continue
            status = value.get("status")
            if status != "pass":
                issues.append(f"{item_id} is {status}")
                continue
            evidence_ids = value.get("evidence")
            if not isinstance(evidence_ids, list) or not evidence_ids:
                issues.append(f"{item_id} passes without evidence")
                continue
            for evidence_id in evidence_ids:
                if (
                    not isinstance(evidence_id, str)
                    or not EVIDENCE_ID_RE.fullmatch(evidence_id)
                ):
                    issues.append(
                        f"{item_id} has invalid evidence reference {evidence_id!r}"
                    )
                    continue
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    issues.append(
                        f"{item_id} references unknown evidence {evidence_id}"
                    )
                elif evidence.get("outcome") != "success":
                    issues.append(
                        f"{item_id} references non-success evidence {evidence_id} "
                        f"(outcome={evidence.get('outcome') or 'unknown'})"
                    )
            contract = item.get("verification_contract")
            if isinstance(contract, dict) and contract.get("mode") == "enforced":
                missing = unresolved_proof_obligations(state).get(item_id, [])
                if missing:
                    details = []
                    for obligation_id in missing[:4]:
                        try:
                            details.append(
                                f"{obligation_id}"
                                f"[{obligation_binding_diagnostic(state, item_id, obligation_id)}]"
                            )
                        except ValueError:
                            details.append(obligation_id)
                    issues.append(
                        f"{item_id} has unresolved proof obligations: "
                        + ",".join(details)
                    )
                proof_evidence = {
                    evidence_id
                    for proof in state.get("proofs", [])
                    if proof.get("item_id") == item_id
                    for evidence_id in proof.get("evidence_ids", [])
                    if proof.get("obligation_id")
                    in {
                        obligation.get("id")
                        for obligation in contract.get("obligations", [])
                        if isinstance(obligation, dict)
                    }
                }
                omitted = sorted(proof_evidence.difference(evidence_ids))
                if omitted:
                    issues.append(
                        f"{item_id} checkpoint omits proof evidence: {','.join(omitted)}"
                    )
    open_items = checkpoint.get("open_items")
    if not isinstance(open_items, list):
        issues.append("open_items must be a list")
    elif open_items:
        issues.append("open_items is not empty: " + ", ".join(map(str, open_items[:12])))
    return issues


def apply_checkpoint(
    state: dict[str, Any], checkpoint: dict[str, Any], turn_id: str
) -> None:
    for collection, key in (
        ("requirements", "requirements"),
        ("acceptance_items", "acceptance"),
    ):
        reported = checkpoint.get(key, {})
        if not isinstance(reported, dict):
            continue
        for item in state[collection]:
            value = reported.get(item["id"])
            if not isinstance(value, dict):
                continue
            item["status"] = "pass"
            item["evidence"] = list(value.get("evidence", []))
    scope_units = set(checkpoint.get("scope_unit_ids", []))
    closed_at = utc_now()
    for unit in state.get("work_units", []):
        if isinstance(unit, dict) and unit.get("id") in scope_units:
            unit["status"] = "passed"
            unit["closed_at"] = closed_at
    state["open_items"] = open_item_ids(state)
    state["completion_checkpoint"] = {
        "created_at": closed_at,
        "turn_id": turn_id,
        "status": "complete",
        "work_unit_id": checkpoint.get("work_unit_id"),
        "sha256": sha256_text(canonical_json(checkpoint)),
    }
    state["completion_attempt"] = None


def terminal_stop_policy(
    *,
    explicit_persistence: bool,
    persistence_allows_deferred: bool,
    declared_disposition: str | None,
) -> str:
    """Return the protocol-authoritative terminal action for a Stop request."""
    if (
        explicit_persistence
        and not persistence_allows_deferred
        and declared_disposition not in {"user_wait", "external_wait"}
    ):
        return "gate_explicit_persistence"
    return {
        "user_wait": "yield_user_wait",
        "external_wait": "yield_external_wait",
        "deferred": "yield_deferred",
        "continue": "yield_continue_advisory",
        None: "yield_default",
    }[declared_disposition]


def disposition_matches_observed(
    declared_disposition: str | None, observed_outcome: str
) -> bool:
    if declared_disposition in {None, "continue"}:
        return True
    expected = {
        "user_wait": "allow_user_handoff",
        "external_wait": "allow_external_wait",
        "deferred": "allow_out_of_scope_deferred",
    }
    return expected.get(declared_disposition) == observed_outcome


def handle_stop(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if not state["mode"]["active"] or state["mode"]["manual_off"]:
        return {}
    try:
        require_usable_state(state)
    except StateIntegrityError:
        return {
            "continue": False,
            "stopReason": (
                "Context Guard stopped completion because private task state "
                "could not be reconstructed safely."
            ),
            "systemMessage": (
                "Context Guard private-state integrity failed. Review the "
                "preserved corrupt state and immutable prompt ledger."
            ),
        }
    text = assistant_text(payload)
    authoritative_prompt = latest_requirement_text(session_dir, state)
    attempt = state.get("completion_attempt")
    turn_id = str(
        payload.get("turn_id")
        or (attempt.get("turn_id") if isinstance(attempt, dict) else "")
    )
    prompt_integrity = bool(authoritative_prompt) or not state.get("requirements")
    observed = classify_stop_decision(
        text, authoritative_prompt, prompt_integrity=prompt_integrity
    )
    decision = dict(observed)
    decision.update(
        {
            "protocol_version": STOP_PROTOCOL_VERSION,
            "decision_source": "nlp_diagnostic",
            "declared_disposition": None,
            "observed_outcome": observed["outcome"],
        }
    )
    if observed["outcome"] == "fail_closed_integrity":
        decision["decision_source"] = "integrity"
        append_decision_log(state, decision, turn_id)
        save_state(session_dir, state)
        return {
            "continue": False,
            "stopReason": (
                "Context Guard stopped completion because the authoritative "
                "prompt boundary could not be verified."
            ),
            "systemMessage": (
                "Context Guard prompt integrity is ambiguous. Review the immutable "
                "prompt ledger before retrying."
            ),
        }

    legacy_checkpoint = CHECKPOINT_RE.search(text) is not None
    privacy_classification, privacy_reasons = classify_private_metadata(text)
    leaked_private_metadata = privacy_classification != "explanatory_reference"
    turn_matches = (
        isinstance(attempt, dict)
        and str(attempt.get("turn_id")) == turn_id
    )
    staged_control = (
        attempt.get("staged_control")
        if turn_matches and isinstance(attempt, dict)
        else None
    )
    explicit_persistence = bool(
        authoritative_prompt
        and USER_PERSISTENCE_RE.search(authoritative_prompt)
    )
    issues: list[str] = []
    if legacy_checkpoint:
        issues.append(
            "legacy inline checkpoint metadata is not accepted; stage it privately"
        )
    elif leaked_private_metadata:
        issues.append(
            "user-facing reply contains private control metadata or a "
            "credential-like binding"
        )
    if issues:
        decision.update(
            {
                "outcome": "fail_closed_integrity",
                "reason_codes": [
                    "private_metadata_leak",
                    privacy_classification,
                    *privacy_reasons,
                ],
                "decision_source": "integrity",
            }
        )

    checkpoint: dict[str, Any] | None = None
    declared_disposition: str | None = None
    if staged_control is not None:
        try:
            control = validate_staged_control(staged_control)
            if control["kind"] == "checkpoint":
                checkpoint = control["checkpoint"]
            else:
                declared_disposition = str(control["disposition"])
        except ValueError:
            issues.append("invalid staged private checkpoint or disposition")
            decision.update(
                {
                    "outcome": "fail_closed_integrity",
                    "reason_codes": ["invalid_staged_control"],
                    "decision_source": "integrity",
                }
            )

    # A valid checkpoint is the only protocol declaration of completion. It
    # satisfies an explicit persistence request and outranks reply diagnostics.
    if checkpoint is not None and not issues:
        checkpoint_problems = checkpoint_issues(state, checkpoint)
        if checkpoint_problems:
            issues.extend(checkpoint_problems)
            decision.update(
                {
                    "outcome": "fail_closed_integrity",
                    "reason_codes": ["checkpoint_validation_failed"],
                    "decision_source": "protocol_checkpoint",
                    "declared_disposition": "complete",
                }
            )
        else:
            apply_checkpoint(state, checkpoint, turn_id)
            state["continuation_attempts"] = 0
            decision.update(
                {
                    "outcome": "consume_checkpoint",
                    "reason_codes": ["validated_turn_bound_checkpoint"],
                    "decision_source": "protocol_checkpoint",
                    "declared_disposition": "complete",
                }
            )
            append_decision_log(state, decision, turn_id)
            save_state(session_dir, state)
            return {}

    prompt_scope = prompt_action_scope(authoritative_prompt)
    deferred_bindings = deferred_action_bindings(text, prompt_scope)
    persistence_allows_deferred = bool(
        explicit_persistence
        and declared_disposition == "deferred"
        and deferred_bindings
    )
    if (
        not issues
        and declared_disposition is not None
        and not disposition_matches_observed(
            declared_disposition, str(observed.get("outcome") or "")
        )
    ):
        issues.append("declared disposition does not match the observed ownership boundary")
        decision.update(
            {
                "outcome": observed["outcome"],
                "reason_codes": [
                    "disposition_observation_mismatch",
                    f"declared_{declared_disposition}",
                    f"observed_{observed['outcome']}",
                ],
                "decision_source": "protocol_disposition_validation",
                "declared_disposition": declared_disposition,
            }
        )
    policy = (
        None
        if issues
        else terminal_stop_policy(
            explicit_persistence=explicit_persistence,
            persistence_allows_deferred=persistence_allows_deferred,
            declared_disposition=declared_disposition,
        )
    )
    if policy == "gate_explicit_persistence":
        issues.append("authoritative user prompt requires persistence")
        decision.update(
            {
                "outcome": "gate_authorized_remaining_work",
                "reason_codes": ["explicit_user_persistence"],
                "decision_source": "protocol_user_persistence",
                "declared_disposition": declared_disposition,
            }
        )

    if not issues and declared_disposition is not None:
        disposition_outcomes = {
            "user_wait": "allow_user_handoff",
            "external_wait": "allow_external_wait",
            "deferred": "allow_out_of_scope_deferred",
        }
        outcome = disposition_outcomes.get(declared_disposition)
        if outcome is not None:
            state["completion_attempt"] = None
            state["continuation_attempts"] = 0
            decision.update(
                {
                    "outcome": outcome,
                    "reason_codes": [
                        f"protocol_{declared_disposition}",
                        DISPOSITION_REASONS[declared_disposition],
                    ]
                    + (
                        ["authoritative_prompt_bounds_deferred_action"]
                        + [
                            f"deferred_{category}"
                            for category in deferred_bindings[:4]
                        ]
                        if persistence_allows_deferred
                        else []
                    ),
                    "decision_source": "protocol_disposition",
                    "declared_disposition": declared_disposition,
                }
            )
            append_decision_log(state, decision, turn_id)
            save_state(session_dir, state)
            return {}

        if policy == "yield_continue_advisory":
            # A terminal reply and a staged continue declaration can disagree:
            # the declaration is prepared before the final reply exists. Never
            # turn that within-turn mismatch into an expensive forced retry.
            # Explicit prompt-bound persistence was handled above; otherwise a
            # continue declaration is advisory and unresolved items stay open.
            state["completion_attempt"] = None
            state["continuation_attempts"] = 0
            decision.update(
                {
                    "outcome": "allow_neutral",
                    "reason_codes": [
                        "protocol_continue_advisory",
                        DISPOSITION_REASONS[declared_disposition],
                        "safe_yield_pending_preserved",
                    ],
                    "decision_source": "protocol_disposition",
                    "declared_disposition": declared_disposition,
                }
            )
            append_decision_log(state, decision, turn_id)
            save_state(session_dir, state)
            return {}

    if not issues:
        state["completion_attempt"] = None
        state["continuation_attempts"] = 0
        decision.update(
            {
                "outcome": "allow_neutral",
                "reason_codes": ["protocol_default_yield"],
                "decision_source": "protocol_default",
            }
        )
        append_decision_log(state, decision, turn_id)
        save_state(session_dir, state)
        return {}

    concise = "; ".join(dict.fromkeys(issues[:12]))
    expected_ids = (
        "Expected IDs: requirements="
        + (",".join(item["id"] for item in state["requirements"]) or "none")
        + "; acceptance="
        + (",".join(item["id"] for item in state["acceptance_items"]) or "none")
        + "."
    )
    if state["continuation_attempts"] >= 2:
        decision["reason_codes"] = list(decision["reason_codes"]) + [
            "completion_contract_failed_twice"
        ]
        append_decision_log(state, decision, turn_id)
        save_state(session_dir, state)
        return {
            "continue": False,
            "stopReason": "Context Guard stopped an unverified completion after two correction attempts.",
            "systemMessage": (
                "Context Guard stopped an unverified completion. Review the private "
                "evidence ledger before retrying."
            )
        }
    state["continuation_attempts"] += 1
    decision["reason_codes"] = list(decision["reason_codes"]) + [
        "protocol_control_rejected"
    ]
    append_decision_log(state, decision, turn_id)
    save_state(session_dir, state)
    if decision["outcome"] == "gate_authorized_remaining_work":
        correction = (
            "Continue the authorized work, or stage an exact user_wait/external_wait "
            "disposition only when that boundary is actually reached."
        )
    else:
        correction = (
            "Resolve or explicitly report these items. If claiming completion, use "
            "the private checkpoint commands injected for the continuation turn; do "
            "not put checkpoint metadata in the user-facing reply."
        )
    return {
        "decision": "block",
        "reason": (
            f"{INTERNAL_CONTINUATION_PREFIX} The task is not yet safely complete. "
            f"{correction} "
            f"{concise}. {expected_ids}"
        ),
    }


def safe_export_path(state: dict[str, Any], argument: str | None) -> Path:
    cwd = Path(str(state["session"].get("cwd") or os.getcwd())).expanduser().resolve()
    if argument:
        try:
            parsed = shlex.split(argument, posix=os.name != "nt")
        except ValueError as exc:
            raise ValueError(f"invalid export path: {exc}") from exc
        if len(parsed) != 1:
            raise ValueError("export accepts exactly one path")
        parsed_path = parsed[0]
        if (
            len(parsed_path) >= 2
            and parsed_path[0] == parsed_path[-1]
            and parsed_path[0] in {"'", '"'}
        ):
            parsed_path = parsed_path[1:-1]
        candidate = Path(parsed_path).expanduser()
        candidate = candidate if candidate.is_absolute() else cwd / candidate
    else:
        candidate = cwd / ".codex" / "context-guard" / "CONTEXT_HANDOFF.md"
    resolved = candidate.resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError as exc:
        raise ValueError("export path must stay inside the current project") from exc
    return resolved


def project_root_from_state(state: dict[str, Any]) -> Path:
    root = Path(str(state["session"].get("cwd") or os.getcwd())).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("current project root is not an existing directory")
    return root


def parse_single_path_argument(argument: str | None, label: str) -> str | None:
    if not argument:
        return None
    try:
        parsed = shlex.split(argument, posix=os.name != "nt")
    except ValueError as exc:
        raise ValueError(f"invalid {label} path: {exc}") from exc
    if len(parsed) != 1:
        raise ValueError(f"{label} accepts exactly one path")
    value = parsed[0]
    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        value = value[1:-1]
    return value


def inspect_regular_file(
    path: Path, expected_size: int, *, count_lines: bool = False
) -> tuple[str, int | None]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    descriptor = os.open(str(path), flags)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
            raise ValueError("declared successor file changed before hashing")
        bytes_read = 0
        newline_count = 0
        last = b""
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            bytes_read += len(chunk)
            if count_lines:
                newline_count += chunk.count(b"\n")
                last = chunk[-1:]
        if bytes_read != expected_size or os.fstat(handle.fileno()).st_size != expected_size:
            raise ValueError("declared successor file changed while hashing")
    line_count = (
        newline_count + (1 if last and last != b"\n" else 0)
        if count_lines
        else None
    )
    return digest.hexdigest(), line_count


def read_bounded_regular_file(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"{label} must be a regular file")
            if info.st_size > limit:
                raise ValueError(f"{label} exceeds its byte limit")
            raw = handle.read(limit + 1)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {exc}") from exc
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds its byte limit")
    return raw


def successor_project_file(root: Path, raw_path: Any, label: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError(f"{label}.path must be a non-empty project-relative path")
    lexical = Path(raw_path)
    if lexical.is_absolute():
        raise ValueError(f"{label}.path must be project-relative")
    candidate = root / lexical
    if candidate.is_symlink():
        raise ValueError(f"{label}.path must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label}.path must stay inside the current project") from exc
    if not resolved.is_file():
        raise ValueError(f"{label}.path must identify a regular file")
    return resolved


def bounded_single_line(value: Any, label: str, limit: int = 1200) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\n" in value
        or "\r" in value
        or len(value) > limit
    ):
        raise ValueError(f"{label} must be non-empty bounded single-line text")
    return redact_text(value.strip())


def validate_authorization_index(
    value: Any, state: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    categories = {"granted", "consumed", "pending", "forbidden"}
    if not isinstance(value, dict) or set(value) != categories:
        raise ValueError(
            "authorization must contain exactly granted, consumed, pending, and forbidden"
        )
    requirement_ids = {
        item["id"]
        for item in state["requirements"] + state["acceptance_items"]
        if item.get("status") != "superseded"
    }
    evidence_ids = {
        item["id"]
        for item in state["evidence"]
        if isinstance(item.get("id"), str) and item.get("outcome") == "success"
    }
    normalized: dict[str, list[dict[str, Any]]] = {}
    for category in sorted(categories):
        items = value.get(category)
        if not isinstance(items, list) or len(items) > 40:
            raise ValueError(f"authorization.{category} must be a bounded list")
        normalized_items: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            label = f"authorization.{category}[{index}]"
            if not isinstance(item, dict) or set(item) != {"text", "source_ids"}:
                raise ValueError(f"{label} must contain exactly text and source_ids")
            text = bounded_single_line(item.get("text"), f"{label}.text", 1000)
            source_ids = item.get("source_ids")
            if (
                not isinstance(source_ids, list)
                or not source_ids
                or len(source_ids) > 20
                or any(not isinstance(source_id, str) for source_id in source_ids)
            ):
                raise ValueError(f"{label}.source_ids must be a non-empty string list")
            allowed = requirement_ids | evidence_ids
            unknown = sorted(set(source_ids) - allowed)
            if unknown:
                raise ValueError(
                    f"{label}.source_ids contains unknown IDs: {', '.join(unknown)}"
                )
            if category != "consumed" and not set(source_ids).issubset(requirement_ids):
                raise ValueError(
                    f"{label} may reference only requirement or acceptance IDs"
                )
            normalized_items.append(
                {"text": text, "source_ids": list(dict.fromkeys(source_ids))}
            )
        normalized[category] = normalized_items
    return normalized


def validate_successor_artifacts(
    root: Path, data: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    current = data.get("current_step_reads")
    audit = data.get("audit_only_files")
    if not isinstance(current, list) or len(current) > MAX_SUCCESSOR_CURRENT_READS:
        raise ValueError(
            f"current_step_reads must contain at most {MAX_SUCCESSOR_CURRENT_READS} items"
        )
    if not isinstance(audit, list) or len(audit) > MAX_SUCCESSOR_AUDIT_FILES:
        raise ValueError(
            f"audit_only_files must contain at most {MAX_SUCCESSOR_AUDIT_FILES} items"
        )
    normalized_current: list[dict[str, Any]] = []
    normalized_audit: list[dict[str, Any]] = []
    seen: set[Path] = set()
    full_bytes = 0
    targeted_lines = 0
    current_hash_bytes = 0
    audit_bytes = 0
    for index, item in enumerate(current):
        label = f"current_step_reads[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        mode = item.get("read_mode")
        keys = {"path", "purpose", "read_mode"}
        if mode == "lines":
            keys.add("line_ranges")
        if set(item) != keys or mode not in {"full", "lines"}:
            raise ValueError(f"{label} has invalid keys or read_mode")
        path = successor_project_file(root, item.get("path"), label)
        if path in seen:
            raise ValueError(f"{label}.path duplicates another declared file")
        seen.add(path)
        size = path.stat().st_size
        if current_hash_bytes + size > MAX_SUCCESSOR_HASH_BYTES:
            raise ValueError("current-step hash byte budget exceeded")
        if mode == "full" and full_bytes + size > MAX_SUCCESSOR_FULL_READ_BYTES:
            raise ValueError("current full-read byte budget exceeded")
        digest, maximum_line = inspect_regular_file(
            path, size, count_lines=mode == "lines"
        )
        current_hash_bytes += size
        normalized = {
            "path": path.relative_to(root).as_posix(),
            "purpose": bounded_single_line(item.get("purpose"), f"{label}.purpose", 1000),
            "read_mode": mode,
            "size": size,
            "sha256": digest,
        }
        if mode == "full":
            full_bytes += size
        else:
            ranges = item.get("line_ranges")
            if not isinstance(ranges, list) or not ranges:
                raise ValueError(f"{label}.line_ranges must be non-empty")
            normalized_ranges: list[list[int]] = []
            previous_end = 0
            assert maximum_line is not None
            for range_index, line_range in enumerate(ranges):
                range_label = f"{label}.line_ranges[{range_index}]"
                if (
                    not isinstance(line_range, list)
                    or len(line_range) != 2
                    or any(
                        isinstance(number, bool) or not isinstance(number, int)
                        for number in line_range
                    )
                    or line_range[0] < 1
                    or line_range[1] < line_range[0]
                    or line_range[0] <= previous_end
                    or line_range[1] > maximum_line
                ):
                    raise ValueError(
                        f"{range_label} must be sorted, non-overlapping, and inside the file"
                    )
                previous_end = line_range[1]
                selected_lines = line_range[1] - line_range[0] + 1
                if targeted_lines + selected_lines > MAX_SUCCESSOR_TARGETED_LINES:
                    raise ValueError("current targeted-line budget exceeded")
                targeted_lines += selected_lines
                normalized_ranges.append(line_range)
            normalized["line_ranges"] = normalized_ranges
        normalized_current.append(normalized)
    for index, item in enumerate(audit):
        label = f"audit_only_files[{index}]"
        if not isinstance(item, dict) or set(item) != {"path", "purpose"}:
            raise ValueError(f"{label} must contain exactly path and purpose")
        path = successor_project_file(root, item.get("path"), label)
        if path in seen:
            raise ValueError(f"{label}.path duplicates another declared file")
        seen.add(path)
        size = path.stat().st_size
        if audit_bytes + size > MAX_SUCCESSOR_AUDIT_BYTES:
            raise ValueError("audit-only hash byte budget exceeded")
        digest, _ = inspect_regular_file(path, size)
        audit_bytes += size
        normalized_audit.append(
            {
                "path": path.relative_to(root).as_posix(),
                "purpose": bounded_single_line(
                    item.get("purpose"), f"{label}.purpose", 1000
                ),
                "size": size,
                "sha256": digest,
            }
        )
    return (
        normalized_current,
        normalized_audit,
        {
            "full_read_bytes": full_bytes,
            "targeted_lines": targeted_lines,
            "current_hash_bytes": current_hash_bytes,
            "audit_hash_bytes": audit_bytes,
        },
    )


def load_successor_input(
    root: Path, state: dict[str, Any]
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    input_path = root / ".codex" / "context-guard" / SUCCESSOR_INPUT_FILENAME
    if not input_path.exists():
        raise ValueError(
            f"missing successor input {input_path}; prepare it before requesting rollover"
        )
    if input_path.is_symlink():
        raise ValueError(f"invalid successor input {input_path}: must not be a symlink")
    try:
        resolved_input = input_path.resolve(strict=True)
        resolved_input.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(
            f"invalid successor input {input_path}: must stay inside the current project"
        ) from exc
    try:
        raw = read_bounded_regular_file(
            resolved_input, MAX_SUCCESSOR_INPUT_BYTES, "successor input"
        )
    except ValueError as exc:
        raise ValueError(
            f"invalid successor input {input_path}: {exc}"
        ) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"successor input is invalid UTF-8 JSON: {exc}") from exc
    expected = {
        "schema_version",
        "current_status",
        "exact_next_action",
        "authorization",
        "current_step_reads",
        "audit_only_files",
    }
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError(f"successor input must contain exactly {sorted(expected)}")
    if data.get("schema_version") != 1:
        raise ValueError("successor input schema_version must be 1")
    normalized = {
        "schema_version": 1,
        "current_status": bounded_single_line(
            data.get("current_status"), "current_status", 1200
        ),
        "exact_next_action": bounded_single_line(
            data.get("exact_next_action"), "exact_next_action", 1200
        ),
        "authorization": validate_authorization_index(
            data.get("authorization"), state
        ),
    }
    current, audit, budgets = validate_successor_artifacts(root, data)
    normalized["current_step_reads"] = current
    normalized["audit_only_files"] = audit
    normalized["budgets"] = budgets
    return input_path, normalized, {"sha256": hashlib.sha256(raw).hexdigest()}


def successor_output_dir(
    root: Path, state: dict[str, Any], argument: str | None
) -> Path:
    parsed = parse_single_path_argument(argument, "rollover")
    if parsed is None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        candidate = (
            root
            / ".codex"
            / "context-guard"
            / "successor-packs"
            / f"{stamp}-{state['content_hash'][:8]}"
        )
    else:
        raw = Path(parsed).expanduser()
        candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("rollover output must stay inside the current project") from exc
    if resolved.exists():
        raise ValueError("rollover output directory already exists; refusing to overwrite")
    return resolved


def successor_handoff_text(
    state: dict[str, Any], normalized: dict[str, Any]
) -> str:
    lines = [
        "# Context Guard Successor Handoff",
        "",
        f"- Generated: {utc_now()}",
        f"- Source state SHA-256: `{state['content_hash']}`",
        f"- Current status: {normalized['current_status']}",
        f"- Exact next action: {normalized['exact_next_action']}",
        "- Authority rule: this pack grants no new permission; original user requirements remain authoritative.",
        "",
        "## Requirements and acceptance",
        "",
    ]
    for collection in ("requirements", "acceptance_items"):
        for item in state[collection]:
            if item.get("status") == "superseded":
                continue
            lines.append(
                f"- {item['id']} [{item.get('status', 'pending')}]: "
                f"{redact_text(bounded(item.get('text', ''), 700))}"
            )
    lines.extend(["", "## Authorization index", ""])
    for category in ("granted", "consumed", "pending", "forbidden"):
        lines.append(f"### {category.title()}")
        entries = normalized["authorization"][category]
        if not entries:
            lines.append("- None recorded.")
        for entry in entries:
            lines.append(
                f"- {entry['text']} (sources: {', '.join(entry['source_ids'])})"
            )
        lines.append("")
    lines.extend(["## Selective read plan", ""])
    if not normalized["current_step_reads"]:
        lines.append("- No current-step body reads declared.")
    for item in normalized["current_step_reads"]:
        suffix = (
            f" lines={item['line_ranges']}"
            if item["read_mode"] == "lines"
            else ""
        )
        lines.append(
            f"- `{item['path']}` mode={item['read_mode']}{suffix}; "
            f"purpose={item['purpose']}; SHA-256 `{item['sha256']}`"
        )
    lines.extend(["", "## Hash-only historical evidence", ""])
    if not normalized["audit_only_files"]:
        lines.append("- None declared.")
    for item in normalized["audit_only_files"]:
        lines.append(
            f"- `{item['path']}`; purpose={item['purpose']}; "
            f"SHA-256 `{item['sha256']}`"
        )
    lines.extend(
        [
            "",
            "The successor must verify the manifest and declared file hashes before substantive work.",
            "Audit-only file bodies remain unread unless the user explicitly requests a full audit or an integrity mismatch requires it.",
            "",
        ]
    )
    return redact_text("\n".join(lines))


def export_successor_pack(
    session_dir: Path, state: dict[str, Any], argument: str | None = None
) -> Path:
    del session_dir
    require_usable_state(state)
    root = project_root_from_state(state)
    input_path, normalized, input_receipt = load_successor_input(root, state)
    output = successor_output_dir(root, state, argument)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=".context-guard-pack.", dir=output.parent)
    )
    try:
        handoff_text = successor_handoff_text(state, normalized)
        handoff_path = temporary / SUCCESSOR_HANDOFF_FILENAME
        atomic_write_text(handoff_path, handoff_text)
        manifest = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "project_root": ".",
            "source_session_id_sha256": sha256_text(str(state["session"]["id"])),
            "source_state_sha256": state["content_hash"],
            "input": {
                "path": input_path.relative_to(root).as_posix(),
                "sha256": input_receipt["sha256"],
            },
            "authority": {
                "grants_new_authority": False,
                "index_is_declarative_only": True,
                "requirements_remain_authoritative": True,
            },
            "current_status": normalized["current_status"],
            "exact_next_action": normalized["exact_next_action"],
            "requirements": [
                {
                    "id": item["id"],
                    "status": item.get("status", "pending"),
                    "text": redact_text(bounded(item.get("text", ""), 700)),
                    "source_prompt_sha256": item.get("sha256"),
                }
                for item in state["requirements"]
                if item.get("status") != "superseded"
            ],
            "acceptance": [
                {
                    "id": item["id"],
                    "status": item.get("status", "pending"),
                    "text": redact_text(bounded(item.get("text", ""), 700)),
                    "evidence": item.get("evidence", []),
                }
                for item in state["acceptance_items"]
                if item.get("status") != "superseded"
            ],
            "open_items": open_item_ids(state),
            "compaction_count": len(state["compactions"]),
            "authorization": normalized["authorization"],
            "read_policy": {
                "mode": "selective",
                "audit_only_bodies_default": False,
            },
            "current_step_reads": normalized["current_step_reads"],
            "audit_only_files": normalized["audit_only_files"],
            "budgets": normalized["budgets"],
            "handoff": {
                "path": SUCCESSOR_HANDOFF_FILENAME,
                "sha256": sha256_text(handoff_text),
            },
        }
        atomic_write_json(temporary / SUCCESSOR_MANIFEST_FILENAME, manifest)
        os.replace(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output


def export_handoff(
    session_dir: Path, state: dict[str, Any], argument: str | None = None
) -> Path:
    del session_dir
    target = safe_export_path(state, argument)
    lines = [
        "# Context Guard Handoff",
        "",
        f"- Generated: {utc_now()}",
        f"- Session state hash: `{state['content_hash']}`",
        f"- Protected: `{state['mode']['active']}`",
        "",
        "## Task boundaries",
        "",
    ]
    for item in state["requirements"]:
        lines.append(
            f"- {item['id']} [{item['status']}]: {redact_text(bounded(item['text'], 700))}"
        )
        for evidence in item.get("evidence", []):
            lines.append(f"  - Evidence: {redact_text(bounded(evidence, 500))}")
    lines.extend(["", "## Acceptance criteria", ""])
    for item in state["acceptance_items"]:
        lines.append(
            f"- {item['id']} [{item['status']}]: {redact_text(bounded(item['text'], 700))}"
        )
        for evidence in item.get("evidence", []):
            lines.append(f"  - Evidence: {redact_text(bounded(evidence, 500))}")
    lines.extend(["", "## Supersessions", ""])
    if state["supersedes"]:
        for item in state["supersedes"]:
            lines.append(f"- {item['new_id']} supersedes {item['old_id']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Open items", ""])
    open_ids = open_item_ids(state)
    lines.append("- " + (", ".join(open_ids) if open_ids else "None"))
    lines.extend(["", "## Recent bounded evidence", ""])
    if state["evidence"]:
        for item in state["evidence"][-12:]:
            lines.append(
                f"- {item['id']} [{item['outcome']}]: {redact_text(bounded(item['summary'], 700))}"
            )
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "> Raw prompts, transcripts, credentials, URL query values, and plugin-private paths are intentionally omitted.",
            "",
        ]
    )
    atomic_write_text(target, redact_text("\n".join(lines)))
    return target


def cleanup_old_sessions(root: Path, current: Path | None = None) -> int:
    sessions = root / "sessions"
    if not sessions.is_dir():
        return 0
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=RETENTION_DAYS)
    removed = 0
    for candidate in sessions.iterdir():
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        if current is not None and candidate.resolve() == current.resolve():
            continue
        state_path = candidate / "state.json"
        try:
            with state_path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
            if not isinstance(state, dict):
                continue
            validate_state_integrity(state)
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            StateIntegrityError,
            TypeError,
            ValueError,
        ):
            continue
        ended = parse_time(state.get("session", {}).get("ended_at"))
        if ended is None or ended >= cutoff:
            continue
        for path in sorted(candidate.rglob("*"), reverse=True):
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        candidate.rmdir()
        removed += 1
    return removed


def handle_session_end(
    session_dir: Path, state: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    del payload
    state["session"]["ended_at"] = utc_now()
    save_state(session_dir, state)
    if state["mode"]["active"]:
        write_recovery(session_dir, state, "SessionEnd")
    cleanup_old_sessions(data_root(), current=session_dir)
    return {}


def dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    repaired_payload, unicode_repairs = repair_unicode_scalars(payload)
    if not isinstance(repaired_payload, dict):
        raise TypeError("hook payload must be an object")
    payload = repaired_payload
    if unicode_repairs:
        payload["_context_guard_unicode_repairs"] = unicode_repairs
    event = str(payload.get("hook_event_name") or payload.get("event") or "")
    session_dir = session_dir_for(payload)
    with session_lock(session_dir):
        state = load_state(session_dir, payload)
        handlers = {
            "UserPromptSubmit": handle_user_prompt,
            "PreToolUse": handle_pre_tool,
            "PostToolUse": handle_post_tool,
            "PreCompact": handle_pre_compact,
            "SessionStart": handle_session_start,
            "SubagentStart": handle_subagent_start,
            "SubagentStop": handle_subagent_stop,
            "Stop": handle_stop,
            "SessionEnd": handle_session_end,
        }
        handler = handlers.get(event)
        if handler is None:
            return {}
        return handler(session_dir, state, payload)


def safe_dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    event = str(payload.get("hook_event_name") or payload.get("event") or "")
    try:
        return dispatch(payload)
    except Exception as exc:
        message = bounded(f"{type(exc).__name__}: {exc}", 800)
        if event == "PreCompact":
            return {
                "continue": False,
                "systemMessage": f"Context Guard could not save the recovery packet: {message}",
            }
        if event == "Stop":
            return {
                "continue": False,
                "stopReason": (
                    "Context Guard stopped an unverified completion because "
                    "private validation failed."
                ),
            }
        if event == "PreToolUse":
            return _pre_tool_decision(
                "deny",
                "Context Guard failed closed while validating this pre-action authorization.",
            )
        return {"systemMessage": f"Context Guard {event or 'hook'} warning: {message}"}


def command_hook() -> int:
    try:
        raw = sys.stdin.buffer.read()
    except AttributeError:
        raw = sys.stdin.read().encode("utf-8", errors="strict")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        console_write(
            json.dumps(
                {
                    "systemMessage": (
                        "Context Guard received hook payload bytes that are not "
                        "valid UTF-8; the event was not journaled"
                    )
                },
                ensure_ascii=True,
            )
        )
        return 0
    except json.JSONDecodeError as exc:
        console_write(
            json.dumps(
                {"systemMessage": f"Context Guard received invalid hook JSON: {exc.msg}"},
                ensure_ascii=True,
            )
        )
        return 0
    console_write(json.dumps(safe_dispatch(payload), ensure_ascii=True))
    return 0


def find_latest_state(root: Path) -> tuple[Path, dict[str, Any]] | None:
    candidates: list[tuple[float, Path, dict[str, Any]]] = []
    sessions = root / "sessions"
    if not sessions.is_dir():
        return None
    for candidate in sessions.iterdir():
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            state_path = candidate / "state.json"
            if not state_path.is_file():
                continue
            state = load_state(candidate, {"session_id": candidate.name})
            require_usable_state(state)
            mtime = state_path.stat().st_mtime
        except (OSError, RuntimeError, StateIntegrityError, TypeError, ValueError):
            continue
        if isinstance(state, dict):
            candidates.append((mtime, candidate, state))
    if not candidates:
        return None
    _, session_dir, state = max(candidates, key=lambda item: item[0])
    return session_dir, state


def command_status() -> int:
    latest = find_latest_state(data_root())
    if latest is None:
        print("Context Guard has no local session state.")
        return 0
    _, state = latest
    print(status_context(state))
    return 0


def command_diagnose(args: argparse.Namespace) -> int:
    latest = find_latest_state(data_root())
    if latest is None:
        print(
            json.dumps(
                {
                    "protocol_version": STOP_PROTOCOL_VERSION,
                    "classifier_version": CLASSIFIER_VERSION,
                    "decisions": [],
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        return 0
    _, state = latest
    limit = max(1, min(int(args.limit), 20))
    decisions = [
        item
        for item in state.get("decision_log", [])[-limit:]
        if isinstance(item, dict)
    ]
    print(
        json.dumps(
            {
                "protocol_version": STOP_PROTOCOL_VERSION,
                "classifier_version": CLASSIFIER_VERSION,
                "decisions": decisions,
            },
            ensure_ascii=True,
            indent=2,
        )
    )
    return 0


def command_checkpoint_status(args: argparse.Namespace) -> int:
    try:
        snapshot = checkpoint_status(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
            full=args.full,
            item_id=args.item,
            after_revision=args.after_revision,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    console_write(json.dumps(snapshot, ensure_ascii=True, indent=2))
    return 0


def command_clear_pending(args: argparse.Namespace) -> int:
    try:
        cleared = clear_pending_request(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    console_write(json.dumps({"cleared": cleared}, ensure_ascii=True))
    return 0


def command_stage_checkpoint(args: argparse.Namespace) -> int:
    try:
        checkpoint_sha256 = validate_checkpoint_request(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
            args.requirement,
            args.acceptance,
            args.replace,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    print(f"{STAGE_REQUEST_MARKER} {checkpoint_sha256}")
    print("Script completed")
    return 0


def command_stage_disposition(args: argparse.Namespace) -> int:
    try:
        request_sha256 = validate_disposition_request(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
            args.disposition,
            args.replace,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    print(f"{DISPOSITION_REQUEST_MARKER} {request_sha256}")
    print("Script completed")
    return 0


def command_register_proof(args: argparse.Namespace) -> int:
    try:
        proof_sha256 = validate_proof_request(
            args.data_dir.expanduser().resolve(),
            args.session_id,
            args.turn_id,
            args.token,
            args.manifest.expanduser().resolve(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console_write(f"[FAIL] {bounded(exc, 800)}", stream=sys.stderr)
        return 1
    print(f"{PROOF_REQUEST_MARKER} {proof_sha256}")
    print("Script completed")
    return 0


def command_self_test() -> int:
    hooks = Path(__file__).resolve().parent.parent / "hooks" / "hooks.json"
    config = read_json(hooks)
    expected = {
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PreCompact",
        "SessionStart",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "SessionEnd",
    }
    actual = set(config.get("hooks", {})) if isinstance(config, dict) else set()
    if expected != actual:
        print(f"FAIL hook events: expected {sorted(expected)}, got {sorted(actual)}")
        return 1
    if sys.version_info < (3, 10):
        print(f"FAIL Python 3.10+ required, got {sys.version.split()[0]}")
        return 1
    print(
        f"PASS context-guard self-test: Python {sys.version.split()[0]}, "
        f"{len(actual)} hook events"
    )
    return 0


def main() -> int:
    if sys.version_info < (3, 10):
        print(f"Python 3.10+ required, got {sys.version.split()[0]}")
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("hook", help="Read one Codex hook payload from stdin")
    subparsers.add_parser("status", help="Show the latest private session summary")
    diagnose = subparsers.add_parser(
        "diagnose", help="Show bounded, hash-only recent Stop decisions"
    )
    diagnose.add_argument("--limit", type=int, default=5)
    subparsers.add_parser("cleanup", help="Delete ended sessions older than 30 days")
    subparsers.add_parser("self-test", help="Validate the runtime and hook bundle")
    proof = subparsers.add_parser(
        "register-proof", help="Register an immutable Proof protocol manifest"
    )
    proof.add_argument("--data-dir", type=Path, required=True)
    proof.add_argument("--session-id", required=True)
    proof.add_argument("--turn-id", required=True)
    proof.add_argument("--token", required=True)
    proof.add_argument("--manifest", type=Path, required=True)
    for name, help_text in (
        (
            "checkpoint-status",
            "Inspect turn-bound private requirements and successful evidence",
        ),
        (
            "stage-checkpoint",
            "Stage a validated private checkpoint before the final response",
        ),
        (
            "stage-disposition",
            "Stage a typed incomplete-turn disposition before the final response",
        ),
        (
            "clear-pending",
            "Clear deterministic pending operation records; requirements and evidence stay immutable",
        ),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--data-dir", type=Path, required=True)
        command.add_argument("--session-id", required=True)
        command.add_argument("--turn-id", required=True)
        command.add_argument("--token", required=True)
        if name == "stage-checkpoint":
            command.add_argument("--requirement", action="append", default=[])
            command.add_argument("--acceptance", action="append", default=[])
            command.add_argument("--replace", action="store_true")
        elif name == "stage-disposition":
            command.add_argument(
                "--disposition",
                required=True,
                choices=tuple(DISPOSITION_REASONS),
            )
            command.add_argument("--replace", action="store_true")
        elif name == "checkpoint-status":
            mode = command.add_mutually_exclusive_group()
            mode.add_argument("--full", action="store_true")
            mode.add_argument("--item")
            command.add_argument("--after-revision")
    args = parser.parse_args()
    if args.command == "hook":
        return command_hook()
    if args.command == "status":
        return command_status()
    if args.command == "diagnose":
        return command_diagnose(args)
    if args.command == "cleanup":
        print(f"Removed {cleanup_old_sessions(data_root())} expired session(s).")
        return 0
    if args.command == "register-proof":
        return command_register_proof(args)
    if args.command == "checkpoint-status":
        return command_checkpoint_status(args)
    if args.command == "clear-pending":
        return command_clear_pending(args)
    if args.command == "stage-checkpoint":
        return command_stage_checkpoint(args)
    if args.command == "stage-disposition":
        return command_stage_disposition(args)
    return command_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
