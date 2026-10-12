"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PRINCIPALS_PATH = DATA_DIR / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    """Đọc cấu hình phân quyền mô phỏng từ data/principals.json."""
    if not PRINCIPALS_PATH.exists():
        return {}
    return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    """Policy Enforcement Point (PEP): Kiểm tra chính sách và phân quyền OBO."""

    # 1. Rule TỐI THIỂU: Dữ liệu restricted đi kèm egress -> DENY tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "deny: egress_enabled is True for restricted data classification"

    # 2. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                return False, f"deny: delegation token expired at {context.expires_at}"
        except Exception:
            return False, f"deny: invalid expires_at format '{context.expires_at}'"

    # 3. Kiểm tra danh tính Principal (On-Behalf-Of)
    if not context.principal_id:
        return False, "deny: principal_id is required"

    principals = _load_principals()
    if context.principal_id not in principals:
        return False, f"deny: unknown principal '{context.principal_id}'"

    principal_data = principals[context.principal_id]

    # Kiểm tra mục đích sử dụng (purpose)
    allowed_purposes = principal_data.get("purposes", [])
    if context.request_purpose and allowed_purposes and context.request_purpose not in allowed_purposes:
        return False, f"deny: purpose '{context.request_purpose}' not permitted for principal '{context.principal_id}'"

    # 4. Tính quyền hiệu lực (giao các tập scopes)
    if not context.agent_scopes:
        return False, "deny: agent_scopes is required and cannot be empty"

    effective_tools = set(principal_data.get("allowed_tools", [])).intersection(context.agent_scopes)

    # Nếu ủy quyền qua nhiều tầng (delegation_depth > 0), không được mở rộng quyền ngoài parent_scopes
    if context.delegation_depth > 0:
        effective_tools = effective_tools.intersection(context.parent_scopes)

    # 5. Kiểm tra quyền của tool được gọi
    if context.requested_tool:
        if context.requested_tool not in effective_tools:
            return False, (
                f"deny: tool '{context.requested_tool}' not in effective tools "
                f"{sorted(effective_tools)} for principal '{context.principal_id}'"
            )
    else:
        return False, "deny: requested_tool is required"

    return True, (
        f"allow: tool '{context.requested_tool}' permitted for principal "
        f"'{context.principal_id}' with purpose '{context.request_purpose}'"
    )

