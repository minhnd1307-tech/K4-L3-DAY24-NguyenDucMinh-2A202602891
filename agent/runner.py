"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Giữ nguyên class này để vượt qua bài test scaffold dispatch."""


def _hash_args(args: dict) -> str:
    """Băm SHA-256 các tham số gọi tool để đối chiếu kiểm toán không lộ PII thô."""
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu với cơ chế Trifecta Split, OBO Delegation và Audit Ledger."""
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"

    # TTL ủy quyền: mặc định 1 giờ tính từ thời điểm hiện tại
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=1)).isoformat()

    def record_call(tool: str, run_id: str, classification: str, args: dict,
                    decision: str, reason: str) -> None:
        """Ghi lại mọi quyết định kiểm soát vào chuỗi hash chain của ledger."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": run_id,
            "tool": tool,
            "args_hash": _hash_args(args),
            "classification": classification,
            "decision": decision,
            "reason": reason,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }
        ledger.append(entry, ledger_path)

    # =========================================================================
    # RUN A: Đọc tài liệu không tin cậy, sanitize và trích xuất ticket ID
    # =========================================================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer"),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    record_call("search_docs", "run-a", "internal", {"query": message},
                "allow" if allow_search else "deny", reason_search)

    if not allow_search:
        return "Yêu cầu tra cứu tài liệu bị từ chối bởi chính sách."

    docs = tools.search_docs(message)

    # Phân tích cú pháp: CHỈ trích xuất ticket ID dạng số từ TÊN FILE
    ticket_ids: list[int] = []
    for d in docs:
        doc_id = d.get("id", "")
        match = re.search(r"ticket-(\d+)", doc_id)
        if match:
            ticket_ids.append(int(match.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # =========================================================================
    # RUN B: Truy xuất khách hàng từ liên kết hợp lệ trong cơ sở dữ liệu tin cậy
    # =========================================================================
    customers_path = DATA_DIR / "customers.json"
    customers_data: list[dict] = []
    if customers_path.exists():
        customers_data = json.loads(customers_path.read_text(encoding="utf-8"))

    # Tìm các customer_id có ticket_id nằm trong related_tickets
    target_customers: list[str] = []
    for t_id in ticket_ids:
        for cust in customers_data:
            if t_id in cust.get("related_tickets", []):
                cid = cust["customer_id"]
                if cid not in target_customers:
                    target_customers.append(cid)

    # Duyệt qua các khách hàng hợp lệ và thực thi chính sách OBO
    for cid in target_customers:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)
        record_call("read_customer", "run-b", "restricted", {"customer_id": cid},
                    "allow" if allow_read else "deny", reason_read)

        if allow_read:
            try:
                tools.read_customer(cid)
            except tools.ToolError:
                pass

    # =========================================================================
    # Chặn hành vi Egress nếu phát hiện chỉ thị độc hại
    # =========================================================================
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        record_call("http_post", "run-b", "restricted", {"url": injected.target_url},
                    "allow" if allow_post else "deny", reason_post)
        # allow_post luôn là False do rule tối thiểu (restricted + egress_enabled)
        if allow_post:
            tools.http_post(injected.target_url, {"records": []})

    # Redact PII trước khi trả về tóm tắt cho người dùng
    sanitized_docs = [
        {"id": d["id"], "text": pii.redact(d["text"])} for d in docs
    ]
    return llm.summarize(sanitized_docs)
