"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# 1. Regex cho Email: tìm các địa chỉ email chuẩn
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# 2. Regex cho Số tài khoản ngân hàng (STK):
# 8-16 chữ số đi liền sau các từ khóa chỉ dẫn như "STK", "số tài khoản", "tài khoản"
_BANK_RE = re.compile(
    r"(?i)(?:STK|số\s+tài\s+khoản|tài\s+khoản)\s*[:.]?\s*(\d{8,16})\b"
)

# 3. Regex cho Số CCCD: chính xác 12 chữ số liên tiếp
_CCCD_RE = re.compile(r"\b\d{12}\b")

# 4. Regex cho Số điện thoại Việt Nam:
# 10 chữ số liên tiếp bắt đầu bằng 0
_PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII (CCCD, SĐT, STK, Email) và trả về offset."""
    entities: list[dict] = []
    occupied_spans: list[tuple[int, int]] = []

    def is_overlapping(start: int, end: int) -> bool:
        """Kiểm tra xem vùng (start, end) có bị đè lên thực thể đã phát hiện trước đó không."""
        return any(start < o_end and o_start < end for o_start, o_end in occupied_spans)

    # Ưu tiên 1: Quét Email (tránh nhầm lẫn ký tự số trong email)
    for m in _EMAIL_RE.finditer(text):
        start, end = m.span()
        if not is_overlapping(start, end):
            entities.append({"type": "EMAIL", "start": start, "end": end})
            occupied_spans.append((start, end))

    # Ưu tiên 2: Quét Số tài khoản ngân hàng (có ngữ cảnh STK)
    # Cần ưu tiên trước CCCD vì STK 12 chữ số nếu không bắt ở đây sẽ bị nhận nhầm thành CCCD
    for m in _BANK_RE.finditer(text):
        start, end = m.span(1)
        if not is_overlapping(start, end):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied_spans.append((start, end))

    # Ưu tiên 3: Quét CCCD (12 chữ số độc lập không phải STK)
    for m in _CCCD_RE.finditer(text):
        start, end = m.span()
        if not is_overlapping(start, end):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied_spans.append((start, end))

    # Ưu tiên 4: Quét Số điện thoại (10 chữ số bắt đầu bằng 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.span()
        if not is_overlapping(start, end):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied_spans.append((start, end))

    # Sắp xếp các thực thể theo thứ tự xuất hiện từ đầu đến cuối văn bản
    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    if not entities:
        return text

    # Sắp xếp từ cuối về đầu (start giảm dần) để việc cắt chuỗi không làm lệch offset của các entity phía trước
    entities_sorted = sorted(entities, key=lambda e: e["start"], reverse=True)
    res = text
    for e in entities_sorted:
        tag = f"[REDACTED_{e['type']}]"
        res = res[: e["start"]] + tag + res[e["end"] :]
    return res

