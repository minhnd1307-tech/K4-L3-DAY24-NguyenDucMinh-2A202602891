"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(data: dict) -> str:
    """Tính mã SHA-256 từ nội dung entry (bỏ qua field 'hash' nếu có)."""
    payload = {k: v for k, v in data.items() if k != "hash"}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi một dòng kiểm toán vào file ledger với liên kết hash chain."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Xác định prev_hash từ dòng cuối cùng của file
    prev_hash = "0" * 64
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của chuỗi hash chain trong file ledger."""
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        # Điều kiện 1: reason không được rỗng
        if not record.get("reason"):
            return False

        # Điều kiện 2: prev_hash phải khớp với hash dòng trước
        if record.get("prev_hash") != expected_prev:
            return False

        # Điều kiện 3: hash lưu trữ phải khớp với hash tính toán lại
        stored_hash = record.get("hash")
        computed_hash = _compute_hash(record)
        if stored_hash != computed_hash:
            return False

        expected_prev = stored_hash

    return True

