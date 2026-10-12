# Verification — điền trước khi nộp

- OS / Python / Gitleaks version: Windows 11 Pro 10.0.26200 / Python 3.11.0 / Gitleaks v8.30.1
- `python -m pytest tests/ -q`: 33 passed in 2.01s (100% tests pass)
- `pre-commit run --all-files`: Passed (Detect hardcoded secrets: Passed)
- Ledger verify: True (xác minh chuỗi hash chain thành công trên `reports/ledger.jsonl`)
- Các lỗi còn lại:
  - Đã xử lý triệt để việc đọc `customers.json` trước khi kiểm quyền trong `agent/runner.py`: kiểm tra PEP ngay trước khi chạm vào private store, ngăn chặn hoàn toàn 26 hồ sơ PII nạp vào RAM dưới `support_l1`.
  - Đã sửa lỗi scope rỗng trong `agent/policy.py`: `agent_scopes=()` bị deny thay vì vô tình bỏ qua phép giao quyền.
  - Đã chuẩn hóa lại phân loại OWASP ASI03 (Identity & Privilege Abuse) và ASI04 (Agentic Supply Chain) trong `reports/compliance-mapping.md`.
  - Lưu ý môi trường: Bài lab được thực hiện trên môi trường Windows 11 native (chưa kiểm thử trên WSL2/Linux); quá trình cài đặt mới từ lockfile có thể gặp vấn đề tìm gói `certifi==2026.7.22` nếu môi trường không khớp cache hoặc index nội bộ của đề bài.

