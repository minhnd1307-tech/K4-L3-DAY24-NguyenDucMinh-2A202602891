# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 (Bảo vệ dữ liệu cá nhân) | PII detection & redaction tự động che giấu CCCD/STK/SĐT/email; Policy PEP chặn egress dữ liệu restricted | `agent/pii.py:52-107`, `agent/policy.py:70-73`, `reports/attack-after.log` (rỗng, 0 bytes), `reports/ledger.jsonl:23,26` | Sử dụng regex-based recognition, tập trung vào PII Việt Nam phổ biến; điều khoản thi hành chi tiết: chưa xác minh |
| NĐ 356/2025/NĐ-CP (Biện pháp bảo vệ DLCN) | On-Behalf-Of (OBO) phân quyền tối thiểu (support_l1 bị deny, dpo allow); Audit Ledger hash chain tamper-evident | `agent/policy.py:86-118`, `agent/runner.py:101-118`, `agent/ledger.py:52-110`, `reports/ledger.jsonl:1-26` | Hash chain lưu trên file cục bộ, chưa có external timestamping authority; điều khoản cụ thể: chưa xác minh |
| Luật AI 134/2025/QH15 (An toàn hệ thống AI) | Trifecta Split cô lập Run A (untrusted content) khỏi Run B (private data); kiểm soát egress chặn rò rỉ dữ liệu tự động | `agent/runner.py:68-155`, `tests/test_split.py:75-117` | Kiểm thử trên mô hình mô phỏng (MockLLM); chưa kiểm thử trên mô hình production; điều khoản cụ thể: chưa xác minh |
| OWASP ASI01, ASI03, ASI04 | ASI01 (Indirect Prompt Injection): Trifecta Split cô lập Run A (untrusted content) khỏi Run B; ASI03 (Identity & Privilege Abuse): OBO delegation, phân quyền tối thiểu chặn support_l1 truy cập private store & PEP chặn egress; ASI04 (Agentic Supply Chain Vulnerabilities): Khóa hash dependency trong requirements.lock & quét secret qua Gitleaks hook | `agent/runner.py:68-155`, `agent/policy.py:70-118`, `requirements.lock:7-40`, `.pre-commit-config.yaml:1-6` | Phù hợp với kiến trúc agent trong lab; triển khai thực tế cần thêm API gateway, WAF và KMS quản lý secret |




Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
