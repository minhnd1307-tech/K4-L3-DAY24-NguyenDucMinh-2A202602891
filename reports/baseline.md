# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa. Trong `agent/loop.py` tại hàm `_naive_loop(message, llm)` (dòng 27), hàm không nhận `principal_id`, không tạo `agent_id` hay `run_id`, và không gắn bất kỳ thông tin danh tính/ngữ cảnh ủy quyền nào vào các lượt gọi tool.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có cơ chế kiểm duyệt nào cho phép; `_naive_loop()` trong `agent/loop.py` (dòng 44) tự động gọi thẳng `tools.http_post` ngay khi phát hiện chỉ thị injection (`injected is not None`), hoàn toàn không thông qua Policy Enforcement Point (PEP) hay kiểm tra quyền hạn. Phía `agent/tools.py` tại hàm `http_post` (dòng 75–85) cũng chỉ kiểm tra host/port allowlist chứ không kiểm tra quyền gửi dữ liệu.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Bằng chứng được lưu tại file `reports/sink.log`, do hàm `do_POST` thuộc `Handler` trong `sink/sink.py` (dòng 44–47) ghi lại toàn bộ request body mà agent gửi tới endpoint 127.0.0.1:10024.

