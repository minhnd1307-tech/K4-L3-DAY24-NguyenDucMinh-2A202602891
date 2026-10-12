# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu nội bộ (`internal`): Nội dung văn bản các ticket hỗ trợ khách hàng trong `corpus/*.md`.
- Dữ liệu cá nhân nhạy cảm (`restricted`): Dữ liệu định danh cá nhân (PII) trong `data/customers.json`, gồm Căn cước công dân (CCCD 12 số), Số tài khoản ngân hàng (STK), Số điện thoại (SĐT 10 số), Địa chỉ email và Họ tên khách hàng.

2. Mục đích xử lý và principal:
- `support_l1`: Nhân viên hỗ trợ bậc 1, mục đích xử lý là `summarize-tickets` và `support-reply`. Chỉ được cấp quyền đọc tài liệu qua `search_docs`, bị từ chối truy cập `read_customer` để đảm bảo nguyên tắc đặc quyền tối thiểu (Least Privilege).
- `dpo`: Cán bộ bảo vệ dữ liệu (Data Protection Officer), mục đích xử lý là `support-reply` và `privacy-audit`. Được phép gọi `read_customer` đối với các hồ sơ có vé hỗ trợ liên kết hợp lệ trong `related_tickets`.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A: Tiếp nhận truy vấn, gọi `tools.search_docs` để lấy nội dung ticket (nội dung không tin cậy). Chỉ trích xuất danh sách `ticket_id: list[int]` từ tên file, áp dụng `pii.redact()` để che giấu PII trong phản hồi người dùng.
- Run B: Tiếp nhận danh sách ticket ID, tra cứu quan hệ trong `data/customers.json` để xác định đúng khách hàng, gọi `tools.read_customer` sau khi được PEP phê duyệt.
- Endpoint mạng (Egress): `http://127.0.0.1:10024/reconcile` (mô phỏng đích của kẻ tấn công). Mọi thao tác gọi `http_post` đều bị Policy PEP chặn đứng (deny) do dữ liệu là `restricted` và kích hoạt cờ egress.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng:
  - File `reports/attack-after.log` rỗng (0 bytes), chứng minh không còn PII nào bị gửi ra ngoài sau khi thiết lập containment.
  - File `reports/ledger.jsonl` có đầy đủ các bản ghi allow/deny với lý do rõ ràng, xác thực danh tính `on_behalf_of`, và dòng deny `http_post`.
- Giới hạn của mock:
  - Dữ liệu trong bài lab hoàn toàn là dữ liệu tổng hợp (synthetic), không chứa PII thực tế của người dùng thật.
  - Mock LLM hoạt động dựa trên các bộ marker từ khóa xác định, không phản ánh toàn bộ tính đa dạng và bất định của mô hình ngôn ngữ lớn thật.
  - Cơ chế danh tính `--as` là mô phỏng fixture, không phải giải pháp xác thực bảo mật chuẩn production (như mTLS, OIDC hay OAuth2 JWT).

