# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`)
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` (dòng 1)
  - Rule ID: `lab24-synthetic-token`
  - Kết quả quét lịch sử: Lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .` phát hiện 1 secret giả (`leaks found: 1`) tại commit `1bdd849`.
- Kết quả quét file hiện tại:
  - Lệnh `gitleaks dir --config .gitleaks.toml .` báo `no leaks found` (các file hiện tại ở HEAD sạch hoàn toàn).
- Nếu đây là credential thật, cần xử lý thế nào:
  - Cần lập tức thu hồi (revoke) và thay thế/đổi khóa (rotate) credential trên hệ thống dịch vụ tương ứng để vô hiệu hóa token cũ ngay lập tức.
  - Rà soát audit log trên hệ thống đích để kiểm tra xem token bị lộ đã bị kẻ xấu lạm dụng hay chưa.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Việc xoá file khỏi HEAD chỉ làm ẩn file ở commit mới nhất, nhưng secret vẫn tồn tại vĩnh viễn trong lịch sử Git (`.git/objects`) ở commit `1bdd849`. Bất kỳ ai clone repo đều có thể checkout commit cũ và trích xuất secret.
  - Pin dependency (dùng `requirements.lock` kèm mã băm SHA-256) chỉ bảo vệ chuỗi cung ứng trước các gói thư viện bị chỉnh sửa mã nguồn độc hại, không thể thay thế bước thu hồi và rotate secret đã bị lộ ra bên ngoài.

