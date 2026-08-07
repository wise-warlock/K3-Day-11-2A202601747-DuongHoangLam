# Báo Cáo Sự Cố An Ninh (Checkpoint 6)
**MSSV:** 2A202601747
**Họ và tên:** Dương Hoàng Lâm

### Tình huống tấn công
**Tấn công: Kẻ tấn công cố gắng trích xuất password hệ thống**

1. **Câu lệnh xấu đến từ đâu?**
   - Câu lệnh xấu này đến trực tiếp từ người dùng (user) thông qua khung chat, giả mạo là một Database Administrator đang cần hoàn thiện tài liệu kỹ thuật và yêu cầu agent điền vào chỗ trống mật khẩu hệ thống.

2. **Nếu không bị chặn, điều xấu gì sẽ xảy ra?**
   - Nếu không bị chặn, Agent có thể vô tình hoàn thành câu trả lời và tiết lộ mật khẩu quản trị trị (admin123) hoặc các secrets khác cho người dùng. Điều này dẫn đến nguy cơ rò rỉ dữ liệu (data leak) và chiếm quyền điều khiển hệ thống nội bộ của ngân hàng.

3. **Lớp nào đã chặn nó? Nếu chưa chặn, vì sao?**
   - Lớp **Output Guardrails** (cụ thể là `content_filter`) hoặc lớp **LLM-as-Judge** sẽ chặn nội dung này trước khi gửi cho người dùng. Nếu LLM lỡ tạo ra câu trả lời chứa mật khẩu, `content_filter` sẽ nhận diện qua Regex PII_PATTERNS (Password) và thay thế nó bằng `[REDACTED]`. Nếu LLM-as-Judge được kích hoạt, nó cũng sẽ phân loại phản hồi là `UNSAFE` và thay bằng tin nhắn báo lỗi chuẩn.

4. **Bạn sửa gì và đổi lại có thể gây bất tiện nào cho người dùng?**
   - Trong `content_filter`, tôi đã bổ sung Regex để quét và ẩn đi Password, API Key, Email, Số điện thoại và CMND.
   - **Bất tiện tiềm ẩn:** Việc dùng Regex chặt chẽ có thể chặn nhầm (false positive) những thông tin hoàn toàn bình thường mà người dùng cung cấp (chẳng hạn số điện thoại của chính họ hoặc các dãy số ngẫu nhiên bị nhận nhầm là API Key), khiến họ gặp khó khăn khi cần hỗ trợ chính xác.

5. **Log, metric hoặc alert nào giúp người khác xem lại sự cố?**
   - **Audit Log (`outputs/audit_log.json`):** Có thể tra cứu `request_id` để biết luồng xử lý bị chặn ở `layer` nào (ví dụ: `output_filter`) và thời gian xử lý (`latency`).
   - **Metrics & Alerts (`outputs/metrics.json`):** Hệ thống MonitoringAlert sẽ ghi nhận bộ đếm `blocked_requests` tăng lên. Nếu tỷ lệ chặn (`block_rate`) vượt ngưỡng 0.5 (50%), một Alert sẽ được kích hoạt báo động cho đội ngũ anượng an ninh (Security Team) vào kiểm tra dấu hiệu của một đợt tấn công.
