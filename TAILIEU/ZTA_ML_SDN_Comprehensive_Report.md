# Báo cáo Nghiên cứu & Hiện thực Kiến trúc An ninh mạng Lai ZTA-SDN dựa trên Học máy (AI)

> [!NOTE]
> Báo cáo này tổng hợp cơ sở lý thuyết từ các bài báo khoa học trong thư mục tài liệu và đối chiếu trực tiếp với mã nguồn thực tế của hệ thống giám sát, phát hiện và giảm thiểu DDoS/DoS/Port Scan sử dụng Ryu Controller và Mininet.

---

## Giới thiệu chung (Introduction)
Trong kỷ nguyên số hóa hiện đại, mô hình bảo mật truyền thống dựa trên phòng ngự biên giới (perimeter defense) đã lộ rõ nhiều lỗ hổng nghiêm trọng. Một khi kẻ tấn công vượt qua được bức tường lửa bên ngoài, chúng có thể tự do di chuyển ngang (lateral movement) để phá hoại hệ thống bên trong. 

Để giải quyết triệt để thách thức này, **Kiến trúc An ninh mạng Không tin cậy (Zero Trust Architecture - ZTA)** ra đời với nguyên lý cốt lõi: *"Never Trust, Always Verify"* (Không bao giờ tin tưởng, luôn luôn xác thực). Khi tích hợp ZTA vào công nghệ **Mạng xác định bằng phần mềm (Software-Defined Networking - SDN)**, chúng ta có được khả năng giám sát tập trung và lập trình luồng dữ liệu cực kỳ mềm dẻo. Bằng cách bổ sung thêm **Trí tuệ nhân tạo / Học máy (AI/ML)** làm bộ não phân tích hành vi, hệ thống có thể chủ động phát hiện và ngăn chặn các cuộc tấn công mạng thời gian thực một cách linh hoạt, khắc phục hoàn toàn nhược điểm của các luật chính sách tĩnh truyền thống.

---

## Nguồn tài liệu khảo sát & Đối chiếu (Academic Sources)
Báo cáo này kế thừa trực tiếp các thành tựu lý thuyết từ 3 nghiên cứu khoa học lớn:
1. **Paper 1 (Mukul Mangla, 2024)**: *Integrating Machine Learning with Zero Trust Principles for Real-Time Threat Detection and Response*.
   * **Đóng góp**: Phương pháp tích hợp chỉ số bất thường từ ML vào chính sách Zero Trust để đưa ra hành động phản phó động (Adaptive Response) thay vì các bộ quy tắc tĩnh.
2. **Paper 2 (Manar H. Bashaa et al., 2025)**: *Integration of Zero Trust Architecture and Machine Learning for Improving the Security of Software Defined Networking: A Review*.
   * **Đóng góp**: Cách thức ánh xạ các thành phần logic ZTA của tiêu chuẩn **NIST SP 800-207** lên hạ tầng mạng SDN sử dụng OpenFlow; phân tích các thách thức về hiệu năng điều khiển.
3. **Paper 3 (Ebuka Mmaduekwe Paul et al., 2024)**: *Zero trust architecture and AI: A synergistic approach to next-generation cybersecurity frameworks*.
   * **Đóng góp**: Làm rõ tính cộng hưởng (synergy) giữa ZTA và AI giúp tối ưu hóa thời gian phản hồi (Response Latency), tự động hóa các phản ứng giảm thiểu và duy trì xác minh liên tục (Continuous Verification).

---

## 1. Ánh xạ Kiến trúc Logic ZTA lên Hạ tầng SDN
Đối chiếu với tiêu chuẩn **NIST SP 800-207**, hệ thống modular của bạn đã hiện thực hóa hoàn hảo mô hình kiến trúc Zero Trust:

| Thành phần NIST SP 800-207 | Module Triển khai Thực tế trong Code | Vai trò chức năng trong Hệ thống |
| :--- | :--- | :--- |
| **Policy Engine (PE)** (Bộ quyết định chính sách) | `ml_engine.py` & `policy_engine.py` | PE đóng vai trò là bộ não đưa ra quyết định. `ml_engine.py` nạp mô hình Random Forest phân loại 4 lớp luồng (BENIGN, DDoS, DoS, Port Scan) thời gian thực. `policy_engine.py` kết hợp nhãn dự đoán này với thông tin định danh để chấm điểm tin cậy động (Dynamic Trust Score) cho từng host. |
| **Policy Administrator (PA)** (Bộ quản trị chính sách) | `policy_engine.py` (Hành động quyết định) | PA chịu trách nhiệm gửi các chỉ thị bảo mật. Dựa vào điểm tin cậy động của host, PA sẽ quyết định áp dụng hình thức xử lý tương ứng: Cách ly cứng (`HARD_ISOLATION`), Bóp băng thông (`RATE_LIMITING`), hay Cho phép truy cập (`ALLOW`). |
| **Policy Enforcement Point (PEP)** (Bộ thực thi chính sách) | `mitigation_strategies.py` & OpenFlow Switches (OVS) | PEP là nơi thực thi trực tiếp các chỉ thị dưới tầng dữ liệu. `mitigation_strategies.py` tương tác qua Ryu Controller gửi các bản tin FlowMod xuống các Switch ảo OpenFlow trong Mininet để thiết lập luật DROP hoặc chuyển hướng qua Meter Table. |

### Sơ đồ Luồng xử lý và Ra quyết định (ZTA-SDN Control Flow)

```mermaid
graph TD
    subgraph Data Plane (PEP)
        OVS1["OpenFlow Switch (s1, s2, s3, s4)"]
        Host["Thiết bị gửi traffic (User/Attacker)"] <--> OVS1
    end
    
    subgraph Control Plane (PDP)
        subgraph Policy Engine (PE)
            ML["ML Engine (Random Forest Model)"]
            Ctx["Identity Context Analyzer"]
        end
        
        subgraph Policy Administrator (PA)
            PE_Logic["Dynamic Policy Engine"]
        end
        
        Ryu["Ryu Security Controller"] <--> PEP_Exec["Mitigation Executor"]
    end
    
    subgraph Identity Provider
        AAA["Mock AAA Server (aaa_users.json)"]
    end
    
    OVS1 -- 1. Gửi Flow Stats / Packet-In --> Ryu
    Ryu -- 2. Trích xuất đặc trưng mạng --> PE_Logic
    PE_Logic -- 3. Đánh giá hành vi mạng --> ML
    PE_Logic -- 4. Truy vấn định danh ngữ cảnh --> Ctx
    Ctx -- 5. Xác thực & Đọc tư thế thiết bị --> AAA
    ML -- 6. Nhãn dự đoán & Độ tin cậy --> PE_Logic
    PE_Logic -- 7. Tính Trust Score & Ánh xạ Hành động --> PEP_Exec
    PEP_Exec -- 8. Gửi FlowMod / Meter Config --> OVS1
```

---

## 2. Hiện thực hóa các Nguyên lý Zero Trust cốt lõi trong Mã nguồn
Hệ thống ZTA-SDN của bạn không chỉ là lý thuyết suông mà được lập trình vô cùng chặt chẽ thông qua các cơ chế sau:

### A. Xác minh liên tục (Continuous Verification - "Never Trust, Always Verify")
* Thay vì chỉ xác thực một lần lúc kết nối, Ryu Controller duy trì một luồng giám sát tuần hoàn (`_monitor()`) gửi yêu cầu thống kê luồng dữ liệu (`OFPFlowStatsRequest`) xuống tất cả switch định kỳ.
* Mọi luồng dữ liệu hoạt động đều được trích xuất các đặc trưng mạng (flow count, packet rate, unique destination ports,...) và đưa qua mô hình Machine Learning để thẩm định lại hành vi mỗi 10 giây.

### B. Điểm tin cậy động (Dynamic Trust Score) và Hồi phục (Trust Recovery)
* Mỗi host khi mới kết nối vào mạng sẽ được gán điểm tin cậy khởi tạo $T(t) = 1.0$. Khi phát hiện dấu hiệu tấn công, điểm số sẽ bị trừ (Decay) dựa trên độ nguy hiểm của loại hình tấn công:
  * **DDoS / DoS (High Severity)**: Trừ điểm nặng: $Penalty = 0.3 \times Combined\_Risk$.
  * **Port Scan (Medium Severity)**: Trừ điểm vừa: $Penalty = 0.15 \times Combined\_Risk$.
  * **Benign (Low Severity / Lưu lượng sạch)**: Trừ điểm âm (tương đương cộng nhẹ $0.05$ vào điểm tin cậy).
* **Cơ chế khôi phục (Trust Recovery)**: Nhằm giảm thiểu tỷ lệ nhận diện sai (False Positive), hệ thống áp dụng cơ chế tự động hồi phục điểm tin cậy (`apply_recovery()`). Nếu thiết bị hoạt động hoàn toàn sạch sẽ, điểm tin cậy sẽ tăng dần trở lại $+0.02$ sau mỗi 10 giây (được chạy âm thầm dưới nền để tránh gây loãng log giám sát). Khi điểm số vượt qua ngưỡng an toàn, các hạn chế trên switch sẽ tự động được thu hồi.

### C. Nhận thức Ngữ cảnh Định danh (Identity & Context-Awareness)
* Hệ thống khắc phục điểm yếu dễ bị giả mạo IP của mạng truyền thống bằng cách tích hợp module `identity_provider.py` kết nối với cơ sở dữ liệu AAA (`aaa_users.json`).
* Hệ thống tính toán **Rủi ro Ngữ cảnh (Context Risk)** dựa trên:
  * Vai trò của người dùng (nhân viên, quản trị viên, hay khách lạ).
  * Tư thế an toàn của thiết bị (Hệ điều hành có hợp lệ không, chứng chỉ bảo mật có tuân thủ không).
* Điểm rủi ro kết hợp cuối cùng được tính bằng công thức lai:
  $$Combined\_Risk = 0.6 \times ML\_Probability + 0.4 \times Context\_Risk$$

---

## 3. Ma trận Phản phó và Thực thi Chính sách Bảo mật (Mitigation Matrix)
Tương ứng với các mức điểm tin cậy động $T(t)$, hệ thống sẽ tự động thực thi các hành động bảo mật mềm dẻo dưới tầng dữ liệu:

| Trạng thái Hành vi | Ngưỡng điểm tin cậy $T(t)$ | Hành động Bảo mật (PA) | Phương thức Thực thi OpenFlow dưới Switch (PEP) |
| :--- | :--- | :--- | :--- |
| **AN TOÀN (ALLOW)** | $0.85 \le T(t) \le 1.0$ | Cho phép truy cập bình thường | Gỡ bỏ mọi FlowMod hạn chế cũ (nếu có) bằng lệnh `OFPFC_DELETE` áp dụng cho cả chiều đi và chiều về của IP đó. |
| **NGHI NGỜ (RATE LIMITING)** | $0.40 \le T(t) < 0.85$ | Giới hạn băng thông | Áp dụng Meter Table trên switch OVS (Meter ID 1 giới hạn tốc độ ở mức **50 pps** - packets per second). Đồng thời xóa flow rule cũ của host để ép dữ liệu đi qua Meter. |
| **TẤN CÔNG (HARD ISOLATION)** | $0.0 \le T(t) < 0.40$ | Cô lập cứng hoàn toàn | Gửi FlowMod có mức độ ưu tiên cao (`priority=100`) với hành động rỗng (`actions=[]` - DROP) cho cả 2 chiều: từ nguồn tấn công (`ipv4_src=attacker_ip`) và đến đích tấn công (`ipv4_dst=attacker_ip`). |

---

## 4. Các giải pháp Tối ưu hóa Thực tế (Độc quyền trong Mã nguồn)
Mã nguồn của bạn giải quyết xuất sắc các thách thức thực tế lớn trong hạ tầng SDN mà các bài báo khoa học lý thuyết chỉ mới dừng lại ở mức cảnh báo:

1. **Chống cạn kiệt bảng lưu lượng Switch (TCAM Exhaustion Protection)**:
   * *Thách thức (Paper 2)*: Các cuộc tấn công DDoS giả mạo IP nguồn ngẫu nhiên (`hping3 --rand-source`) gửi hàng triệu gói tin chứa IP nguồn ảo. Nếu cài luật chặn cho từng IP này, bảng lưu lượng TCAM của Switch sẽ bị tràn và làm treo thiết bị phần cứng.
   * *Giải pháp*: Trong `ZTA_controller.py`, hệ thống chỉ cài flow rule riêng lẻ cho các IP thuộc mạng nội bộ (`10.0.0.0/24`). Đối với các IP lạ ngoài mạng, controller chỉ ghi nhận cảnh báo tổng hợp, giúp bảo vệ switch an toàn tuyệt đối.
2. **Chống tấn công từ chối dịch vụ tự phát sinh (Self-DoS Prevention via Whitelisting)**:
   * *Thách thức (Paper 2)*: Kẻ tấn công có thể giả mạo IP nguồn của các Web Server hoặc DNS Server trong mạng để lừa hệ thống tự cô lập các máy chủ quan trọng này.
   * *Giải pháp*: Tích hợp `server_whitelist` cho các dải IP máy chủ (`10.0.0.1` đến `10.0.0.6`). Nếu các máy chủ này phát sinh lưu lượng bất thường, hệ thống chỉ ghi nhận log cảnh báo bảo mật chứ tuyệt đối không cô lập để đảm bảo dịch vụ luôn sẵn sàng hoạt động.
3. **Theo dõi trạng thái phạt thông minh (Stateful Restriction Tracking)**:
   * *Thách thức*: Gửi FlowMod xóa luật chặn định kỳ cho các host an toàn gây tốn tài nguyên xử lý của switch và làm tràn ngập log khôi phục truy cập (`[ZTA POLICY - RESTORE]`).
   * *Giải pháp*: Sử dụng bộ lưu trạng thái `restricted_ips` để ghi nhớ chính xác những host nào đang bị hạn chế. Lệnh gỡ phạt và log khôi phục chỉ được kích hoạt đúng 1 lần duy nhất khi IP đó chuyển từ trạng thái bị phạt sang trạng thái an toàn.

---

## 5. Đánh giá Ưu điểm & Hạn chế và Đề xuất Hướng đi Tiếp theo

### 🎯 Ưu điểm nổi bật
* **Độ chính xác cao**: Mô hình Random Forest đa lớp được tối ưu hóa đạt độ chính xác phân loại ấn tượng trong việc tách biệt các hành vi BENIGN, DDoS, DoS, và Port Scan.
* **Kiến trúc phân lớp chuẩn ZTA**: Việc tách biệt rõ ràng giữa các thành phần PE, PA, và PEP giúp hệ thống dễ dàng mở rộng và bảo trì.
* **Kiểm thử tự động vững chắc**: Sở hữu bộ unit test gồm 17 kịch bản kiểm thử tự động, đảm bảo mọi sự thay đổi trong code đều được kiểm tra tính đúng đắn ngay lập tức.

### ⚠️ Hạn chế cần cải thiện & Hướng phát triển tương lai
* **Tích hợp học tăng cường (Incremental / Online Learning)**: Mô hình Random Forest hiện tại là tĩnh (offline-trained). Trong tương lai, hệ thống cần hỗ trợ học tăng cường từ các luồng traffic mới để tự cập nhật bộ trọng số mà không cần dừng controller.
* **Phân tích chuỗi thời gian (Temporal Features)**: Hiện tại các đặc trưng mới chỉ được tính toán tĩnh trên mỗi chu kỳ giám sát. Việc bổ sung các mô hình chuỗi thời gian (như LSTM hay GRU) sẽ giúp nhận diện các cuộc tấn công DDoS tốc độ chậm (Slowloris/DoS) chính xác hơn.
* **Trí tuệ nhân tạo có thể giải thích (Explainable AI - XAI)**: Tích hợp thư viện giải thích (SHAP/LIME) để hiển thị rõ thuộc tính mạng nào (ví dụ: packet rate tăng vọt hay số lượng cổng đích tăng đột biến) đã dẫn đến quyết định giảm điểm tin cậy của thiết bị, gia tăng tính minh bạch cho hệ thống quản trị Zero Trust.
