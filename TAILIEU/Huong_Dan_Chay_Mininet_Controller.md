

## 1. Khởi Chạy Ryu Controller (Control Plane)
source ~/ryu-env/bin/activate
cd "/home/vuxtrung/KLTN_ver2/Source Code/Controller"
ryu-manager ZTA_controller.py 


## 2. Khởi Chạy Mạng Mô Phỏng Mininet (Data Plane)

cd /home/vuxtrung/KLTN_ver2/Source Code/Mininet
sudo python3 topology_zta.py


## 3. Các Kịch Bản Kiểm Thử 
### Bước chuẩn bị: Khởi chạy dịch vụ Web Server trên các Host đích

mininet> h1 python3 -m http.server 80 &
mininet> h2 python3 -m http.server 80 &


### Kịch bản 1: Truy cập hợp lệ (Benign Traffic)
mininet> h7 while true; do curl -s http://10.0.0.1/ >/dev/null; sleep 0.5; done &

mininet> h7 ab -n 100 -c 10 http://10.0.0.1/

mininet> h7 wget -qO- http://10.0.0.1/

mininet> h7 pkill -9 -P $$


mininet> h7 ping 10.0.0.1


### Kịch bản 2: Tấn công DDoS Flood (TCP SYN / UDP / ICMP)

* **Thực hiện**:
  * Tấn công TCP SYN Flood 
    mininet> h8 hping3 -S -p 80 --flood 10.0.0.1
  * Tấn công UDP Flood:
    mininet> h8 hping3 --udp -p 53 --flood 10.0.0.3
  * Tấn công ICMP Flood:
    mininet> h8 hping3 -1 --flood 10.0.0.1


### Kịch bản 3: Port Scanning
nmap SYN scan
mininet> h8 nmap -sS -p 1-1000 10.0.0.1
nmap UDP
mininet> h8 nmap -sU -p 1-100 10.0.0.1
nmap Connect scan
mininet> h8 nmap -sT -p 1-1000 10.0.0.1





### Kịch bản 4: DoS
Tấn công Slowloris
mininet> h8 slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://10.0.0.1/
Tấn công Slow POST 
mininet> h8 slowhttptest -c 1000 -B -i 10 -r 200 -s 8192 -t POST -u http://10.0.0.1/


HULK DOS
mininet> h8 python3 "/home/vuxtrung/KLTN_ver2/Source Code/Mininet/hulk.py" http://10.0.0.1/


GOLDEN EYE DOS
mininet> h8 python3 "/home/vuxtrung/KLTN_ver2/Source Code/Mininet/goldeneye.py" http://10.0.0.1/ -w 20 -s 100


## 4. Thu Thập Số Liệu & Đánh Giá Hiệu Năng (Chương Thực Nghiệm KLTN)

Sau khi tích hợp hoàn chỉnh hệ thống ZTA Modular, Ryu Controller sẽ tự động ghi lại toàn bộ nhật ký phân loại và hành động an ninh theo chu kỳ vào file:
`/home/vuxtrung/KLTN_ver2/Source Code/Controller/zta_evaluation_metrics.csv`

### Các bước lấy số liệu và vẽ đồ thị tự động:
1. Đảm bảo bạn đã cài đặt các thư viện hỗ trợ xử lý số liệu:
   ```bash
   pip install pandas matplotlib
   ```

2. Sau khi chạy mô phỏng xong các kịch bản tấn công ở trên, tắt Mininet và Ryu Controller.

3. Chạy script phân tích để nhận báo cáo số liệu và tự động xuất đồ thị biến thiên điểm tin cậy:
   ```bash
   cd "/home/vuxtrung/KLTN_ver2/Source Code/Controller"
   python3 evaluate_zta_metrics.py
   ```

### Kết quả đầu ra:
* **Báo cáo trên Terminal:** Hiển thị tỉ lệ phần trăm các loại luồng quét qua AI, thống kê hành động kiểm soát ZTA của Switch, độ trễ thời gian phát hiện và cô lập cuộc tấn công (Detection Latency).
* **Đồ thị trực quan:** File hình ảnh `zta_trust_scores_progression.png` được tự động tạo ra, biểu diễn chi tiết luồng thay đổi điểm tin cậy (Trust Score) của từng Host. Bạn chỉ cần copy file ảnh này dán trực tiếp vào slide thuyết trình hoặc quyển báo cáo khóa luận!
