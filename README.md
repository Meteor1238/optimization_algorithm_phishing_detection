# Phishing URL Classification — So sánh các thuật toán chọn đặc trưng (FS)

## 1. Mục tiêu
Phân loại nhị phân trang web lừa đảo (phishing) và uy tín (legitimate), trọng tâm là **so sánh hiệu quả của các thuật toán tối ưu trong việc chọn đặc trưng**.

Tài liệu này **tóm lược các lỗi tiềm ẩn phát hiện được ở bước EDA** trên hai dataset. EDA chỉ *ghi nhận* lỗi, **không loại và không sửa** cột nào: toàn bộ đặc trưng được giữ nguyên để đánh giá các thuật toán FS trên dữ liệu gốc.

| Notebook | Dataset | Mã lỗi |
|---|---|---|
| `01_eda_dataset_B_05_2020.ipynb` | `dataset_B_05_2020.csv` | `L1`–`L22` |
| `01_eda_dataset_small.ipynb` | `dataset_small.csv` | `L1`–`L19` |

*(Mã `L#` của hai dataset độc lập nhau; mỗi mã đều có bằng chứng trong cell tương ứng của notebook.)*

## 2. Tổng quan hai dataset

| | dataset_B_05_2020 | dataset_small |
|---|---|---|
| Số dòng × số đặc trưng | 11.430 × 87 | 58.645 × 111 |
| Nhãn | 5.715 phishing / 5.715 legit (cân bằng) | 30.647 phishing / 27.998 legit |
| Ô NaN | 0 | 0 |
| Kiểu dữ liệu | số, 5 nhóm (URL-cấu trúc, URL-thống kê, HTML-liên kết, HTML-nội dung, tra cứu ngoài) | số (110 int, 1 float), 6 nhóm (`_url`, `_domain`, `_directory`, `_file`, `_params`, tra cứu ngoài) |
| Có dictionary tác giả | Có | Không (nhóm cột suy ra từ hậu tố tên cột) |
| Phân loại cột | 6 hằng số · 31 nhị phân · 19 rời rạc · 31 liên tục | 13 hằng số · 13 nhị phân · 61 rời rạc · 24 liên tục |

Cả hai dataset **không có NaN**, nhưng thiếu dữ liệu được **mã hóa ngầm** bằng giá trị số (xem mục 4).

## 3. Lỗi theo từng dataset

### 3.1 dataset_B_05_2020

| Nhóm lỗi | Mã | Cột liên quan | Bằng chứng chính |
|---|---|---|---|
| Dòng trùng | L1 | toàn bộ | 174 dòng trùng đặc trưng (1 URL trùng), không mâu thuẫn nhãn |
| Hằng số / gần hằng số | L3, L4, L6 | `nb_or`, `ratio_nullHyperlinks`, `ratio_intRedirection`, `ratio_intErrors`, `submit_email`, `sfh`; 13/31 nhị phân; `nb_dollar`, `nb_comma` | 6 cột chỉ có 1 giá trị; 13 cột nhị phân có thiểu số < 1%; 2 cột rời rạc ≥ 99,8% một giá trị |
| Mã hóa / miền giá trị | L5, L8, L9 | `statistical_report`, `domain_age`, `domain_registration_length`, `links_in_tags`, `safe_anchor`, `ratio_intMedia`, `ratio_extMedia`, `ratio_extRedirection` | Cột cờ có 3 giá trị {0,1,2}; `domain_age` âm ở 1.837 dòng (1.781 dòng = −1); thang 0–100 lẫn với 0–1; `ratio_extRedirection` max = 2 (50 dòng > 1) |
| Thiếu ẩn (số 0 giả) | L7, L10, L17 | `page_rank`, `web_traffic`, `nb_hyperlinks` và 9 cột HTML khác | 12 cột có ≥ 10% số 0 (`web_traffic` 38,9%, `page_rank` 23,3%); 14/19 cột HTML luôn = 0 khi `nb_hyperlinks = 0`; 1.381 trang không tải được (12,1%) |
| Sai đơn vị | L12 | `domain_registration_length` | Trung vị 242, max 29.829: đơn vị là ngày, không phải năm như dictionary |
| Phân phối / ngoại lai | L11 | 26/31 cột liên tục | \|skew\| ≥ 1; 6 cột skew ≥ 10; `length_url` max 1.641; `web_traffic` max ~10,8 triệu |
| Ngữ nghĩa đảo / sai | L13, L14, L15, L18 | `https_token`, `google_index`, `domain_in_title`, `whois_registered_domain`, `dns_record`, `ip`, `nb_com` | `https_token` đảo giá trị (corr = −1 với URL, do gán giá trị nhị phân sai); `ip` = 1 ở 1.721 dòng nhưng chỉ 97 URL có host là IPv4; `nb_com` không tái lập được (lệch 62,9%); 4 cột nhị phân đổi chiều ngược logic tên |
| Bất nhất logic | L19 | `ratio_extRedirection`, `char_repeat` | 2/16 bất biến bị vi phạm (50 dòng và 1 dòng) |
| Dư thừa | L16, L21 | `ratio_intHyperlinks`/`ratio_extHyperlinks`; 4 cặp tương quan cao | Hai cột bù nhau tuyệt đối (tổng = 1 ở mọi trang sống); \|ρ\| 0,91–0,98: `nb_dots`–`nb_subdomains`, `longest_word_path`–`avg_word_path`, `nb_qm`–`nb_eq`, `length_url`–`length_words_raw` |
| Liên quan nhãn | L20, L22 | các cột thiếu ẩn | `page_rank = 0`: 44,9% phishing vs 1,8% legit; `web_traffic = 0`: 63,2% vs 14,6%; các bất thường cộng dồn theo dòng (tỷ lệ phishing tăng từ ~16% lên 100%) |

### 3.2 dataset_small

| Nhóm lỗi | Mã | Cột liên quan | Bằng chứng chính |
|---|---|---|---|
| Dòng trùng | L1 | toàn bộ | 1.240 dòng trùng; 1.664 dòng thuộc nhóm trùng (87% legit); 6 nhóm (13 dòng) cùng đặc trưng nhưng khác nhãn |
| Hằng số / gần hằng số | L2, L4, L6 | 13 cột `_domain`; 4 nhị phân; 11 rời rạc | 13 cột `_domain` luôn = 0 (tên miền không thể chứa các ký tự này); thiểu số < 1% hoặc chủ đạo ≥ 99% |
| Sentinel -1 | L5, L8, L11 | 66/111 cột: 18 `_directory`, 18 `_file`, 20 `_params`, 10 cột tra cứu | -1 chiếm 6–87%; không có giá trị âm nào khác; làm méo mean/std (vd `params_length` mean 8,5 trong khi 87% dòng = -1) |
| Mã hóa nhị phân sai | L3 | 7 cột `qty_questionmark_directory`, `qty_hashtag_directory`, `qty_slash_file`, `qty_questionmark_file`, `qty_hashtag_file`, `qty_dollar_file`, `qty_hashtag_params` | Mã hóa {-1, 0}; trùng khít chỉ báo "URL không có phần này" |
| Khối thông tin lặp | L12, L13 | `*_directory` ⊇ `*_file`; khối `directory`/`file`/`params` | `length_url` = domain + directory + params đúng 99,4% (cộng thêm file chỉ đúng 63,0%); -1 xuất hiện đồng loạt trong mỗi khối, 0 dòng lẻ |
| Mã hóa "tra cứu thất bại" không thống nhất | L7, L14, L15 | `qty_redirects`, `qty_mx_servers`, `tls_ssl_certificate`, `qty_nameservers`, `domain_spf` | Khi DNS lỗi: -1 ở cột này, 0 ở cột khác (số 0 có hai nghĩa); sentinel chia thành 2 cụm (DNS và WHOIS) |
| Định danh bị mã hóa số | L10 | `asn_ip` | 2.567 mã lặp theo cụm (13335, 15169, 20013): là mã ASN nhưng lưu như số liên tục *(suy luận từ domain knowledge, cần đối chiếu dictionary)* |
| Phân phối / ngoại lai | L9 | 23/24 cột liên tục | \|skew\| ≥ 1; 9 cột \|skew\| ≥ 10; `length_url` max 4.165 so với P99 = 253 |
| Bất nhất logic | L16 | `time_domain_activation`/`time_domain_expiration`, `qty_params`, `qty_dot_domain`, `qty_tld_url`, `domain_in_ip`, `ttl_hostname` | 7/16 bất biến bị vi phạm; nặng nhất: 2.220 dòng WHOIS lệch, 237 dòng có `=` trong params nhưng `qty_params = 0` |
| Dư thừa / tương quan giả | L18 | 629/652 cặp trong khối sentinel; `qty_equal_url` ↔ `*_params` | 30 cặp \|ρ\| = 1,000; chỉ 3 cặp dư thừa thật (`qty_slash_url`–`qty_slash_directory` 0,991, `qty_at_url`–`email_in_url` 0,974, `qty_slash_url`–`directory_length` 0,940) |
| Liên quan nhãn | L17, L19 | các cột sentinel | "Không có path": 59,9% legit vs 2,4% phishing; số tín hiệu -1 liên quan mạnh đến nhãn nhưng không đơn điệu (86,8% phishing ở 0 tín hiệu, còn ~1% ở ≥ 8 tín hiệu) |

## 4. Lỗi chung của hai dataset

| Lỗi chung | dataset_B_05_2020 | dataset_small |
|---|---|---|
| Cột hằng số / gần hằng số | 6 hằng số, 13 nhị phân, 2 rời rạc | 13 hằng số, 4 nhị phân, 11 rời rạc |
| Thiếu dữ liệu mã hóa ngầm | -1 ở `domain_age`, số 0 giả ở 12 cột HTML/tra cứu | -1 ở 66/111 cột |
| Lỗi thang đo / phân phối | Thang 0–100 lẫn 0–1; 26/31 cột lệch | 23/24 cột lệch; ngoại lai cực đoan |
| Dư thừa giữa các cột | Hai cột bù nhau; 4 cặp \|ρ\| > 0,9 | `*_file` ⊂ `*_directory`; tương quan giả do sentinel |
| Ngữ nghĩa / mã hóa sai | 5 cột đảo nghĩa, `ip` sai định nghĩa, `nb_com` không tái lập | 7 cột {-1,0} giả nhị phân; `asn_ip` là mã định danh |
| Bất nhất logic | 2/16 bất biến | 7/16 bất biến |
| Thiếu dữ liệu liên quan nhãn | Có (`page_rank`, `web_traffic`, trang chết) | Có (không có path, không có params, lỗi tra cứu) |
| Dòng trùng | 174 dòng | 1.240 dòng, 6 nhóm mâu thuẫn nhãn |

**Khác biệt đáng chú ý:**
- dataset_B có lỗi **ngữ nghĩa** (đảo nghĩa, sai định nghĩa) do dictionary và cách gán giá trị.
- dataset_small có lỗi **cấu trúc** (dùng -1 làm mã hóa chung, các phần URL chồng lấn nhau).

## 5. Ảnh hưởng dự kiến đến việc so sánh thuật toán FS
*(Đây là giả thuyết từ kết quả EDA, cần kiểm chứng ở bước thực nghiệm.)*

| Nhóm thuật toán FS | Lỗi có thể ảnh hưởng |
|---|---|
| Lọc theo phương sai / near-constant | Cột hằng số và gần hằng số (dễ bị loại, kết quả có thể giống nhau giữa các thuật toán) |
| Dựa trên tương quan / dư thừa (mRMR, CFS...) | Dư thừa tuyệt đối và tương quan giả do sentinel làm sai lệch số cặp "dư thừa" |
| Dựa trên khoảng cách hoặc mô hình tuyến tính (L1, ANOVA...) | Sentinel -1 và thang đo lẫn lộn làm méo mean/std và hệ số |
| Dựa trên nhãn (MI, thống kê đơn biến) | Mẫu thiếu dữ liệu lệch theo nhãn có thể khiến cột "thiếu" được xếp hạng cao dù không phản ánh tín hiệu thật |
| Embedded / cây quyết định | Ít nhạy với thang đo, nhưng vẫn chịu ảnh hưởng của sentinel và dòng trùng |

## 6. Phạm vi và hạn chế
- EDA chỉ phát hiện và ghi nhận lỗi; việc xử lý (nếu có) thuộc bước tiền xử lý sau.
- Một số kết luận là suy luận, cần đối chiếu mã nguồn hoặc dictionary của tác giả: `ip`, `nb_com` (dataset_B) và `asn_ip` (dataset_small).
- Ngưỡng `WARNING` ở các bảng EDA (1%, 99%, \|skew\| ≥ 10, max/P99 ≥ 10, ≥ 10% số 0) là ngưỡng chọn tay, có thể điều chỉnh trong hàm `why()` của từng notebook.