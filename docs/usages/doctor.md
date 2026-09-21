# Lệnh `doctor`

Kiểm tra toàn diện môi trường runtime, phát hiện thông tin xác thực (credentials), vị trí file nhị phân `tailscale` cục bộ và khả năng tương tác với Tailscale API mà **không tạo ra bất kỳ tác dụng phụ (side-effects) nào**.

---

## 1. Cú pháp & Bảng Tham số

```bash
tailsacle-cli doctor [options]
```

| Cờ (Flag) | Kiểu | Mặc định | Ý nghĩa & Hành vi |
| :--- | :--- | :---: | :--- |
| `--detect-credentials` | `boolean` | `false` | Tự động quét môi trường để phát hiện các biến chứa Tailscale trust credential (`tskey-client-...`) và cho phép nhắc nhập credential tương tác khi chưa tìm thấy credential nào (mặc định chỉ phát hiện thụ động, không hỏi trong TTY). |
| `--show-resolution` | `boolean` | `false` | Hiển thị thêm chi tiết giải quyết credential đầy đủ (`auth` với `source` và giá trị đã mask) trong JSON output. |
| `--deep` | `boolean` | `false` | Chạy thêm các bài kiểm tra API chỉ đọc (read-only API probes): kiểm tra các quyền (scopes `devices:core`, `policy_file`, `dns`, `all`), trạng thái HTTPS của tailnet, quyền của người dùng (root/admin), và khả năng sẵn sàng của Funnel. |
| `--credential-env <name>` | `string` | `undefined` | Chỉ định tên biến môi trường chứa credential cần kiểm tra (ví dụ `TS_CLIENT_SECRET`). |
| `--profile <profile>` | `string` | `auto` | Hồ sơ triển khai (`dev`, `ephemeral`, `ci`, `container`, `vm`, `production`). |
| `--config <path>` | `string` | `undefined` | Đường dẫn file cấu hình `tailscale-cli.config.json`. |
| `--json` | `boolean` | `false` | Xuất kết quả dưới dạng JSON envelope chuẩn. |

---

## 2. Các Tình huống Sử dụng Thực tế

### Trường hợp 1: Kiểm tra nhanh trước khi Deploy trong CI/CD
```bash
tailsacle-cli doctor --detect-credentials --json
```

### Trường hợp 2: Kiểm tra sâu quyền hạn API và Tailnet HTTPS (`--deep`)
```bash
tailsacle-cli doctor --deep --credential-env TS_CLIENT_SECRET --json
```

### Trường hợp 3: Kiểm tra cấu hình kết hợp profile cụ thể
```bash
tailsacle-cli doctor --profile vm --config ./tailscale-cli.config.json
```

---

## 3. Cấu trúc Output JSON Envelope (`--json`)

```json
{
  "ok": true,
  "command": "doctor",
  "resolved": {
    "config": {
      "profile": "vm",
      "tailnet": "my-tailnet.ts.net",
      "hostname": "server-01",
      "tags": ["tag:server"],
      "keyExpiry": "max",
      "ephemeral": false
    },
    "credential": {
      "source": "TS_CLIENT_SECRET",
      "type": "oauth_client",
      "masked": "tskey-client-***"
    },
    "binary": {
      "found": true,
      "path": "C:\\Program Files\\Tailscale\\tailscale.exe",
      "version": "1.102.3"
    },
    "deep": {
      "httpsEnabled": true,
      "magicDns": true,
      "funnelReady": true,
      "scopes": {
        "devicesCore": "ok",
        "policyFile": "ok",
        "dns": "ok",
        "all": "ok"
      }
    }
  },
  "warnings": [],
  "durationMs": 350
}
```

> Khi thêm `--show-resolution`, output `resolved` sẽ bổ sung trường `auth` chứa chi tiết giải quyết credential (`found`, `kind`, `source`, `masked`). Khi thêm `--detect-credentials`, nếu không có credential trong môi trường, doctor sẽ nhắc nhập trust credential tương tác trong TTY (không có flag này: chỉ phát hiện thụ động).

---

## 4. Các Mã Warning Thường Gặp
- `CREDENTIAL_NOT_FOUND`: Không tìm thấy credential trong môi trường.
- `CREDENTIAL_AMBIGUOUS`: Phát hiện nhiều credential xung đột, cần dùng `--credential-env` để chỉ định.
- `HTTPS_DISABLED`: Tailnet chưa bật HTTPS (Funnel sẽ không hoạt động cho đến khi bật qua API hoặc `--enable-https`).
- `FUNNEL_ATTR_MISSING`: Tag hiện tại chưa được cấp node attribute `funnel` trong ACL policy.
