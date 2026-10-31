<?php
// index.php - Chạy trên Render kết nối PostgreSQL
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// Xử lý request Preflight (OPTIONS) từ trình duyệt
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

header('Content-Type: application/json');
date_default_timezone_set('Asia/Ho_Chi_Minh');

// CẤU HÌNH KẾT NỐI POSTGRESQL RENDER
$db_url = getenv('DATABASE_URL') ?: 'postgresql://license_user:QnFq2ZtFDgVCdVdd1wFYjQqRwADoNGAp@dpg-dbikb04s728c73fi7re0-a/license_db_av4p';
$dbopts = parse_url($db_url);

$db_host = $dbopts['host'];
$db_port = $dbopts['port'] ?? 5432;
$db_user = $dbopts['user'];
$db_pass = $dbopts['pass'];
$db_name = ltrim($dbopts['path'], '/');

$admin_api_key = 'promise7';

try {
    $pdo = new PDO("pgsql:host=$db_host;port=$db_port;dbname=$db_name", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    die(json_encode(['status' => 'false', 'message' => 'Lỗi kết nối CSDL PostgreSQL: ' . $e->getMessage()]));
}

// Hàm chống XSS
function clean($data)
{
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}

// Hàm lấy Authorization Token chuẩn mọi môi trường Server
function getBearerToken()
{
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER["Authorization"]);
    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
    } else if (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }

    // Fallback: Lấy token qua Query Parameter nếu Header bị Web Server xóa
    if (empty($headers)) {
        return $_REQUEST['admin_token'] ?? '';
    }

    return $headers;
}

// Hàm kiểm tra quyền Admin
function checkAdminAuth($admin_api_key)
{
    $auth = getBearerToken();
    if ($auth !== 'Bearer ' . $admin_api_key && $auth !== $admin_api_key) {
        die(json_encode(['status' => 'false', 'message' => 'Unauthorized']));
    }
}

$token_in_request = getBearerToken();
$is_admin_request = ($token_in_request === 'Bearer ' . $admin_api_key || $token_in_request === $admin_api_key);

// 2. Tường lửa chống DDoS Rate Limit (Bỏ qua hoàn toàn nếu là Admin Request)
$ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$time = time();

if (!$is_admin_request) {
    // Chỉ áp dụng kiểm tra Rate Limit và Banned IP đối với người dùng thông thường / Client
    $stmt = $pdo->prepare("SELECT * FROM ip_logs WHERE ip_address = ?");
    $stmt->execute([$ip]);
    $log = $stmt->fetch();

    if ($log) {
        if ($log['is_blocked']) {
            die(json_encode(['status' => 'false', 'message' => 'IP Banned (DDoS/Brute-force Detected).']));
        }
        if (($time - $log['last_request']) < 5) {
            $count = $log['request_count'] + 1;
            $is_blocked = ($count > 50) ? 1 : 0; // Quá 20 request / 5s -> Ban IP
            $pdo->prepare("UPDATE ip_logs SET request_count = ?, last_request = ?, is_blocked = ? WHERE ip_address = ?")
                ->execute([$count, $time, $is_blocked, $ip]);
            if ($is_blocked) {
                die(json_encode(['status' => 'false', 'message' => 'IP Banned do truy cập quá nhanh.']));
            }
        } else {
            $pdo->prepare("UPDATE ip_logs SET request_count = 1, last_request = ? WHERE ip_address = ?")->execute([$time, $ip]);
        }
    } else {
        $pdo->prepare("INSERT INTO ip_logs (ip_address, last_request) VALUES (?, ?)")->execute([$ip, $time]);
    }
}

$action = $_GET['action'] ?? '';

// ROUTE 1: ADMIN TẠO KEY
if ($action === 'create') {
    checkAdminAuth($admin_api_key);

    $email = clean($_POST['email'] ?? '');
    $max_activations = (int)($_POST['max_activations'] ?? 1);

    if (empty($email)) {
        die(json_encode(['status' => 'false', 'message' => 'Email không được để trống.']));
    }

    $raw = strtoupper(md5(uniqid($email . time() . random_bytes(10), true)));
    $key = substr($raw, 0, 4) . '-' . substr($raw, 4, 4) . '-' . substr($raw, 8, 4) . '-' . substr($raw, 12, 4);

    $pdo->prepare("INSERT INTO licenses (email, license_key, max_activations) VALUES (?, ?, ?)")
        ->execute([$email, $key, $max_activations]);

    echo json_encode(['status' => 'success', 'license_key' => $key]);
    exit;
}

// ROUTE 2: SOURCE CODE KHÁCH HÀNG CHECK ACTIVE
if ($action === 'active') {
    $email = clean($_POST['email'] ?? '');
    $key = clean($_POST['license_key'] ?? '');

    if (empty($email) || empty($key)) {
        die(json_encode(['status' => 'false', 'message' => 'Thiếu thông tin kích hoạt.']));
    }

    // 1. Kiểm tra IP xem đã bị khóa chưa
    $stmt = $pdo->prepare("SELECT failed_attempts, is_blocked FROM ip_logs WHERE ip_address = ?");
    $stmt->execute([$ip]);
    $ipData = $stmt->fetch();

    if ($ipData && ($ipData['failed_attempts'] >= 5 || $ipData['is_blocked'] == 1)) {
        die(json_encode(['status' => 'banned', 'message' => 'IP của bạn đã bị khóa do thử sai Key quá 5 lần!']));
    }

    // 2. Kiểm tra License Key
    $stmt = $pdo->prepare("SELECT * FROM licenses WHERE email = ? AND license_key = ?");
    $stmt->execute([$email, $key]);
    $license = $stmt->fetch();

    if (!$license) {
        $pdo->prepare("UPDATE ip_logs SET failed_attempts = failed_attempts + 1 WHERE ip_address = ?")->execute([$ip]);

        $currentFailed = $ipData ? (int)$ipData['failed_attempts'] + 1 : 1;
        $attemptsLeft = 5 - $currentFailed;

        if ($attemptsLeft <= 0) {
            $pdo->prepare("UPDATE ip_logs SET is_blocked = 1 WHERE ip_address = ?")->execute([$ip]);
            die(json_encode(['status' => 'banned', 'message' => 'IP đã bị khóa vĩnh viễn do nhập sai Key 5 lần!']));
        }

        die(json_encode(['status' => 'false', 'message' => "Sai thông tin! Bạn còn $attemptsLeft lần thử trước khi bị khóa."]));
    }

    if ($license['status'] === 'locked') {
        die(json_encode(['status' => 'false', 'message' => 'Key đã bị khóa bởi Admin.']));
    }

    if ($license['current_activations'] >= $license['max_activations']) {
        die(json_encode(['status' => 'false', 'message' => 'Key đã đạt giới hạn số lần kích hoạt.']));
    }

    // 3. Kích hoạt thành công -> Reset số lần sai về 0
    $pdo->prepare("UPDATE ip_logs SET failed_attempts = 0 WHERE ip_address = ?")->execute([$ip]);
    $pdo->prepare("UPDATE licenses SET current_activations = current_activations + 1 WHERE id = ?")->execute([$license['id']]);

    echo json_encode(['status' => 'success', 'message' => 'Kích hoạt thành công!']);
    exit;
}

// ROUTE 3: ADMIN KHÓA KEY (REVOKE)
if ($action === 'revoke') {
    checkAdminAuth($admin_api_key);

    $key_to_revoke = clean($_POST['license_key'] ?? '');

    if (empty($key_to_revoke)) {
        die(json_encode(['status' => 'false', 'message' => 'Vui lòng cung cấp License Key.']));
    }

    $stmt = $pdo->prepare("UPDATE licenses SET status = 'locked' WHERE license_key = ?");
    $stmt->execute([$key_to_revoke]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(['status' => 'success', 'message' => 'Đã khóa vĩnh viễn License này!']);
    } else {
        echo json_encode(['status' => 'false', 'message' => 'Không tìm thấy License Key này.']);
    }
    exit;
}

// ROUTE 4: ADMIN TRA CỨU THÔNG TIN KEY
if ($action === 'info') {
    checkAdminAuth($admin_api_key);

    $key_to_check = clean($_GET['license_key'] ?? '');
    if (empty($key_to_check)) {
        die(json_encode(['status' => 'false', 'message' => 'Vui lòng nhập License Key.']));
    }

    $stmt = $pdo->prepare("SELECT * FROM licenses WHERE license_key = ?");
    $stmt->execute([$key_to_check]);
    $license = $stmt->fetch();

    if (!$license) {
        die(json_encode(['status' => 'false', 'message' => 'Không tìm thấy License Key này trong hệ thống.']));
    }

    echo json_encode([
        'status' => 'success',
        'data' => [
            'email' => $license['email'],
            'license_key' => $license['license_key'],
            'max_activations' => $license['max_activations'],
            'current_activations' => $license['current_activations'],
            'status' => $license['status'],
            'created_at' => $license['created_at']
        ]
    ]);
    exit;
}

// ROUTE 5: ADMIN UNBAN IP
if ($action === 'unban') {
    checkAdminAuth($admin_api_key);

    $ip_to_unban = clean($_POST['ip_address'] ?? '');

    if (empty($ip_to_unban)) {
        die(json_encode(['status' => 'false', 'message' => 'Vui lòng cung cấp địa chỉ IP cần mở khóa.']));
    }

    $stmt = $pdo->prepare("UPDATE ip_logs SET failed_attempts = 0, is_blocked = 0 WHERE ip_address = ?");
    $stmt->execute([$ip_to_unban]);

    if ($stmt->rowCount() > 0) {
        echo json_encode(['status' => 'success', 'message' => "Đã mở khóa thành công IP: $ip_to_unban!"]);
    } else {
        echo json_encode(['status' => 'false', 'message' => "Không tìm thấy IP này trong danh sách bị khóa."]);
    }
    exit;
}

// ROUTE 6: LẤY DANH SÁCH IP BỊ KHÓA
if ($action === 'list_banned') {
    checkAdminAuth($admin_api_key);

    $stmt = $pdo->prepare("SELECT ip_address, failed_attempts, last_request FROM ip_logs WHERE is_blocked = 1 ORDER BY last_request DESC LIMIT 50");
    $stmt->execute();
    $banned_ips = $stmt->fetchAll();

    echo json_encode([
        'status' => 'success',
        'data' => $banned_ips
    ]);
    exit;
}

// ROUTE 7: DANH SÁCH TOÀN BỘ LICENSE KEY KÈM BỘ LỌC
if ($action === 'list_licenses') {
    checkAdminAuth($admin_api_key);

    $status_filter = clean($_GET['status'] ?? 'all');

    if ($status_filter === 'active') {
        $stmt = $pdo->prepare("SELECT * FROM licenses WHERE status = 'active' ORDER BY id DESC LIMIT 100");
        $stmt->execute();
    } elseif ($status_filter === 'locked') {
        $stmt = $pdo->prepare("SELECT * FROM licenses WHERE status = 'locked' ORDER BY id DESC LIMIT 100");
        $stmt->execute();
    } else {
        $stmt = $pdo->prepare("SELECT * FROM licenses ORDER BY id DESC LIMIT 100");
        $stmt->execute();
    }

    $licenses = $stmt->fetchAll();

    echo json_encode([
        'status' => 'success',
        'data' => $licenses
    ]);
    exit;
}

// ROUTE 8: IMPORT LICENSES TỪ FILE CSV (ĐÃ CHUYỂN SANG POSTGRESQL ON CONFLICT)
if ($action === 'import_csv') {
    checkAdminAuth($admin_api_key);

    $raw_data = file_get_contents('php://input');
    $request = json_decode($raw_data, true);
    $items = $request['items'] ?? [];

    if (empty($items) || !is_array($items)) {
        die(json_encode(['status' => 'false', 'message' => 'Dữ liệu CSV không hợp lệ hoặc rỗng.']));
    }

    $imported = 0;
    $stmt = $pdo->prepare("
        INSERT INTO licenses (email, license_key, max_activations, current_activations, status)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (license_key) DO UPDATE SET
            email = EXCLUDED.email,
            max_activations = EXCLUDED.max_activations,
            current_activations = EXCLUDED.current_activations,
            status = EXCLUDED.status
    ");

    foreach ($items as $item) {
        $email = clean($item['email'] ?? '');
        $key = clean($item['license_key'] ?? '');
        $max = (int)($item['max_activations'] ?? 1);
        $curr = (int)($item['current_activations'] ?? 0);
        $status = in_array($item['status'] ?? '', ['active', 'locked']) ? $item['status'] : 'active';

        if (!empty($email) && !empty($key)) {
            $stmt->execute([$email, $key, $max, $curr, $status]);
            $imported++;
        }
    }

    echo json_encode([
        'status' => 'success',
        'message' => "Đã đồng bộ/khôi phục thành công $imported bản ghi!"
    ]);
    exit;
}

// ROUTE 9: LẤY SỐ LIỆU THỐNG KÊ TỔNG QUAN
if ($action === 'stats') {
    checkAdminAuth($admin_api_key);

    $total_keys  = $pdo->query("SELECT COUNT(*) FROM licenses")->fetchColumn();
    $active_keys = $pdo->query("SELECT COUNT(*) FROM licenses WHERE status = 'active'")->fetchColumn();
    $locked_keys = $pdo->query("SELECT COUNT(*) FROM licenses WHERE status = 'locked'")->fetchColumn();
    $banned_ips  = $pdo->query("SELECT COUNT(*) FROM ip_logs WHERE is_blocked = 1")->fetchColumn();

    echo json_encode([
        'status' => 'success',
        'data' => [
            'total_keys'  => (int)$total_keys,
            'active_keys' => (int)$active_keys,
            'locked_keys' => (int)$locked_keys,
            'banned_ips'  => (int)$banned_ips
        ]
    ]);
    exit;
}

echo json_encode(['status' => 'false', 'message' => 'Invalid action']);
?>