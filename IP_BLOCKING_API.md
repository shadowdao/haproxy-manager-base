# IP Blocking API Documentation

This document describes the IP blocking functionality added to HAProxy Manager, which allows WHP (Web Hosting Platform) to manage blocked IP addresses through the API.

## Overview

The IP blocking feature allows administrators to:
- Block specific IP addresses from accessing any sites managed by HAProxy
- Unblock previously blocked IP addresses
- View all currently blocked IP addresses
- Track who blocked an IP and when

When an IP is blocked, visitors from that IP address will receive a 403 Forbidden response.

## Features

- **Runtime IP blocking**: Changes take effect immediately without HAProxy restarts
- **Map file based**: No ACL word limits, supports unlimited blocked IPs
- **Safe configuration management**: Automatic validation and rollback on failures
- **Runtime map synchronization**: Keep database and HAProxy runtime in sync
- **Audit logging**: All operations are logged for monitoring and compliance

## API Endpoints

### Authentication

All IP blocking endpoints require API key authentication when `HAPROXY_API_KEY` is set:

```bash
Authorization: Bearer your-api-key
```

### 1. Get All Blocked IPs

Retrieve a list of all currently blocked IP addresses.

**Endpoint:** `GET /api/blocked-ips`

**Response:**
```json
[
    {
        "id": 1,
        "ip_address": "192.168.1.100",
        "reason": "Suspicious activity detected",
        "blocked_at": "2024-01-15 10:30:00",
        "blocked_by": "WHP Admin Panel"
    },
    {
        "id": 2,
        "ip_address": "10.0.0.50",
        "reason": "Brute force attempts",
        "blocked_at": "2024-01-15 11:45:00",
        "blocked_by": "Security System"
    }
]
```

**Example Request:**
```bash
curl -X GET http://localhost:8000/api/blocked-ips \
  -H "Authorization: Bearer your-api-key"
```

### 2. Block an IP Address

Add an IP address to the blocked list.

**Endpoint:** `POST /api/blocked-ips`

**Request Body:**
```json
{
    "ip_address": "192.168.1.100",
    "reason": "Suspicious activity detected",
    "blocked_by": "WHP Admin Panel"
}
```

**Parameters:**
- `ip_address` (required): The IP address to block (e.g., "192.168.1.100")
- `reason` (optional): Reason for blocking (default: "No reason provided")
- `blocked_by` (optional): Who/what initiated the block (default: "API")

**Response:**
```json
{
    "status": "success",
    "blocked_ip_id": 1,
    "message": "IP 192.168.1.100 has been blocked"
}
```

**Error Responses:**
- `400 Bad Request`: IP address is missing
- `409 Conflict`: IP address is already blocked
- `500 Internal Server Error`: Configuration generation failed

**Example Request:**
```bash
curl -X POST http://localhost:8000/api/blocked-ips \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "reason": "Multiple failed login attempts",
    "blocked_by": "WHP Security Module"
  }'
```

### 3. Unblock an IP Address

Remove an IP address from the blocked list.

**Endpoint:** `DELETE /api/blocked-ips`

**Request Body:**
```json
{
    "ip_address": "192.168.1.100"
}
```

**Parameters:**
- `ip_address` (required): The IP address to unblock

**Response:**
```json
{
    "status": "success",
    "message": "IP 192.168.1.100 has been unblocked"
}
```

**Error Responses:**
- `400 Bad Request`: IP address is missing
- `404 Not Found`: IP address not found in blocked list
- `500 Internal Server Error`: Configuration generation failed

**Example Request:**
```bash
curl -X DELETE http://localhost:8000/api/blocked-ips \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100"}'
```

## Integration with WHP

### PHP Integration Example

Here's how to integrate the IP blocking API into WHP using PHP:

```php
<?php
class HAProxyIPBlocker {
    private $apiUrl;
    private $apiKey;
    
    public function __construct($apiUrl, $apiKey) {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->apiKey = $apiKey;
    }
    
    /**
     * Get all blocked IPs
     */
    public function getBlockedIPs() {
        return $this->makeRequest('GET', '/api/blocked-ips');
    }
    
    /**
     * Block an IP address
     */
    public function blockIP($ipAddress, $reason = null, $blockedBy = 'WHP Control Panel') {
        $data = [
            'ip_address' => $ipAddress,
            'reason' => $reason ?: 'Blocked via WHP Control Panel',
            'blocked_by' => $blockedBy
        ];
        
        return $this->makeRequest('POST', '/api/blocked-ips', $data);
    }
    
    /**
     * Unblock an IP address
     */
    public function unblockIP($ipAddress) {
        $data = ['ip_address' => $ipAddress];
        return $this->makeRequest('DELETE', '/api/blocked-ips', $data);
    }
    
    /**
     * Make API request
     */
    private function makeRequest($method, $endpoint, $data = null) {
        $url = $this->apiUrl . $endpoint;
        
        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Content-Type: application/json'
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        
        if ($data) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        $result = json_decode($response, true);
        
        if ($httpCode >= 200 && $httpCode < 300) {
            return ['success' => true, 'data' => $result];
        } else {
            return ['success' => false, 'error' => $result['message'] ?? 'Unknown error', 'code' => $httpCode];
        }
    }
}

// Usage example:
$haproxyBlocker = new HAProxyIPBlocker('http://haproxy-manager:8000', 'your-api-key-here');

// Block an IP
$result = $haproxyBlocker->blockIP('192.168.1.100', 'Spam detection', 'WHP Anti-Spam Module');
if ($result['success']) {
    echo "IP blocked successfully: " . $result['data']['message'];
} else {
    echo "Error: " . $result['error'];
}

// Get all blocked IPs
$blockedIPs = $haproxyBlocker->getBlockedIPs();
if ($blockedIPs['success']) {
    foreach ($blockedIPs['data'] as $ip) {
        echo "Blocked IP: {$ip['ip_address']} - Reason: {$ip['reason']}\n";
    }
}

// Unblock an IP
$result = $haproxyBlocker->unblockIP('192.168.1.100');
if ($result['success']) {
    echo "IP unblocked successfully";
}
?>
```

### WHP Control Panel Integration

To add IP blocking management to the WHP control panel:

1. **Create a management interface page** (`/admin/ip-blocking.php`):

```php
<?php
// Initialize the HAProxy IP Blocker
$haproxyBlocker = new HAProxyIPBlocker(
    getenv('HAPROXY_MANAGER_URL') ?: 'http://haproxy-manager:8000',
    getenv('HAPROXY_API_KEY')
);

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'block':
                $ip = filter_var($_POST['ip_address'], FILTER_VALIDATE_IP);
                if ($ip) {
                    $result = $haproxyBlocker->blockIP(
                        $ip,
                        $_POST['reason'] ?? '',
                        $_SESSION['admin_username'] ?? 'WHP Admin'
                    );
                    $message = $result['success'] 
                        ? "IP {$ip} has been blocked" 
                        : "Error: " . $result['error'];
                }
                break;
                
            case 'unblock':
                $ip = filter_var($_POST['ip_address'], FILTER_VALIDATE_IP);
                if ($ip) {
                    $result = $haproxyBlocker->unblockIP($ip);
                    $message = $result['success'] 
                        ? "IP {$ip} has been unblocked" 
                        : "Error: " . $result['error'];
                }
                break;
        }
    }
}

// Get current blocked IPs
$blockedIPs = $haproxyBlocker->getBlockedIPs();
?>

<!DOCTYPE html>
<html>
<head>
    <title>IP Blocking Management - WHP</title>
</head>
<body>
    <h1>IP Blocking Management</h1>
    
    <?php if (isset($message)): ?>
        <div class="alert"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    
    <!-- Block IP Form -->
    <h2>Block an IP Address</h2>
    <form method="POST">
        <input type="hidden" name="action" value="block">
        <label>IP Address: <input type="text" name="ip_address" required pattern="\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"></label><br>
        <label>Reason: <input type="text" name="reason" size="50"></label><br>
        <button type="submit">Block IP</button>
    </form>
    
    <!-- Currently Blocked IPs -->
    <h2>Currently Blocked IPs</h2>
    <table border="1">
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Blocked By</th>
                <th>Blocked At</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php if ($blockedIPs['success']): ?>
                <?php foreach ($blockedIPs['data'] as $ip): ?>
                <tr>
                    <td><?= htmlspecialchars($ip['ip_address']) ?></td>
                    <td><?= htmlspecialchars($ip['reason']) ?></td>
                    <td><?= htmlspecialchars($ip['blocked_by']) ?></td>
                    <td><?= htmlspecialchars($ip['blocked_at']) ?></td>
                    <td>
                        <form method="POST" style="display:inline">
                            <input type="hidden" name="action" value="unblock">
                            <input type="hidden" name="ip_address" value="<?= htmlspecialchars($ip['ip_address']) ?>">
                            <button type="submit">Unblock</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</body>
</html>
```

2. **Environment Configuration**

Add these environment variables to your WHP configuration:

```bash
# HAProxy Manager API Configuration
HAPROXY_MANAGER_URL=http://haproxy-manager:8000
HAPROXY_API_KEY=your-secure-api-key-here
```

3. **Automatic Blocking Integration**

You can automatically block IPs based on certain criteria:

```php
// Example: Auto-block after multiple failed login attempts
function handleFailedLogin($username, $ipAddress) {
    global $haproxyBlocker;
    
    // Track failed attempts (implement your own logic)
    $failedAttempts = getFailedAttempts($ipAddress);
    
    if ($failedAttempts >= 5) {
        $haproxyBlocker->blockIP(
            $ipAddress,
            "5+ failed login attempts for user: {$username}",
            "WHP Security System"
        );
        
        // Log the blocking action
        error_log("Auto-blocked IP {$ipAddress} due to multiple failed login attempts");
    }
}
```

## How It Works

1. **Database Storage**: Blocked IPs are stored in the SQLite database table `blocked_ips`
2. **HAProxy Configuration**: When an IP is blocked/unblocked, the HAProxy configuration is regenerated
3. **ACL Rules**: HAProxy uses ACL rules to check if a source IP is in the blocked list
4. **Blocked Page**: Blocked IPs are served a custom "Access Denied" page via the default backend

## Testing

To test the IP blocking functionality:

```bash
# Block your test IP
curl -X POST http://localhost:8000/api/blocked-ips \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "YOUR_TEST_IP", "reason": "Testing"}'

# Try to access a site (you should see the blocked page)
curl -H "X-Forwarded-For: YOUR_TEST_IP" http://localhost

# Unblock the IP
curl -X DELETE http://localhost:8000/api/blocked-ips \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "YOUR_TEST_IP"}'
```

## Notes

- IP blocks are applied globally to all domains managed by HAProxy
- Changes take effect immediately without HAProxy restarts (runtime updates)
- Blocked IPs are persistent across HAProxy restarts (stored in database and map file)
- Map files support unlimited IPs (no ACL word limit restrictions)
- Consider implementing rate limiting on the API endpoints to prevent abuse

## New API Endpoints (Map File Era)

### 4. Safe Configuration Reload

Safely reload the HAProxy configuration with validation and automatic rollback.

**Endpoint:** `POST /api/config/reload`

**Response:**
```json
{
    "status": "success",
    "message": "HAProxy configuration reloaded safely"
}
```

**Error Response:**
```json
{
    "status": "error", 
    "message": "Safe reload failed: Config validation failed: ..."
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8000/api/config/reload \
  -H "Authorization: Bearer your-api-key"
```

### 5. Sync Runtime Map

Synchronize blocked IPs from database to HAProxy runtime map.

**Endpoint:** `POST /api/blocked-ips/sync`

**Response:**
```json
{
    "status": "success",
    "message": "Synced 150/150 IPs to runtime map",
    "total_ips": 150,
    "synced_ips": 150
}
```

**Example Request:**
```bash
curl -X POST http://localhost:8000/api/blocked-ips/sync \
  -H "Authorization: Bearer your-api-key"
```

## Runtime Map Commands

For advanced users, you can interact directly with HAProxy's runtime API:

```bash
# Add IP to runtime (immediate effect)
echo "add map #0 192.168.1.100" | socat stdio /var/run/haproxy.sock

# Remove IP from runtime
echo "del map #0 192.168.1.100" | socat stdio /var/run/haproxy.sock

# Clear all blocked IPs from runtime
echo "clear map #0" | socat stdio /var/run/haproxy.sock

# Show all runtime map entries
echo "show map #0" | socat stdio /var/run/haproxy.sock
```

## Migration from ACL Method

If you're upgrading from the old ACL-based method:

1. **Automatic**: Just update the HAProxy Manager code - it will automatically migrate
2. **Validation**: The new system includes automatic config validation and rollback
3. **No Downtime**: Runtime updates mean no service interruptions
4. **Scalable**: No more 64 IP limit - handle thousands of blocked IPs