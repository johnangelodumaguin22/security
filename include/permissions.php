<?php
// Delegable Admin permission system. Superadmin always has full access to
// every module (checked first, short-circuits before ever touching
// admin_permissions) — this table only ever grants Admins access to things
// they don't have by default. Role changes are deliberately NOT part of this
// catalog: that's how someone becomes a Superadmin, so it stays permanently
// Superadmin-only rather than delegable.
// 'group' places a module under a PERMISSION_GROUPS parent for display.
// 'bundle' collapses a module's view + every action into a single checkbox
// in the privilege editor (Account Requests below) — checking it grants
// the whole feature, unchecking revokes all of it, with no partial
// approve-only/reject-only state. Modules without 'bundle' still render
// their full view+action checkbox matrix (e.g. Registration Management).
const PERMISSION_MODULES = [
    'edit_user_info' => [
        'label' => 'Edit User Information',
        'description' => "Edit a User/Admin account's profile details (name, address, birthdate, email) from the Accounts table.",
        'group' => 'account_management',
        'bundle' => true,
        'actions' => ['edit' => 'Edit'],
    ],
    'create_account' => [
        'label' => 'Create Account',
        'description' => 'Create a new Admin account (username + email only, fixed temporary password). Always limited to the Admin role — an Admin can never create a Superadmin account, even with this granted.',
        'group' => 'account_management',
        'bundle' => true,
        'actions' => ['create' => 'Create'],
    ],
    'delete_requests' => [
        'label' => 'Delete Request',
        'description' => 'Review and decide on account-deletion requests submitted by Admins.',
        'group' => 'account_requests',
        'bundle' => true,
        'actions' => ['approve' => 'Approve', 'reject' => 'Reject'],
    ],
    'registration_management' => [
        'label' => 'Registration Management',
        'description' => 'Approve, reject, or block newly submitted registrations.',
        'actions' => ['approve' => 'Approve', 'reject' => 'Reject', 'block' => 'Block'],
    ],
];

// Parent groupings shown in the privilege editor — purely a display
// grouping over PERMISSION_MODULES above; module keys/rows in
// admin_permissions are unchanged and unaware of groups.
const PERMISSION_GROUPS = [
    'account_management' => [
        'label' => 'Account Management',
        'description' => 'Delegated ability to directly manage account details. Each sub-feature below is an independent permission.',
    ],
    'account_requests' => [
        'label' => 'Account Requests',
        'description' => 'Delegated account-request workflows. Each sub-feature below is an independent permission — enabling one does not grant the other.',
    ],
];

function admin_has_permission($conn, $adminIdNumber, $module, $action) {
    $stmt = $conn->prepare("SELECT 1 FROM admin_permissions WHERE admin_id_number = ? AND module = ? AND action = ? LIMIT 1");
    $stmt->bind_param("sss", $adminIdNumber, $module, $action);
    $stmt->execute();
    $found = (bool)$stmt->get_result()->fetch_row();
    $stmt->close();
    return $found;
}

// The actual security boundary. Called at the top of every gated view render
// AND every gated POST handler — sidebar state, JS, and URL params are never
// trusted on their own.
function require_module_permission($conn, $module, $action) {
    if (($_SESSION['role'] ?? '') === 'superadmin') {
        return true;
    }
    if (($_SESSION['role'] ?? '') === 'admin' && !empty($_SESSION['id_number'])) {
        return admin_has_permission($conn, $_SESSION['id_number'], $module, $action);
    }
    return false;
}

// [module => [action => true, ...]]
function get_admin_permissions($conn, $adminIdNumber) {
    $stmt = $conn->prepare("SELECT module, action FROM admin_permissions WHERE admin_id_number = ?");
    $stmt->bind_param("s", $adminIdNumber);
    $stmt->execute();
    $res = $stmt->get_result();
    $out = [];
    while ($row = $res->fetch_assoc()) {
        $out[$row['module']][$row['action']] = true;
    }
    $stmt->close();
    return $out;
}

function log_permission_change($conn, $superadminUsername, $adminIdNumber, $adminUsername, $module, $action, $changeType) {
    $stmt = $conn->prepare("INSERT INTO permission_audit_log (superadmin_username, admin_id_number, admin_username, module, action, change_type) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssss", $superadminUsername, $adminIdNumber, $adminUsername, $module, $action, $changeType);
    $stmt->execute();
    $stmt->close();
}

// Separate audit trail from log_permission_change() above: this records
// *registration review* actions (approve/reject/block a pending account),
// not privilege grants. permission_used is NULL for Superadmin (needs no
// permission) and set to "registration_management.<action>" for an Admin
// acting under a granted permission.
function log_registration_action($conn, $action, $performedByRole, $performedByUsername, $permissionUsed, $targetIdNumber, $targetName, $previousStatus, $newStatus, $reason = null) {
    $stmt = $conn->prepare("INSERT INTO registration_audit_log (action, performed_by_role, performed_by_username, permission_used, target_id_number, target_name, previous_status, new_status, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssssss", $action, $performedByRole, $performedByUsername, $permissionUsed, $targetIdNumber, $targetName, $previousStatus, $newStatus, $reason);
    $stmt->execute();
    $stmt->close();
}

function list_admin_accounts($conn) {
    return $conn->query("SELECT id_number, first_name, middle_name, last_name, username, status
                          FROM users WHERE role = 'admin' ORDER BY last_name, first_name");
}

// -----------------------------------------------------------------
// Superadmin role management: promote an Admin to Superadmin, demote a
// Superadmin back to Admin, or reactivate a blocked Admin/Superadmin with
// an explicitly chosen role. Every path below clears admin_permissions for
// the target first — permissions must always reflect the account's CURRENT
// role and CURRENT explicit grants, never anything left over from a
// previous stint as Admin or Superadmin. Superadmin itself never uses
// admin_permissions (require_module_permission() below short-circuits for
// it), so clearing on promote just keeps the table's contents unambiguous.
// -----------------------------------------------------------------

// "At least one active Superadmin" means role=superadmin AND status=
// approved — a blocked Superadmin doesn't count, since they can't actually
// act as one. Used to guard demotion (and block) against zeroing this out.
function active_superadmin_count($conn) {
    $res = $conn->query("SELECT COUNT(*) c FROM users WHERE role = 'superadmin' AND status = 'approved'");
    return (int)$res->fetch_assoc()['c'];
}

function clear_admin_permissions($conn, $idNumber) {
    $stmt = $conn->prepare("DELETE FROM admin_permissions WHERE admin_id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $stmt->close();
}

// Shared audit entry for promote/demote/reactivate — reuses
// registration_audit_log (previous_role/new_role sit alongside the existing
// previous_status/new_status columns) rather than standing up a parallel
// log table. Only a Superadmin can ever perform these three actions.
// permission_used doesn't apply here (no permission was checked — Superadmin
// acts unconditionally), so it's repurposed to record which module/page the
// action was performed from, same free-text column, different meaning for
// this action family.
function log_role_change($conn, $action, $performedByUsername, $targetIdNumber, $targetName, $previousStatus, $newStatus, $previousRole, $newRole, $module = 'Account Management', $reason = null) {
    $performedByRole = 'superadmin';
    $stmt = $conn->prepare("INSERT INTO registration_audit_log
        (action, performed_by_role, performed_by_username, permission_used, target_id_number, target_name, previous_status, new_status, previous_role, new_role, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssssssss", $action, $performedByRole, $performedByUsername, $module, $targetIdNumber, $targetName, $previousStatus, $newStatus, $previousRole, $newRole, $reason);
    $stmt->execute();
    $stmt->close();
}

// Admin -> Superadmin, effective immediately: require_role() (see
// include/auth_guard.php) re-reads role/status from the database on every
// request, so the promoted account picks this up on its very next
// navigation — no logout/re-login, no separate approval step.
function promote_to_superadmin($conn, $idNumber) {
    $stmt = $conn->prepare("UPDATE users SET role = 'superadmin' WHERE id_number = ? AND role = 'admin' AND status = 'approved'");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $ok = $stmt->affected_rows > 0;
    $stmt->close();
    if ($ok) {
        clear_admin_permissions($conn, $idNumber);
    }
    return $ok;
}

// Superadmin -> Admin, effective immediately (same mechanism as above).
// Callers must independently check "not self" and active_superadmin_count()
// before calling — this function only re-validates the row's own state.
function demote_to_admin($conn, $idNumber) {
    $stmt = $conn->prepare("UPDATE users SET role = 'admin' WHERE id_number = ? AND role = 'superadmin' AND status = 'approved'");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $ok = $stmt->affected_rows > 0;
    $stmt->close();
    if ($ok) {
        clear_admin_permissions($conn, $idNumber);
    }
    return $ok;
}

// Reactivates a blocked Admin/Superadmin with an explicitly chosen role —
// never silently restores whatever role they had before being blocked.
function reactivate_account($conn, $idNumber, $newRole) {
    $stmt = $conn->prepare("UPDATE users SET role = ?, status = 'approved' WHERE id_number = ? AND role IN ('admin','superadmin') AND status = 'blocked'");
    $stmt->bind_param("ss", $newRole, $idNumber);
    $stmt->execute();
    $ok = $stmt->affected_rows > 0;
    $stmt->close();
    if ($ok) {
        clear_admin_permissions($conn, $idNumber);
    }
    return $ok;
}

// -----------------------------------------------------------------
// Unified "Recent Activity" feed for the Overview page — merges
// registration_audit_log (approvals/rejections/blocks/role changes/
// deletions/account creation/delete-request lifecycle) and
// permission_audit_log (grants/revokes) into one timeline, each row
// already carrying its display icon/color and a plain-language sentence
// so the view template stays a dumb renderer.
//
// $onlyUsername === null  -> everything (Superadmin's full-oversight view)
// $onlyUsername === 'x'   -> only actions performed by that username
//                            (Admin's own-activity view — never shows
//                            what other Admins or the Superadmin did)
// -----------------------------------------------------------------
function get_recent_activity($conn, $limit = 15, $onlyUsername = null) {
    $items = [];

    $actionMeta = [
        'approve'                  => ['bi-check-circle-fill', 'icon-success', 'approved the registration of'],
        'reject'                   => ['bi-x-circle-fill', 'icon-danger', 'rejected the registration of'],
        'block'                    => ['bi-slash-circle-fill', 'icon-warning', 'blocked'],
        'unblock'                  => ['bi-unlock-fill', 'icon-success', 'unblocked'],
        'delete'                   => ['bi-trash-fill', 'icon-danger', 'deleted the account of'],
        'create_account'           => ['bi-person-plus-fill', 'icon-success', 'created an account for'],
        'delete_request_submitted' => ['bi-flag-fill', 'icon-warning', 'requested deletion of'],
        'delete_request_approved'  => ['bi-trash-fill', 'icon-danger', 'approved deletion of'],
        'delete_request_rejected'  => ['bi-shield-x', 'icon-info', 'rejected the deletion request for'],
    ];

    $sql = "SELECT action, performed_by_role, performed_by_username, target_id_number, target_name, previous_status, new_status, previous_role, new_role, created_at
            FROM registration_audit_log"
        . ($onlyUsername !== null ? " WHERE performed_by_username = ?" : "")
        . " ORDER BY created_at DESC LIMIT ?";
    $stmt = $conn->prepare($sql);
    if ($onlyUsername !== null) {
        $stmt->bind_param("si", $onlyUsername, $limit);
    } else {
        $stmt->bind_param("i", $limit);
    }
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        // Promote/demote/reactivate carry a role change the generic
        // fixed-fragment $actionMeta shape below can't express (the target
        // role varies), so they get their own sentence built from
        // previous_role/new_role instead of a table lookup.
        if ($row['action'] === 'promote') {
            $items[] = [
                'icon' => 'bi-arrow-up-circle-fill', 'class' => 'icon-success',
                'text' => h($row['performed_by_username']) . ' promoted ' . h($row['target_name'] ?: $row['target_id_number']) . ' to Superadmin',
                'created_at' => $row['created_at'],
            ];
            continue;
        }
        if ($row['action'] === 'demote') {
            $items[] = [
                'icon' => 'bi-arrow-down-circle-fill', 'class' => 'icon-warning',
                'text' => h($row['performed_by_username']) . ' demoted ' . h($row['target_name'] ?: $row['target_id_number']) . ' to Admin',
                'created_at' => $row['created_at'],
            ];
            continue;
        }
        if ($row['action'] === 'reactivate') {
            $items[] = [
                'icon' => 'bi-person-check-fill', 'class' => 'icon-success',
                'text' => h($row['performed_by_username']) . ' unblocked ' . h($row['target_name'] ?: $row['target_id_number']) . ' as ' . h(ucfirst($row['new_role'])),
                'created_at' => $row['created_at'],
            ];
            continue;
        }
        $meta = $actionMeta[$row['action']] ?? ['bi-info-circle-fill', 'icon-muted', $row['action'] . ' for'];
        $items[] = [
            'icon' => $meta[0],
            'class' => $meta[1],
            'text' => h($row['performed_by_username']) . ' ' . $meta[2] . ' ' . h($row['target_name'] ?: $row['target_id_number']),
            'created_at' => $row['created_at'],
        ];
    }
    $stmt->close();

    // Permission grants/revokes are always performed by a Superadmin, so
    // they only ever belong in the full (Superadmin) feed — an Admin's
    // own-activity view is about what that Admin did, not what was done
    // to them.
    if ($onlyUsername === null) {
        $stmt2 = $conn->prepare("SELECT superadmin_username, admin_username, module, action, change_type, created_at
                                  FROM permission_audit_log ORDER BY created_at DESC LIMIT ?");
        $stmt2->bind_param("i", $limit);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        while ($row = $res2->fetch_assoc()) {
            $moduleLabel = PERMISSION_MODULES[$row['module']]['label'] ?? $row['module'];
            $actionLabel = PERMISSION_MODULES[$row['module']]['actions'][$row['action']] ?? $row['action'];
            $granted = $row['change_type'] === 'granted';
            $items[] = [
                'icon' => $granted ? 'bi-key-fill' : 'bi-key',
                'class' => 'icon-purple',
                'text' => h($row['superadmin_username']) . ' ' . ($granted ? 'granted' : 'revoked') . ' "' . h($actionLabel) . '" on ' . h($moduleLabel) . ' for ' . h($row['admin_username']),
                'created_at' => $row['created_at'],
            ];
        }
        $stmt2->close();
    }

    usort($items, function ($a, $b) { return strcmp($b['created_at'], $a['created_at']); });
    return array_slice($items, 0, $limit);
}

// -----------------------------------------------------------------
// Full, filterable, paginated Activity Logs view (Superadmin-only
// dedicated page) — unlike get_recent_activity() above (which is a
// capped, sentence-style feed for the Overview panel), this returns
// raw normalized rows from all three audit tables so they can be
// rendered as a searchable table with an actual "When/Source/Actor/
// Action/Target/IP" breakdown.
// -----------------------------------------------------------------
// $filters['admin_scope'], when set to an Admin's own username, narrows the
// combined feed to what that Admin is allowed to see: their OWN permission
// grants/revokes (not other Admins'), and OTP/security events for 'user'-role
// accounts only (not another Admin's or Superadmin's own security events).
// Registration-source rows stay unrestricted — approvals/blocks/creations
// are ordinary account-management history an Admin needs for their job, not
// a privacy-sensitive security trail.
function get_activity_log_entries($conn, array $filters, $page = 1, $perPage = 25) {
    $source = $filters['source'] ?? 'all';
    $search = trim((string)($filters['search'] ?? ''));
    $dateFrom = trim((string)($filters['date_from'] ?? ''));
    $dateTo = trim((string)($filters['date_to'] ?? ''));
    $adminScope = trim((string)($filters['admin_scope'] ?? ''));

    $union = "
        SELECT created_at, 'registration' AS source, performed_by_username AS actor, performed_by_role AS actor_role,
               action, target_name AS target,
               CONCAT(
                   CASE
                       WHEN previous_role IS NOT NULL AND previous_status <> new_status
                           THEN CONCAT(previous_role, ' -> ', new_role, ' (', previous_status, ' -> ', new_status, ')')
                       WHEN previous_role IS NOT NULL
                           THEN CONCAT(previous_role, ' -> ', new_role)
                       ELSE CONCAT(previous_status, ' -> ', new_status)
                   END,
                   IF(reason IS NOT NULL AND reason <> '', CONCAT(' — Reason: ', reason), '')
               ) AS detail,
               NULL AS ip_address
        FROM registration_audit_log
        UNION ALL
        SELECT created_at, 'permission' AS source, superadmin_username AS actor, 'superadmin' AS actor_role,
               change_type AS action, admin_username AS target, CONCAT(module, '.', action) AS detail, NULL AS ip_address
        FROM permission_audit_log
        UNION ALL
        SELECT created_at, 'otp' AS source, COALESCE(email, id_number, 'unknown') AS actor, COALESCE(role, '') AS actor_role,
               action, COALESCE(id_number, '') AS target, NULL AS detail, ip_address
        FROM otp_audit_log
    ";

    $where = [];
    $params = [];
    $types = '';

    if (in_array($source, ['registration', 'permission', 'otp'], true)) {
        $where[] = "source = ?";
        $params[] = $source;
        $types .= 's';
    }
    if ($search !== '') {
        $where[] = "(actor LIKE ? OR target LIKE ?)";
        $like = '%' . $search . '%';
        $params[] = $like;
        $params[] = $like;
        $types .= 'ss';
    }
    if ($dateFrom !== '') {
        $where[] = "created_at >= ?";
        $params[] = $dateFrom . ' 00:00:00';
        $types .= 's';
    }
    if ($dateTo !== '') {
        $where[] = "created_at <= ?";
        $params[] = $dateTo . ' 23:59:59';
        $types .= 's';
    }
    if ($adminScope !== '') {
        // registration: only THIS Admin's own decisions/actions — not other
        // staff's history on other accounts (a block/promote/reactivate on
        // another Admin or Superadmin is peer-staff history this role
        // shouldn't see, and the log has no clean way to tell "target was a
        // regular user" apart from "target was staff" for every action type,
        // so the safe cut is by actor, not by guessing the target's role).
        // permission: only grants/revokes ABOUT this Admin.
        // otp: only 'user'-role accounts' own security events.
        $where[] = "(source != 'registration' OR actor = ?) AND (source != 'permission' OR target = ?) AND (source != 'otp' OR actor_role = 'user')";
        $params[] = $adminScope;
        $params[] = $adminScope;
        $types .= 'ss';
    }

    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    $countSql = "SELECT COUNT(*) c FROM ($union) combined $whereSql";
    $stmt = $conn->prepare($countSql);
    if ($types !== '') {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $total = (int)$stmt->get_result()->fetch_assoc()['c'];
    $stmt->close();

    $perPage = max(1, min(100, (int)$perPage));
    $totalPages = max(1, (int)ceil($total / $perPage));
    $page = max(1, min((int)$page, $totalPages));
    $offset = ($page - 1) * $perPage;

    $listSql = "SELECT * FROM ($union) combined $whereSql ORDER BY created_at DESC LIMIT ? OFFSET ?";
    $stmt = $conn->prepare($listSql);
    $listTypes = $types . 'ii';
    $listParams = array_merge($params, [$perPage, $offset]);
    $stmt->bind_param($listTypes, ...$listParams);
    $stmt->execute();
    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    return [
        'rows' => $rows,
        'total' => $total,
        'page' => $page,
        'per_page' => $perPage,
        'total_pages' => $totalPages,
    ];
}

// Maps a log row to a pill color class, matching the green/red/neutral
// language already used for account status pills elsewhere in the console.
function activity_log_badge_class($source, $action) {
    if ($source === 'permission') {
        return $action === 'granted' ? 'approved' : 'blocked';
    }
    if ($source === 'registration') {
        if (in_array($action, ['approve', 'unblock', 'create_account', 'promote', 'reactivate'], true)) {
            return 'approved';
        }
        if (in_array($action, ['reject', 'block', 'delete', 'delete_request_approved', 'demote'], true)) {
            return 'blocked';
        }
    }
    return 'pending';
}

const ACTIVITY_LOG_SOURCE_META = [
    'registration' => ['label' => 'Registration', 'icon' => 'bi-person-check-fill', 'class' => 'icon-info'],
    'permission'   => ['label' => 'Permission', 'icon' => 'bi-key-fill', 'class' => 'icon-purple'],
    'otp'          => ['label' => 'OTP / Security', 'icon' => 'bi-shield-lock-fill', 'class' => 'icon-warning'],
];
