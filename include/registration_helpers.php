<?php
// Shared registration/account logic used by both the public register.php form
// and the Superadmin "create Admin/Superadmin account" flow, so both paths
// enforce identical field rules and use the same id_number scheme.
include_once __DIR__ . '/common_passwords.php';

// The hardcoded recovery Superadmin (include/default_superadmin.php) has no
// `users` row, so the normal username-uniqueness query below can never see
// it — without this check, a real registration could end up "taking" that
// username right out from under it.
function is_reserved_username($username) {
    $default = require __DIR__ . '/default_superadmin.php';
    return hash_equals($default['username'], strtolower((string)$username));
}

const MIN_AGE = 18;
const EMAIL_DOMAIN = 'csucc.edu.ph';

const Q1_OPTIONS = ['best_friend_elementary', 'first_pet', 'favorite_teacher_highschool'];
const Q2_OPTIONS = ['favorite_teacher', 'childhood_nickname', 'favorite_food'];
const Q3_OPTIONS = ['favorite_color', 'favorite_sport', 'dream_job'];

// The 17 official regions of the Philippines — this system only operates
// locally, so "Region" replaces the old free-text "Country" field.
const REGION_OPTIONS = [
    'NCR (National Capital Region)',
    'CAR (Cordillera Administrative Region)',
    'Region I (Ilocos Region)',
    'Region II (Cagayan Valley)',
    'Region III (Central Luzon)',
    'Region IV-A (CALABARZON)',
    'MIMAROPA (Region IV-B)',
    'Region V (Bicol Region)',
    'Region VI (Western Visayas)',
    'Region VII (Central Visayas)',
    'Region VIII (Eastern Visayas)',
    'Region IX (Zamboanga Peninsula)',
    'Region X (Northern Mindanao)',
    'Region XI (Davao Region)',
    'Region XII (SOCCSKSARGEN)',
    'Region XIII (Caraga)',
    'BARMM (Bangsamoro Autonomous Region in Muslim Mindanao)',
];

const ID_PREFIX = 'INR-';

// -----------------------------------------------------------------
// Small validation helpers
// -----------------------------------------------------------------
function hasHtmlOrScript($v) {
    return preg_match('/[<>]/', $v) === 1;
}

function hasBadSpacing($raw) {
    return preg_match('/^\s|\s$/', $raw) === 1 || preg_match('/\s{2,}/', $raw) === 1;
}

// Letters (incl. Ñ/ñ) in runs separated by a single space, hyphen, or
// apostrophe — covers "John", "John Angelo", "Mary-Jane", "O'Connor", "Peña"
// — while a leading/trailing/doubled separator (" 'John", "John--Angelo",
// "John'") fails to match since every separator must be followed by another
// letter run.
function isNamePart($trimmed) {
    return preg_match('/^[A-Za-zÑñ]+(?:[\' \-][A-Za-zÑñ]+)*$/u', $trimmed) === 1;
}

function isOnlyDigits($v) {
    return preg_match('/^[0-9\s]+$/', $v) === 1;
}

// Same character repeated 3+ times in a row — "aaaa", "1111", "John@@@".
// Scoped to name fields (see validateRegistration()); not applied to fields
// like Zip Code where a repeated digit can be a perfectly real value.
function hasRepeatedChars($trimmed) {
    return preg_match('/(.)\1\1/u', $trimmed) === 1;
}

// Lowercase Spanish/Filipino connector words that legitimately stay
// lowercase inside an otherwise Title Case place name — "Agusan del Norte",
// "Surigao del Sur". Real official Philippine province/city names, not an
// edge case.
const PLACE_NAME_CONNECTORS = ['de', 'del', 'dela', 'de la', 'la', 'las', 'los', 'y'];

// Word-by-word Title Case check (first letter uppercase, rest lowercase) for
// Names, Street/Barangay/City/Province. Splits on space, hyphen, AND
// apostrophe so each name/address *part* is checked on its own — "O'Connor"
// is "O" + "Connor", "Mary-Jane" is "Mary" + "Jane", each independently
// Title Case. A part containing a digit (e.g. the "9A" in a "Purok 9A" style
// unit label) is skipped — casing doesn't meaningfully apply to it.
function hasProperWordCasing($trimmed) {
    foreach (preg_split('/[\s\'\-]+/u', $trimmed) as $word) {
        if ($word === '' || preg_match('/[0-9]/', $word)) continue;
        if (in_array(mb_strtolower($word), PLACE_NAME_CONNECTORS, true)) continue;
        $first = mb_substr($word, 0, 1);
        $rest = mb_substr($word, 1);
        if ($first !== mb_strtoupper($first) || $rest !== mb_strtolower($rest)) {
            return false;
        }
    }
    return true;
}

// Shared address-line validator (Street/Barangay/Municipality/Province) used
// by both validateRegistration() and validateProfileEdit() so the two flows'
// character rules can't drift apart. Returns [errorMessage|null, cleanValue].
function validateAddressLine($raw, $label, $pattern, $rejectDigitsOnly = false, $maxLen = 100, $allowDigits = true) {
    if ($raw === '') {
        return ["$label is required.", ''];
    }
    if (hasBadSpacing($raw)) {
        return ["$label cannot have leading, trailing, or repeated spaces.", trim($raw)];
    }
    $trimmed = trim($raw);
    // Checks run most-specific-first so the message always names the actual
    // violation instead of a generic catch-all: a digit gets called out by
    // name (for fields that don't allow one at all) before falling back to
    // the generic "special characters" message, and both run before length
    // so a short-but-invalid value isn't reported as merely "too short".
    if (!$allowDigits && preg_match('/[0-9]/', $trimmed)) {
        return ["$label: Numbers are not allowed.", $trimmed];
    }
    if (hasHtmlOrScript($trimmed) || !preg_match($pattern, $trimmed)) {
        return ["$label: Special characters are not allowed.", $trimmed];
    }
    if (mb_strlen($trimmed) < 2 || mb_strlen($trimmed) > $maxLen) {
        return ["$label must be between 2 and $maxLen characters.", $trimmed];
    }
    if ($rejectDigitsOnly && isOnlyDigits($trimmed)) {
        return ["$label cannot contain only numbers.", $trimmed];
    }
    if (!hasProperWordCasing($trimmed)) {
        return ["$label: Each word must start with an uppercase letter, rest lowercase.", $trimmed];
    }
    return [null, $trimmed];
}

// -----------------------------------------------------------------
// Server-side ID generation, locked against concurrent registrations.
// Format: INR-YYYY-NNNN — the current year, then a 4-digit sequence that
// resets to 0001 at the start of each year (e.g. INR-2026-0001,
// INR-2026-0002, ..., INR-2027-0001). The year comes from MySQL's own
// clock (never PHP's date()) — see the comment in auth_guard.php on why
// this box's MySQL and PHP clocks can't be compared directly.
//
// A pending self-registration reserves its id_number in pending_registration
// (see createUserAccount()) before it's ever a real `users` row, and keeps
// that same id_number when it's later promoted — so the sequence has to be
// read from both tables, or an id handed to a still-pending applicant could
// collide with one given to a concurrently-approved account.
// -----------------------------------------------------------------
function generateNextId($conn) {
    $year = $conn->query("SELECT YEAR(NOW()) y")->fetch_assoc()['y'];
    $likePattern = ID_PREFIX . $year . '-%';

    $maxNum = 0;
    foreach (['users', 'pending_registration'] as $table) {
        $stmt = $conn->prepare("SELECT id_number FROM $table WHERE id_number LIKE ? ORDER BY id_number DESC LIMIT 1 FOR UPDATE");
        $stmt->bind_param("s", $likePattern);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            $last = $result->fetch_assoc()['id_number'];
            $seq = substr($last, strlen(ID_PREFIX) + strlen($year) + 1);
            $maxNum = max($maxNum, intval($seq));
        }
        $stmt->close();
    }
    $padded = str_pad((string)($maxNum + 1), 4, "0", STR_PAD_LEFT);
    return ID_PREFIX . $year . "-" . $padded;
}

// -----------------------------------------------------------------
// Validates the 3-question/3-answer security-question block on its own —
// shared by public registration, the mandatory first-login profile
// completion for Admin/Superadmin, and the one-time "set your security
// questions" gate for pre-existing Admin/Superadmin accounts, so the rules
// (valid/distinct questions, answer format) can never drift between them.
// -----------------------------------------------------------------
function validateSecurityQuestionFields($data) {
    $errors = [];
    $clean = [];

    $qLists = ['a1_question' => Q1_OPTIONS, 'a2_question' => Q2_OPTIONS, 'a3_question' => Q3_OPTIONS];
    $qValues = [];
    foreach ($qLists as $key => $options) {
        $val = (string)($data[$key] ?? '');
        $qValues[$key] = $val;
        $clean[$key] = $val;
        if (!in_array($val, $options, true)) {
            $errors[$key] = "Please select a valid question.";
        }
    }
    if ($qValues['a1_question'] !== '' && $qValues['a1_question'] === $qValues['a2_question']) {
        $errors['a2_question'] = $errors['a2_question'] ?? "Question 2 must be different from Question 1.";
    }
    if ($qValues['a1_question'] !== '' && $qValues['a1_question'] === $qValues['a3_question']) {
        $errors['a3_question'] = $errors['a3_question'] ?? "Question 3 must be different from Question 1.";
    }
    if ($qValues['a2_question'] !== '' && $qValues['a2_question'] === $qValues['a3_question']) {
        $errors['a3_question'] = $errors['a3_question'] ?? "Question 3 must be different from Question 2.";
    }

    foreach (['a1_answer', 'a2_answer', 'a3_answer'] as $key) {
        // Not trimmed before checking — a leading/trailing space must be
        // caught and rejected, not silently stripped, same as every other
        // text field.
        $answerRaw = (string)($data[$key] ?? '');
        $raw = trim($answerRaw);
        $clean[$key] = $raw;
        if ($answerRaw === '') {
            $errors[$key] = "This answer is required.";
        } elseif (hasBadSpacing($answerRaw)) {
            $errors[$key] = "Answer cannot have leading, trailing, or repeated spaces.";
        } elseif (hasHtmlOrScript($raw)) {
            $errors[$key] = "Answer: Special characters are not allowed.";
        } elseif (mb_strlen($raw) < 2 || mb_strlen($raw) > 100) {
            $errors[$key] = "Answer must be between 2 and 100 characters.";
        }
    }

    return [$errors, $clean];
}

// Same hashing rule everywhere a security-question answer is stored:
// lower-cased first (so verification is case-insensitive) then bcrypt'd —
// never compared or stored as plain text.
function hashSecurityAnswer($answer) {
    return password_hash(mb_strtolower($answer), PASSWORD_DEFAULT);
}

// -----------------------------------------------------------------
// Full server-side validation for a new account (public self-registration
// or Superadmin-created Admin/Superadmin). Never trust the client — every
// field posted here is re-checked regardless of what the JS layer already did.
// -----------------------------------------------------------------
function validateRegistration($conn, $data, $requireSecurityQuestions = true, $requirePassword = true) {
    $errors = [];
    $clean = [];

    // ---- Names ----
    foreach ([['first_name', 'First name', true], ['middle_name', 'Middle name', false], ['last_name', 'Last name', true]] as [$key, $label, $required]) {
        $raw = (string)($data[$key] ?? '');
        if ($raw === '') {
            if ($required) $errors[$key] = "$label is required.";
            $clean[$key] = '';
            continue;
        }
        if (hasBadSpacing($raw)) {
            $errors[$key] = "$label cannot have leading, trailing, or repeated spaces.";
            continue;
        }
        $trimmed = trim($raw);
        // Checks run most-specific-first — character-set and casing issues
        // are flagged before length, so e.g. a single lowercase letter is
        // told the actual problem (casing) instead of a generic "too short"
        // message that doesn't explain why the letter itself is wrong.
        if (preg_match('/\d/', $trimmed)) {
            $errors[$key] = "$label: Numbers are not allowed.";
        } elseif (!isNamePart($trimmed)) {
            $errors[$key] = "$label: Special characters are not allowed.";
        } elseif (hasRepeatedChars($trimmed)) {
            $errors[$key] = "$label: The same character cannot repeat 3 or more times in a row.";
        } elseif (!hasProperWordCasing($trimmed)) {
            $errors[$key] = "$label: First letter must be uppercase, rest lowercase.";
        } elseif (mb_strlen($trimmed) < 2 || mb_strlen($trimmed) > 50) {
            $errors[$key] = "$label must be between 2 and 50 characters.";
        }
        $clean[$key] = $trimmed;
    }

    // ---- Extension ----
    // Not trimmed before checking — a leading/trailing space must be caught
    // and rejected, not silently stripped, same as every other text field.
    $extRaw = (string)($data['extension'] ?? '');
    $clean['extension'] = '';
    if ($extRaw !== '' && hasBadSpacing($extRaw)) {
        $errors['extension'] = "Extension cannot have leading, trailing, or repeated spaces.";
    } elseif ($extRaw !== '') {
        if (preg_match('/\d/', $extRaw)) {
            $errors['extension'] = "Extension: Numbers are not allowed.";
        } elseif (!preg_match('/^[A-Za-z]+$/', $extRaw)) {
            $errors['extension'] = "Extension: Special characters are not allowed.";
        } else {
            $normalized = strtoupper($extRaw);
            $map = [
                'JR' => 'Jr', 'SR' => 'Sr',
                'II' => 'II', 'III' => 'III', 'IV' => 'IV', 'V' => 'V',
                'VI' => 'VI', 'VII' => 'VII', 'VIII' => 'VIII', 'IX' => 'IX', 'X' => 'X',
            ];
            if (!isset($map[$normalized])) {
                $errors['extension'] = "Extension must be one of: Jr, Sr, II, III, IV, V, VI, VII, VIII, IX, X.";
            } else {
                $clean['extension'] = $map[$normalized];
            }
        }
    }

    // ---- Sex ----
    $sex = (string)($data['sex'] ?? '');
    if (!in_array($sex, ['Male', 'Female'], true)) {
        $errors['sex'] = "Please select a valid sex.";
    }
    $clean['sex'] = $sex;

    // ---- Birthdate & age (age is always recalculated server-side) ----
    $birthdate = (string)($data['birthdate'] ?? '');
    $clean['birthdate'] = $birthdate;
    $clean['age'] = '';
    $d = DateTime::createFromFormat('Y-m-d', $birthdate);
    if (!$birthdate || !$d || $d->format('Y-m-d') !== $birthdate) {
        $errors['birthdate'] = "Please enter a valid birthdate.";
    } else {
        $today = new DateTime('today');
        if ($d > $today) {
            $errors['birthdate'] = "Birthdate cannot be in the future.";
        } else {
            $age = $today->diff($d)->y;
            $clean['age'] = (string)$age;
            if ($age < MIN_AGE) {
                $errors['birthdate'] = "You must be at least " . MIN_AGE . " years old to register.";
            }
        }
    }

    // ---- Address fields ----
    [$err, $clean['street']] = validateAddressLine((string)($data['street'] ?? ''), 'Street/Purok', '/^[A-Za-z0-9][A-Za-z0-9Ññ\s.,\-\/\']*$/u', false, 100);
    if ($err) $errors['street'] = $err;

    [$err, $clean['barangay']] = validateAddressLine((string)($data['barangay'] ?? ''), 'Barangay', '/^[A-Za-z0-9][A-Za-z0-9Ññ\s.\-\']*$/u', true, 100);
    if ($err) $errors['barangay'] = $err;

    foreach ([['city', 'Municipality/City'], ['province', 'Province']] as [$key, $label]) {
        [$err, $clean[$key]] = validateAddressLine((string)($data[$key] ?? ''), $label, '/^[A-Za-zÑñ][A-Za-zÑñ\s.\-\']*$/u', false, 100, false);
        if ($err) $errors[$key] = $err;
    }

    $region = (string)($data['region'] ?? '');
    $clean['region'] = $region;
    if (!in_array($region, REGION_OPTIONS, true)) {
        $errors['region'] = "Please select a valid region.";
    }

    // Not trimmed before checking — a leading/trailing space must be caught
    // and rejected, not silently stripped, so it never masks the fact that
    // spaces were typed into a digits-only field.
    $zip = (string)($data['zip'] ?? '');
    $clean['zip'] = $zip;
    if ($zip === '') {
        $errors['zip'] = "Zip Code is required.";
    } elseif (preg_match('/\s/', $zip)) {
        $errors['zip'] = "Zip Code: Spaces are not allowed.";
    } elseif (preg_match('/[A-Za-z]/', $zip)) {
        $errors['zip'] = "Zip Code: Letters are not allowed.";
    } elseif (preg_match('/[^0-9]/', $zip)) {
        $errors['zip'] = "Zip Code: Special characters are not allowed.";
    } elseif (!preg_match('/^\d{4}$/', $zip)) {
        $errors['zip'] = "Zip Code must be exactly 4 digits.";
    }

    // ---- Email (required: OTP email verification depends on having one) ----
    // Not trimmed before checking — a leading/trailing space must be caught
    // and rejected, not silently stripped, same as every other text field.
    $emailRaw = (string)($data['email'] ?? '');
    $email = strtolower(trim($emailRaw));
    $clean['email'] = $email === '' ? null : $email;
    if ($emailRaw === '') {
        $errors['email'] = "Email is required.";
    } elseif (hasBadSpacing($emailRaw)) {
        $errors['email'] = "Email cannot have leading, trailing, or repeated spaces.";
    } else {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = "Please enter a valid email address.";
        } elseif (mb_strlen($email) > 100) {
            $errors['email'] = "Email must be at most 100 characters.";
        } elseif (!str_ends_with($email, '@' . EMAIL_DOMAIN)) {
            $errors['email'] = "Email must be a valid @" . EMAIL_DOMAIN . " address.";
        } else {
            // A pending self-registration's email lives in pending_registration
            // until it's decided, so it must be checked here too — otherwise
            // two people could register with the same email while the first
            // one is still awaiting review.
            $stmt = $conn->prepare("SELECT
                (SELECT COUNT(*) FROM users WHERE email = ?) +
                (SELECT COUNT(*) FROM pending_registration WHERE email = ?) AS c");
            $stmt->bind_param("ss", $email, $email);
            $stmt->execute();
            $stmt->bind_result($count);
            $stmt->fetch();
            $stmt->close();
            if ($count > 0) {
                $errors['email'] = "This email is already registered.";
            }
        }
    }

    // ---- Username ----
    // Not trimmed before checking — a leading/trailing space must be caught
    // and rejected, not silently stripped, same as every other text field.
    $usernameRaw = (string)($data['username'] ?? '');
    $username = trim($usernameRaw);
    $clean['username'] = strtolower($username);
    if ($usernameRaw === '') {
        $errors['username'] = "Username is required.";
    } elseif (hasBadSpacing($usernameRaw)) {
        $errors['username'] = "Username cannot have leading, trailing, or repeated spaces.";
    } elseif (preg_match('/\s/', $username)) {
        $errors['username'] = "Username must not contain spaces.";
    // The three structural rules below were previously one combined regex —
    // split out and ordered most-specific-first so, e.g., a stray symbol is
    // named directly instead of surfacing as a generic length/format message.
    } elseif (preg_match('/[^A-Za-z0-9_.]/', $username)) {
        $errors['username'] = "Username: Special characters are not allowed.";
    } elseif (!preg_match('/^[A-Za-z]/', $username)) {
        $errors['username'] = "Username must start with a letter.";
    } elseif (mb_strlen($username) < 5 || mb_strlen($username) > 30) {
        $errors['username'] = "Username must be between 5 and 30 characters.";
    } elseif (!preg_match('/[A-Z]/', $username)) {
        $errors['username'] = "Username must contain at least one uppercase letter.";
    } elseif (!preg_match('/[0-9]/', $username)) {
        $errors['username'] = "Username must contain at least one number.";
    } elseif (!preg_match('/[_.]/', $username)) {
        $errors['username'] = "Username must contain at least one special character (_ or .).";
    } elseif (is_reserved_username($username)) {
        $errors['username'] = "This username is already taken.";
    } else {
        $stmt = $conn->prepare("SELECT
            (SELECT COUNT(*) FROM users WHERE LOWER(username) = ?) +
            (SELECT COUNT(*) FROM pending_registration WHERE LOWER(username) = ?) AS c");
        $stmt->bind_param("ss", $clean['username'], $clean['username']);
        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();
        if ($count > 0) {
            $errors['username'] = "This username is already taken.";
        }
    }

    // ---- Password ----
    // Skipped entirely when a Superadmin is creating another Superadmin
    // account — the creator must never be able to set (or even see) that
    // account's credential; a random password is generated server-side
    // instead and the new Superadmin sets their own via Reset via Email OTP.
    if ($requirePassword) {
        $password = (string)($data['password'] ?? '');
        $repassword = (string)($data['repassword'] ?? '');
        // Max stays 72, not a rounder number like 128 — password_hash()'s
        // bcrypt algorithm silently ignores any byte past the 72nd, so a
        // longer max would accept input the hash never actually uses in
        // full.
        if ($password === '') {
            $errors['password'] = "Password is required.";
        } elseif (preg_match('/^\s|\s$/', $password)) {
            $errors['password'] = "Password cannot start or end with a space.";
        } elseif (mb_strlen($password) < 8 || mb_strlen($password) > 72) {
            $errors['password'] = "Password must be between 8 and 72 characters.";
        } elseif (!preg_match('/[A-Z]/', $password)) {
            $errors['password'] = "Password must contain at least one uppercase letter.";
        } elseif (!preg_match('/[a-z]/', $password)) {
            $errors['password'] = "Password must contain at least one lowercase letter.";
        } elseif (!preg_match('/[0-9]/', $password)) {
            $errors['password'] = "Password must contain at least one number.";
        } elseif (!preg_match('/[!@#$%^&*()_\-+=?]/', $password)) {
            $errors['password'] = "Password must contain at least one special character (! @ # $ % ^ & * ( ) _ - + = ?).";
        } elseif (isCommonWeakPassword($password)) {
            $errors['password'] = "This password is too common. Please choose another.";
        } elseif ($clean['username'] !== '' && stripos($password, $clean['username']) !== false) {
            $errors['password'] = "Password must not contain your username.";
        } elseif ($clean['first_name'] !== '' && stripos($password, $clean['first_name']) !== false) {
            $errors['password'] = "Password must not contain your first name.";
        } elseif ($clean['last_name'] !== '' && stripos($password, $clean['last_name']) !== false) {
            $errors['password'] = "Password must not contain your last name.";
        }

        if ($repassword === '') {
            $errors['repassword'] = "Please re-enter your password.";
        } elseif ($password !== '' && $password !== $repassword) {
            $errors['repassword'] = "Passwords do not match.";
        }
    }

    // ---- Security questions & answers ----
    // Admin/Superadmin-created accounts skip these entirely — email OTP alone
    // is their account-recovery method instead (forgot_password.php detects
    // the absence of question1 and skips straight from OTP to the new-password
    // step for such accounts, rather than asking for questions that don't exist).
    if (!$requireSecurityQuestions) {
        foreach (['a1_question', 'a1_answer', 'a2_question', 'a2_answer', 'a3_question', 'a3_answer'] as $key) {
            $clean[$key] = '';
        }
    } else {
        [$qErrors, $qClean] = validateSecurityQuestionFields($data);
        $errors = array_merge($errors, $qErrors);
        $clean = array_merge($clean, $qClean);
    }

    return [$errors, $clean];
}

// -----------------------------------------------------------------
// Inserts a validated ($clean from validateRegistration) account with a
// caller-chosen role/status. Used by both the public 'user'/'pending' flow
// and the Superadmin 'admin|superadmin'/'approved' creation flow.
//
// A 'pending' status is never written to `users` — it lands in
// pending_registration instead, and only becomes a real `users` row once a
// reviewer decides its fate (see promotePendingRegistration() /
// discardPendingRegistration() below). Every other status (an Admin/
// Superadmin-created account, always 'approved') goes straight into `users`
// exactly as before.
// -----------------------------------------------------------------
function createUserAccount($conn, $clean, $rawPassword, $role, $status) {
    $hashedPassword = password_hash($rawPassword, PASSWORD_DEFAULT);
    // Accounts created without security questions (Admin/Superadmin "Create
    // Account") store empty question/answer columns — nothing to hash, and
    // forgot_password.php treats an empty question1 as "use OTP reset instead".
    $hasSecurityQuestions = $clean['a1_question'] !== '';
    $hashedA1 = $hasSecurityQuestions ? password_hash(mb_strtolower($clean['a1_answer']), PASSWORD_DEFAULT) : '';
    $hashedA2 = $hasSecurityQuestions ? password_hash(mb_strtolower($clean['a2_answer']), PASSWORD_DEFAULT) : '';
    $hashedA3 = $hasSecurityQuestions ? password_hash(mb_strtolower($clean['a3_answer']), PASSWORD_DEFAULT) : '';

    $maxRetries = 3;
    for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
        $conn->begin_transaction();
        try {
            $id_number = generateNextId($conn);

            if ($status === 'pending') {
                $stmt = $conn->prepare("INSERT INTO pending_registration (
                    id_number, first_name, middle_name, last_name, extension, sex, birthdate, age,
                    street, barangay, city, province, region, zip_code, email, username, password,
                    question1, answer1, question2, answer2, question3, answer3
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                if (!$stmt) {
                    throw new mysqli_sql_exception('Prepare failed: ' . $conn->error);
                }

                $stmt->bind_param(
                    str_repeat('s', 23),
                    $id_number, $clean['first_name'], $clean['middle_name'], $clean['last_name'], $clean['extension'],
                    $clean['sex'], $clean['birthdate'], $clean['age'],
                    $clean['street'], $clean['barangay'], $clean['city'], $clean['province'], $clean['region'],
                    $clean['zip'], $clean['email'],
                    $clean['username'], $hashedPassword,
                    $clean['a1_question'], $hashedA1, $clean['a2_question'], $hashedA2, $clean['a3_question'], $hashedA3
                );
            } else {
                $stmt = $conn->prepare("INSERT INTO users (
                    id_number, first_name, middle_name, last_name, extension, sex, birthdate, age,
                    street, barangay, city, province, region, zip_code, email, username, password,
                    role, status, question1, answer1, question2, answer2, question3, answer3
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                if (!$stmt) {
                    throw new mysqli_sql_exception('Prepare failed: ' . $conn->error);
                }

                $stmt->bind_param(
                    str_repeat('s', 25),
                    $id_number, $clean['first_name'], $clean['middle_name'], $clean['last_name'], $clean['extension'],
                    $clean['sex'], $clean['birthdate'], $clean['age'],
                    $clean['street'], $clean['barangay'], $clean['city'], $clean['province'], $clean['region'],
                    $clean['zip'], $clean['email'],
                    $clean['username'], $hashedPassword,
                    $role, $status,
                    $clean['a1_question'], $hashedA1, $clean['a2_question'], $hashedA2, $clean['a3_question'], $hashedA3
                );
            }

            $stmt->execute();
            $conn->commit();
            return ['status' => true, 'id_number' => $id_number];
        } catch (mysqli_sql_exception $e) {
            $conn->rollback();
            if ($e->getCode() === 1062) {
                if (str_contains($e->getMessage(), 'username')) {
                    return ['status' => false, 'message' => 'Please fix the highlighted errors.', 'errors' => ['username' => 'This username is already taken.']];
                }
                if (str_contains($e->getMessage(), 'email')) {
                    return ['status' => false, 'message' => 'Please fix the highlighted errors.', 'errors' => ['email' => 'This email is already registered.']];
                }
                // Otherwise it was the id_number primary key colliding with a concurrent
                // registration — retry with a freshly generated id.
                continue;
            }
            error_log('Account creation failed: ' . $e->getMessage());
            return ['status' => false, 'message' => 'A server error occurred. Please try again later.'];
        }
    }

    return ['status' => false, 'message' => 'A server error occurred. Please try again later.'];
}

// -----------------------------------------------------------------
// Lighter validation for the Admin/Superadmin "edit account" form — profile
// and address fields only (no username/password/security-Q&A editing here;
// reuses the same character-rule helpers as validateRegistration so the
// rules stay identical, but the field set and email-uniqueness check
// (excluding the row being edited) differ enough to warrant its own function.
// -----------------------------------------------------------------
function validateProfileEdit($conn, $data, $currentIdNumber) {
    $errors = [];
    $clean = [];

    foreach ([['first_name', 'First name', true], ['middle_name', 'Middle name', false], ['last_name', 'Last name', true]] as [$key, $label, $required]) {
        $raw = (string)($data[$key] ?? '');
        if ($raw === '') {
            if ($required) $errors[$key] = "$label is required.";
            $clean[$key] = '';
            continue;
        }
        if (hasBadSpacing($raw)) {
            $errors[$key] = "$label cannot have leading, trailing, or repeated spaces.";
            continue;
        }
        $trimmed = trim($raw);
        // Checks run most-specific-first — character-set and casing issues
        // are flagged before length, so e.g. a single lowercase letter is
        // told the actual problem (casing) instead of a generic "too short"
        // message that doesn't explain why the letter itself is wrong.
        if (preg_match('/\d/', $trimmed)) {
            $errors[$key] = "$label: Numbers are not allowed.";
        } elseif (!isNamePart($trimmed)) {
            $errors[$key] = "$label: Special characters are not allowed.";
        } elseif (hasRepeatedChars($trimmed)) {
            $errors[$key] = "$label: The same character cannot repeat 3 or more times in a row.";
        } elseif (!hasProperWordCasing($trimmed)) {
            $errors[$key] = "$label: First letter must be uppercase, rest lowercase.";
        } elseif (mb_strlen($trimmed) < 2 || mb_strlen($trimmed) > 50) {
            $errors[$key] = "$label must be between 2 and 50 characters.";
        }
        $clean[$key] = $trimmed;
    }

    $extRaw = trim((string)($data['extension'] ?? ''));
    $clean['extension'] = '';
    if ($extRaw !== '') {
        if (preg_match('/\d/', $extRaw)) {
            $errors['extension'] = "Extension: Numbers are not allowed.";
        } elseif (!preg_match('/^[A-Za-z]+$/', $extRaw)) {
            $errors['extension'] = "Extension: Special characters are not allowed.";
        } else {
            $normalized = strtoupper($extRaw);
            $map = [
                'JR' => 'Jr', 'SR' => 'Sr',
                'II' => 'II', 'III' => 'III', 'IV' => 'IV', 'V' => 'V',
                'VI' => 'VI', 'VII' => 'VII', 'VIII' => 'VIII', 'IX' => 'IX', 'X' => 'X',
            ];
            if (!isset($map[$normalized])) {
                $errors['extension'] = "Extension must be one of: Jr, Sr, II, III, IV, V, VI, VII, VIII, IX, X.";
            } else {
                $clean['extension'] = $map[$normalized];
            }
        }
    }

    $sex = (string)($data['sex'] ?? '');
    if (!in_array($sex, ['Male', 'Female'], true)) {
        $errors['sex'] = "Please select a valid sex.";
    }
    $clean['sex'] = $sex;

    $birthdate = (string)($data['birthdate'] ?? '');
    $clean['birthdate'] = $birthdate;
    $clean['age'] = '';
    $d = DateTime::createFromFormat('Y-m-d', $birthdate);
    if (!$birthdate || !$d || $d->format('Y-m-d') !== $birthdate) {
        $errors['birthdate'] = "Please enter a valid birthdate.";
    } else {
        $today = new DateTime('today');
        if ($d > $today) {
            $errors['birthdate'] = "Birthdate cannot be in the future.";
        } else {
            $clean['age'] = (string)$today->diff($d)->y;
        }
    }

    [$err, $clean['street']] = validateAddressLine((string)($data['street'] ?? ''), 'Street/Purok', '/^[A-Za-z0-9][A-Za-z0-9Ññ\s.,\-\/\']*$/u', false, 100);
    if ($err) $errors['street'] = $err;

    [$err, $clean['barangay']] = validateAddressLine((string)($data['barangay'] ?? ''), 'Barangay', '/^[A-Za-z0-9][A-Za-z0-9Ññ\s.\-\']*$/u', true, 100);
    if ($err) $errors['barangay'] = $err;

    foreach ([['city', 'Municipality/City'], ['province', 'Province']] as [$key, $label]) {
        [$err, $clean[$key]] = validateAddressLine((string)($data[$key] ?? ''), $label, '/^[A-Za-zÑñ][A-Za-zÑñ\s.\-\']*$/u', false, 100, false);
        if ($err) $errors[$key] = $err;
    }

    $region = (string)($data['region'] ?? '');
    $clean['region'] = $region;
    if (!in_array($region, REGION_OPTIONS, true)) {
        $errors['region'] = "Please select a valid region.";
    }

    // Not trimmed before checking — a leading/trailing space must be caught
    // and rejected, not silently stripped, so it never masks the fact that
    // spaces were typed into a digits-only field.
    $zip = (string)($data['zip'] ?? '');
    $clean['zip'] = $zip;
    if ($zip === '') {
        $errors['zip'] = "Zip Code is required.";
    } elseif (preg_match('/\s/', $zip)) {
        $errors['zip'] = "Zip Code: Spaces are not allowed.";
    } elseif (preg_match('/[A-Za-z]/', $zip)) {
        $errors['zip'] = "Zip Code: Letters are not allowed.";
    } elseif (preg_match('/[^0-9]/', $zip)) {
        $errors['zip'] = "Zip Code: Special characters are not allowed.";
    } elseif (!preg_match('/^\d{4}$/', $zip)) {
        $errors['zip'] = "Zip Code must be exactly 4 digits.";
    }

    $emailRaw = (string)($data['email'] ?? '');
    $email = strtolower(trim($emailRaw));
    $clean['email'] = $email === '' ? null : $email;
    if ($emailRaw !== '' && hasBadSpacing($emailRaw)) {
        $errors['email'] = "Email cannot have leading, trailing, or repeated spaces.";
    } elseif ($email !== '') {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = "Please enter a valid email address.";
        } elseif (mb_strlen($email) > 100) {
            $errors['email'] = "Email must be at most 100 characters.";
        } elseif (!str_ends_with($email, '@' . EMAIL_DOMAIN)) {
            $errors['email'] = "Email must be a valid @" . EMAIL_DOMAIN . " address.";
        } else {
            $stmt = $conn->prepare("SELECT
                (SELECT COUNT(*) FROM users WHERE email = ? AND id_number != ?) +
                (SELECT COUNT(*) FROM pending_registration WHERE email = ?) AS c");
            $stmt->bind_param("sss", $email, $currentIdNumber, $email);
            $stmt->execute();
            $stmt->bind_result($count);
            $stmt->fetch();
            $stmt->close();
            if ($count > 0) {
                $errors['email'] = "This email is already registered.";
            }
        }
    }

    // Username is only validated when the caller's form actually collects it
    // (admin_dashboard.php's Edit Account form, which lets an Admin rename a
    // co-admin/user) — superadmin_dashboard.php's own Edit Account form never
    // sends a 'username' key, so this block is a no-op there and $clean stays
    // exactly as it was before this was added.
    if (array_key_exists('username', $data)) {
        $usernameRaw = (string)($data['username'] ?? '');
        $username = trim($usernameRaw);
        $clean['username'] = strtolower($username);
        if ($usernameRaw === '') {
            $errors['username'] = "Username is required.";
        } elseif (hasBadSpacing($usernameRaw)) {
            $errors['username'] = "Username cannot have leading, trailing, or repeated spaces.";
        } elseif (preg_match('/\s/', $username)) {
            $errors['username'] = "Username must not contain spaces.";
        } elseif (preg_match('/[^A-Za-z0-9_.]/', $username)) {
            $errors['username'] = "Username: Special characters are not allowed.";
        } elseif (!preg_match('/^[A-Za-z]/', $username)) {
            $errors['username'] = "Username must start with a letter.";
        } elseif (mb_strlen($username) < 5 || mb_strlen($username) > 30) {
            $errors['username'] = "Username must be between 5 and 30 characters.";
        } elseif (!preg_match('/[A-Z]/', $username)) {
            $errors['username'] = "Username must contain at least one uppercase letter.";
        } elseif (!preg_match('/[0-9]/', $username)) {
            $errors['username'] = "Username must contain at least one number.";
        } elseif (!preg_match('/[_.]/', $username)) {
            $errors['username'] = "Username must contain at least one special character (_ or .).";
        } elseif (is_reserved_username($username)) {
            $errors['username'] = "This username is already taken.";
        } else {
            $stmt = $conn->prepare("SELECT
                (SELECT COUNT(*) FROM users WHERE LOWER(username) = ? AND id_number != ?) +
                (SELECT COUNT(*) FROM pending_registration WHERE LOWER(username) = ?) AS c");
            $stmt->bind_param("sss", $clean['username'], $currentIdNumber, $clean['username']);
            $stmt->execute();
            $stmt->bind_result($count);
            $stmt->fetch();
            $stmt->close();
            if ($count > 0) {
                $errors['username'] = "This username is already taken.";
            }
        }
    }

    return [$errors, $clean];
}

// -----------------------------------------------------------------
// Validates a "bare" Admin/Superadmin account creation — Superadmin's
// Create Account form now only collects a login identity (username +
// password), never confidential personal information. The new hire fills
// in the rest of their own profile on first login (see
// validateProfileCompletion()/completeStaffProfile() below).
// -----------------------------------------------------------------
function validateBareAccountCreation($conn, $data) {
    $errors = [];
    $clean = [];

    // Required so the new Admin/Superadmin can be emailed their username
    // and initial password — this account has no other way to receive them.
    $emailRaw = (string)($data['email'] ?? '');
    $email = strtolower(trim($emailRaw));
    $clean['email'] = $email;
    if ($emailRaw === '') {
        $errors['email'] = "Email is required.";
    } elseif (hasBadSpacing($emailRaw)) {
        $errors['email'] = "Email cannot have leading, trailing, or repeated spaces.";
    } else {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = "Please enter a valid email address.";
        } elseif (mb_strlen($email) > 100) {
            $errors['email'] = "Email must be at most 100 characters.";
        } elseif (!str_ends_with($email, '@' . EMAIL_DOMAIN)) {
            $errors['email'] = "Email must be a valid @" . EMAIL_DOMAIN . " address.";
        } else {
            $stmt = $conn->prepare("SELECT
                (SELECT COUNT(*) FROM users WHERE email = ?) +
                (SELECT COUNT(*) FROM pending_registration WHERE email = ?) AS c");
            $stmt->bind_param("ss", $email, $email);
            $stmt->execute();
            $stmt->bind_result($count);
            $stmt->fetch();
            $stmt->close();
            if ($count > 0) {
                $errors['email'] = "This email is already registered.";
            }
        }
    }

    $usernameRaw = (string)($data['username'] ?? '');
    $username = trim($usernameRaw);
    $clean['username'] = strtolower($username);
    if ($usernameRaw === '') {
        $errors['username'] = "Username is required.";
    } elseif (hasBadSpacing($usernameRaw)) {
        $errors['username'] = "Username cannot have leading, trailing, or repeated spaces.";
    } elseif (preg_match('/\s/', $username)) {
        $errors['username'] = "Username must not contain spaces.";
    } elseif (preg_match('/[^A-Za-z0-9_.]/', $username)) {
        $errors['username'] = "Username: Special characters are not allowed.";
    } elseif (!preg_match('/^[A-Za-z]/', $username)) {
        $errors['username'] = "Username must start with a letter.";
    } elseif (mb_strlen($username) < 5 || mb_strlen($username) > 30) {
        $errors['username'] = "Username must be between 5 and 30 characters.";
    } elseif (!preg_match('/[A-Z]/', $username)) {
        $errors['username'] = "Username must contain at least one uppercase letter.";
    } elseif (!preg_match('/[0-9]/', $username)) {
        $errors['username'] = "Username must contain at least one number.";
    } elseif (!preg_match('/[_.]/', $username)) {
        $errors['username'] = "Username must contain at least one special character (_ or .).";
    } elseif (is_reserved_username($username)) {
        $errors['username'] = "This username is already taken.";
    } else {
        $stmt = $conn->prepare("SELECT
            (SELECT COUNT(*) FROM users WHERE LOWER(username) = ?) +
            (SELECT COUNT(*) FROM pending_registration WHERE LOWER(username) = ?) AS c");
        $stmt->bind_param("ss", $clean['username'], $clean['username']);
        $stmt->execute();
        $stmt->bind_result($count);
        $stmt->fetch();
        $stmt->close();
        if ($count > 0) {
            $errors['username'] = "This username is already taken.";
        }
    }

    // No password field to validate here — every bare Admin/Superadmin
    // account created this way starts on the same fixed, locked default
    // password (DEFAULT_STAFF_PASSWORD in superadmin_dashboard.php), never a
    // Superadmin-chosen one. Safe specifically because completeStaffProfile()
    // forces a real, self-chosen replacement password on first login before
    // the account can reach any dashboard.

    return [$errors, $clean];
}

// -----------------------------------------------------------------
// Inserts a bare Admin/Superadmin account (username + password only —
// no confidential personal info yet). profile_status starts 'incomplete';
// the account is unusable beyond login until completeStaffProfile() runs
// (enforced server-side by require_role() in include/auth_guard.php).
// -----------------------------------------------------------------
function createBareStaffAccount($conn, $username, $rawPassword, $role, $email) {
    $hashedPassword = password_hash($rawPassword, PASSWORD_DEFAULT);

    $maxRetries = 3;
    for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
        $conn->begin_transaction();
        try {
            $id_number = generateNextId($conn);

            $stmt = $conn->prepare("INSERT INTO users (
                id_number, username, password, role, email, status, profile_status,
                question1, answer1, question2, answer2, question3, answer3
            ) VALUES (?, ?, ?, ?, ?, 'approved', 'incomplete', '', '', '', '', '', '')");

            if (!$stmt) {
                throw new mysqli_sql_exception('Prepare failed: ' . $conn->error);
            }

            $stmt->bind_param("sssss", $id_number, $username, $hashedPassword, $role, $email);
            $stmt->execute();
            $conn->commit();
            return ['status' => true, 'id_number' => $id_number];
        } catch (mysqli_sql_exception $e) {
            $conn->rollback();
            if ($e->getCode() === 1062) {
                if (str_contains($e->getMessage(), 'username')) {
                    return ['status' => false, 'message' => 'Please fix the highlighted errors.', 'errors' => ['username' => 'This username is already taken.']];
                }
                if (str_contains($e->getMessage(), 'email')) {
                    return ['status' => false, 'message' => 'Please fix the highlighted errors.', 'errors' => ['email' => 'This email is already registered.']];
                }
                // Otherwise it was the id_number primary key colliding with a
                // concurrent creation — retry with a freshly generated id.
                continue;
            }
            error_log('Bare account creation failed: ' . $e->getMessage());
            return ['status' => false, 'message' => 'A server error occurred. Please try again later.'];
        }
    }

    return ['status' => false, 'message' => 'A server error occurred. Please try again later.'];
}

// -----------------------------------------------------------------
// Validates the mandatory first-login "complete your profile" form for a
// bare Admin/Superadmin account. Mirrors validateProfileEdit()'s field
// rules (same shared helpers, so the character/casing/length rules can
// never drift from the rest of the system) but differs in three ways:
// email is required here (it's optional on a routine profile edit), a
// minimum-age check is enforced (this is first-time identity setup, same
// as public registration), and a new password is collected and hashed —
// the account owner replaces whatever temporary password the Superadmin
// set for them at creation, so that password is never known to anyone but
// its owner from this point on.
// -----------------------------------------------------------------
function validateProfileCompletion($conn, $data, $currentIdNumber, $lockedEmail = null) {
    $errors = [];
    $clean = [];

    foreach ([['first_name', 'First name', true], ['middle_name', 'Middle name', false], ['last_name', 'Last name', true]] as [$key, $label, $required]) {
        $raw = (string)($data[$key] ?? '');
        if ($raw === '') {
            if ($required) $errors[$key] = "$label is required.";
            $clean[$key] = '';
            continue;
        }
        if (hasBadSpacing($raw)) {
            $errors[$key] = "$label cannot have leading, trailing, or repeated spaces.";
            continue;
        }
        $trimmed = trim($raw);
        if (preg_match('/\d/', $trimmed)) {
            $errors[$key] = "$label: Numbers are not allowed.";
        } elseif (!isNamePart($trimmed)) {
            $errors[$key] = "$label: Special characters are not allowed.";
        } elseif (hasRepeatedChars($trimmed)) {
            $errors[$key] = "$label: The same character cannot repeat 3 or more times in a row.";
        } elseif (!hasProperWordCasing($trimmed)) {
            $errors[$key] = "$label: First letter must be uppercase, rest lowercase.";
        } elseif (mb_strlen($trimmed) < 2 || mb_strlen($trimmed) > 50) {
            $errors[$key] = "$label must be between 2 and 50 characters.";
        }
        $clean[$key] = $trimmed;
    }

    $extRaw = (string)($data['extension'] ?? '');
    $clean['extension'] = '';
    if ($extRaw !== '' && hasBadSpacing($extRaw)) {
        $errors['extension'] = "Extension cannot have leading, trailing, or repeated spaces.";
    } elseif ($extRaw !== '') {
        if (preg_match('/\d/', $extRaw)) {
            $errors['extension'] = "Extension: Numbers are not allowed.";
        } elseif (!preg_match('/^[A-Za-z]+$/', $extRaw)) {
            $errors['extension'] = "Extension: Special characters are not allowed.";
        } else {
            $normalized = strtoupper($extRaw);
            $map = [
                'JR' => 'Jr', 'SR' => 'Sr',
                'II' => 'II', 'III' => 'III', 'IV' => 'IV', 'V' => 'V',
                'VI' => 'VI', 'VII' => 'VII', 'VIII' => 'VIII', 'IX' => 'IX', 'X' => 'X',
            ];
            if (!isset($map[$normalized])) {
                $errors['extension'] = "Extension must be one of: Jr, Sr, II, III, IV, V, VI, VII, VIII, IX, X.";
            } else {
                $clean['extension'] = $map[$normalized];
            }
        }
    }

    $sex = (string)($data['sex'] ?? '');
    if (!in_array($sex, ['Male', 'Female'], true)) {
        $errors['sex'] = "Please select a valid sex.";
    }
    $clean['sex'] = $sex;

    $birthdate = (string)($data['birthdate'] ?? '');
    $clean['birthdate'] = $birthdate;
    $clean['age'] = '';
    $d = DateTime::createFromFormat('Y-m-d', $birthdate);
    if (!$birthdate || !$d || $d->format('Y-m-d') !== $birthdate) {
        $errors['birthdate'] = "Please enter a valid birthdate.";
    } else {
        $today = new DateTime('today');
        if ($d > $today) {
            $errors['birthdate'] = "Birthdate cannot be in the future.";
        } else {
            $age = $today->diff($d)->y;
            $clean['age'] = (string)$age;
            if ($age < MIN_AGE) {
                $errors['birthdate'] = "You must be at least " . MIN_AGE . " years old.";
            }
        }
    }

    [$err, $clean['street']] = validateAddressLine((string)($data['street'] ?? ''), 'Street/Purok', '/^[A-Za-z0-9][A-Za-z0-9Ññ\s.,\-\/\']*$/u', false, 100);
    if ($err) $errors['street'] = $err;

    [$err, $clean['barangay']] = validateAddressLine((string)($data['barangay'] ?? ''), 'Barangay', '/^[A-Za-z0-9][A-Za-z0-9Ññ\s.\-\']*$/u', true, 100);
    if ($err) $errors['barangay'] = $err;

    foreach ([['city', 'Municipality/City'], ['province', 'Province']] as [$key, $label]) {
        [$err, $clean[$key]] = validateAddressLine((string)($data[$key] ?? ''), $label, '/^[A-Za-zÑñ][A-Za-zÑñ\s.\-\']*$/u', false, 100, false);
        if ($err) $errors[$key] = $err;
    }

    $region = (string)($data['region'] ?? '');
    $clean['region'] = $region;
    if (!in_array($region, REGION_OPTIONS, true)) {
        $errors['region'] = "Please select a valid region.";
    }

    $zip = (string)($data['zip'] ?? '');
    $clean['zip'] = $zip;
    if ($zip === '') {
        $errors['zip'] = "Zip Code is required.";
    } elseif (preg_match('/\s/', $zip)) {
        $errors['zip'] = "Zip Code: Spaces are not allowed.";
    } elseif (preg_match('/[A-Za-z]/', $zip)) {
        $errors['zip'] = "Zip Code: Letters are not allowed.";
    } elseif (preg_match('/[^0-9]/', $zip)) {
        $errors['zip'] = "Zip Code: Special characters are not allowed.";
    } elseif (!preg_match('/^\d{4}$/', $zip)) {
        $errors['zip'] = "Zip Code must be exactly 4 digits.";
    }

    // ---- Email (required here, unlike the routine profile-edit form) ----
    // If the Superadmin already set an email when creating this account
    // (Create Account now requires one, and that's exactly where the login
    // credentials were emailed), it's locked here — never taken from
    // $data/$_POST, regardless of what the client sends, so a tampered
    // request can't smuggle a different address through. Only a
    // pre-existing account created before email collection existed (no
    // email on file yet) falls back to the original editable/required
    // behavior below.
    if ($lockedEmail !== null && $lockedEmail !== '') {
        $clean['email'] = strtolower(trim($lockedEmail));
    } else {
        $emailRaw = (string)($data['email'] ?? '');
        $email = strtolower(trim($emailRaw));
        $clean['email'] = $email === '' ? null : $email;
        if ($emailRaw === '') {
            $errors['email'] = "Email is required.";
        } elseif (hasBadSpacing($emailRaw)) {
            $errors['email'] = "Email cannot have leading, trailing, or repeated spaces.";
        } else {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $errors['email'] = "Please enter a valid email address.";
            } elseif (mb_strlen($email) > 100) {
                $errors['email'] = "Email must be at most 100 characters.";
            } elseif (!str_ends_with($email, '@' . EMAIL_DOMAIN)) {
                $errors['email'] = "Email must be a valid @" . EMAIL_DOMAIN . " address.";
            } else {
                $stmt = $conn->prepare("SELECT
                    (SELECT COUNT(*) FROM users WHERE email = ? AND id_number != ?) +
                    (SELECT COUNT(*) FROM pending_registration WHERE email = ?) AS c");
                $stmt->bind_param("sss", $email, $currentIdNumber, $email);
                $stmt->execute();
                $stmt->bind_result($count);
                $stmt->fetch();
                $stmt->close();
                if ($count > 0) {
                    $errors['email'] = "This email is already registered.";
                }
            }
        }
    }

    // ---- New password (replaces the temporary one the Superadmin set) ----
    $newPassword = (string)($data['new_password'] ?? '');
    $confirmNewPassword = (string)($data['confirm_new_password'] ?? '');
    if ($newPassword === '') {
        $errors['new_password'] = "Password is required.";
    } elseif (preg_match('/^\s|\s$/', $newPassword)) {
        $errors['new_password'] = "Password cannot start or end with a space.";
    } elseif (mb_strlen($newPassword) < 8 || mb_strlen($newPassword) > 72) {
        $errors['new_password'] = "Password must be between 8 and 72 characters.";
    } elseif (isCommonWeakPassword($newPassword)) {
        $errors['new_password'] = "This password is too common. Please choose another.";
    }

    if ($confirmNewPassword === '') {
        $errors['confirm_new_password'] = "Please re-enter your new password.";
    } elseif ($newPassword !== '' && $newPassword !== $confirmNewPassword) {
        $errors['confirm_new_password'] = "Passwords do not match.";
    }

    // ---- Security questions (no longer exempt for Admin/Superadmin) ----
    [$qErrors, $qClean] = validateSecurityQuestionFields($data);
    $errors = array_merge($errors, $qErrors);
    $clean = array_merge($clean, $qClean);

    return [$errors, $clean];
}

// -----------------------------------------------------------------
// Saves the mandatory first-login profile completion: fills in the
// confidential personal info the Superadmin never collected at creation,
// replaces the temporary password with one only the account owner knows,
// sets the security questions every Admin/Superadmin must now have, and
// flips profile_status to 'complete' so require_role() lets them through
// to their dashboard from now on.
// -----------------------------------------------------------------
function completeStaffProfile($conn, $idNumber, $clean, $rawNewPassword) {
    $hashedPassword = password_hash($rawNewPassword, PASSWORD_DEFAULT);
    $hashedA1 = hashSecurityAnswer($clean['a1_answer']);
    $hashedA2 = hashSecurityAnswer($clean['a2_answer']);
    $hashedA3 = hashSecurityAnswer($clean['a3_answer']);
    $stmt = $conn->prepare("UPDATE users SET
        first_name=?, middle_name=?, last_name=?, extension=?, sex=?, birthdate=?, age=?,
        street=?, barangay=?, city=?, province=?, region=?, zip_code=?, email=?, password=?,
        question1=?, answer1=?, question2=?, answer2=?, question3=?, answer3=?,
        profile_status='complete'
        WHERE id_number=?");
    $stmt->bind_param(
        str_repeat('s', 22),
        $clean['first_name'], $clean['middle_name'], $clean['last_name'], $clean['extension'],
        $clean['sex'], $clean['birthdate'], $clean['age'],
        $clean['street'], $clean['barangay'], $clean['city'], $clean['province'], $clean['region'],
        $clean['zip'], $clean['email'], $hashedPassword,
        $clean['a1_question'], $hashedA1, $clean['a2_question'], $hashedA2, $clean['a3_question'], $hashedA3,
        $idNumber
    );
    return $stmt->execute();
}

// -----------------------------------------------------------------
// Saves the one-time "set your security questions" gate for a pre-existing
// Admin/Superadmin account whose profile is already complete but predates
// (or was created via a path that skipped) the security-question
// requirement. Touches only the question/answer columns.
// -----------------------------------------------------------------
function saveSecurityQuestionsOnly($conn, $idNumber, $clean) {
    $hashedA1 = hashSecurityAnswer($clean['a1_answer']);
    $hashedA2 = hashSecurityAnswer($clean['a2_answer']);
    $hashedA3 = hashSecurityAnswer($clean['a3_answer']);
    $stmt = $conn->prepare("UPDATE users SET
        question1=?, answer1=?, question2=?, answer2=?, question3=?, answer3=?
        WHERE id_number=?");
    $stmt->bind_param(
        "sssssss",
        $clean['a1_question'], $hashedA1, $clean['a2_question'], $hashedA2, $clean['a3_question'], $hashedA3,
        $idNumber
    );
    return $stmt->execute();
}

// -----------------------------------------------------------------
// A public self-registration lands in pending_registration, never directly
// in `users` (see createUserAccount()'s 'pending' branch above) — it holds a
// fully validated, reserved-id_number application that isn't a real account
// yet: it can't log in and won't appear in any Accounts/Statistics query
// against `users`. The three functions below are how a reviewer's decision
// resolves that row.
// -----------------------------------------------------------------
function fetch_pending_registration($conn, $idNumber) {
    $stmt = $conn->prepare("SELECT * FROM pending_registration WHERE id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

// Approve or block-on-sight: the applicant becomes a real `users` row with
// the reviewer's chosen final status, then the pending row is gone. The
// original registration timestamp is carried over (not reset to NOW()) so
// registration history stays in true chronological order.
function promotePendingRegistration($conn, $idNumber, $status) {
    $conn->begin_transaction();
    try {
        $stmt = $conn->prepare("SELECT * FROM pending_registration WHERE id_number = ? FOR UPDATE");
        $stmt->bind_param("s", $idNumber);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if (!$row) {
            $conn->rollback();
            return null;
        }

        $stmt = $conn->prepare("INSERT INTO users (
            id_number, first_name, middle_name, last_name, extension, sex, birthdate, age,
            street, barangay, city, province, region, zip_code, email, username, password,
            role, status, profile_status, question1, answer1, question2, answer2, question3, answer3, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', ?, 'complete', ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param(
            str_repeat('s', 25),
            $row['id_number'], $row['first_name'], $row['middle_name'], $row['last_name'], $row['extension'],
            $row['sex'], $row['birthdate'], $row['age'],
            $row['street'], $row['barangay'], $row['city'], $row['province'], $row['region'],
            $row['zip_code'], $row['email'], $row['username'], $row['password'],
            $status,
            $row['question1'], $row['answer1'], $row['question2'], $row['answer2'], $row['question3'], $row['answer3'],
            $row['created_at']
        );
        $stmt->execute();

        $del = $conn->prepare("DELETE FROM pending_registration WHERE id_number = ?");
        $del->bind_param("s", $idNumber);
        $del->execute();

        $conn->commit();
        return $row;
    } catch (mysqli_sql_exception $e) {
        $conn->rollback();
        error_log('promotePendingRegistration failed: ' . $e->getMessage());
        return null;
    }
}

// Rejects the application outright — it never becomes a `users` row at all.
// The row is still returned (pre-deletion) so the caller can log the
// decision and email the applicant.
function discardPendingRegistration($conn, $idNumber) {
    $stmt = $conn->prepare("SELECT * FROM pending_registration WHERE id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$row) {
        return null;
    }

    $del = $conn->prepare("DELETE FROM pending_registration WHERE id_number = ?");
    $del->bind_param("s", $idNumber);
    $del->execute();
    return $row;
}
