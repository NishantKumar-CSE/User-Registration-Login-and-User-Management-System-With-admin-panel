# Security Advisory: Multiple SQL Injection Vulnerabilities

**Project:** User Registration and login System with admin panel
**Location:** `loginsystem/` folder (local copy scanned under `~/Downloads/User Registration and login System with admin panel`)
**Advisory ID:** (internal) SQLi-2025-UserRegLogin-01

---

## Summary

Multiple SQL Injection (CWE-89) vulnerabilities were identified across the `loginsystem/` PHP application. User-supplied input is directly embedded in SQL query strings executed with `mysqli_query()` across authentication, registration, search, profile management, and administrative user-management endpoints. This advisory documents observed issues, impact, and remediation guidance. It **does not** include exploit payloads or step‑by-step exploit instructions.

---

## Affected files (observed from static scan)

* `admin/bwdates-report-result.php`
* `admin/edit-profile.php`
* `admin/index.php`
* `admin/manage-users.php`
* `admin/lastsevendays-reg-users.php`
* `admin/lastthirtyays-reg-users.php`
* `admin/yesterday-reg-users.php`
* `admin/search-result.php`
* `admin/user-profile.php`
* `change-password.php` / `admin/change-password.php`
* `login.php`
* `signup.php`
* `password-recovery.php`

*(Total findings reported by Semgrep: 53 SQL-related issues across 28 PHP files.)*

---

## Vulnerability Type

* **CWE:** 89 (SQL Injection)
* **Nature:** Direct interpolation or concatenation of variables derived from HTTP input (GET/POST) into SQL query strings executed with `mysqli_query()`.

---

## Representative vulnerable patterns (non-exploitable snippets)

```php
// authentication
$ret = mysqli_query($con, "SELECT * FROM admin WHERE username='$adminusername' and password='$pass'");

// user lookup / deletion
$msg = mysqli_query($con, "delete from users where id='$adminid'");

// range query
$ret = mysqli_query($con, "select * from users where date(posting_date) between '$fdate' and '$tdate'");

// search
$ret = mysqli_query($con, "select * from users where (fname like '%$searchkey%' || email like '%$searchkey%')");

// registration
$msg = mysqli_query($con, "insert into users(fname,lname,email,password,contactno) values('$fname','$lname','$email','$password','$contact')");
```

---

## Observed behavior / High-level impact (non-actionable)

* Authentication endpoints use raw input inside credential-checking SQL statements.
* Search and reporting endpoints construct `SELECT` / `BETWEEN` queries using user-controllable parameters.
* Administrative pages perform `DELETE` / `UPDATE` operations using unvalidated identifiers.

**Potential impacts (based on observed query types):**

* Authentication bypass (login endpoints performing `SELECT` on username/password).
* Unauthorized data disclosure (`SELECT` queries).
* Data modification or deletion (`UPDATE` / `DELETE` / `INSERT` queries).
* Elevated impact if administrative endpoints are reachable.

**Important:** This document intentionally avoids providing exploit payloads, detailed exploitation steps, or proof-of-concept code. Use internal, controlled testing environments for validation.

---

## Advisory Text (for CVE/CNA submission)

Multiple SQL Injection vulnerabilities exist in the "User Registration and login System with admin panel" project (loginsystem folder, 28 PHP files). User input from HTTP parameters and form fields is directly interpolated into SQL queries executed via `mysqli_query()` without sanitization or parameterization. Affected endpoints include login (`login.php`, `admin/index.php`), registration (`signup.php`), password recovery (`password-recovery.php`), profile management (`admin/edit-profile.php`, `admin/user-profile.php`), user search (`admin/search-result.php`), and administrative user management (`admin/manage-users.php`, related report pages). Vulnerable code patterns include `SELECT`, `INSERT`, `UPDATE`, and `DELETE` statements where variables such as `$useremail`, `$password`, `$adminid`, `$fname`, `$lname`, `$email`, `$contact`, `$searchkey`, `$fdate`, and `$tdate` are directly used in SQL strings. Exploitation could allow attackers to bypass authentication, read or modify database records, or delete users. In total, 53 SQL injection points were identified across the scanned PHP files (CWE-89).

---

## Proof-of-Concept (POC) Policy

A detailed POC including exploit payloads or step-by-step execution is **not** included in this public advisory.

For verifiers or CNAs who require a POC, share it through a secure private channel and ensure testing is performed against an isolated test instance.

---

## Remediation Guidance

**General guidance:** prefer parameterized queries / prepared statements, validate and normalize input, and handle authentication with secure password hashing.

### Use prepared statements for `SELECT` (authentication check)

```php
$stmt = $con->prepare("SELECT id, fname FROM users WHERE email = ? AND password = ?");
$stmt->bind_param("ss", $useremail, $dec_password);
$stmt->execute();
$result = $stmt->get_result();
```

### Use prepared statements for `INSERT` (registration)

```php
$stmt = $con->prepare("INSERT INTO users (fname, lname, email, password, contactno) VALUES (?, ?, ?, ?, ?)");
$stmt->bind_param("sssss", $fname, $lname, $email, $password, $contact);
$stmt->execute();
```

### Use parameterized queries for `LIKE` searches

```php
$like = "%" . $searchkey . "%";
$stmt = $con->prepare("SELECT * FROM users WHERE fname LIKE ? OR email LIKE ? OR contactno LIKE ?");
$stmt->bind_param("sss", $like, $like, $like);
$stmt->execute();
$result = $stmt->get_result();
```

### Secure password handling

```php
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
if (password_verify($_POST['password'], $stored_hash_from_db)) {
    // authenticated
}
```

---

## Responsible Disclosure & Contact

If you are the project owner or CNA verifying this issue and require additional verification artifacts, contact the reporter via a secure channel and provide a test environment where reproductions can be safely performed.

Reported by: Nishant Kumar (https://www.linkedin.com/in/nishant-kumar-cyber/)
Tooling: Semgrep CLI (PHP + OWASP packs)
Generated: 2025-10-20
