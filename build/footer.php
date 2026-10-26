<!-- GLOBAL JS -->
<script src="/SECURITY/HTML_PHP/js/login.js"></script>
<script src="/SECURITY/HTML_PHP/js/password_register.js"></script>
<script src="/SECURITY/HTML_PHP/js/personal_information_register.js"></script>
<script src="/SECURITY/HTML_PHP/js/security_question_register.js"></script>
<script src="/SECURITY/HTML_PHP/js/address_account_register.js"></script>
<script src="/SECURITY/HTML_PHP/js/forgot_password.js"></script>

<?php
if (!empty($page_js)) {
    echo '<script src="/SECURITY/HTML_PHP/js/' . htmlspecialchars($page_js) . '"></script>';
}
?>

</body>
</html>
