<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

session_start();
require_once('includes/connect.php');
require_once('includes/smtp.php');
// require_once('if-loggedin.php');

require 'PHPMailer-master/src/Exception.php';
require 'PHPMailer-master/src/PHPMailer.php';
require 'PHPMailer-master/src/SMTP.php';

$url = "https://apslup.com/";

if (isset($_POST) & !empty($_POST)) {
    if (empty($_POST['password'])) {
        $errors[] = "Password field is Required";
    } else {
        // check the repeat password
        if (empty($_POST['passwordr'])) {
            $errors[] = "Repeat Password field is Required";
        } else {
            // compare both passwords, if they match. Generate the Password Hash
            if ($_POST['password'] == $_POST['passwordr']) {
                // create password hash
                $pass_hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
            } else {
                // Display Error Message
                $errors[] = "Both Passwords Should Match";
            }
        }
    }

    // CSRF Token Validation
    if (isset($_POST['csrf_token'])) {
        if ($_POST['csrf_token'] === $_SESSION['csrf_token']) {
        } else {
            $errors[] = "Problem with CSRF Token Validation";
        }
    }
    // CSRF Token Time Validation
    $max_time = 60 * 60 * 24; // in seconds
    if (isset($_SESSION['csrf_token_time'])) {
        $token_time = $_SESSION['csrf_token_time'];
        if (($token_time + $max_time) >= time()) {
        } else {
            $errors[] = "CSRF Token Expired";
            unset($_SESSION['csrf_token']);
            unset($_SESSION['csrf_token_time']);
        }
    } else {
        unset($_SESSION['csrf_token']);
        unset($_SESSION['csrf_token_time']);
    }

    if (empty($errors)) {
        // Update the password after submitting new password
        $sql = "SELECT * FROM password_reset WHERE reset_token=:reset_token AND uid=:uid";
        $result = $db->prepare($sql);
        $values = array(
            ':reset_token'     => $_POST['key'],
            ':uid'             => $_POST['id']
        );
        $result->execute($values);
        $count = $result->rowCount();
        if ($count == 1) {
            // Update the password here
            $updsql = "UPDATE users SET password=:activate, password=NOW() WHERE id=:id";
            $updresult = $db->prepare($updsql);
            $values = array(
                ':password'     => $pass_hash,
                ':id'          => $_POST['id']
                            );
            $updres = $updresult->execute($values);
            if($updres){
                //Inserting Activity into Database Table
                $actsql = "INSERT INTO user_activity (uid, activity) VALUES (:uid, :activity)";
                $actresult = $db->prepare($actsql);
                $values = array(
                    ':uid'          => $_POST['id'],
                    ':activity'     => 'Password Updated with Reset Password'
                );
                $actresult->execute($values);

                //deleting the reset token password_reset table
                $delsql = "DELETE FROM password_reset WHERE reset_token=?";
                $delresult = $db->prepare($delsql);
                $delres = $delresult->execute(array($_POST['key']));
                if($delres){
                    // send email
                    $mail = new PHPMailer(true);

                    try {
                        //Server settings
                        $mail->isSMTP();                                            // Send using SMTP
                        $mail->Host       = $smtphost;                              // Set the SMTP server to send through
                        $mail->SMTPAuth   = true;                                   // Enable SMTP authentication
                        $mail->Username   = $smtpuser;                              // SMTP username
                        $mail->Password   = $smtppass;                              // SMTP password
                        $mail->SMTPSecure = 'tls';                                  // Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` encouraged
                        $mail->Port       = 587;                                    // TCP port to connect to, use 465 for `PHPMailer::ENCRYPTION_SMTPS` above
            
                        //Recipients
                        $mail->setFrom($_POST['email']);
                        //Update recipient email with dynamic email
                        $mail->addAddress('chijindu.nwokeohuru@apslup.com', 'Chijindu Nwokeohuru');     // Add a recipient
            
                        // Content
                        $mail->isHTML(true);                                  // Set email format to HTML
                        $mail->Subject = 'Password Updated';
                        $mail->Body    = 'Account Acccount password Updated successfully, Please Login to your account';
                        $mail->AltBody = 'This is the body in plain text for non-HTML mail clients';
            
                        $mail->send();
                        $messages[] = 'Password Update Confirmation Email Sent!';
                    } catch (Exception $e) {
                        echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
                    }
                }
            }
        } else {
            $errors[] = 'There is problem with Reset Token, Contact Site Admin!';
        }
    }
}

//Create CSRF token
$token = md5(uniqid(rand(), TRUE));
$_SESSION['csrf_token'] = $token;
$_SESSION['csrf_token_time'] = time();

//fetch the usern details from database and display them in disabled input fields, username & email
$sql = "SELECT * FROM password_reset WHERE reset_token=:reset_token AND uid=:uid";
$result = $db->prepare($sql);
$values = array(
    ':reset_token'     => $_GET['key'],
    ':uid'             => $_GET['id']
);
$result->execute($values);
$count = $result->rowCount();
if ($count == 1) {
    // Select SQL query to fetch user details from users table using user id
    $usersql = "SELECT * FROM users WHERE id=? AND activate=1";
    $userresult = $db->prepare($usersql);
    $userresult->execute(array($_GET['id']));
    $usercount = $userresult->rowCount();
    $userres = $userresult->fetch(PDO::FETCH_ASSOC);
    if ($usercount == 1) {
        // $messages[] = 'Do nothing, but display the details in form';
    } else {
        $errors[] = 'Your Account is not active, Please activate before resetting your password';
    }
} else {
    $errors[] = 'There is problem with Reset Token, Contact Site Admin!';
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, shrink-to-fit=no">
    <title>Apslup | Update Password </title>
    <link rel="icon" type="image/x-icon" href="assets/img/favicon.ico" />
    <!-- BEGIN GLOBAL MANDATORY STYLES -->
    <link href="https://fonts.googleapis.com/css?family=Nunito:400,600,700" rel="stylesheet">
    <link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" type="text/css" />
    <link href="assets/css/plugins.css" rel="stylesheet" type="text/css" />
    <link href="assets/css/authentication/form-1.css" rel="stylesheet" type="text/css" />
    <!-- END GLOBAL MANDATORY STYLES -->
    <link rel="stylesheet" type="text/css" href="assets/css/forms/theme-checkbox-radio.css">
    <link rel="stylesheet" type="text/css" href="assets/css/forms/switches.css">
</head>

<body class="form">


    <div class="form-container">
        <div class="form-form">
            <div class="form-form-wrap">
                <div class="form-container">
                    <div class="form-content">

                        <h1 class="">Update Password</h1>
                        <p class="signup-link">Enter your new password!</p>

                        <?php
                        if (!empty($errors)) {
                            echo "<div class='alert alert-danger'>";
                            foreach ($errors as $error) {
                                echo "<span class='glyphicon glyphicon-remove'></span>&nbsp;" . $error . "<br>";
                            }
                            echo "</div>";
                        }
                        ?>
                        <?php
                        if (!empty($messages)) {
                            echo "<div class='alert alert-success'>";
                            foreach ($messages as $message) {
                                echo "<span class='glyphicon glyphicon-ok'></span>&nbsp;" . $message . "<br>";
                            }
                            echo "</div>";
                        }
                        ?>

                        <form class="text-left" method="POST" role="form">
                            <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                            <input type="hidden" name="key" value="<?php echo $_GET['key']; ?>">
                            <input type="hidden" name="id" value="<?php echo $_GET['id']; ?>">
                            <fieldset>
                                <div class="form">
                                    <div id="username-field" class="field-wrapper input">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-user">
                                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                            <circle cx="12" cy="7" r="4"></circle>
                                        </svg>
                                        <input id="username" name="username" type="text" autofocus disabled placeholder="Username" value="<?php if (isset($userres['username'])) {
                                                                                                                                                echo $userres['username'];
                                                                                                                                            } ?>">
                                    </div>
                                    <div id="email-field" class="field-wrapper input">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-at-sign">
                                            <circle cx="12" cy="12" r="4"></circle>
                                            <path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"></path>
                                        </svg>
                                        <input id="email" name="email" type="text" autofocus disabled placeholder="Email" value="<?php if (isset($userres['email'])) {
                                                                                                                                        echo $userres['email'];
                                                                                                                                    } ?>">
                                    </div>
                                    <div id="password-field" class="field-wrapper input mb-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-lock">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                                        </svg>
                                        <input class="form-control" placeholder="Password" name="password" type="password" value="">
                                    </div>
                                    <div id="password-field" class="field-wrapper input mb-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-key">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
                                        </svg>
                                        <input class="form-control" placeholder="Repeat Password" name="passwordr" type="password" value="">
                                    </div>
                                    <div class="d-sm-flex justify-content-between">
                                        <div class="field-wrapper">
                                            <button type="submit" class="btn btn-primary" value="">Change Password</button>
                                        </div>
                                    </div>
                                </div>
                            </fieldset>
                        </form>
                        <p class="terms-conditions">© 2020 All Rights Reserved. <a href="index.php">APSLUP</a> is a product of <a href="mailto:chijindu.nwokeohuru@gmail.com" target="_top">chijindu nwokeohuru </a>, <a href="pages_privacy.html">Privacy</a>, and <a href="pages_privacy.html">Terms</a>.</p>

                    </div>
                </div>
            </div>
        </div>
        <div class="form-image">
            <div class="l-image">
            </div>
        </div>
    </div>

    <!-- BEGIN GLOBAL MANDATORY SCRIPTS -->
    <script src="assets/js/libs/jquery-3.1.1.min.js"></script>
    <script src="bootstrap/js/popper.min.js"></script>
    <script src="bootstrap/js/bootstrap.min.js"></script>

    <!-- END GLOBAL MANDATORY SCRIPTS -->
    <script src="assets/js/authentication/form-1.js"></script>

</body>

</html>