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
    if (empty($_POST['email'])) {
        $errors[] = "Email / Username field is Required";
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
        $sql = "SELECT * FROM users WHERE ";
        if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
            $sql .= "email=?";
        } else {
            $sql .= "username=?";
        }
        $sql .= "AND activate=1";
        $result = $db->prepare($sql);
        $result->execute(array($_POST['email']));
        $count = $result->rowCount();
        $res = $result->fetch(PDO::FETCH_ASSOC);
        $userid = $res['id'];
        if ($count == 1) {
            $messages[] = 'If Username / Email Exists in database, create reset token and send email';
             //Generating and Inserting Activation Reset Token in DB Table - password_reset
             $reset_token = md5($res['username']).time();
             $resetsql = "INSERT INTO password_reset (uid, reset_token) VALUES (:uid, :reset_token)";
             $resetresult = $db->prepare($resetsql);
             $values = array(
                 ':uid'              => $userid,
                 ':reset_token'     => $reset_token
             );
             $resetresult->execute($values);

             //Insert Activity into DB Table
             $actsql = "INSERT INTO user_activity (uid, activity) VALUES (:uid, :activity)";
             $actresult = $db->prepare($actsql);
             $values = array(
                 ':uid'          => $userid,
                 ':activity'     => 'Password Reset Initiated'
             );
             $actresult->execute($values);

             //Send Email to User
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
                 $mail->Subject = 'Reset Your Password';
                 $mail->Body    = "{$url}reset-password.php?key={$reset_token}&id={$userid}</b>";
                 $mail->AltBody = 'This is the body in plain text for non-HTML mail clients';

                 $mail->send();
                 $messages[] = "Password Reset Email sent. Please follow the instructions in your mail to continue to login page!";
             } catch (Exception $e) {
                 echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
             }
        }else {
            $errors[] = 'Sorry your account is not avaialable in our activated accounts, please check with the site Admin!';
        }
    }
}

//Create CSRF token
$token = md5(uniqid(rand(), TRUE));
$_SESSION['csrf_token'] = $token;
$_SESSION['csrf_token_time'] = time();

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, shrink-to-fit=no">
    <title>Apslup | Password Reset </title>
    <link rel="icon" type="image/x-icon" href="assets/img/favicon.ico"/>
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

                        <h1 class="">Password Reset</h1>
                        <p class="signup-link">Enter your email and instructions will sent to you!</p>

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
                                <fieldset>
                                    <div class="form">
                                        <div id="email-field" class="field-wrapper input">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-at-sign"><circle cx="12" cy="12" r="4"></circle><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"></path></svg>
                                            <input id="email" name="email" type="text" value="" placeholder="Email or Username" value="<?php if(isset($_POST['email'])){echo $_POST['email'];} ?>">
                                        </div>
                                        <div class="d-sm-flex justify-content-between">
                                            <div class="field-wrapper">
                                                <button type="submit" class="btn btn-primary" value="">Reset Password</button>
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