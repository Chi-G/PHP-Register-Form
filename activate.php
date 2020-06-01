<?php 
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
session_start();
require_once('includes/connect.php');
include('recaptchalib.php');
require_once('includes/smtp.php');
// require_once('if-loggedin.php');

require 'PHPMailer-master/src/Exception.php'; 
require 'PHPMailer-master/src/PHPMailer.php';
require 'PHPMailer-master/src/SMTP.php';

//check the activation key in user_active table
$sql = "SELECT * FROM user_active WHERE active_token=:active_token AND uid=:uid";
$result = $db->prepare($sql);
$values = array(':active_token'     => $_GET['key'],
                ':uid'              => $_GET['id']
                );
$result->execute($values);
$count = $result->rowCount();
if($count == 1){
    $messages[] = "Account Exist";
    // if the activation key exists, make the user as active and remove the key
    $updsql = "UPDATE users SET activate=:activate, updated=NOW() WHERE id=:id";
    $updresult = $db->prepare($updsql);
    $values = array(':activate'     => 1,
                    ':id'          => $_GET['id']
                    );
    $updresult->execute($values);
    if($updresult){
        $messages[] = "Account Activated Successfully";
        //delete activation key from user_active table
        $delsql = "DELETE FROM user_active WHERE active_token=?";
        $delresult = $db->prepare($delsql);
        $delresult->execute(array($_GET['key']));
        $messages[] = 'Preparing your account for First Time Login';
        //adding activity in user_activity table
        $actsql = "INSERT INTO user_activity (uid, activity) VALUES (:uid, :activity)";
        $actresult = $db->prepare($actsql);
        $values = array(':uid'          => $_GET['id'],
                        ':activity'     => 'User Account Activated'
                        );
        $actresult->execute($values);
        $messages[] = 'Adding User Registration Log Entry';

        // send confirmation email to user
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
            $mail->Subject = 'Account Activated';
            $mail->Body    = 'Account Activated, Please Login';
            $mail->AltBody = 'This is the body in plain text for non-HTML mail clients';

            $mail->send();
            $messages[] = 'Activation Email sent. Please follow the instructions in your mail to continue to login page!';
        } catch (Exception $e) {
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }
} else{
    $errors[] = 'Failed to Activate Account, Please contact the site Admin';
}


?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, shrink-to-fit=no">
    <title>Confirm Activation | Apslup </title>
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

                        <h1 class="">Please Register<br/></h1>
                        <p class="signup-link">Already have an account? <a href="login.php">Log in</a></p>

                        <?php
                        if(!empty($errors)){
                            echo "<div class='alert alert-danger'>";
                            foreach ($errors as $error) {
                                echo "<span class='glyphicon glyphicon-remove'></span>&nbsp;".$error."<br>";
                            }
                            echo "</div>";
                        }
                        ?>
                        <?php
                            if(!empty($messages)){
                                echo "<div class='alert alert-success'>";
                                foreach ($messages as $message) {
                                    echo "<span class='glyphicon glyphicon-ok'></span>&nbsp;".$message."<br>";
                                }
                                echo "</div>";
                            }
                        ?>
                        
                        <p class="terms-conditions">© 2020 All Rights Reserved. <a href="index.html">APSLUP</a> is a product of <a href="mailto:chijindu.nwokeohuru@gmail.com" target="_top">chijindu nwokeohuru </a>, <a href="javascript:void(0);">Privacy</a>, and <a href="javascript:void(0);">Terms</a>.</p>

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