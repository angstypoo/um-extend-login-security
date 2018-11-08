# um-extend-login-security
This plugin extends WordPress login security by forcing users to use Google recaptcha after n unsuccessful login attempts to discourage brute force attacks.

Before you can use this plugin you need to go to https://www.google.com/recaptcha/admin and add a site

Place the sitekey and secret provided to you by google in the member variables $sitekey and $secret

You can change the lifespan of the stored list of ip's by changing the value for $lifespan (in days)

You can change the amount of time log in attempts per ip stack by changing the value for $attemptduration (in hours)

Upload this file into a folder of the same name in the Wordpress Plugin Directory to use it.

You will then just need to activate the plugin inside of your WP admin control panel.


Additional Notes:
-IP's from users that successfully log in are automatically whitelisted
-This plugin also adds functionality to login via my-account page with Woocommerce


