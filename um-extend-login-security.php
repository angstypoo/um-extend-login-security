<?php
/**
 *
 *
 *
 * @link              umethod.net
 * @since             1.0.0
 * @package           Um-Extend-Login-Security
 *
 * @wordpress-plugin
 * Plugin Name:       Extend WP Login Security Upsell by Umethod
 * Plugin URI:        umethod.net
 * Description:       This plugin allows extends WP login security by forcing users to use Google recaptcha after n unsuccessful login attempts to discourage brute force attacks.
 * Version:           1.0.0
 * Author:            Bryce Leue
 * Author URI:        umethod.net
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       um-extend-login-security
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
  die;
}

class Um_Extend_Login_Security {

  protected $version = '1.0.0';

  protected $plugin_name = 'um-extend-login-security';

  protected $sitekey = ''; //GOOGLE RECAPTCHA SITEKEY

  protected $secret = ''; //GOOGLE RECAPTCHA SECRET

  protected static $iptablename = 'umextendloginsecurity';

  protected $maxattempts = 3;

  //how long do you want to keep the list of ip's? (in days - must have a minimum length)
  //this includes the whitelist, and any ip that has failed a login attempt with its number of failed attempts
  protected $lifespan = 7;

  //how long do you want to view the count of failed log in attempts per ip as relevant? (in hours)
  protected $attemptduration = 24;

  public function __construct() {
    //convert lifespan and attemptduration to seconds for use with time();
    $this->lifespan = $this->lifespan * 24 * 60 * 60;
    $this->attemptduration = $this->attemptduration * 60 * 60;
  }

  public static function activate() {
    global $wpdb;

    $table = $wpdb->prefix . self::$iptablename;

    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table (
       ID INT( 11 ) AUTO_INCREMENT PRIMARY KEY,
       title TEXT NOT NULL,
       value TEXT NOT NULL
    ) $charset_collate;";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

    dbDelta( $sql );

    $iplistarr = array(
      'master' => array(
        'refreshed' => time()
      ),
      'list' => array()
    );
    $iplistarr = base64_encode(serialize($iplistarr));

    $wpdb->replace(
      $table,
      array(
        'title' => 'iplist',
        'value' => $iplistarr
      )
    );

  }
  public static function deactivate() {
    global $wpdb;
    $table = $wpdb->prefix . self::$iptablename;

    $wpdb->query( "DROP TABLE IF EXISTS $table" );
  }

  private function get_client_ip() {

    //check ip from share internet
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
      $ip=$_SERVER['HTTP_CLIENT_IP'];

    //to check ip is pass from proxy
    } else if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $ip=$_SERVER['HTTP_X_FORWARDED_FOR'];

    } else {
      $ip=$_SERVER['REMOTE_ADDR'];
    }

    return $ip;
  }

  private function checkrecaptcha($response) {
     $clientip = $this->get_client_ip();
     $recaptchadata = array(
       'secret' => $this->secret,
       'response' => $response,
       'remoteip' => $this->get_client_ip()
     );
     $recaptchaurl = 'https://www.google.com/recaptcha/api/siteverify';
     $connection = curl_init($recaptchaurl);
     $postdata = http_build_query($recaptchadata);
     curl_setopt($connection, CURLOPT_POST, 1);
     curl_setopt($connection, CURLOPT_POSTFIELDS, $postdata);
     curl_setopt($connection, CURLOPT_RETURNTRANSFER, true);
     $response = curl_exec($connection);
     curl_close($connection);
     $array = json_decode($response, true);
     $valid = ($array['success']==true) ? 1 : 0;
     return $valid;
   }

  public function google_recaptcha_div() {
    echo '<div style="height:auto;overflow:visible;" class="g-recaptcha" data-sitekey="'.$this->sitekey.'"></div>';
  }

  private function update_user_attempts() {
    //grab the iplist array
    global $wpdb;
    $table = $wpdb->prefix . self::$iptablename;
    $sql = "SELECT * FROM ".$table." WHERE title='iplist'";
    $iprow = $wpdb->get_row($sql);
    $id = $iprow->ID;
    $iplist = $iprow->value;
    $iplist = unserialize(base64_decode($iplist));
    $ipmaster = $iplist['master'];
    $time = time();
    $ipexists = false;
    $clientip = $this->get_client_ip();
    //reset list every $this->lifespan days
    if($time > $ipmaster['refreshed']+$this->lifespan || !$iplist) {
      $iplist = array(
        'master' => array(
          'refreshed' => time()
        ),
        'list' => array(),
        'whitelist' => array()
      );
      //add current user ip if refreshing
      $iplist['list'][$clientip] = array (
        'lastattempt' => $time,
        'attempts' => 1
      );
      $ipexists = true;
    }

    //if the list has not just been refreshed check for existence of ip and update
    if(!$ipexists) {
      $resetting = false;
      //ip exists
      if(array_key_exists($clientip, $iplist['list'])) {
        $ipexists = true;
        //reset if not attempted for $this->attemptduration hours
        if($iplist['list'][$clientip]['lastattempt']+$this->attemptduration < $time) {
          $resetting = true;
          $iplist['list'][$clientip] = array (
            'lastattempt' => $time,
            'attempts' => 1
          );
        }
        //append attempt if not resetting
        if(!$resetting) {
          $iplist['list'][$clientip] = array (
            'lastattempt' => $time,
            'attempts' => $iplist['list'][$clientip]['attempts']+1
          );
        }

      }
    }

    //if the ip still is not present add new
    if(!$ipexists) {
      //add current user ip
      $iplist['list'][$clientip] = array (
        'lastattempt' => $time,
        'attempts' => 1
      );
    }
    $iplist = base64_encode(serialize($iplist));

    //update the iplist
    $wpdb->replace(
      $table,
      array(
        'ID' => $id,
        'title' => 'iplist',
        'value' => $iplist
      )
    );
  }

  private function whitelist_ip() {
    //grab the iplist array
    global $wpdb;
    $table = $wpdb->prefix . self::$iptablename;
    $sql = "SELECT * FROM ".$table." WHERE title='iplist'";
    $iprow = $wpdb->get_row($sql);
    $id = $iprow->ID;
    $iplist = $iprow->value;
    $iplist = unserialize(base64_decode($iplist));
    $time = time();
    $clientip = $this->get_client_ip();

    $iplist['whitelist'][$clientip] = 1;

    $iplist = base64_encode(serialize($iplist));

    //update the iplist
    $wpdb->replace(
      $table,
      array(
        'ID' => $id,
        'title' => 'iplist',
        'value' => $iplist
      )
    );
  }

  private function is_ip_whitelisted() {
    //grab the iplist array
    global $wpdb;
    $table = $wpdb->prefix . self::$iptablename;
    $sql = "SELECT * FROM ".$table." WHERE title='iplist'";
    $iprow = $wpdb->get_row($sql);
    $id = $iprow->ID;
    $iplist = $iprow->value;
    $iplist = unserialize(base64_decode($iplist));
    $time = time();
    $clientip = $this->get_client_ip();

    if(array_key_exists('whitelist', $iplist)) {
      if(array_key_exists($clientip, $iplist['whitelist'])) return true;
    }

    return false;

  }

  private function get_user_attempts() {
    //grab the iplist array
    global $wpdb;
    $table = $wpdb->prefix . self::$iptablename;
    $sql = "SELECT * FROM ".$table." WHERE title='iplist'";
    $iplist = $wpdb->get_row($sql)->value;
    $iplist = unserialize(base64_decode($iplist));
    $clientip = $this->get_client_ip();
    if(array_key_exists($clientip, $iplist['list'])) {
      return $iplist['list'][$clientip]['attempts'];
    } else {
      return 0;
    }
  }

  public function login_callback($user) {
    //current number of previous attempts
    $attempts = $this->get_user_attempts();

    //max attempts exceeded
    if($attempts > $this->maxattempts) {
      //response 0 in case post var is not set
      $response=0;
      //check for valid response
      if(isset($_POST['g-recaptcha-response'])) {
        $response = $this->checkrecaptcha($_POST['g-recaptcha-response']);
      }
      //valid response
      if($response) {
        //whitelist ip
        $this->whitelist_ip();
        return $user;

      //invalid response
      } else {
        $this->update_user_attempts();
        global $wp_error;
        $wp_error = new WP_Error();
        $wp_error->add('error', 'Recaptcha error');
        return $wp_error;
      }

    //still within allowed attempts
    } else {
      $this->update_user_attempts();
      return $user;
    }

  }

  public function enqueue_google_js() {
    wp_enqueue_script('google-recaptcha', 'https://www.google.com/recaptcha/api.js', array(), '3', true);
  }

  public function add_security_measures() {
    if($this->is_ip_whitelisted()) return;
    if(is_user_logged_in()) return;
    if($this->get_user_attempts()>=$this->maxattempts) {
      add_action('login_enqueue_scripts', array($this, 'enqueue_google_js'));
      add_action('login_form', array($this, 'google_recaptcha_div'));
    }
    add_filter('authenticate', array($this, 'login_callback'), 100);
    //Woocommerce compatibility
    if ( in_array( 'woocommerce/woocommerce.php', apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) ) {
      if($this->get_user_attempts()>=$this->maxattempts) {
        add_action('wp_enqueue_scripts', array($this, 'enqueue_google_js'));
        add_action('woocommerce_login_form', array($this, 'google_recaptcha_div'));
      }
    }
  }



  public function run() {
    add_action('init', array($this, 'add_security_measures'));
  }



}

function activate_um_extend_login_security() {
  Um_Extend_Login_Security::activate();
}

function deactivate_um_extend_login_security() {
  Um_Extend_Login_Security::deactivate();
}

register_activation_hook( __FILE__, 'activate_um_extend_login_security' );
register_deactivation_hook( __FILE__, 'deactivate_um_extend_login_security' );

function run_um_extend_login_security() {
  $plugin = new Um_Extend_Login_Security();
  $plugin->run();
}

//run teh plugin
run_um_extend_login_security();
