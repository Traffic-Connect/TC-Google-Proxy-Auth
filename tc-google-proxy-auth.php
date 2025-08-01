<?php

/**
 * Plugin Name: TC Google Proxy Auth
 * Description: Авторизация Google в админ панель
 * Version: 1.0.3
 * Author: Traffic Connect
 */

defined( 'ABSPATH' ) || exit;

class AuthGoogle {

	private $token = '';
	private $urlRedirect = '';
	private $accessDomain = '';
	private $managerUrl = '';
	private $managerToken = '';
	private $cacheKey = '';

	public function __construct() {

		//

	}

	public function init() {
		add_action( 'init', [ $this, 'oauth_init' ] );
		add_action( 'login_form', [ $this, 'login_form' ] );
		add_action( 'login_message', [ $this, 'login_message' ] );
		add_action( 'login_enqueue_scripts', [ $this, 'login_enqueue_scripts' ] );

		add_action( 'login_head', [ $this, 'hide_form_login' ] );
		add_action( 'init', [ $this, 'auth_redirect_url' ] );
	}

	public function auth_redirect_url() {

		if ( ! is_user_logged_in() && isset( $_GET['auth_google'] ) && $_GET['auth_google'] == 1 ) {
			$redirect  = esc_url( site_url( '/wp-login.php' ) );
			$oauth_url = sprintf( '%s?redirect=%s', $this->urlRedirect, $redirect );
			wp_redirect( $oauth_url );
			exit;
		}
	}

	private function get_current_url_with_param() {

		$scheme = ( ! empty( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] !== 'off' ) ? "https" : "http";
		$host   = $_SERVER['HTTP_HOST'];
		$uri    = $_SERVER['REQUEST_URI'];
		$url    = $scheme . "://" . $host . $uri;

		$url = add_query_arg( 'auth_google', '1', $url );

		return $url;
	}

	/**
	 * Outputs custom CSS styles to adjust the appearance of the login error message.
	 *
	 * @return void
	 */
	public function login_enqueue_scripts() {
		?>
		<style>
			#login_error {
				background-color: #f8d7da;
				border-left: 4px solid #dc3545;
				color: #721c24;
				padding: 12px;
				margin-bottom: 20px;
				font-weight: bold;
				border-radius: 4px;
			}
			.google-login-button-wrapper {
				margin-bottom: 20px !important;
				text-align: center;
				box-sizing: border-box;
			}

			.google-login-button {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				background-color: #ffffff;
				color: #3c4043;
				border: 1px solid #dadce0;
				font-size: 14px;
				font-weight: 500;
				padding: 10px 16px !important;
				border-radius: 4px;
				text-decoration: none;
				width: 100%;
				max-width: 100%;
				box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
				transition: background-color 0.2s ease, box-shadow 0.2s ease;
				box-sizing: border-box;
			}

			.google-login-button:hover {
				background-color: #f7f8f8;
				box-shadow: 0 1px 3px rgba(0, 0, 0, 0.15);
			}

			.google-login-button .google-icon {
				height: 18px;
				width: 18px;
				margin-right: 10px;
				background-color: transparent;
				box-sizing: border-box;
			}

			.google-login-button span {
				white-space: nowrap;
				box-sizing: border-box;
			}
		</style>
		<?php
	}

	/**
	 * Modifies the login message displayed on the login screen based on the presence of an error query parameter.
	 *
	 * @param  string  $message  The original login message.
	 *
	 * @return string The modified or original login message.
	 */
	public function login_message( $message ) {
		if ( isset( $_GET['error'] ) ) {
			$error = sanitize_text_field( $_GET['error'] );

			return '<div id="login_error">' . esc_html( $error ) . '</div>';
		}

		return $message;
	}

	/**
	 * @return void
	 */
	public function oauth_init(): void {
		if ( is_user_logged_in() ) {
			return;
		}

		if ( isset( $_GET['oauth_token'] ) ) {

			//Get Email
			$email = $this->decryptToken( $_GET['oauth_token'] );

			//Get Role
			$role = $this->decryptToken( $_GET['role'] );

			//Get Teams
			$teams = $this->decryptToken( $_GET['teams'] );
			$teams = explode( ',', $teams );


			$api = get_transient( $this->cacheKey );

			if ( $email && str_ends_with( $email, sprintf( '@%s', $this->accessDomain ) ) ) {
				$user = get_user_by( 'email', $email );

				if ( $user ) {
					wp_set_auth_cookie( $user->ID, true );
					wp_redirect( admin_url() );
					exit;
				}

				if ( $api === false || ! isset( $api['team'] ) ) {
					wp_redirect( site_url( '/wp-login.php?error=' . urlencode( 'The site is not in the manager software.' ) ) );
					exit;
				}

				if ( empty( $teams ) || ! in_array( $api['team'], $teams ) ) {
					wp_redirect( site_url( '/wp-login.php?error=' . urlencode( 'The command doesn\'t match' ) ) );
					exit;
				}

				if ( empty( $role ) ) {
					wp_redirect( site_url( '/wp-login.php?error=' . urlencode( 'Role not found' ) ) );
					exit;
				}

				if ( $role == 'administrator' ) {
					$user = get_user_by( 'login', 'administrator' );
					if ( $user ) {
						wp_set_auth_cookie( $user->ID, true );
						wp_redirect( admin_url() );
						exit;
					}
				}

				if ( $role == 'editor' ) {
					$user = get_user_by( 'login', 'editor' );
					if ( $user ) {
						wp_set_auth_cookie( $user->ID, true );
						wp_redirect( admin_url() );
						exit;
					}
				}

				$users = get_users( [
					'number'  => 1,
					'orderby' => 'user_registered',
					'order'   => 'ASC',
				] );
				$user  = $users[0] ?? null;

				if ( $user ) {
					wp_set_auth_cookie( $user->ID, true );
					wp_redirect( admin_url() );
					exit;

				}

				wp_redirect( site_url( '/wp-login.php?error=' . urlencode( 'Unknown error. Please contact your administrator.' ) ) );
				exit;

			} else {

				wp_redirect( site_url( '/wp-login.php?error=' . urlencode( 'Invalid email.' ) ) );
				exit;

			}
		}


		if ( isset( $_GET['error'] ) ) {
			add_filter( 'login_errors', function () {
				return sanitize_text_field( $_GET['error'] );
			} );
		}
	}

	/**
	 * @return void
	 */
	public function login_form(): void {

		$url = $this->get_current_url_with_param();

		echo '<div class="google-login-button-wrapper">';
		echo '<a href="' . esc_url( $url ) . '" class="google-login-button">';
		echo '<img src="https://developers.google.com/identity/images/g-logo.png" alt="Google" class="google-icon" />';
		echo '<span>Войти через Google</span>';
		echo '</a>';
		echo '</div>';

	}

	/**
	 * Decrypts a given token using AES-256-CBC encryption algorithm.
	 *
	 * @param  string  $token  The base64 encoded token to decrypt.
	 *
	 * @return string|false The decrypted string if successful, or false on failure.
	 */
	private function decryptToken( $token ): bool|string {
		$key = $this->token;
		$iv  = substr( $key, 0, 16 );

		$decoded = base64_decode( $token );
		if ( ! $decoded ) {
			return false;
		}

		return openssl_decrypt( $decoded, 'aes-256-cbc', $key, 0, $iv );
	}

	public function hide_form_login() {

		$site_url = site_url();
		$domain   = parse_url( $site_url, PHP_URL_HOST );

		//delete_transient($this->cacheKey);
		$api = get_transient( $this->cacheKey );

		if ( $api === false ) {
			$url      = sprintf( '%s/api/site/team?domain=%s', $this->managerUrl, $domain );
			$response = wp_remote_get( $url, [
				'headers' => [
					'Authorization' => 'Bearer ' . $this->managerToken,
					'Accept'        => 'application/json',
				],
				'timeout' => 10,
			] );

			if ( is_wp_error( $response ) ) {
				$api = null;
			}

			$body = json_decode( wp_remote_retrieve_body( $response ), true );

			$data = isset( $body['auth_type'] ) ? $body : null;

			// Save Cache 10 minutes
            if(is_null($api))
            {
                delete_transient($this->cacheKey);
            }else{
                set_transient( $this->cacheKey, $data, 1 * MINUTE_IN_SECONDS );
            }

			$api = $data;
		}

		if ( isset( $api['auth_type'] ) && $api['auth_type'] == 'sso' ) {
			echo '<style>
            #loginform label[for="user_login"],
            #user_login,
             #loginform label[for="user_pass"],
             #user_pass,
              #loginform .forgetmenot,
               #loginform .submit {
                display: none !important;
            }
        </style>';
		}

		if ( isset( $api['auth_type'] ) && $api['auth_type'] == 'form' ) {
			remove_action( 'init', [ $this, 'oauth_init' ] );
			remove_action( 'login_form', [ $this, 'login_form' ] );
			remove_action( 'login_message', [ $this, 'login_message' ] );
			remove_action( 'login_enqueue_scripts', [ $this, 'login_enqueue_scripts' ] );
			remove_action( 'init', [ $this, 'auth_redirect_url' ] );
		}
	}

}

$auth = new AuthGoogle();
$auth->init();
