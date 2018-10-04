<?php

use Ntb\RestAPI\IAuth;
use Ntb\RestAPI\ApiSession;
use Ntb\RestAPI\AuthFactory;
use Ntb\RestAPI\RestUserException;

namespace Ntb\APIBasicAuth;

/**
 * Authentication mechanism using a BasicAuth request.
 *
 * @author Andre Lohmann <lohmann.andre@gmail.com>
 */
class BasicAuth extends \Object implements \Ntb\RestAPI\IAuth {

        public static function authenticate($key, $secret) {
            $authenticator = \Injector::inst()->get('ApiMemberAuthenticator');
            if($member = $authenticator->authenticate(['Email' => $key, 'Password' => $secret])) {
                    return self::createSession($member);
            }
        }

	/**
	 * @param \Member $user
	 * @return ApiSession
	 */
	public static function createSession($user) {
		$user->logIn();
		/** @var \Member $user */
		$user = \DataObject::get(Config::inst()->get('BaseRestController', 'Owner'))->byID($user->ID);

		// create session
		$session = \Ntb\RestAPI\ApiSession::create();
		$session->User = $user;
		$session->Token = \Ntb\RestAPI\AuthFactory::generate_token($user);

		return $session;
	}

	public static function delete($request) {
            $owner = self::current($request);
            if(!$owner) {
                throw new \Ntb\RestAPI\RestUserException("No session found", 404, 404);
            }
            $owner->logOut();
            return true;
        }


        /**
         * @param SS_HTTPRequest $request
         * @return Member
         */
        public static function current($request) {
            $member = self::getBasicAuth($request);
            return ($member instanceof \Member) ? \DataObject::get(\Config::inst()->get('BaseRestController', 'Owner'))->byID($member->ID) : null;
        }

        /**
         * @param SS_HTTPRequest $request
         * @return Member
         */
        protected static function getBasicAuth($request){

            // Check for running test
            $isRunningTests = (class_exists('\SapphireTest', false) && \SapphireTest::is_running_test());
            if($isRunningTests){
                $headers = $request->getheaders();
                if(isset($headers['Authorization'])){
                  $authHeader = $headers['Authorization'];
                }else{
                  $authHeader = null;
                }
            }else{
                /*
                 * Enable HTTP Basic authentication workaround for PHP running in CGI mode with Apache
                 * Depending on server configuration the auth header may be in HTTP_AUTHORIZATION or
                 * REDIRECT_HTTP_AUTHORIZATION
                 *
                 * The follow rewrite rule must be in the sites .htaccess file to enable this workaround
                 * RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
                 */
                $authHeader = (isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] :
                              (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : null));
            }

            $matches = array();
            if ($authHeader &&
                    preg_match('/Basic\s+(.*)$/i', $authHeader, $matches)) {
                    list($name, $password) = explode(':', base64_decode($matches[1]));
                    $_SERVER['PHP_AUTH_USER'] = strip_tags($name);
                    $_SERVER['PHP_AUTH_PW'] = strip_tags($password);
            }
            $member = null;
            if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
                    $authenticator = \Injector::inst()->get('ApiMemberAuthenticator');
                    if($member = $authenticator->authenticate([
                        'Email' => $_SERVER['PHP_AUTH_USER'],
                        'Password' => $_SERVER['PHP_AUTH_PW']
                    ])){
                        if($member->canLogIn()){
                          $member->logIn();
                          return $member;
                        }
                        return null;
                    }
            }
            return $member;
        }

}
