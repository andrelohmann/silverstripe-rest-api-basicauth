<?php

use Ntb\RestAPI\RestTest;

namespace Ntb\APIBasicAuth;

/**
 * Rest test class can work as base class for your functional tests. It provides some helpful methods to test your rest
 * api more easily.
 */
abstract class RestTest extends \Ntb\RestAPI\RestTest {

    public function setUp() {
        parent::setUp();
        // clear cache
        \SS_Cache::factory('rest_cache')->clean(\Zend_Cache::CLEANING_MODE_ALL);
    }


    /**
     * Perform an api request with the given options
     *
     * @param string $path the request path; can consist of resource name, identifier and GET params
     * @param array $options
     *  * string `body` the data
     *  * int `code` the expected response code
     *  * string `method` the http method
     *  * ApiSession `session` the test session
     *  * string `token` the auth token
     *  * array `postVars` the post data, eg. multi form or files
     * @return array
     * @throws \SS_HTTPResponse_Exception
     */
    protected function makeApiRequest($path, $options=[]) {
        $settings = array_merge([
            'session' => null,
            'token' => null,
            'method' => 'GET',
            'body' => null,
            'postVars' => null,
            'code' => 200
        ], $options);
        $headers = [
            'Accept' => 'application/json'
        ];
        if($settings['token']) {
            $headers['Authorization'] = "Basic {$settings['token']}";
        }
        $response = \Director::test(
            $path,
            $settings['postVars'],
            $settings['session'],
            $settings['method'],
            $settings['body'],
            $headers
        );

        $this->assertEquals($settings['code'], $response->getStatusCode(), "Wrong status code: {$response->getBody()}");
        return json_decode($response->getBody(), true);
    }

    /**
     * Creates a session for the api.
     *
     * @param string $email the email of the user
     * @param string $password the password for the user
     * @return array the current session with `token`
     */
    protected function createSession($email='considine.colby@gmail.com', $password='password') {
        return ['token' => base64_encode($email.":".$password)];
    }
}
