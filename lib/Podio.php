<?php

/**
 * @deprecated replace 'Podio::' with 'PodioInstance->getInstance()'
 */
class Podio
{
    /**
     * @deprecated use e.g. PodioInstance::setOauth
     */
    public static $oauth, $debug, $logger, $session_manager, $last_response, $auth_type;

    const VERSION = '4.1.0';

    const GET = 'GET';
    const POST = 'POST';
    const PUT = 'PUT';
    const DELETE = 'DELETE';

    public static function setup($client_id, $client_secret, $options = array('session_manager' => null, 'curl_options' => array()))
    {
        PodioInstance::getInstance()->setup($client_id, $client_secret, $options);
    }

    public static function authenticate_with_app($app_id, $app_token)
    {
        PodioInstance::getInstance()->authenticate_with_app($app_id, $app_token);
    }

    public static function authenticate_with_password($username, $password)
    {
        PodioInstance::getInstance()->authenticate_with_password($username, $password);
    }

    public static function authenticate_with_authorization_code($authorization_code, $redirect_uri)
    {
        PodioInstance::getInstance()->authenticate_with_authorization_code($authorization_code, $redirect_uri);
    }

    public static function refresh_access_token()
    {
        PodioInstance::getInstance()->refresh_access_token();
    }

    public static function authenticate($grant_type, $attributes)
    {
        PodioInstance::getInstance()->authenticate($grant_type, $attributes);
    }

    public static function clear_authentication()
    {
        PodioInstance::getInstance()->clear_authentication();
    }

    public static function authorize_url($redirect_uri)
    {
        PodioInstance::getInstance()->authorize_url($redirect_uri);
    }

    public static function is_authenticated()
    {
        PodioInstance::getInstance()->is_authenticated();
    }

    public static function request($method, $url, $attributes = array(), $options = array())
    {
        PodioInstance::getInstance()->request($method, $url, $attributes, $options);
    }

    public static function get($url, $attributes = array(), $options = array())
    {
        PodioInstance::getInstance()->get($url, $attributes, $options);
    }

    public static function post($url, $attributes = array(), $options = array())
    {
        PodioInstance::getInstance()->post($url, $attributes, $options);
    }

    public static function put($url, $attributes = array())
    {
        PodioInstance::getInstance()->put($url, $attributes);
    }

    public static function delete($url, $attributes = array())
    {
        PodioInstance::getInstance()->delete($url, $attributes);
    }

    public static function curl_headers()
    {
        PodioInstance::getInstance()->curl_headers();
    }

    public static function encode_attributes($attributes)
    {
        PodioInstance::getInstance()->encode_attributes($attributes);
    }

    public static function url_with_options($url, $options)
    {
        PodioInstance::getInstance()->url_with_options($url, $options);
    }

    public static function parse_headers($headers)
    {
        PodioInstance::getInstance()->parse_headers($headers);
    }

    public static function rate_limit_remaining()
    {
        PodioInstance::getInstance()->rate_limit_remaining();
    }

    public static function rate_limit()
    {
        PodioInstance::getInstance()->rate_limit();
    }

    /**
     * Set debug config
     *
     * @param $toggle True to enable debugging. False to disable
     * @param string $output Output mode. Can be "stdout" or "file". Default is "stdout"
     */
    public static function set_debug($toggle, $output = "stdout")
    {
        PodioInstance::getInstance()->set_debug($toggle, $output);
    }

    public static function log_request($method, $url, $encoded_attributes, $response, $curl_info)
    {
        PodioInstance::getInstance()->log_request($method, $url, $encoded_attributes, $response, $curl_info);
    }

    public static function shutdown()
    {
        PodioInstance::getInstance()->shutdown();
    }
}
