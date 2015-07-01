<?php

/**
 * Non-static version of the former Podio class. Generally this is a singleton (always use the instance from
 * #getInstance()) - but for testing purposes instances can be created manually.
 */
class PodioInstance
{
    static $instance = null;

    /**
     * @return PodioInstance
     */
    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new PodioInstance();
        }
        return self::$instance;
    }

    /**
     * This should only be used in testing (or otherwise defined) scenarios. You must prevent to use distinct instances at the same time, as they interfere! Use {@link PodioInstance#getInstance}!
     */
    public function __construct() {

    }

    private $oauth = null, $debug = null, $logger = null, $session_manager = null, $last_response = null, $auth_type = null;
    protected $url, $client_id, $client_secret, $secret, $ch, $headers;
    private $stdout;

    const VERSION = '4.1.0';

    const GET = 'GET';
    const POST = 'POST';
    const PUT = 'PUT';
    const DELETE = 'DELETE';

    public function setup($client_id, $client_secret, $options = array('session_manager' => null, 'curl_options' => array())) {
        // Setup client info
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;

        // Setup curl
        $this->url = empty($options['api_url']) ? 'https://api.podio.com:443' : $options['api_url'];
        $this->debug = $this->debug ? $this->debug : false;
        $this->ch = curl_init();
        $this->headers = array(
            'Accept' => 'application/json',
        );
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, 1);
        curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($this->ch, CURLOPT_USERAGENT, 'Podio PHP Client/'.self::VERSION);
        curl_setopt($this->ch, CURLOPT_HEADER, true);
        curl_setopt($this->ch, CURLINFO_HEADER_OUT, true);

        //Update CA root certificates - require: https://github.com/Kdyby/CurlCaBundle
        if(class_exists('\\Kdyby\\CurlCaBundle\\CertificateHelper')) {
            /** @noinspection PhpUndefinedNamespaceInspection */
            \Kdyby\CurlCaBundle\CertificateHelper::setCurlCaInfo($this->ch);
        }

        if ($options && !empty($options['curl_options'])) {
            curl_setopt_array($this->ch, $options['curl_options']);
        }

        $this->setSessionManager(null);
        if ($options && !empty($options['session_manager'])) {
            if(is_string($options['session_manager']) && class_exists($options['session_manager'])) {
                $this->setSessionManager(new $options['session_manager']);
                $this->setOauth($this->getSessionManager()->get());
            }
        }

        // Register shutdown function for debugging and session management
        register_shutdown_function(array(&$this, 'shutdown'));
    }

    public function authenticate_with_app($app_id, $app_token) {
        return $this->authenticate('app', array('app_id' => $app_id, 'app_token' => $app_token));
    }

    public function authenticate_with_password($username, $password) {
        return $this->authenticate('password', array('username' => $username, 'password' => $password));
    }

    public function authenticate_with_authorization_code($authorization_code, $redirect_uri) {
        return $this->authenticate('authorization_code', array('code' => $authorization_code, 'redirect_uri' => $redirect_uri));
    }

    public function refresh_access_token() {
        return $this->authenticate('refresh_token', array('refresh_token' => $this->getOauth()->refresh_token));
    }

    public function authenticate($grant_type, $attributes) {
        $data = array();
        $auth_type = array('type' => $grant_type);

        switch ($grant_type) {
            case 'password':
                $data['grant_type'] = 'password';
                $data['username'] = $attributes['username'];
                $data['password'] = $attributes['password'];

                $auth_type['identifier'] = $attributes['username'];
                break;
            case 'refresh_token':
                $data['grant_type'] = 'refresh_token';
                $data['refresh_token'] = $attributes['refresh_token'];
                break;
            case 'authorization_code':
                $data['grant_type'] = 'authorization_code';
                $data['code'] = $attributes['code'];
                $data['redirect_uri'] = $attributes['redirect_uri'];
                break;
            case 'app':
                $data['grant_type'] = 'app';
                $data['app_id'] = $attributes['app_id'];
                $data['app_token'] = $attributes['app_token'];

                $auth_type['identifier'] = $attributes['app_id'];
            default:
                break;
        }

        $request_data = array_merge($data, array('client_id' => $this->client_id, 'client_secret' => $this->client_secret));
        if ($response = $this->request(self::POST, '/oauth/token', $request_data, array('oauth_request' => true))) {
            $body = $response->json_body();
            $this->setOauth(new PodioOAuth($body['access_token'], $body['refresh_token'], $body['expires_in'], $body['ref']));

            // Don't touch auth_type if we are refreshing automatically as it'll be reset to null
            if ($grant_type !== 'refresh_token') {
                $this->setAuthType($auth_type);
            }

            if ($this->session_manager) {
                $this->session_manager->set($this->getOauth(), $this->auth_type);
            }

            return true;
        }
        return false;
    }

    public function clear_authentication() {
        $this->setOauth(new PodioOAuth());

        if ($this->session_manager) {
            $this->session_manager->set($this->getOauth(), $this->auth_type);
        }
    }

    public function authorize_url($redirect_uri) {
        $parsed_url = parse_url($this->url);
        $host = str_replace('api.', '', $parsed_url['host']);
        return 'https://'.$host.'/oauth/authorize?response_type=code&client_id='.$this->client_id.'&redirect_uri='.rawurlencode($redirect_uri);
    }

    public function is_authenticated() {
        return $this->getOauth() && $this->getOauth()->access_token;
    }

    public function request($method, $url, $attributes = array(), $options = array()) {
        if (!$this->ch) {
            throw new Exception('Client has not been setup with client id and client secret.');
        }

        // Reset attributes so we can reuse curl object
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, null);
        unset($this->headers['Content-length']);
        $original_url = $url;
        $encoded_attributes = null;

        if (is_object($attributes) && substr(get_class($attributes), 0, 5) == 'Podio') {
            $attributes = $attributes->as_json(false);
        }

        if (!is_array($attributes) && !is_object($attributes)) {
            throw new PodioDataIntegrityError('Attributes must be an array');
        }

        switch ($method) {
            case self::GET:
                curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, self::GET);
                $this->headers['Content-type'] = 'application/x-www-form-urlencoded';

                $separator = strpos($url, '?') ? '&' : '?';
                if ($attributes) {
                    $query = $this->encode_attributes($attributes);
                    $url = $url.$separator.$query;
                }

                $this->headers['Content-length'] = "0";
                break;
            case self::DELETE:
                curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, self::DELETE);
                $this->headers['Content-type'] = 'application/x-www-form-urlencoded';

                $separator = strpos($url, '?') ? '&' : '?';
                if ($attributes) {
                    $query = $this->encode_attributes($attributes);
                    $url = $url.$separator.$query;
                }

                $this->headers['Content-length'] = "0";
                break;
            case self::POST:
                curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, self::POST);
                if (!empty($options['upload'])) {
                    curl_setopt($this->ch, CURLOPT_POST, TRUE);
                    curl_setopt($this->ch, CURLOPT_SAFE_UPLOAD, FALSE);
                    curl_setopt($this->ch, CURLOPT_POSTFIELDS, $attributes);
                    $this->headers['Content-type'] = 'multipart/form-data';
                }
                elseif (empty($options['oauth_request'])) {
                    // application/json
                    $encoded_attributes = json_encode($attributes);
                    curl_setopt($this->ch, CURLOPT_POSTFIELDS, $encoded_attributes);
                    $this->headers['Content-type'] = 'application/json';
                }
                else {
                    // x-www-form-urlencoded
                    $encoded_attributes = $this->encode_attributes($attributes);
                    curl_setopt($this->ch, CURLOPT_POSTFIELDS, $encoded_attributes);
                    $this->headers['Content-type'] = 'application/x-www-form-urlencoded';
                }
                break;
            case self::PUT:
                $encoded_attributes = json_encode($attributes);
                curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, self::PUT);
                curl_setopt($this->ch, CURLOPT_POSTFIELDS, $encoded_attributes);
                $this->headers['Content-type'] = 'application/json';
                break;
        }

        // Add access token to request
        if ($this->getOauth() && !empty($this->getOauth()->access_token) && !(isset($options['oauth_request']) && $options['oauth_request'] == true)) {
            $token = $this->getOauth()->access_token;
            $this->headers['Authorization'] = "OAuth2 {$token}";
        }
        else {
            unset($this->headers['Authorization']);
        }

        // File downloads can be of any type
        if (empty($options['file_download'])) {
            $this->headers['Accept'] = 'application/json';
        }
        else {
            $this->headers['Accept'] = '*/*';
        }

        curl_setopt($this->ch, CURLOPT_HTTPHEADER, $this->curl_headers());
        curl_setopt($this->ch, CURLOPT_URL, empty($options['file_download']) ? $this->url.$url : $url);

        $response = new PodioResponse();

        if(isset($options['return_raw_as_resource_only']) && $options['return_raw_as_resource_only'] == true) {
            $result_handle = fopen('php://temp', 'w');
            curl_setopt($this->ch, CURLOPT_FILE, $result_handle);
            curl_exec($this->ch);
            if(isset($this->stdout) && is_resource($this->stdout)) {
                fclose($this->stdout);
            }
            $this->stdout = fopen('php://stdout','w');
            curl_setopt($this->ch, CURLOPT_FILE, $this->stdout);
            curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
            $raw_headers_size = curl_getinfo($this->ch, CURLINFO_HEADER_SIZE);

            fseek($result_handle, 0);
            $response->status = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
            $response->headers = $this->parse_headers(fread($result_handle, $raw_headers_size));
            $this->setLastResponse($response);
            return $result_handle;
        }

        $raw_response = curl_exec($this->ch);
        if($raw_response === false) {
            throw new PodioConnectionError('Connection to Podio API failed: [' . curl_errno($this->ch) . '] ' . curl_error($this->ch), curl_errno($this->ch));
        }
        $raw_headers_size = curl_getinfo($this->ch, CURLINFO_HEADER_SIZE);

        $response->body = substr($raw_response, $raw_headers_size);
        $response->status = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
        $response->headers = $this->parse_headers(substr($raw_response, 0, $raw_headers_size));
        $this->setLastResponse($response);

        if (!isset($options['oauth_request'])) {
            $curl_info = curl_getinfo($this->ch, CURLINFO_HEADER_OUT);
            $this->log_request($method, $url, $encoded_attributes, $response, $curl_info);
        }

        switch ($response->status) {
            case 200 :
            case 201 :
            case 204 :
                return $response;
                break;
            case 400 :
                // invalid_grant_error or bad_request_error
                $body = $response->json_body();
                if (strstr($body['error'], 'invalid_grant')) {
                    // Reset access token & refresh_token
                    $this->clear_authentication();
                    throw new PodioInvalidGrantError($response->body, $response->status, $url);
                    break;
                }
                else {
                    throw new PodioBadRequestError($response->body, $response->status, $url);
                }
                break;
            case 401 :
                $body = $response->json_body();
                if (strstr($body['error_description'], 'expired_token') || strstr($body['error'], 'invalid_token')) {
                    if ($this->getOauth()->refresh_token) {
                        // Access token is expired. Try to refresh it.
                        if ($this->authenticate('refresh_token', array('refresh_token' => $this->getOauth()->refresh_token))) {
                            // Try the original request again.
                            return $this->request($method, $original_url, $attributes);
                        }
                        else {
                            $this->clear_authentication();
                            throw new PodioAuthorizationError($response->body, $response->status, $url);
                        }
                    }
                    else {
                        // We have tried in vain to get a new access token. Log the user out.
                        $this->clear_authentication();
                        throw new PodioAuthorizationError($response->body, $response->status, $url);
                    }
                }
                elseif (strstr($body['error'], 'invalid_request') || strstr($body['error'], 'unauthorized')) {
                    // Access token is invalid.
                    $this->clear_authentication();
                    throw new PodioAuthorizationError($response->body, $response->status, $url);
                }
                break;
            case 403 :
                throw new PodioForbiddenError($response->body, $response->status, $url);
                break;
            case 404 :
                throw new PodioNotFoundError($response->body, $response->status, $url);
                break;
            case 409 :
                throw new PodioConflictError($response->body, $response->status, $url);
                break;
            case 410 :
                throw new PodioGoneError($response->body, $response->status, $url);
                break;
            case 420 :
                throw new PodioRateLimitError($response->body, $response->status, $url);
                break;
            case 500 :
                throw new PodioServerError($response->body, $response->status, $url);
                break;
            case 502 :
            case 503 :
            case 504 :
                throw new PodioUnavailableError($response->body, $response->status, $url);
                break;
            default :
                throw new PodioError($response->body, $response->status, $url);
                break;
        }
        return false;
    }

    public function get($url, $attributes = array(), $options = array()) {
        return $this->request(self::GET, $url, $attributes, $options);
    }
    public function post($url, $attributes = array(), $options = array()) {
        return $this->request(self::POST, $url, $attributes, $options);
    }
    public function put($url, $attributes = array()) {
        return $this->request(self::PUT, $url, $attributes);
    }
    public function delete($url, $attributes = array()) {
        return $this->request(self::DELETE, $url, $attributes);
    }

    public function curl_headers() {
        $headers = array();
        foreach ($this->headers as $header => $value) {
            $headers[] = "{$header}: {$value}";
        }
        return $headers;
    }
    public function encode_attributes($attributes) {
        $return = array();
        foreach ($attributes as $key => $value) {
            $return[] = urlencode($key).'='.urlencode($value);
        }
        return join('&', $return);
    }
    public function url_with_options($url, $options) {
        $parameters = array();

        if (isset($options['silent']) && $options['silent']) {
            $parameters[] = 'silent=1';
        }

        if (isset($options['hook']) && !$options['hook']) {
            $parameters[] = 'hook=false';
        }

        if (!empty($options['fields'])) {
            $parameters[] = 'fields='.$options['fields'];
        }

        return $parameters ? $url.'?'.join('&', $parameters) : $url;
    }
    public function parse_headers($headers) {
        $list = array();
        $headers = str_replace("\r", "", $headers);
        $headers = explode("\n", $headers);
        foreach ($headers as $header) {
            if (strstr($header, ':')) {
                $name = strtolower(substr($header, 0, strpos($header, ':')));
                $list[$name] = trim(substr($header, strpos($header, ':')+1));
            }
        }
        return $list;
    }
    public function rate_limit_remaining() {
        return $this->getLastResponse()->headers['x-rate-limit-remaining'];
    }
    public function rate_limit() {
        return $this->getLastResponse()->headers['x-rate-limit-limit'];
    }

    /**
     * Set debug config
     *
     * @param $toggle True to enable debugging. False to disable
     * @param $output Output mode. Can be "stdout" or "file". Default is "stdout"
     */
    public function set_debug($toggle, $output = "stdout") {
        if ($toggle) {
            $this->debug = $output;
        }
        else {
            $this->setDebug(false);
        }
    }

    public function log_request($method, $url, $encoded_attributes, $response, $curl_info) {
        if ($this->debug) {
            $timestamp = gmdate('Y-m-d H:i:s');
            $text = "{$timestamp} {$response->status} {$method} {$url}\n";
            if (!empty($encoded_attributes)) {
                $text .= "{$timestamp} Request body: ".$encoded_attributes."\n";
            }
            $text .= "{$timestamp} Reponse: {$response->body}\n\n";

            if ($this->debug === 'file') {
                if (!$this->logger) {
                    $this->setLogger(new PodioLogger());
                }
                $this->logger->log($text);
            }
            elseif ($this->debug === 'stdout' && php_sapi_name() === 'cli') {
                print $text;
            }
            elseif ($this->debug === 'stdout' && php_sapi_name() === 'cli') {
                require_once 'vendor/kint/Kint.class.php';
                Kint::dump("{$method} {$url}", $encoded_attributes, $response, $curl_info);
            }

            $this->logger->call_log[] = curl_getinfo($this->ch, CURLINFO_TOTAL_TIME);
        }

    }

    public function shutdown() {
        // Write any new access and refresh tokens to session.
        if ($this->session_manager) {
            $this->session_manager->set($this->getOauth(), $this->auth_type);
        }

        // Log api call times if debugging
        if($this->debug && $this->logger) {
            $timestamp = gmdate('Y-m-d H:i:s');
            $count = sizeof($this->logger->call_log);
            $duration = 0;
            if ($this->logger->call_log) {
                foreach ($this->logger->call_log as $val) {
                    $duration += $val;
                }
            }

            $text = "\n{$timestamp} Performed {$count} request(s) in {$duration} seconds\n";
            if ($this->debug === 'file') {
                if (!$this->logger) {
                    $this->setLogger(new PodioLogger());
                }
                $this->logger->log($text);
            }
            elseif ($this->debug === 'stdout' && php_sapi_name() === 'cli') {
                print $text;
            }
        }
    }

    /*
    The public members of Podio ($oauth, $debug, $logger, $session_manager, $last_response, $auth_type) are converted
    to instance variables. They are only written using these setters to ensure backwards compatibility with
    applications reading these values from Podio.
    */

    public function setOauth($oauth)
    {
        $this->oauth = $oauth;
        Podio::$oauth = $oauth;
    }

    public function setDebug($debug)
    {
        $this->debug = $debug;
        Podio::$debug = $debug;
    }

    public function setLogger($logger)
    {
        $this->logger = $logger;
        Podio::$logger = $logger;
    }


    public function setSessionManager($session_manager)
    {
        $this->session_manager = $session_manager;
        Podio::$session_manager = $session_manager;
    }


    public function setLastResponse($last_response)
    {
        $this->last_response = $last_response;
        Podio::$last_response = $last_response;
    }


    public function setAuthType($auth_type)
    {
        $this->auth_type = $auth_type;
        Podio::$auth_type = $auth_type;
    }

    public function getOauth()
    {
        $this->oauth = Podio::$oauth;
        return $this->oauth;
    }

    public function getDebug()
    {
        $this->debug = Podio::$debug;
        return $this->debug;
    }

    public function getLogger()
    {
        $this->logger = Podio::$logger;
        return $this->logger;
    }


    public function getSessionManager()
    {
        $this->session_manager = Podio::$session_manager;
        return $this->session_manager;
    }


    public function getLastResponse()
    {
        $this->last_response = Podio::$last_response;
        return $this->last_response;
    }


    public function getAuthType()
    {
        $this->auth_type = Podio::$auth_type;
        return $this->auth_type;
    }
}