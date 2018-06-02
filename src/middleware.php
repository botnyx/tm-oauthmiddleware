<?php


namespace botnyx\tmoauthmiddleware;


use Slim\Http\Request;
use Slim\Http\Response;

// $z = new \botnyx\tmoauthmiddleware\oauthmiddleware($server,$clientid,$clientsecret,$jwt_public_key)

//https://api.mysite.com/authorize?response_type=code&client_id=TestClient&redirect_uri=https://myredirecturi.com/cb


class oauthmiddleware {
    
	var $server; 		// http://idp.trustmaster.nl
	var $authorize_uri;	// /authorize
	
	// 
	var $callback_uri;  // /callback
	
	var $client_id;		//
	var $client_secret;	//
	var $jwt_public_key;// /somelocation/pub.key
	
	var $callback;
	
	function __construct($server,$clientid,$clientsecret,$jwt_public_key){
		$this->server	=$server;
		$this->client_id=$clientid;
		$this->client_secret=$clientsecret;
		$this->jwt_public_key=$jwt_public_key;
	}
	
	/**
     * Example middleware invokable class
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $request  PSR7 request
     * @param  \Psr\Http\Message\ResponseInterface      $response PSR7 response
     * @param  callable                                 $next     Next middleware
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke($request, $response, $next)
    {
        $cookieMan = new cookiemanager($this->server,$this->client_id,$this->client_secret,$this->jwt_public_key);
		
		$redirect = false;
		$authenticated = false;
		
		echo "<pre>";
		
		// verify the request
		if(!$cookieMan->verify()){
			//  anon, or invalid token.
			echo "anon, or invalid token.\n";
			if(!in_array('anon',$this->scopes)){
				// anon is not allowed, do something.
				$redirect = true;
				$redirectUrl = urlencode($cookieMan->requestedUrl);
			}
			
		}else{
			// authenticated user details.
			echo "authenticated user details.\n";
			
			$authenticated =  true;
			$cookieMan->payload->sub;
			$cookieMan->payload->exp;
			$cookieMan->payload->aud;
			$cookieMan->payload->scope;
			
			$cookieMan->refreshToken;
			$cookieMan->accessToken;
			
		}
		
		$cookieMan->client_id="redacted";
		$cookieMan->client_secret="redacted";
		//print_r($cookieMan);
		
		#$container = $this->getContainer();
		
		#var_dump($container);
		#print_r($this->scopes);
		//$this->scopes;
		#echo "</pre>";

		

		if($redirect){
			return $response->withRedirect('https://accounts.trustmaster.nl/signin?ref='.$redirectUrl, 301);
		}
		
		
		#$response->getBody()->write(json_encode($this->payload) );
		
		#$response->getBody()->write('BEFORE');
        $response = $next($request, $response);
		//$response = $response->withHeader('Access-Control-Allow-Origin', '*');
		
		#$response->getBody()->write('AFTER');

		$response->cookieMan = $cookieMan;
		
        return $response;
    }
	
	
	/**
     * Returns a callable function to be used as a authorization middleware with a specified scope.
     *
     * @param array $scopes Scopes require for authorization.
     *
     * @return Authorization
     */
    public function withRequiredScope(array $scopes)
    {
        $clone = clone $this;
        $clone->scopes = $clone->formatScopes($scopes);
        return $clone;
    }
    /**
     * Helper method to ensure given scopes are formatted properly.
     *
     * @param array $scopes Scopes required for authorization.
     *
     * @return array The formatted scopes array.
     */
    private function formatScopes(array $scopes)
    {
        if (empty($scopes)) {
            return [null]; //use at least 1 null scope
        }
        array_walk(
            $scopes,
            function (&$scope) {
                if (is_array($scope)) {
                    $scope = implode(' ', $scope);
                }
            }
        );
        return $scopes;
    }	
}

