<?php


namespace botnyx\tmoauthmiddleware;

use ArrayAccess;
use Slim\Http\Request;
use Slim\Http\Response;

// $z = new \botnyx\tmoauthmiddleware\oauthmiddleware($server,$clientid,$clientsecret,$jwt_public_key)

//https://api.mysite.com/authorize?response_type=code&client_id=TestClient&redirect_uri=https://myredirecturi.com/cb


class middleware {
    
	var $server; 		// http://idp.trustmaster.nl
	
	var $authorize_uri= '/authorize';	// /authorize
	var $callback_uri = "/callback";  // /callback
	var $token_uri    = "/token";  // /callback
	
	var $client_id;		//
	var $client_secret;	//
	var $jwt_public_key;// /somelocation/pub.key
	
	var $callback;
	
	function __construct($settings,$container){
		
		$this->server 			=  $settings->idp_server;
		$this->client_id 		=  $settings->idp_clientid;
		$this->client_secret	=  $settings->idp_clientsecret;
		$this->jwt_public_key 	=  $settings->idp_public_key;
		
		$this->token_uri 		=  $settings->idp_token_uri;
		$this->authorize_uri 	=  $settings->idp_authorize_uri;
		$this->callback_uri		=  $settings->local_callback_uri;
		
		
		/*
		$a['client_id'];
		$a['client_secret'];
		$a['jwt_public_key'];
		$a['idp_server'];
		$a['authorize_uri'];
		$a['callback_uri'];
		$a['token_uri'];
		*/
		
		#$this->server	=$server;
		#$this->client_id=$clientid;
		#$this->client_secret=$clientsecret;
		#$this->jwt_public_key=$jwt_public_key;
		
		$this->container = $this->validateContainer($container);
		
		// start a new cookiemanager.
		$this->cookieMan = new cookiemanager($this->server,$this->client_id,$this->client_secret,$this->jwt_public_key);
		
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
        // 
		$allGetVars 	= $request->getQueryParams();
		$allPostPutVars = $request->getParsedBody();
		$allUrlVars 	= $request->getQueryParams();
		
		//
		$url_path 	= $request->getUri()->getPath();
		$method 	= $request->getMethod();
		
		//
		$isAuthenticated = $this->cookieMan->verify();
		
		
		
		/************************************************************************
		
				CALLBACK URL
		
		************************************************************************/
		if( $url_path==$this->callback){
			// This is the Callback URI. 
			if(array_key_exists('code',$allGetVars)){
				try{
					// a code is found, 
					$cookieMan->receiveAuthCode($allGetVars['code']);
				}catch(Exception $e){
					var_dump($e->getMessage());
					die($e->getMessage());			
				}

			}else{
				// no code supplied, this is a invalid request.
			}
			//print_r($cookieMan);
			//die();
			//$response = $next($request, $response);
			return $response;
		}

		
		/***********************************************************************
		
				TOKEN URL
		
		************************************************************************/
		if( $url_path==$this->token_uri){
			// This is the Token URI. we proxy this request to our internal IDP.
			$response = $next($request, $response);
			return $response;
		}
		
		
		echo "<pre>This page (".$_SERVER['SCRIPT_URI'].") needs at least one of these scopes.\n";
		print_r($this->scopes);
		echo "\n";

		
		if( !in_array('anon',$this->scopes) && !$isAuthenticated && $url_path!=$this->authorize_uri ){
			// Anonymous access is not allowed.
			// in a normal oauth situation we should be redirected to the authorisation endpoint.
			error_log("middleware: "."ANON NOT ALLOWED!");
			
			if($isAuthenticated){
				echo "You are authenticated!\n";
			}else{
				echo "You are NOT loggedin!\n";
			}
			
			$redirectUrl = $_SERVER['SCRIPT_URI'];
			echo "PROTECTED URL : ".$redirectUrl."\n";
			$_SESSION['lastUrl']= $redirectUrl;
			
			
			$endpoint = "https://accounts.trustmaster.nl/authorize?response_type=code&client_id=".$this->client_id."&state=".time()."&redirect_uri=".$redirectUrl;
			echo "REDIRECT:\n<a href='".$endpoint."'>".$endpoint."</a>";
			die();
			//return $response->withRedirect($endpoint, 302);
		}
		
		
		/************************************************************************
		
				AUTHORIZE URL
		
		************************************************************************/
		if( $url_path==$this->authorize_uri)
		{
			echo "middleware: "."We are at the AUTHORIZE URI\n";
			$authorizeRoute = new \botnyx\tmoauthmiddleware\authorize($request);
			
			
			echo "Referred via :".$allGetVars['redirect_uri']."\n";
			
			
			$idp = new \botnyx\tmidpconn\idpconn($this->server,$this->client_id,$this->client_secret);
			
			
			if($isAuthenticated){
				echo "You are authenticated!\n";
				
				
				if($method!='POST'){
					echo "present Grant Auth screen\n";
					return $this->container['view']->render($response, 'base-layout.phtml', [
						'screen' => 'authorize',
						'data'=>array('client_id'=>$allGetVars['client_id']),
						'error'=>''
					]);	
				}else{
					echo "receive GrantScreen data via post.";
					print_r($allPostPutVars);
					
						
					
					#print_r($this->cookieMan);
					#$this->cookieMan->payload->aud
					
					$R = $idp->receiveAuthCode(strtolower($allPostPutVars['authorized']),$allGetVars['client_id'],$this->cookieMan->payload->sub);
					
					
					if($R['code']==302){
						// YES we have a redirect!
						$R['data']['code'];
						$R['data']['state'];
						$R['data']['url'];
						$parsedUrl = parse_url($R['data']['url']);
						var_dump($parsedUrl);


						parse_str($parsedUrl['query'], $idp_response);
						var_dump($idp_response);
						
						$uri = $R['data']['url']."&redirect_uri=".$allGetVars['redirect_uri'];
						
						
						echo "<a href='$uri'>REDIR!</a>";
						die();
						return $response->withRedirect($uri, 301);
						
						
					}else{
						$R['data']['error'];
						$R['data']['error_description'];
						
						
					}
					//print_r($R);
					die();
					
					
					
					
					
					die();
				}
				
				
				
				
				

			
			}
			else
			{
				echo "You are NOT loggedin!\n";
				echo "present LOGIN screen\n";
				echo $method."\n";
				if($method=='POST'){
					//$authorizeRoute->login();
					echo "Referred via :".$_SESSION['lastUrl']."\n";
					
					$r = $idp->oauthLogin($allPostPutVars['TMinputEmail']."@trustmaster.nl",$allPostPutVars['TMinputPassword']);
					if($r['code']==200){
						// OK!
						// Doublecheck by verifying the the JWT token. 
						if(!$this->cookieMan->verifyJWT($r['data']['access_token']) ){
							echo "Something terrible happened, jwt didnt pass verification!\n";
							die();
						}
						
						echo "We are authenticated! set cookies!\n";
						$this->cookieMan->setNewCookies($r['data']);
						
						
						echo "\nREDIRECT:\n<a href='https://accounts.trustmaster.nl".$_SERVER['REQUEST_URI']."'>".$_SERVER['REQUEST_URI']."</a>";
						die();
						return $response->withRedirect($_SERVER['REQUEST_URI'], 301);
						
						#var_dump($_SERVER['REQUEST_URI']);
						#print_r($r);
						#die();
					}else{
						// nok!
						return $this->container['view']->render($response, 'base-layout.phtml', [
							'screen' => 'signin',
							'error'=>$r
						]);	
					}
					
					
					
					
				}else{
					return $this->container['view']->render($response, 'base-layout.phtml', [
						'screen' => 'signin'
					]);	
				}
				
				//var_dump($method);
				
				
			}
			
			
			
			//return $this->authorizeRoute();
		}
		
		
				

		/*
		
		if(!$isAuthenticated){
			error_log("middleware: "."This is a ANONYMOUS USER.");
			
			// check for the anon scope.
			if(!in_array('anon',$this->scopes)){
				// Anonymous access is not allowed.
				error_log("middleware: "."ANON NOT ALLOWED!");
				#error_log("remember this url! ".$url_path);
				#setcookie('last_url',$url_path,160);
				
				
				
				//$endpoint = "/signin?ref=https://accounts.trustmaster.nl/opmaak";
				//$endpoint = "https://accounts.trustmaster.nl/authorize?response_type=code&client_id=".$cookieMan->client_id."&state=".time();//."&redirect_uri=".$redirectUrl;
				// 
				//error_log("Redirect to :".$endpoint);
				//return $response->withRedirect($endpoint, 301);
				
			}else{
				error_log("middleware: "."ANON IS ALLOWED!");
				
			}
			
		}
		
		
		
		
		
		
		
		if( !$this->cookieMan->verify() && $url_path!=$this->authorize_uri ){
			// this is a unauthorized user on a endpoint with authorisation.
			// lets check if 'anon' is allowed.
			error_log("middleware: "."This is a ANONYMOUS USER.");
			if(!in_array('anon',$this->scopes)){
				// Anonymous access is not allowed.
				error_log("middleware: "."ANON NOT ALLOWED!");
				
				
				error_log("remember this url! ".$url_path);
				setcookie('last_url',$url_path,160);
				
				
				
				//$endpoint = "/signin?ref=https://accounts.trustmaster.nl/opmaak";
				$endpoint = "https://accounts.trustmaster.nl/authorize?response_type=code&client_id=".$cookieMan->client_id."&state=".time();//."&redirect_uri=".$redirectUrl;
				// 
				error_log("Redirect to :".$endpoint);
				return $response->withRedirect($endpoint, 301);
				
			}else{
				error_log("middleware: "."ANON IS ALLOWED!");
				
			}
			
		}
		
		
		
		
		
		
		if( $url_path!=$this->callback_uri &&  $url_path!=$this->authorize_uri) {
			error_log("middleware: "."We are at a normal url.");
			
			
		}
		
		
		
		
		
		
		error_log("------------------------------------------");
		
		error_log("middleware: ".$url_path);
		error_log("cb uri:".$this->callback_uri);
		error_log("auth uri:".$this->authorize_uri);
		
		echo "<pre>";
		print_r($this->cookieMan->verify());
		die();
		
		if( $url_path==$this->callback_uri ) {
			error_log("middleware: "."We are at the CALLBACK URI");
			
		}
		
		if( $url_path==$this->authorize_uri){
			error_log("middleware: "."We are at the AUTHORIZE URI");
			
			return $this->authorizeRoute();
		}
		
		
		
		
		//print_r($this->scopes);
		
		if( !$this->cookieMan->verify() && $url_path!=$this->authorize_uri ){
			// this is a unauthorized user on a endpoint with authorisation.
			// lets check if 'anon' is allowed.
			error_log("middleware: "."This is a ANONYMOUS USER.");
			if(!in_array('anon',$this->scopes)){
				// Anonymous access is not allowed.
				error_log("middleware: "."ANON NOT ALLOWED!");
				
				
				error_log("remember this url! ".$url_path);
				setcookie('last_url',$url_path,160);
				
				
				
				//$endpoint = "/signin?ref=https://accounts.trustmaster.nl/opmaak";
				$endpoint = "https://accounts.trustmaster.nl/authorize?response_type=code&client_id=".$cookieMan->client_id."&state=".time();//."&redirect_uri=".$redirectUrl;
				// 
				error_log("Redirect to :".$endpoint);
				return $response->withRedirect($endpoint, 301);
				
			}else{
				error_log("middleware: "."ANON IS ALLOWED!");
				
			}
			
		}

		
		
	
		//die();
		
		//  check if url has ?code=
		#$allGetVars = $request->getQueryParams();
		
		//Single GET parameter
		//$code = $allGetVars['code'];
		
		
		
		/*
		# we are at the callback url.
		// this is NOT NEEDED ON ACCOUNTS.TRUSTMASTER.nl
		$url_path = $request->getUri()->getPath();
		if( $url_path==$this->callback_uri){
			// Check if code is supplied.
			if(array_key_exists('code',$allGetVars)){
				try{
					// a code is found, 
					$cookieMan->receiveAuthCode($allGetVars['code']);
				}catch(Exception $e){
					var_dump($e->getMessage());
					die($e->getMessage());			
				}

			}else{
				// no code supplied, this is a invalid request.
			}
		}else{
			#this is NOT the callbackurl.
			error_log("this is NOT the callbackurl.");
		}
		
		
		
		$redirect = false;
		$authenticated = false;
		
		//echo "<pre>";
		
		// verify the request
		if(!$cookieMan->verify()){
			error_log("cookieMan->verify() is FALSE");
			//  anon, or invalid token.
			//echo "anon, or invalid token.\n";
			if(!in_array('anon',$this->scopes)){
				error_log("Anonymous access is not allowed.  NOT IN SCOPES!");
				// anon is not allowed, do something.
				$redirect = true;
				error_log("The requested url is : ".$cookieMan->requestedUrl);
				$redirectUrl = $cookieMan->requestedUrl;
				return $response->withRedirect("/signin?ref=".$redirectUrl, 301);
				
				
				
			}
			
		}else{
			// authenticated user details.
			//echo "authenticated user details.\n";
			
			$authenticated =  true;
			$cookieMan->payload->sub;
			$cookieMan->payload->exp;
			$cookieMan->payload->aud;
			$cookieMan->payload->scope;
			
			#$cookieMan->client_id="redacted";
			#$cookieMan->client_secret="redacted";
			
			$cookieMan->refreshToken;
			$cookieMan->accessToken;
			
			
			$rezz = array(	"refresh_token"=>$cookieMan->refreshToken,
						  	"access_token"=>$cookieMan->accessToken,
						  	"exp"=>$cookieMan->payload->exp,
						  	"aud"=>$cookieMan->payload->aud,
						  	"sub"=>$cookieMan->payload->sub,
						  	"scope"=>$cookieMan->payload->scope
						 );
			
			$this->setToken($rezz);
			
			//print_r($rezz);
			
		}
		
		
		#die("_*_");
		//print_r($cookieMan);
		
		#$container = $this->getContainer();
		
		#var_dump($container);
		#print_r($this->scopes);
		//$this->scopes;
		#echo "</pre>";

		$endpoint = "https://accounts.trustmaster.nl/authorize".
		"?response_type=code&client_id=".$cookieMan->client_id."&state=".time();//."&redirect_uri=".$redirectUrl;
		

			
		#error_log($cookieMan->client_id." ".$endpoint);
		
		
		if($redirect){
			//$endpoint = "/signin?ref=https://accounts.trustmaster.nl/opmaak";
			#return $response->withRedirect($endpoint, 301);
			#die($endpoint);
			
		}
		
		
		#$response->getBody()->write(json_encode($this->payload) );
		
		//$response->getBody()->write('SUB: '.$cookieMan->payload->sub." client:".$cookieMan->client_id);
        */
		
		$response = $next($request, $response);
		//$response = $response->withHeader('Access-Control-Allow-Origin', '*');
		
		#$response->getBody()->write('AFTER');

		
        return $response;
    }
	
	
    private function validateContainer($container)
    {
        if (is_a($container, ArrayAccess::class)) {
            return $container;
        }

        if (method_exists($container, 'set')) {
            return $container;
        }

        throw new \InvalidArgumentException("\$container does not implement ArrayAccess or contain a 'set' method");
    }
	
	
	 /**
     * Helper method to set the token value in the container instance.
     *
     * @param array $token The token from the incoming request.
     *
     * @return void
     */
    private function setToken(array $token)
    {
        if (is_a($this->container, '\\ArrayAccess')) {
            $this->container['token'] = $token;
            return;
        }

        $this->container->set('token', $token);
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

