<?php


namespace botnyx\tmoauthmiddleware;


use Slim\Http\Request;
use Slim\Http\Response;


class cookiemanager {
	
	var $refreshToken;
	var $accessToken;
	
	var $cookiedomain;
	
	var $payload = [];

	var $debug = true;
	
	function __construct($server,$clientid,$clientsecret,$jwt_public_key){

		$this->server	=$server;
		$this->client_id=$clientid;
		$this->client_secret=$clientsecret;
		$this->cookiedomain = $_SERVER['HTTP_HOST'];
		
		
		if(!file_exists($jwt_public_key)){
			throw new \Exception("public key not found! ".$jwt_public_key);
		}
		$this->jwt_public_key=$jwt_public_key;
	
		//$this->init();
		if(!isset($_COOKIE['CONSENT'])) {
			error_log("Visitor hasnt set the consent!");
			//S+NL.nl+V9
		}
		
		
		$this->requestedUrl = $_SERVER['SCRIPT_URI']."?".$_SERVER['QUERY_STRING'];
		
		
		
		


		
	}
	
	public function receiveAuthCode($code){
		#if($this->debug) {
		//	error_log("receiveCode(): Exchange code for token");
		#	echo " cookiemanager->receiveAuthCode($code)";
		#}
		echo "<pre>";
		#var_dump($this->client_id);
		#var_dump($this->client_secret);
		$this->server= "https://idp.trustmaster.nl";
		var_dump($this->server);
		#var_dump($code);
		
		$idp = new \botnyx\tmidpconn\idpconn($this->server,$this->client_id,$this->client_secret);
		
		
		$result = $idp->receiveAuthCode($code );
		#var_dump($result);
		if($result['code']!=200){
			var_dump($result);
			#$result['code'];
			#$result['data']['error'];
			#$result['data']['error_description'];
			return false;
		}else{
			
			
			if( $this->verifyJWT($result['data']['access_token'])){
				// jwt is ok, setcookie.
				if($this->debug) error_log("JWT validated, setcookies! ");

				$this->setNewCookies($result['data']);
				#print_r($result);
				#print_r($this->payload);
				#die();
				return true;
			}else{
				// jwt decoding failed!
				return false;
			}
			
			
			#$result['code'];
			#$result['data']['access_token'];
			#$result['data']['expires_in'];		
			#$result['data']['token_type'];		
			#$result['data']['scope'];		
			#$result['data']['refresh_token'];		
		}
		
		
		
		
		
	}
	
	
	public function verify(){
		if(!$this->checkJsCookie()){
			if($this->debug) error_log("No js cookie.");
			if(!$this->checkSecureCookie()){
				if($this->debug) error_log("no other cookies.");
				
				return false;//echo "Not logged in!";
			}else{
				// set the non-httponly cookies again... in case they get lost.
				$this->setJavascriptCookie("SID",$this->access_token,$this->payload->exp);
				$this->setJavascriptCookie("EAT",$this->payload->exp,$this->payload->exp);

			}
		}
		if($this->debug) error_log("Authenticated user");
			
		return true;
	}
	
	
	private function checkJsCookie(){
		#echo "<hr>checkJsCookie()<br>";
		if(isset($_COOKIE['SID'])){
			if ( $this->verifyJWT($_COOKIE['SID'])){
				// authenticated!
				$this->accessToken=$_COOKIE['SID'];
				$this->refreshToken=$_COOKIE['SRID'];
				return true;
			}else{
				if(isset($_COOKIE['RID'])) {
					// a secure refreshtoken is found!.
					if($this->exchangeRefreshToken($_COOKIE['RID'])){
						// we are authenticated!
						return true;
					}else{
						// NO AUTH!!!!
						return false;
					}
				}else{
					// no refreshtoken.
					return false;
				}
			}
			
		}else{
			if(isset($_COOKIE['RID'])) {
				// a secure refreshtoken is found!.
				if($this->exchangeRefreshToken($_COOKIE['RID'])){
					// we are authenticated!
					return true;
				}else{
					// NO AUTH!!!!
					return false;
				}
			}else{
				// no refreshtoken.
				return false;
			};
		}
		
	}
	
	private function checkSecureCookie(){
		#echo "<hr>checkSecureCookie()<br>";
		if(isset($_COOKIE['SSID'])){
			
			if($this->verifyJWT($_COOKIE['SSID']) ){
				// we are authenticated.
				$this->accessToken=$_COOKIE['SSID'];
				$this->refreshToken=$_COOKIE['SRID'];
				#echo "we are authenticated.<br>";
				return true;
			}else{
				if(isset($_COOKIE['SRID'])) {
					// a secure refreshtoken is found!.
					if($this->exchangeRefreshToken($_COOKIE['SRID'])){
						// we are authenticated!
						return true;
					}else{
						// NO AUTH!!!!
						return false;
					}
				}else{
					// no refreshtoken is found.
					$this->checkJsCookie();
					
				}
			}
			   
		
		}else{
			if(isset($_COOKIE['SRID'])) {
				// a secure refreshtoken is found!.
				if($this->exchangeRefreshToken($_COOKIE['SRID'])){
					// we are authenticated!
					
					return true;
				}else{
					// NO AUTH!!!!
					#echo "Invalid refreshtoken <br>";
					return false;
				}
			}else{
				// no refreshtoken is found.
				$this->checkJsCookie();

			}
		}
	}
	
	private function exchangeRefreshToken($refreshtoken){
		
		if($this->debug) error_log("exchange refreshtoken");
		
		
		$idp = new \botnyx\tmidpconn\idpconn($this->server,$this->client_id,$this->client_secret);
		
		$resp = $idp->getRefreshToken($refreshtoken);
		
		if($resp['code']==200){
			
			if( $this->verifyJWT($resp['data']['access_token'])){
				// jwt is ok, setcookie.
				if($this->debug) error_log("JWT validated, setcookies! ");

				$this->setNewCookies($resp['data']);
				return true;
			}else{
				// jwt decoding failed!
				return false;
			}
			
		}
		if($this->debug) error_log("renew token responded: ".$resp['code']);
		
		
		
		return false;
		
	}
	
	
	private function setNewCookies($resp){
		
		$this->accessToken =$resp['access_token'];
		$this->setHttpOnlyCookie("SSID",$resp['access_token'],$this->payload->exp);
		$this->ssid_expires = $this->payload->exp;
		
		$this->setJavascriptCookie("SID",$resp['access_token'],$this->payload->exp);
		$this->sid_expires = $this->payload->exp;
		
		$this->setJavascriptCookie("EAT",$this->payload->exp,$this->payload->exp);

		$this->refreshToken =$resp['refresh_token'];
		$this->setHttpOnlyCookie("SRID",$resp['refresh_token'],time()+2419200);
		$this->setHttpOnlyCookie("SREAT",time()+2419200,time()+2419200);
		
		$this->srid_expires = time()+2419200;
		
	}
	

	
	public function setJavascriptCookie($name,$value,$expire=0){
		
		$httponly = false;
		$secure = true;
		$domain = $this->cookiedomain;
		$path = "";
		
		
		setcookie ( $name ,  $value  ,  $expire , $path  ,  $domain , $secure ,  $httponly  );
	}
	
	public function setHttpOnlyCookie($name,$value,$expire){
		
		$httponly = true;
		$secure = true;
		$domain = $this->cookiedomain;
		$path = "";
		
		
		setcookie ( $name ,  $value  ,  $expire , $path  ,  $domain , $secure ,  $httponly  );
	}
	
	
	
	

	
	private function verifyJWT($jwt_access_token){
		
		//$token = json_decode($curlResponse);

		//$jwt_access_token = $token['access_token'];

		$separator = '.';

		if (2 !== substr_count($jwt_access_token, $separator)) {
			//throw new \Exception("Incorrect access token format");
			return false;
		}

		list($header, $payload, $signature) = explode($separator, $jwt_access_token);

		$decoded_signature = base64_decode(str_replace(array('-', '_'), array('+', '/'), $signature));

		// The header and payload are signed together
		$payload_to_verify = utf8_decode($header . $separator . $payload);

		// however you want to load your public key
		$public_key = file_get_contents($this->jwt_public_key);

		// default is SHA256
		$verified = openssl_verify($payload_to_verify, $decoded_signature, $public_key, OPENSSL_ALGO_SHA256);

		if ($verified !== 1) {
			//throw new \Exception("Cannot verify signature");
			return false;
		}

		// output the JWT Access Token payload
		$decoded_payload = json_decode(base64_decode($payload));
		
		#echo "<pre>";
		#var_dump(time());
		
		#var_dump($decoded_payload->exp);
		#$left = ($decoded_payload->exp-time());
		
		
		#print_r($_COOKIE);
		
		
		$this->payload = json_decode(base64_decode($payload));
		return true;
		
	}
	
}
