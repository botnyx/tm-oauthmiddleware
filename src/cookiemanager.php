<?php


namespace botnyx\tmoauthmiddleware;


use Slim\Http\Request;
use Slim\Http\Response;


class cookiemanager {
	
	var $refreshToken;
	var $accessToken;
	
	var $payload = [];

	
	
	function __construct($server,$clientid,$clientsecret,$jwt_public_key){

		$this->server	=$server;
		$this->client_id=$clientid;
		$this->client_secret=$clientsecret;
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
	
	public function verify(){
		if(!$this->checkJsCookie()){
			if(!$this->checkSecureCookie()){
				return false;//echo "Not logged in!";
			}
		}
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
		
		#echo "exchange refreshtoken<br>";
		$server= "https://idp.trustmaster.nl";
		$clientid= "accounts.trustmaster";
		$clientsecret= "test123";
		
		$idp = new \botnyx\tmidpconn\idpconn($server,$clientid,$clientsecret);
		
		$resp = $idp->getRefreshToken($refreshtoken);
		
		if($resp['code']==200){
			
			if( $this->verifyJWT($resp['data']['access_token'])){
				// jwt is ok, setcookie.
				$this->setNewCookies($resp['data']);
				return true;
			}else{
				// jwt decoding failed!
				return false;
			}
			
		}
		
		
		return false;
		
	}
	
	
	private function setNewCookies($resp){
		
		$this->accessToken =$resp['access_token'];
		$this->setHttpOnlyCookie("SSID",$resp['access_token'],$this->payload->exp);

		$this->setJavascriptCookie("SID",$resp['access_token'],$this->payload->exp);
		$this->setJavascriptCookie("EAT",$this->payload->exp,$this->payload->exp);

		$this->refreshToken =$resp['refresh_token'];
		$this->setHttpOnlyCookie("SRID",$resp['refresh_token'],time()+2419200);
		
	}
	

	
	public function setJavascriptCookie($name,$value,$expire=0){
		
		$httponly = false;
		$secure = true;
		$domain = ".trustmaster.nl";
		$path = "";
		
		
		setcookie ( $name ,  $value  ,  $expire , $path  ,  $domain , $secure ,  $httponly  );
	}
	
	public function setHttpOnlyCookie($name,$value,$expire){
		
		$httponly = true;
		$secure = true;
		$domain = ".trustmaster.nl";
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