<?php


namespace botnyx\tmoauthmiddleware;


use Slim\Http\Request;
use Slim\Http\Response;



class authorize {
	
	
	function __construct(Request $request){
		$this->request = $request;
		
		$allGetVars = $request->getQueryParams();
		$allPostPutVars = $request->getParsedBody();
		$allUrlVars = $request->getQueryParams();
		
		
	}
	
	function authorizeroute($user,$password){
		
	}
	
	function temp(){
		
			$field_username = "TMinputEmail";
			$field_password = "TMinputPassword";
			
			
			error_log("We are at the authorize uri.");
			error_log($request->getMethod()." ".$url_path);
			
			error_log("First,if GET present login screen.");
			
			$idpconn = new \botnyx\tmidpconn\idpconn($this->server,$this->client_id,$this->client_secret);
			
			
			if($request->getMethod()=='GET'){
				error_log("Present login-screen");
				
				return $this->container->view->render($response, 'base-layout.phtml', [
					'screen' => 'signin',
					'emailfield'=>$field_username,
					'paswdfield'=>$field_password
				]);
				return $response;
				
			}else{
				
				error_log("Process data");
				

				
				
		
				// Check if data was posted from LOGIN 
				if(array_key_exists($field_username,$allPostPutVars) && array_key_exists($field_password,$allPostPutVars)){
					// the login data was posted. 
					$result = $idpconn->oauthLogin($allPostPutVars[$field_username]."@trustmaster.nl" ,$allPostPutVars[$field_password]);
					
					if( $result['code']==200){
						if( $this->cookieMan->verifyJWT($result['data']['access_token'])){
							// jwt is ok, setcookie.
							if($this->cookieMan->debug) error_log("JWT validated, setcookies! ");
							error_log("setNewCookies");
							$this->cookieMan->setNewCookies($result['data']);
							// $this->setToken();
						}
						// login OK.
						$result['code'];
						$result['data']['access_token'];
						$result['data']['expires_in'];
						
						//die("Login ok");
						return $this->container->view->render($response, 'base-layout.phtml', ['screen'=>'authorize']);
					}else{
						// login error
						die("Login error");

					}
					
				}else{
					// check if the AUthorize screen was posted.
					if(!$this->cookieMan->verify()){
						
					}
					if( array_key_exists('authorized',$allPostPutVars)){
						// AUthorize form was posted!
						
						
						echo "COOKIEMAN:<pre>";
						print_r($this->cookieMan);
						die();
						$idp->sendAuthorization($allPostPutVars['authorized']);
							
						if( strtoupper($allPostPutVars['authorized'])=="YES"){
							echo "AUTHORIZED!";
							// idpconn->
							print_r($this->cookieMan);
							
							
							//var_dump ($this->container['token']);
						}else{
							echo "NOT AUTHORIZED!";
						}
						//print_r($allPostPutVars);
						
						die($allPostPutVars['authorized']);
						
					}
					
					
				}
				
				
				#print_r($response);
				
				
		
				
				echo "<pre>";
				//;
			//	$allPostPutVars[$field_password];
				print_r($result);
				print_r($allPostPutVars);
				print_r($allGetVars);
				print_r($allUrlPutVars);
				
				// post tegen idp
				
				//
				
				
				
				die();
				
			}
		
		
	}
	
}