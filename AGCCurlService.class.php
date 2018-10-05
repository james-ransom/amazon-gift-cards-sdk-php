<?php

/**
 * AGCCurlService 
 * 
 * With this class you can Buy/Cancel gift cards.  
 *
 * please feel free to reach out to 
 * me: ransom1538 (a t ) gmail ( d o  t ) com  
 * 
 * ransom1538
 * 
 */
class AGCCurlService
{


	const SERVICE_NAME = "AGCODService";
	const ACCEPT_HEADER = "accept";
	const CONTENT_HEADER = "content-type";
	const HOST_HEADER = "host";
	const XAMZDATE_HEADER = "x-amz-date";
	const XAMZTARGET_HEADER = "x-amz-target";
	const AUTHORIZATION_HEADER = "Authorization";
	const AWS_SHA256_ALGORITHM = "AWS4-HMAC-SHA256";
	const KEY_QUALIFIER = "AWS4";
	const TERMINATION_STRING = "aws4_request";

	private  $secret_key;
	private  $access_key;
	private  $partner_id;
	private $debug; //shows some debug output in html

	const ENDPOINT  ='agcod-v2.amazon.com';

	public function __construct()
	{

		$this->secret_key = [YOUR SECRET KEY HERE];
		$this->partner_id="Appre";
		$this->access_key= [YOUR ACCESS KEY HERE];
		$this->debug = false;

		if ( $this->debug )
		{
			error_reporting(E_ALL);
			ini_set("display_errors", 1);
		}

	}

	/**
	 * Buy a gift cardva
	 *
	 * @param $gcRequestId A generated unique key, with partnerID as the prefix.  Example: $partner_id . time()
	 * @return a formatted array
	 */
	public function buyGiftCard($gcRequestId, $gcValue=1.00)
	{
		$partnerId = $this->partner_id;
		$currency = 'USD';
		$serviceOperation = 'CreateGiftCard';

		$payload = $this->get_paypload_giftcard($partnerId, $gcRequestId, $currency, $gcValue);
		$dateTimeString = $this->getTimeStamp();

		$canonicalRequest = $this->buildCanonicalRequest($serviceOperation, $payload);
		$canonicalRequestHash = $this->myHash($canonicalRequest);


		$curl_response = $this->invokeRequest($payload, $dateTimeString,$canonicalRequest, $serviceOperation);

		$json = json_decode($curl_response);
		if ( isset($json->message)  || ! isset($json->cardInfo) )
		{
			$ret = array();
			$ret['success']=false;
			$ret['errorCode'] = time();
			return $ret;
		}

		$ret = array();
		$ret['success']=true;
		$ret['gcValue']= $json->cardInfo->value->amount;
		$ret["gcCode"]= $json->gcClaimCode;
		$ret["gcResponseId"]= $json->gcId;  ////done
		$ret["gcRequestId"]=$json->creationRequestId;

		return $ret;
	}

	/*
	 * Cancel gift card -
	 *
	 * This wil display "This card has been refunded to the purchaser" to anyone that uses the card
	 * @param $gcRequestId stored in appredeem.reward_codes.external_code1
	 * @param $gcResponseId stored in appredeem.reward_codes.external_code2
	 *
	 */
	public function cancelGiftCard($gcRequestId, $gcResponseId)
	{
		$partnerId = $this->partner_id;
		$currency = 'USD';
		$serviceOperation = 'CancelGiftCard'; ////

		$payload = $this->get_paypload_cancelcard($partnerId, $gcResponseId, $gcRequestId);

		$dateTimeString = $this->getTimeStamp();

		$canonicalRequest = $this->buildCanonicalRequest($serviceOperation, $payload);
		$canonicalRequestHash = $this->myHash($canonicalRequest);

		$curl_response = $this->invokeRequest($payload, $dateTimeString,$canonicalRequest, $serviceOperation);

		$ret = json_decode($curl_response);
		if ( $res->status == 'SUCCESS')
		{
			return true;
		}
		return false;
	}



	/**
	 * Performs a simple get request. Used by HealthCheck call.
	 *
	 * @param $url The url to make a request too.
	 * @return The page output that the request generated.
	 */
	public function doGet($url) {
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 10);
		$output = curl_exec($ch);
		curl_close($ch);
		return $output;
	}


	/**
	 * Performs a hmac hash using sha256, which is what AWS uses.
	 *
	 * @param $data The data to sign.
	 * @param $key The key to sign the data with.
	 * @param $raw true to provide a raw ascii string, false to use a hex string.
	 * @return the hash of $data
	 */
	public function hmac($data, $key, $raw = true) {
		return hash_hmac("sha256", $data, $key, $raw);
	}

	/**
	 * Gets the date for the request, which is either what the client passed in, or today if none was given.
	 *
	 * @return The date in YYYYMMDD format.
	 */
	public function getDateString() {
		$dateTimeString = $this->getTimeStamp();
		return substr($dateTimeString, 0, 8);
	}

	/**
	 * Converts \n to </br> in a string for use in HTML display
	 *
	 * @param $str The line to convert
	 * @return the converted line.
	 */
	public function convertNewline($str) {
		$str = str_replace(array("\r\n","\n","\r"),'</br>', $str);
		return $str;
	}

	/**
	 * Builds the derived key, which is used for authorizating the request.
	 *
	 * @param $rawOutput true to return an ascii string using raw byes, false to return a hex string
	 */

	public function buildDerivedKey($rawOutput = true) {
		$KEY_QUALIFIER = self::KEY_QUALIFIER;
		$TERMINATION_STRING = self::TERMINATION_STRING;
		$SERVICE_NAME= self::SERVICE_NAME;
		 
		// Get pasted AWS Secret Key from user input
		$awsSecretKey = $this->secret_key;
		// Append Key Qaulifier, "AWS4", to secret key per http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
		$signatureAWSKey = $KEY_QUALIFIER . $awsSecretKey;
		$regionName= $this->getRegion();
		$dateString = $this->getDateString();

		$kDate = $this->hmac($dateString, $signatureAWSKey);
		$kRegion = $this->hmac($regionName, $kDate);
		$kService = $this->hmac($SERVICE_NAME, $kRegion);
		 
		// Derived the Signing key (derivedKey aka kSigning)
		$derivedKey =  $this->hmac($TERMINATION_STRING, $kService, $rawOutput);
		return $derivedKey;
	}

	/**
	 * Hashes the string using sha256, the standard AWS hash.
	 *
	 * @param $data a string to sign
	 * @return a string hash of $data
	 */
	public function myHash($data) {
		return hash("sha256",$data);
	}

	/**
	 * Builds the "formal" request that can be hashed to verify the contents of the request.
	 * The request does not get sent to the server in this format, but the hash of this is.
	 *
	 * @return The formal request
	 */
	public function buildCanonicalRequest($serviceOperation, $payload) {

		$ACCEPT_HEADER = self::ACCEPT_HEADER;
		$HOST_HEADER = self::HOST_HEADER;
		$XAMZDATE_HEADER = self::XAMZDATE_HEADER;
		$XAMZTARGET_HEADER = self::XAMZTARGET_HEADER;
		$ACCEPT_HEADER = self::ACCEPT_HEADER;

		$dateTimeString = $this->getTimeStamp();
		$payloadHash = $this->myHash($payload);

		$header1 = $this->header1($serviceOperation);
		$canonicalRequest = "POST\n/$serviceOperation\n\n$header1\n\n$ACCEPT_HEADER;$HOST_HEADER;$XAMZDATE_HEADER;$XAMZTARGET_HEADER\n$payloadHash";
		return $canonicalRequest;
	}

	/**
	 * Get the format that we will make the request in. This tells the server how to parse the request.
	 * This value is retrieved from the client and can either be json or xml.
	 *
	 * @return The request format as to be passed to the AGCOD server.
	 */
	public function getContentType() {
		return "application/json"; //Request in JSON format
	}



	function get_paypload_giftcard($partnerId, $gcRequestId, $currencyCode, $gcAmount)
	{
		$amount = trim($gcAmount);
		$payload = array(
        "creationRequestId" => $gcRequestId,
        "partnerId" => $partnerId,
        "value" =>
		array(
            "currencyCode" => $currencyCode,
            "amount" => floatval($amount)
		)
		);
		return json_encode($payload);
	}


	function get_paypload_cancelcard($partnerId, $gcResponseId, $gcRequestId)
	{
		// Variable for the GC ID from user input text box
		$gcResponseId = trim($gcResponseId);

		$payload = array(
                         "creationRequestId" => $gcRequestId,
                         "partnerId" => $partnerId,
                         "gcId" => $gcResponseId
		);
		return json_encode($payload);
	}


	/**
	 * Gets the region based on the server we connect too.
	 *
	 * @return The region.
	 */
	public function getRegion() {


		$endpoint = self::ENDPOINT;
		$regionName = "us-east-1";

		if ($endpoint == "agcod-v2-eu.amazon.com" || $endpoint == "agcod-v2-eu-gamma.amazon.com") {
			$regionName = "eu-west-1";
		}
		else if ($endpoint == "agcod-v2-fe.amazon.com" || $endpoint == "agcod-v2-fe-gamma.amazon.com") {
			$regionName = "us-west-2";
		}
		return $regionName;
	}

	/**
	 * Returns part of the header used in the canonical request.
	 *
	 * @return the portion of the header.
	 */
	public function header1($serviceOperation) {
		 
		$ACCEPT_HEADER =  self::ACCEPT_HEADER;
		$XAMZDATE_HEADER = self::XAMZDATE_HEADER;
		$XAMZTARGET_HEADER  = self::XAMZTARGET_HEADER;
		$HOST_HEADER = self::HOST_HEADER;
		$dateTimeString = $this->getTimeStamp();
		$endpoint = self::ENDPOINT;
		$contentType = $this->getContentType();
		return
"$ACCEPT_HEADER:$contentType
		$HOST_HEADER:$endpoint
		$XAMZDATE_HEADER:$dateTimeString
		$XAMZTARGET_HEADER:com.amazonaws.agcod.AGCODService.$serviceOperation";
	}

	/**
	 * Makes the service call to the AGCOD server.
	 *
	 * @return The repsonse from the server (in XML or JSON format) with HTML character escaped.
	 */
	public function invokeRequest($payload, $dateTimeString,$canonicalRequest, $serviceOperation) {
		$KEY_QUALIFIER = self::KEY_QUALIFIER;
		$ACCEPT_HEADER = self::ACCEPT_HEADER;
		$CONTENT_HEADER = self::CONTENT_HEADER;
		$HOST_HEADER = self::HOST_HEADER;
		$XAMZDATE_HEADER = self::XAMZDATE_HEADER;
		$XAMZTARGET_HEADER = self::XAMZTARGET_HEADER;
		$AUTHORIZATION_HEADER = self::AUTHORIZATION_HEADER;
		 
		$canonicalRequestHash = $this->myHash($canonicalRequest);

		$stringToSign = $this->buildStringToSign($canonicalRequestHash);
		$authorizationValue = $this->buildAuthSignature($stringToSign);
		$secretKey =$this->secret_key;
		$endpoint = self::ENDPOINT;
		$regionName = $this->getRegion();

		$SERVICE_NAME = "AGCODService";
		$serviceTarget = "com.amazonaws.agcod." . $SERVICE_NAME . "." . $serviceOperation;
		$dateString = $this->getDateString();
		$signatureAWSKey = $KEY_QUALIFIER . $secretKey;

		$kDate = $this->hmac($dateString, $signatureAWSKey);
		$kDate_hexis = $this->hmac($dateString, $signatureAWSKey, false);
		$kRegion = $this->hmac($regionName, $kDate);
		$kRegion_hexis = $this->hmac($regionName, $kDate, false);
		$kService = $this->hmac($SERVICE_NAME, $kRegion);
		$kService_hexis =  $this->hmac($SERVICE_NAME, $kRegion, false);


		$contentType = $this->getContentType();
		$url = "https://" . self::ENDPOINT . "/" .  $serviceOperation;

		//Prepare to send the data to the server
		$handle = curl_init($url);

		//Yes, do POST not GET
		curl_setopt($handle, CURLOPT_POST, true);

		//This is header, not post fields
		curl_setopt($handle, CURLOPT_HTTPHEADER , array(
				   "Content-Type:$contentType",
				   'Content-Length: ' . strlen($payload), 
		$AUTHORIZATION_HEADER. ":" . $authorizationValue,
		$XAMZDATE_HEADER . ":" . $dateTimeString,
		$XAMZTARGET_HEADER . ":" . $serviceTarget,
		$ACCEPT_HEADER . ":" . $contentType
		));
		 
		//Unlike most post requests, this is not a key-value pair, but just the XML/JSON.
		curl_setopt($handle, CURLOPT_POSTFIELDS, $payload);

		//Yes, don't print the result to the web page, just give it to us in a string.
		curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);

		//Do the request
		$result = curl_exec($handle);
		if (empty($result)) {
			// some kind of an error happened
			die(curl_error($handle));
			curl_close($handle); // close cURL handler
		}
		 

		//Free the resource
		curl_close($handle);


		$signaturePos = strpos($authorizationValue, "Signature=");
		if($signaturePos == FALSE || $signaturePos + 10 >= strlen($authorizationValue)) {
			$signatureStr = "Malformed";
		}
		else {
			$signatureStr = substr($authorizationValue, $signaturePos + 10);
		}



		if ( $this->debug )
		{
			echo "
			       <b>Payload:</b><p>" . ($payload) . "</p>
			       <b>Hased Payload:</b><p>" . $this->myHash($payload) . "</p>
			       <b>Canonical Request:</b><p>" . $this->convertNewline($canonicalRequest) . "</p> 
			       <b>Hashed Canonical Request:</b><p>" . $canonicalRequestHash . "</p> 
			       <b>key:</b><p>" . $secretKey . "</p>
			       <b>Secretkey:</b><p>" . $signatureAWSKey . "</p>
			       <b>Hashed Secretkey:</b><p>" . $this->myHash($signatureAWSKey) . "</p>
			       <b>X-amz-date:</b><p>" . $dateTimeString . "</p>
			       <b>String To Sign:</b><p>" . $this->convertNewline($stringToSign) . "</p>
			       <b>Endpoint:</b><p>" . $endpoint . "</p>
			       <b>Region:</b><p>" . $regionName. "</p>
			       <b>Authorization:</b><p>" . $authorizationValue . "</p>
			       <b>kDate:</b><p>" . $kDate_hexis . "</p>
			       <b>kRegion:</b><p>" .  $kRegion_hexis . "</p>
			       <b>kService:</b><p>" . $kService_hexis . "</p>
			       <b>kSigning:</b><p>" . $this->buildDerivedKey(false) . "</p>
			       <b>Signature:</b><p>" .  $signatureStr . "</p>
			       <b>Signed Request:</b><p> 
			       POST /" . $serviceOperation . " HTTP/1.1" . "</br>" . $this->convertNewline($this->header1($serviceOperation)) . "</br>
			       Authorization: " . $authorizationValue  . "</br>" . htmlEntities($payload) . " </p>
			       </br>
			       <b> Response: </b><p>".  htmlspecialchars($result) . "</p>
			       </br>
			       </br>";

		}
		 
		 
		return $result;
	}

	/**
	 * Gets the HTML string that the "Display String to Sign" button produces.
	 *
	 * @return The string to sign in HTML format.
	 */
	public function displayStringToSign() {
		$endpoint = $_POST["endpoint"];
		$dateTimeString = $this->getTimeStamp();
		$canonicalRequest = $this->buildCanonicalRequest();
		$canonicalRequestHash = $this->myHash($canonicalRequest);
		 
		$stringToSign = $this->buildStringToSign($canonicalRequestHash);
		return "<b>String To Sign:</b><p>" . $this->convertNewline($stringToSign) . "</p>";
	}

	/**
	 * Builds the string that gets hashed and used in the authenication.
	 *
	 * @param $canonicalRequestHash The hash of the canonicalRequest
	 * @return The string to sign.
	 */
	public function  buildStringToSign($canonicalRequestHash){
		$AWS_SHA256_ALGORITHM = self::AWS_SHA256_ALGORITHM;
		$TERMINATION_STRING = self::TERMINATION_STRING;
		$SERVICE_NAME = self::SERVICE_NAME;
		 
		$awsSecretKey =  $this->secret_key;
		$regionName = $this->getRegion();
		$dateTimeString = $this->getTimeStamp();
		$dateString = $this->getDateString();
		$stringToSign = "$AWS_SHA256_ALGORITHM\n$dateTimeString\n$dateString/$regionName/$SERVICE_NAME/$TERMINATION_STRING\n$canonicalRequestHash";

		return $stringToSign;
	}

	/**
	 * Builds the authenication string used to prove that the request is allowed and made by the right party.
	 *
	 * @param $stringToSign The string to sign.
	 * @return The authenication signature.
	 */
	public function buildAuthSignature($stringToSign) {
		$AWS_SHA256_ALGORITHM = self::AWS_SHA256_ALGORITHM;
		$SERVICE_NAME = self::SERVICE_NAME;
		$TERMINATION_STRING = self::TERMINATION_STRING;
		$ACCEPT_HEADER = self::ACCEPT_HEADER;
		$HOST_HEADER = self::HOST_HEADER;
		$XAMZDATE_HEADER = self::XAMZDATE_HEADER;
		$XAMZTARGET_HEADER = self::XAMZTARGET_HEADER;
		 
		$awsKeyId = $this->access_key;
		$regionName= $this->getRegion();
		 
		$dateString = $this->getDateString();
		$derivedKey = $this->buildDerivedKey();
		$derivedKey_lower = $this->buildDerivedKey(false);
		// Calculate signature per http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
		$finalSignature = $this->hmac($stringToSign, $derivedKey, false);
		 
		// Assemble Authorization Header with signing information
		// per http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
		$authorizationValue =
		$AWS_SHA256_ALGORITHM
		. " Credential="   . $awsKeyId
		. "/" . $dateString . "/" . $regionName . "/" . $SERVICE_NAME . "/" . $TERMINATION_STRING . ","
		. " SignedHeaders="
		. $ACCEPT_HEADER . ";"  . $HOST_HEADER . ";" . $XAMZDATE_HEADER . ";" . $XAMZTARGET_HEADER . ","
		. " Signature="
		. $finalSignature;
		 
		return $authorizationValue;
	}

	/**
	 * Gets the time stamp used to make the request. If not set by the client it is set to the current time on the first call to this public function.
	 *
	 * @return The time stamp
	 */
	public function getTimeStamp() {
		$timeStamp = gmdate('Ymd\THis\Z');
		return $timeStamp;
	}


}


?>
