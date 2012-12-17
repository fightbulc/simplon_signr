<?php

  namespace Simplon\Signr;

  class Signr
  {
    const SIGNED_REQUEST_ALGORITHM = 'HMAC-SHA256';

    // ##########################################

    /**
     * Base64 encoding that doesn't need to be urlencode()ed.
     * Exactly the same as base64_encode except it uses
     *   - instead of +
     *   _ instead of /
     *
     * @param string $input string
     * @return string base64Url encoded string
     */
    protected function base64UrlEncode($input)
    {
      $str = strtr(base64_encode(trim($input)), '+/', '-_');
      $str = str_replace('=', '', $str);

      return $str;
    }

    // ##########################################

    /**
     * Base64 encoding that doesn't need to be urlencode()ed.
     * Exactly the same as base64_encode except it uses
     *   - instead of +
     *   _ instead of /
     *   No padded =
     *
     * @param string $input base64UrlEncoded string
     * @return string
     */
    protected function base64UrlDecode($input)
    {
      return base64_decode(strtr(trim($input), '-_', '+/'));
    }

    // ##########################################

    /**
     * @param $dataString
     * @param $secretKey
     * @return string
     */
    protected function encryptData($dataString, $secretKey)
    {
      return trim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $secretKey, $dataString, MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND))));
    }

    // ##########################################

    /**
     * @param $encryptedString
     * @param $secretKey
     * @return string
     */
    protected function decryptData($encryptedString, $secretKey)
    {
      return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $secretKey, base64_decode(trim($encryptedString)), MCRYPT_MODE_ECB, mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB), MCRYPT_RAND)));
    }

    // ##########################################

    /**
     * @param $data
     * @param $secretKey
     * @return string
     * @throws \Exception
     */
    public function createSignedRequest(array $data, $secretKey)
    {
      // encrypt "secret"
      if(isset($data['secret']))
      {
        $dataString = json_encode($data['secret']);
        $data['secret'] = $this->encryptData($dataString, $secretKey);
      }

      // add meta data
      $data['algorithm'] = self::SIGNED_REQUEST_ALGORITHM;
      $data['issued_at'] = time();

      // create encoded data
      $json = json_encode($data);
      $b64 = $this->base64UrlEncode($json);

      // create has mac
      $raw_sig = hash_hmac('sha256', $b64, $secretKey, $raw = TRUE);
      $sig = $this->base64UrlEncode($raw_sig);

      return $sig . '.' . $b64;
    }

    // ##########################################

    /**
     * @param $signedRequest
     * @param $secretKey
     * @return mixed
     * @throws \Exception
     */
    public function readSignedRequest($signedRequest, $secretKey)
    {
      list($encoded_sig, $payload) = explode('.', $signedRequest, 2);

      // decode the data
      $sig = $this->base64UrlDecode($encoded_sig);
      $data = json_decode($this->base64UrlDecode($payload), TRUE);

      // validate used algorithm
      if(strtoupper($data['algorithm']) !== self::SIGNED_REQUEST_ALGORITHM)
      {
        throw new \Exception(__NAMESPACE__ . ': unknown algorithm. Expected ' . self::SIGNED_REQUEST_ALGORITHM);
      }

      // validate signature
      $expected_sig = trim(hash_hmac('sha256', $payload, $secretKey, $raw = TRUE));

      if($sig !== $expected_sig)
      {
        throw new \Exception(__NAMESPACE__ . ': invalid signed signature. Good bye!');
      }

      // decrypt "secret"
      if(isset($data['secret']))
      {
        $decryptedString = $this->decryptData($data['secret'], $secretKey);
        $data['secret'] = json_decode($decryptedString, TRUE);
      }

      return $data;
    }
  }