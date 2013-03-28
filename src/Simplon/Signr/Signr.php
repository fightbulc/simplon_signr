<?php

    namespace Simplon\Signr;

    class Signr
    {
        const SIGNED_REQUEST_ALGORITHM = 'HMAC-SHA256';

        protected $_signedRequest;
        protected $_secretKey;
        protected $_data;
        protected $_expireTimeMinutes = 0;

        // ##########################################

        /**
         * @param $message
         * @throws \Exception
         */
        protected function _throwException($message)
        {
            throw new \Exception(__NAMESPACE__ . ': ' . $message . '. Good bye!');
        }

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
         * @return Signr
         */
        public function create()
        {
            // get data
            $data = $this->getData();

            // get secret key
            $secretKey = $this->_getSecretKey();

            // handle validation
            if($data === FALSE || $secretKey === FALSE)
            {
                $this->_throwException('missing data and/or secretKey');
            }

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

            $this->setSignedRequest($sig . '.' . $b64);

            return $this;
        }

        // ##########################################

        /**
         * @return Signr
         */
        public function read()
        {
            // get signed request
            $signedRequest = $this->getSignedRequest();

            // get secret key
            $secretKey = $this->_getSecretKey();

            if(strpos($signedRequest, '.') === FALSE)
            {
                $this->_throwException('invalid signed signature');
            }

            list($encoded_sig, $payload) = explode('.', $signedRequest, 2);

            // decode the data
            $sig = $this->base64UrlDecode($encoded_sig);
            $data = json_decode($this->base64UrlDecode($payload), TRUE);

            // validate used algorithm
            if(strtoupper($data['algorithm']) !== self::SIGNED_REQUEST_ALGORITHM)
            {
                $this->_throwException('unknown algorithm. Expected ' . self::SIGNED_REQUEST_ALGORITHM);
            }

            // validate signature
            $expected_sig = trim(hash_hmac('sha256', $payload, $secretKey, $raw = TRUE));

            if($sig !== $expected_sig)
            {
                $this->_throwException('invalid signed signature');
            }

            // decrypt "secret"
            if(isset($data['secret']))
            {
                $decryptedString = $this->decryptData($data['secret'], $secretKey);
                $data['secret'] = json_decode($decryptedString, TRUE);
            }

            // set data
            $this->setData($data);

            return $this;
        }

        // ##########################################

        /**
         * @param $signedRequest
         * @return Signr
         */
        public function setSignedRequest($signedRequest)
        {
            $this->_signedRequest = $signedRequest;

            return $this;
        }

        // ##########################################

        /**
         * @return mixed
         * @throws \Exception
         */
        public function getSignedRequest()
        {
            if(! empty($this->_signedRequest))
            {
                return $this->_signedRequest;
            }

            $this->_throwException('missing signed signature');
        }

        // ##########################################

        /**
         * @param $secretKey
         * @return Signr
         */
        public function setSecretKey($secretKey)
        {
            $this->_secretKey = $secretKey;

            return $this;
        }

        // ##########################################

        /**
         * @return mixed
         * @throws \Exception
         */
        protected function _getSecretKey()
        {
            if(! empty($this->_secretKey))
            {
                return $this->_secretKey;
            }

            $this->_throwException('missing secret key');
        }

        // ##########################################

        /**
         * @param $data
         * @return Signr
         */
        public function setData($data)
        {
            $this->_data = $data;

            return $this;
        }

        // ##########################################

        /**
         * @return mixed
         * @throws \Exception
         */
        public function getData()
        {
            if(! empty($this->_data))
            {
                return $this->_data;
            }

            $this->_throwException('missing data');
        }

        // ##########################################

        /**
         * @param $minutes
         * @return Signr
         */
        public function setExpireTimeMinutes($minutes)
        {
            $this->_expireTimeMinutes = $minutes;

            return $this;
        }

        // ##########################################

        /**
         * @return mixed
         */
        protected function _getExpireTimeMinutes()
        {
            return $this->_expireTimeMinutes;
        }

        // ##########################################

        /**
         * @return mixed
         * @throws \Exception
         */
        protected function _getIssuedAtTime()
        {
            $data = $this->getData();

            if(isset($data['issued_at']))
            {
                return $data['issued_at'];
            }

            $this->_throwException('missing issued time');
        }

        // ##########################################

        /**
         * @return bool
         * @throws \Exception
         */
        public function isExpired()
        {
            $expireTimeMinutes = $this->_getExpireTimeMinutes();

            // "0" never expires
            if($expireTimeMinutes === 0)
            {
                return FALSE;
            }

            // calculate used time
            $expireTimeInSeconds = $expireTimeMinutes * 60;
            $sessionUsedTime = time() - $expireTimeInSeconds;

            return $sessionUsedTime > $this->_getIssuedAtTime();
        }
    }