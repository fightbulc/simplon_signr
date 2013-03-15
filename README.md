<pre>
     _                 _                   _
 ___(_)_ __ ___  _ __ | | ___  _ __    ___(_) __ _ _ __  _ __
/ __| | '_ ` _ \| '_ \| |/ _ \| '_ \  / __| |/ _` | '_ \| '__|
\__ \ | | | | | | |_) | | (_) | | | | \__ \ | (_| | | | | |
|___/_|_| |_| |_| .__/|_|\___/|_| |_| |___/_|\__, |_| |_|_|
                |_|                          |___/
</pre>

# Simplon Signr

Signr creates an signed-request (also known as access token) by a given data array in combination with a secret key which is only known by the transmitter and receiver of the payload. By default the signed-request is secured against fraud through a [hash_hmac](http://php.net/manual/en/function.hash-hmac.php) signature. Additionally, if the data array holds a key named ```secret``` all data within that key will be encrypted. To ensure that the signed-request can be send via URL it will be encoded via [base64](http://php.net/manual/en/function.base64-encode.php).

## Create a signed request

```php
use Simplon\Signr\Signr;

$secretKeySignedRequest = '123456';

$data = [
  'secret' => [
    'user'         => [
      'gameUid'      => 'xxx',
      'email'        => 'xxx',
      'gameServerId' => 'xxx',
    ],
    'order'        => [
      'checkoutUid'    => 'xxx',
      'inGameCurrency' => 'xxx',
      'realCurrency'   => 'xxx',
      'currencyCode'   => 'xxx',
      'provider'       => 'xxx',
      'created'        => 'xxx',
    ],
    'partnerToken' => 'xxx',
  ],
];

// create signed request
$signedRequest = (new Signr())->createSignedRequest($data, $secretKeySignedRequest);
```

### Generated signed request

```text
VaR6EKGui6clTkLSEVps-fzKgEy9BzEYvK-sWi59kTM.eyJzZWNyZXQiOiJrQ2RXRE50M280MUJvNkZ
cL1drS3lwVUtyeGJUMnB0SVB6eG4zdVBFV3FkMFlsYTc4UlpRWTVCZm55MFp6d3R1bHVzaU5pZDJHK1
BWRDN5VExVVFZwUEw5SHZCYkFTeXd4eGpBemxpajlvTXFOUHIrUFlwOVNVOTdhV1pHSGR5QnduTTBTd
1BYZW1FTXBhVGt6XC9iV3pHTlB6d3JaQ3cxdElHWUtpRDhIUGlOdks3QUorWDdmcTE1cHBrY3lUUHVJ
MUNQd283TXdMbGdPVDdkWWNnVVZCcWlqQjBQWWRZU3NwOElQYzRhYmQxejI5NlBmWmNZTDBBejlhOWo
2WE1CcnoiLCJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImlzc3VlZF9hdCI6MTM2MTc3ODYxMn0
```

## Read a signed request

```php
use Simplon\Signr\Signr;

$signedRequest = 'xxxzzzyyy';
$secretKeySignedRequest = '123456';

// read data should result the following array...
$data = (new Signr())->readSignedRequest($signedRequest, $secretKeySignedRequest);

/*
$data = [
  'secret' => [
    'user'         => [
      'gameUid'      => 'xxx',
      'email'        => 'xxx',
      'gameServerId' => 'xxx',
    ],
    'order'        => [
      'checkoutUid'    => 'xxx',
      'inGameCurrency' => 'xxx',
      'realCurrency'   => 'xxx',
      'currencyCode'   => 'xxx',
      'provider'       => 'xxx',
      'created'        => 'xxx',
    ],
    'partnerToken' => 'xxx',
  ],
];
*/
```