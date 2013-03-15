<?php

  require __DIR__ . '/../vendor/autoload.php';

  // ############################################

  $secretKey = '12345abcd';

  $data = [
    'secret'       => [
      'user' => [
        'id'       => 1,
        'username' => 'AnotherDay',
        'email'    => 'mail@allmails.com',
      ],
      'view' => 'blue01',
    ],
    'gameToken'    => 'kal',
    'partnerToken' => 'jag',
  ];

  echo "<h1>Data package:</h1>";
  var_dump($data);
  echo '<hr>';

  // ############################################

  echo "<h1>SignedRequest:</h1>";
  $signr = new Simplon\Signr\Signr();
  $signedRequest = $signr->createSignedRequest($data, $secretKey);
  var_dump($signedRequest);

  echo "<h1>Decoded SignedRequest:</h1>";
  $decodedSignedRequest = $signr->readSignedRequest($signedRequest, $secretKey);
  var_dump($decodedSignedRequest);
  echo '<hr>';