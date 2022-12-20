<?php
// para executar:
// - Habilite o cUrl no PHP
// - Habilite o OpenSSL no PHP
// - Altere a linha iuru_rsa->api_token, informando seu token
// - Execute o arquivo com o comando abaixo:
// php ./iugu_rsa_sample.php

// #####################################################################################################
// #####################################################################################################
// #####################################################################################################

// #####################################################################################################
//                                           IUGU_RSA_SAMPLE
class IUGU_RSA_SAMPLE
{
    public $echo_vars = false;
    public $api_token = 'TOKEN CREATED ON IUGU PANEL'; // Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#criando-chave-api-com-assinatura
    public $file_private_key = '/file_path/private_key.pem'; // Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#segundo-passo
    public $timezone = 'UTC';

    private function get_request_time()
    {
        // Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#quinto-passo

        $datetime = new \DateTime();
        $datetime->setTimeZone(new \DateTimeZone($this->timezone));
        $datetime_iso8601 = sprintf(
            '%s%s',
            $datetime->format('Y-m-d\TH:i:s'),
            $datetime->format('P')
        );
        return $datetime_iso8601;
    }

    private function get_private_key()
    {
        $text_key = file_get_contents($this->file_private_key);
        return openssl_pkey_get_private($text_key);
    }

    private function sign_body(
        $method,
        $endpoint,
        $request_time,
        $body,
        $private_key
    ) {
        // Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#sexto-passo

        $pattern =
            $method .
            '|' .
            $endpoint .
            "\n" .
            $this->api_token .
            '|' .
            $request_time .
            "\n" .
            $body;
        $ret_sign = '';
        if (
            openssl_sign(
                $pattern,
                $ret_sign,
                $this->get_private_key(),
                OPENSSL_ALGO_SHA256
            )
        ) {
            $ret_sign = base64_encode($ret_sign);
        } else {
            die('error in openssl_sign');
        }
        return $ret_sign;
    }

    private function send_data($method, $endpoint, &$response, $data)
    {
        // Link de referência:  https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#d%C3%A9cimo-primeiro-passo

        $request_time = $this->get_request_time();
        $body = json_encode($data);
        $signature = $this->sign_body(
            $method,
            $endpoint,
            $request_time,
            $body,
            $this->get_private_key()
        );

        if ($this->echo_vars) {
            echo '<h1>endpoint: ' . $method . ' - ' . $endpoint . '</h1>';
            echo '<p>request_time: ' . $request_time . '</p>';
            echo '<p>api_token: ' . $this->api_token . '</p>';
            echo '<p>body: ' . $body . '</p>';
            echo '<p>signature: ' . $signature . '</p>';
        }

        $header = [
            'Content-Type: application/json',
            'accept: application/json',
            'Signature: signature=' . $signature,
            'Request-Time: ' . $request_time,
        ];

        $curl = curl_init();

        // #############################################################################
        //case of error: SSL certificate problem: unable to get local issuer certificate
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
        // #############################################################################

        curl_setopt_array($curl, [
            CURLOPT_URL => 'https://api.iugu.com' . $endpoint,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $header,
        ]);

        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);
        if ($err) {
            $response = $err;
            return false;
        } else {
            return true;
        }
    }

    public function signature_validate(&$response, $data)
    {
        // Link de referência: https://dev.iugu.com/reference/validate-signature

        $method = 'POST';
        $endpoint = '/v1/signature/validate';
        return $this->send_data($method, $endpoint, $response, $data);
    }

    public function transfer_requests(&$response, $data)
    {
        $method = 'POST';
        $endpoint = '/v1/transfer_requests';
        return $this->send_data($method, $endpoint, $response, $data);
    }
}
// #####################################################################################################

//#####################################################################################################
//                                  Example of use IUGU_RSA_SAMPLE
//#####################################################################################################

$iuru_rsa = new IUGU_RSA_SAMPLE();
$iuru_rsa->api_token = '';
$iuru_rsa->echo_vars = true;
$iuru_rsa->file_private_key = __DIR__ . '/private.pem';

// #####################################################################################################
//                                       signature_validate
// Link de referência: https://dev.iugu.com/reference/validate-signature
$json = [
    'api_token' => $iuru_rsa->api_token,
    'mensagem' => 'qualquer coisa',
];
if ($iuru_rsa->signature_validate($response, $json)) {
    echo '<p>Response: ' . $response . '</p>';
} else {
    echo '<p>Error: ' . $response . '</p>';
}
// #####################################################################################################

// #####################################################################################################
//                                        transfer_requests
$json = [
    'api_token' => $iuru_rsa->api_token,
    'transfer_type' => 'pix',
    'amount_cents' => 1,
    'receiver' => [
        'pix' => [
            'key' => '000000000',
            'type' => 'cpf',
        ],
    ],
];
if ($iuru_rsa->transfer_requests($response, $json)) {
    echo '<p>Response: ' . $response . '</p>';
} else {
    echo '<p>Error: ' . $response . '</p>';
}
// #####################################################################################################
