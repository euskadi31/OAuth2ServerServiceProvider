<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Http\Signature;

use InvalidArgumentException;
use Symfony\Component\Security\Core\Util\StringUtils;

/**
 * Default signature
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class DefaultSignature implements SignatureInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign($url, $key)
    {
        $endpoint = http_build_url($url, [], HTTP_URL_STRIP_QUERY | HTTP_URL_STRIP_FRAGMENT);

        $params = [];

        if (strpos($url, '?') !== false) {
            parse_str(parse_url($url, PHP_URL_QUERY), $params);
        }

        $sig = $endpoint;

        if (!empty($params)) {
            ksort($params);

            $sig .= sprintf('?%s', http_build_query($params));
        }

        return hash_hmac('sha256', $sig, $key, false);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($url, $key, $signature = null)
    {
        if (strpos($url, 'sign=') !== false) {
            $params = [];
            parse_str(parse_url($url, PHP_URL_QUERY), $params);

            if (isset($params['sign'])) {
                if (empty($signature)) {
                    $signature = $params['sign'];
                }

                unset($params['sign']);
            }

            $url = http_build_url($url, [
                'query' => http_build_query($params)
            ], HTTP_URL_STRIP_FRAGMENT | HTTP_URL_REPLACE);
        }

        if (empty($signature)) {
            throw new InvalidArgumentException('Signature argument not found.');
        }

        $expected = $this->sign($url, $key);

        return StringUtils::equals($expected, $signature);
    }
}
