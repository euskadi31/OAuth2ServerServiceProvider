<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Core\Exception;

use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Exception;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * OAuthUnauthorizedClientException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthUnauthorizedClientException extends InvalidArgumentException implements OAuthExceptionInterface, HttpExceptionInterface
{
    use OAuthExceptionTrait;

    /**
     *
     * @param string         $message
     * @param integer        $code
     * @param Exception|null $previous
     * @param string         $realmName
     */
    public function __construct($message = '', $code = 401, Exception $previous = null, $realmName = 'API')
    {
        if (empty($message)) {
            $message = 'The authenticated client is not authorized to use this authorization grant type.';
        }

        parent::__construct($message, $code, $previous);

        $this->statusCode   = $code;
        $this->errorCode    = 'unauthorized_client';
        $this->realmName    = $realmName;
    }
}
