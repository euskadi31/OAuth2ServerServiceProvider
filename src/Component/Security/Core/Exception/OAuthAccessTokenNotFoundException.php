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

use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Exception;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * OAuthAccessTokenNotFoundException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthAccessTokenNotFoundException extends AuthenticationCredentialsNotFoundException implements OAuthExceptionInterface, HttpExceptionInterface
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
        parent::__construct($message, $code, $previous);

        $this->statusCode   = $code;
        $this->errorCode    = 'invalid_token';
        $this->realmName    = $realmName;
    }

    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'The access token could not be found.';
    }
}
