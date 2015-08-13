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

use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Exception;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * OAuthAccessTokenExpiredException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
class OAuthAccessTokenExpiredException extends CredentialsExpiredException implements OAuthExceptionInterface/*, HttpExceptionInterface*/
{
    /**
     * @var integer
     */
    private $statusCode;

    /**
     * @var array
     */
    private $headers;

    /**
     *
     * @param string         $message
     * @param integer        $code
     * @param Exception|null $previous
     */
    public function __construct($message = '', $code = 401, Exception $previous = null, $headers = [])
    {
        parent::__construct($message, $code, $previous);

        $this->headers      = $headers;
        $this->statusCode   = $code;
    }

    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'The access token provided has expired.';
    }

    /**
     * {@inheritdoc}
     */
    public function getErrorCode()
    {
        return 'invalid_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode()
    {
        return $this->statusCode;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaders()
    {
        return $this->headers;
    }
}

