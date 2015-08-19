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

/**
 * OAuthException
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
trait OAuthExceptionTrait
{
    /**
     * @var string
     */
    protected $realmName;

    /**
     * @var string
     */
    protected $errorCode;

    /**
     * @var array
     */
    protected $scopes = [];

    /**
     * @var integer
     */
    private $statusCode;

    /**
     * @var array
     */
    private $headers = [];

    /**
     * Quoted string for authenticate header
     *
     * @param  string $str
     * @return string
     */
    protected function quotedString($str)
    {
        $str = preg_replace('~
          [^
            \x21-\x7E
            \x80-\xFF
            \ \t
          ]
          ~x', '', $str);
        $str = addcslashes($str, '"\\');

        return '"' . $str . '"';
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
        $authenticateHeader  = sprintf('Bearer realm=%s', $this->quotedString($this->realmName));
        $authenticateHeader .= sprintf(', error=%s', $this->quotedString($this->errorCode));
        $authenticateHeader .= sprintf(', error_description=%s', $this->quotedString($this->getMessage()));

        if (!empty($this->scopes)) {
            $authenticateHeader .= sprintf(', scope=%s', $this->quotedString(implode(' ', $this->scopes)));
        }


        return [
            'Cache-Control'     => 'no-store',
            'Pragma'            => 'no-cache',
            'WWW-Authenticate'  => $authenticateHeader
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function getErrorCode()
    {
        return $this->errorCode;
    }

    /**
     * Get RealmName
     *
     * @return string
     */
    public function getRealmName()
    {
        return $this->realmName;
    }
}
