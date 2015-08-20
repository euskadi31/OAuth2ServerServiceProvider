<?php
/*
 * This file is part of the OAuth2ServerServiceProvider.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\Storage;

/**
 * ClientInterface
 *
 * @author Axel Etcheverry <axel@etcheverry.biz>
 */
interface ClientInterface
{
    /**
     * Get the client id
     *
     * @return string
     */
    public function getId();

    /**
     * Get the client secret
     *
     * @return string
     */
    public function getSecret();

    /**
     * Get the client name
     *
     * @return string
     */
    public function getName();

    /**
     * Returnt the client redirect URI
     *
     * @return string
     */
    public function getRedirectUri();

    /**
     * Check if client is enabled
     *
     * @return boolean
     */
    public function isEnabled();

    /**
     * Check if client is locked
     *
     * @return boolean
     */
    public function isLocked();

    /**
     * Check if client required signature
     *
     * @return boolean
     */
    public function isSignatureRequired();

    /**
     * Get grant type allowd for client
     *
     * @return array
     */
    public function getGrantTypes();
}
