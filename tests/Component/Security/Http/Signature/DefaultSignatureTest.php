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

use Euskadi31\Component\Security\Http\Signature\DefaultSignature;

class DefaultSignatureTest extends \PHPUnit_Framework_TestCase
{
    protected $key = '32c8e4373e94c8ffa0a05c575d8cae75d1e98c723b877638b606ad53668a';

    public function testSign()
    {
        $signature = new DefaultSignature();

        $sign1 = $signature->sign(
            'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1625&term=hello&fields=type,translations{title,program}',
            $this->key
        );

        $sign2 = $signature->sign(
            'https://api.domain.com/v1/search?fields=type,translations{title,program}&client_id=7f76ff8615d64e788ea5e9633def1625&term=hello',
            $this->key
        );

        $this->assertEquals($sign1, $sign2);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Signature argument not found.
     */
    public function testVerifyWithoutSignature()
    {
        $url = 'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1625&term=hello&fields=type,translations{title,program}';

        $signature = new DefaultSignature();

        $signature->verify($url, $this->key);
    }

    public function testVerifySignatureInUrl()
    {
        $url = 'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1625&term=hello&fields=type,translations{title,program}';

        $signature = new DefaultSignature();

        $sign = $signature->sign(
            $url,
            $this->key
        );

        $urlSigned = $url . '&sign=' . $sign;

        $this->assertTrue($signature->verify($urlSigned, $this->key));
    }

    public function testVerifySignatureInArgument()
    {
        $url = 'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1625&term=hello&fields=type,translations{title,program}';

        $signature = new DefaultSignature();

        $sign = $signature->sign(
            $url,
            $this->key
        );

        $this->assertTrue($signature->verify($url, $this->key, $sign));
    }

    public function testVerifySignatureWithInvalidUrl()
    {
        $url = 'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1625&term=hello&fields=type,translations{title,program}';

        $signature = new DefaultSignature();

        $sign = $signature->sign(
            $url,
            $this->key
        );

        $url = 'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1624&term=hi&fields=type,translations{title,program}';

        $this->assertFalse($signature->verify($url, $this->key, $sign));
    }

    public function testVerifySignatureWithInvalidKey()
    {
        $url = 'https://api.domain.com/v1/search?client_id=7f76ff8615d64e788ea5e9633def1625&term=hello&fields=type,translations{title,program}';

        $signature = new DefaultSignature();

        $sign = $signature->sign(
            $url,
            $this->key
        );

        $this->assertFalse($signature->verify($url, $this->key . '1', $sign));
    }
}
