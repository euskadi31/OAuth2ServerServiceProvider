<?php
/*
 * This file is part of the OAuth2Server.
 *
 * (c) Axel Etcheverry <axel@etcheverry.biz>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Euskadi31\Component\Security\GrantType;

use Euskadi31\Component\Security\GrantType\GrantTypeCollection;
use Euskadi31\Component\Security\GrantType\GrantTypeInterface;

class GrantTypeCollectionTest extends \PHPUnit_Framework_TestCase
{
    public function testCollection()
    {
        $grantTypeMock = $this->getMock('Euskadi31\Component\Security\GrantType\GrantTypeInterface');
        $grantTypeMock->method('getName')
            ->will($this->returnValue('Mock_grant_type'));

        $collection = new GrantTypeCollection();
        $collection->addGrantType($grantTypeMock);

        $this->assertEquals($grantTypeMock, $collection->get('mock_grant_type'));
    }

    /**
     * @expectedException \Euskadi31\Component\Security\Core\Exception\OAuthUnsupportedGrantTypeException
     */
    public function testGetBadGrantType()
    {
        $collection = new GrantTypeCollection();
        $collection->get('bad_name');
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testAddExistingGrantType()
    {
        $grantTypeMock = $this->getMock('Euskadi31\Component\Security\GrantType\GrantTypeInterface');
        $grantTypeMock->method('getName')
            ->will($this->returnValue('Mock_grant_type'));

        $collection = new GrantTypeCollection();
        $collection->addGrantType($grantTypeMock);
        $collection->addGrantType($grantTypeMock);
    }
}
