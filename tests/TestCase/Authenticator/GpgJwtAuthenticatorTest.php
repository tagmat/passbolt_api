<?php
declare(strict_types=1);

/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         3.1.0
 */
namespace App\Test\TestCase\Authenticator;

use App\Authenticator\GpgJwtAuthenticator;
use App\Utility\UuidFactory;
use Authentication\Authenticator\Result;
use Authentication\Identifier\TokenIdentifier;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\ServerRequest;
use Cake\Routing\Router;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;

class GpgJwtAuthenticatorTest extends TestCase
{
    /** @var GpgJwtAuthenticator $sut */
    protected $sut;

    public function setUp(): void
    {
        parent::setUp();
        $this->sut = new GpgJwtAuthenticator(new TokenIdentifier());
    }


    public function testGpgJwtAuthenticatorAuthenticateError_NoData()
    {
        $request = new ServerRequest();
        $authenticator = new GpgJwtAuthenticator(new TokenIdentifier());
//        $request = $request->withAttribute('params', ['controller' => 'AuthLoginController', 'action' => 'loginGet']);
        $result = $authenticator->authenticate($request);
        $this->assertEquals($result->getStatus(), Result::FAILURE_CREDENTIALS_MISSING);
    }


    // ========================================================================
    // Assert checks
    // ========================================================================
    // Server fingerprint
    public function testGpgJwtAuthenticatorAssertServerFingerprint_EmptyError()
    {
        $this->expectException(InternalErrorException::class);
        $this->sut->assertServerFingerprint(null);
    }

    public function testGpgJwtAuthenticatorAssertServerFingerprint_NotFingerprintError()
    {
        $this->expectException(InternalErrorException::class);
        $this->sut->assertServerFingerprint('nope');
    }

    public function testGpgJwtAuthenticatorAssertServerFingerprint_Success()
    {
        $this->sut->assertServerFingerprint('E8FE388E385841B382B674ADB02DADCD9565E1B8');
        $this->assertTrue(true);
    }

    // Server passphrase
    public function testGpgJwtAuthenticatorAssertServerPassphrase_EmptyError()
    {
        $this->expectException(InternalErrorException::class);
        $this->sut->assertServerPassphrase(null);
    }

    public function testGpgJwtAuthenticatorAssertServerPassphrase_NotStringError()
    {
        $this->expectException(InternalErrorException::class);
        $this->sut->assertServerPassphrase([]);
    }

    public function testGpgJwtAuthenticatorAssertServerPassphrase_Success()
    {
        $this->sut->assertServerPassphrase('cofveve');
        $this->assertTrue(true);
    }

    // User id
    public function testGpgJwtAuthenticatorAssertUserId_EmptyError()
    {
        $this->expectException(BadRequestException::class);
        $this->sut->assertUserId(null);
    }

    public function testGpgJwtAuthenticatorAssertUserId_NotStringError()
    {
        $this->expectException(BadRequestException::class);
        $this->sut->assertUserId([]);
    }

    public function testGpgJwtAuthenticatorAssertServerPassphrase_NotUuid()
    {
        $this->expectException(BadRequestException::class);
        $this->sut->assertUserId('');
    }

    public function testGpgJwtAuthenticatorAssertServerPassphrase_NotUuid2()
    {
        $this->expectException(BadRequestException::class);
        $this->sut->assertUserId('test');
    }

    public function testGpgJwtAuthenticatorAssertUserId_Success()
    {
        $this->sut->assertUserId(UuidFactory::uuid());
        $this->assertTrue(true);
    }

    // Armored challenge
    public function testGpgJwtAuthenticatorAssertArmoredChallenge_EmptyError()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->sut->assertArmoredChallenge(null);
    }

    public function testGpgJwtAuthenticatorAssertArmoredChallenge_NotStringError()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->sut->assertArmoredChallenge([]);
    }

    public function testGpgJwtAuthenticatorAssertArmoredChallenge_NotOpenpgpMessageError()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->sut->setOpenPGPBackend();
        $this->sut->assertArmoredChallenge('test');
    }

    // Protocol version
    public function testGpgJwtAuthenticatorAssertVersion_EmptyError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVersion(null);
    }

    public function testGpgJwtAuthenticatorAssertVersion_NotStringError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVersion([]);
    }

    public function testGpgJwtAuthenticatorAssertVersion_NotSemverError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVersion('test');
    }

    public function testGpgJwtAuthenticatorAssertVersion_Success()
    {
        $this->sut->assertVersion(GpgJwtAuthenticator::PROTOCOL_VERSION);
        $this->assertTrue(true);
    }

    // Domain
    public function testGpgJwtAuthenticatorAssertDomain_EmptyError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertDomain(null);
    }

    public function testGpgJwtAuthenticatorAssertDomain_NotStringError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertDomain([]);
    }

    public function testGpgJwtAuthenticatorAssertDomain_NotDomainError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertDomain('nope');
    }

    public function testGpgJwtAuthenticatorAssertDomain_WrongDomainError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertDomain('https://www.google.com');
    }

    public function testGpgJwtAuthenticatorAssertDomain_Success()
    {
        $this->sut->assertDomain(Router::url(true));
        $this->assertTrue(true);
    }

    // Verify token
    public function testGpgJwtAuthenticatorAssertVerifyToken_EmptyError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyToken(null);
    }

    public function testGpgJwtAuthenticatorAssertVerifyToken_NotStringError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyToken([]);
    }

    public function testGpgJwtAuthenticatorAssertVerifyToken_NotShaError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyToken('nope');
    }

    public function testGpgJwtAuthenticatorAssertVerifyToken_ErrorNotNonce()
    {
        $this->markTestIncomplete();
    }

    public function testGpgJwtAuthenticatorAssertVerifyToken_Success()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyToken(Security::hash('test', 'sha512', true));
    }

    // Verify token expiry
    public function testGpgJwtAuthenticatorAssertVerifyTokenExpiry_EmptyError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyTokenExpiry(null);
    }

    public function testGpgJwtAuthenticatorAssertVerifyTokenExpiry_NotIntError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyTokenExpiry('test');
    }

    public function testGpgJwtAuthenticatorAssertVerifyTokenExpiry_PastError()
    {
        $this->expectException(\Exception::class);
        $this->sut->assertVerifyTokenExpiry(1);
    }

    public function testGpgJwtAuthenticatorAssertVerifyTokenExpiry_Success()
    {
        $this->sut->assertVerifyTokenExpiry(Time() + 60);
        $this->assertTrue(true);
    }
}
