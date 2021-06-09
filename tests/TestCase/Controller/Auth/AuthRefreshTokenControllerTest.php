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
 * @since         3.3.0
 */
namespace App\Test\TestCase\Controller\Auth;

use App\Model\Entity\AuthenticationToken;
use App\Service\JwtAuthentication\JwtKeyPairCreateService;
use App\Service\JwtAuthentication\RefreshTokenRenewalService;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use App\Test\Lib\AppIntegrationTestCase;
use App\Test\Lib\Utility\JsonRequestTrait;
use App\Utility\UuidFactory;
use Cake\Datasource\ModelAwareTrait;
use Cake\TestSuite\IntegrationTestTrait;

/**
 * Class AuthRefreshTokenControllerTest
 *
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class AuthRefreshTokenControllerTest extends AppIntegrationTestCase
{
    use IntegrationTestTrait;
    use JsonRequestTrait;
    use ModelAwareTrait;

    public function setUp(): void
    {
        $this->loadModel('AuthenticationTokens');
        (new JwtKeyPairCreateService())->createKeyPair();
    }

    public function testAuthRefreshTokenControllerUnauthenticated()
    {
        $this->postJson('/auth/jwt/refresh.json', ['user_id' => UuidFactory::uuid()]);
        $this->assertResponseError();
    }

    public function testAuthRefreshTokenControllerAuthenticatedWithoutRefreshTokenCookie()
    {
        $user = UserFactory::make()->user()->persist();
        $this->createJwtTokenAndSetInHeader($user->id);

        $this->postJson('/auth/jwt/refresh.json', ['user_id' => $user->id]);
        $this->assertBadRequestError('No refresh token is provided in the request.');
    }

    public function testAuthRefreshTokenControllerAuthenticatedWithValidRefreshTokenCookie()
    {
        $user = UserFactory::make()->user()->persist();
        $oldRefreshToken = AuthenticationTokenFactory::make()
            ->active()
            ->type(AuthenticationToken::TYPE_REFRESH_TOKEN)
            ->userId($user->id)
            ->persist()
            ->token;

        // Set the JWT token in the header
        $this->createJwtTokenAndSetInHeader($user->id);

        $this->cookieEncrypted(
            RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE,
            $oldRefreshToken,
            'aes',
            RefreshTokenRenewalService::getPepper()
        );

        $this->postJson('/auth/jwt/refresh.json', ['user_id' => $user->id]);
        $this->assertResponseOk();

        $jwt = (string)$this->_responseJsonBody;

        // Get a fresh request
        $this->cleanup();
        $this->setJwtTokenInHeader($jwt);
        // Check that the delivered JWT is valid.
        $this->getJson('/auth/is-authenticated.json');
        $this->assertResponseOk();
    }

    public function testAuthRefreshTokenControllerAuthenticatedWithNonEncryptedCookie()
    {
        $user = UserFactory::make()->user()->persist();
        $oldRefreshToken = AuthenticationTokenFactory::make()
            ->active()
            ->type(AuthenticationToken::TYPE_REFRESH_TOKEN)
            ->userId($user->id)
            ->persist()
            ->token;

        // Set the JWT token in the header
        $this->createJwtTokenAndSetInHeader($user->id);

        // Set the refresh key in the cookies
        $this->cookie(
            RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE,
            $oldRefreshToken
        );

        $this->postJson('/auth/jwt/refresh.json', ['user_id' => $user->id]);
        $this->assertBadRequestError('No refresh token is provided in the request.');
    }

    public function testAuthRefreshTokenControllerAuthenticatedWithExpiredEncryptedCookie()
    {
        $user = UserFactory::make()->user()->persist();
        $oldRefreshToken = AuthenticationTokenFactory::make()
            ->active()
            ->type(AuthenticationToken::TYPE_REFRESH_TOKEN)
            ->userId($user->id)
            ->expired()
            ->persist()
            ->token;

        // Set the JWT token in the header
        $this->createJwtTokenAndSetInHeader($user->id);

        // Set the refresh key in the cookies
        $this->cookieEncrypted(
            RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE,
            $oldRefreshToken,
            'aes',
            RefreshTokenRenewalService::getPepper()
        );

        $this->postJson('/auth/jwt/refresh.json', ['user_id' => $user->id]);
        $this->assertResponseCode(401);
        $this->assertResponseError('The refresh token provided is expired.');
    }
}
