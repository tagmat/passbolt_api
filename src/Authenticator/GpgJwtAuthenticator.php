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
namespace App\Authenticator;

use App\Model\Entity\Role;
use App\Model\Entity\User;
use App\Model\Table\GpgkeysTable;
use App\Service\JwtAuthentication\CreateJwtUserSecretTokenService;
use App\Service\JwtAuthentication\RefreshTokenCreateService;
use App\Utility\OpenPGP\OpenPGPBackendFactory;
use Authentication\Authenticator\AbstractAuthenticator;
use Authentication\Authenticator\Result;
use Authentication\Authenticator\ResultInterface;
use Cake\Core\Configure;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\ForbiddenException;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\Log\Log;
use Cake\ORM\TableRegistry;
use Cake\Routing\Router;
use Cake\Validation\Validation;
use Psr\Http\Message\ServerRequestInterface;

class GpgJwtAuthenticator extends AbstractAuthenticator
{
    const PROTOCOL_VERSION = '1.0.0';

    /**
     * @var \App\Utility\OpenPGP\OpenPGPBackendInterface $gpg gpg backend
     * @access protected
     */
    protected $gpg;

    /**
     * @var \Cake\Http\ServerRequest $request request
     * @access protected
     */
    protected $request;

    /**
     * @var User $user user
     * @access protected
     */
    protected $user;

    /**
     * When an unauthenticated user tries to access a protected page this method is called
     *
     * @param \Cake\Http\ServerRequest $request interface for accessing request parameters
     * @param \Cake\Http\Response $response features and functionality for generating HTTP responses
     * @throws \Cake\Http\Exception\ForbiddenException
     * @return void
     */
    public function unauthenticated(ServerRequest $request, Response $response)
    {
        // If it's JSON we show an error message
        if ($request->is('json')) {
            throw new ForbiddenException(__('You need to login to access this location.'));
        }
        // Otherwise we let the controller handle the redirections
    }

    /**
     * Authenticate
     *
     * @param ServerRequestInterface $request interface for accessing request parameters
     * @return \Authentication\Authenticator\ResultInterface User|false the user or false if authentication failed
     */
    public function authenticate(ServerRequestInterface $request): ResultInterface
    {
        try {
            $this->request = $request;
            $this->init();
            $verifyToken = $this->verifyChallenge();

            return $this->successResult($verifyToken);
        } catch (\InvalidArgumentException $exception) {
            return $this->errorResult($exception, Result::FAILURE_CREDENTIALS_MISSING);
        } catch (NotFoundException $exception) {
            return $this->errorResult($exception, Result::FAILURE_IDENTITY_NOT_FOUND);
        } catch(BadRequestException $exception) {
            return $this->errorResult($exception, Result::FAILURE_CREDENTIALS_INVALID);
        } catch(\Exception $exception) {
            return $this->errorResult($exception, Result::FAILURE_OTHER);
        }
    }

    /**
     * Authentication process initialization
     *
     * @throws InternalErrorException if the server or user keys cannot be loaded
     * @throws BadRequestException if the user data is not valid, if the user id is not provided
     * @throws NotFoundException if the user cannot be found, is deleted, is not active
     */
    public function init() {
        $this->setOpenPGPBackend();
        $this->setServerKey();
        $this->loadUserData();
        $this->setUserKey();
    }

    /**
     * Format success results
     *
     * @param string $verifyToken
     * @return Result
     * @access private
     */
    public function successResult(string $verifyToken): Result
    {
        $accessToken = (new CreateJwtUserSecretTokenService())->createToken($this->user->id);
        $refreshToken = (new RefreshTokenCreateService())->createToken($this->user->id);
        $challenge = json_encode([
            'version' => self::PROTOCOL_VERSION,
            'domain' => Router::url(true),
            'verify_token' => $verifyToken,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken->token,
        ]);
        $armoredChallenge = $this->gpg->encryptSign($challenge);
        $data = ['challenge' => $armoredChallenge, 'user' => $this->user];

        return new Result($data, Result::SUCCESS);
    }

    /**
     * Format error result
     * Log additional information about the error for the administrator
     *
     * @param \Exception $exception
     * @param string $reason
     * @return Result
     * @access private
     */
    public function errorResult(\Exception $exception, string $reason): Result
    {
        Log::error($exception->getMessage());
        return new Result(null, $reason);
    }

    /**
     * @throws \Cake\Http\Exception\InternalErrorException if backend cannot be loaded
     */
    public function setOpenPGPBackend(): void
    {
        $this->gpg = OpenPGPBackendFactory::get();
    }

    /**
     * @throws InternalErrorException if the server key cannot be loaded
     */
    public function setServerKey(): void
    {
        // Check if config contains fingerprint
        $fingerprint = Configure::read('passbolt.gpg.serverKey.fingerprint');
        $this->assertServerFingerprint($fingerprint);

        // Check if config contains valid passphrase
        $passphrase = Configure::read('passbolt.gpg.serverKey.passphrase');
        $this->assertServerPassphrase($passphrase);

        // set the key to be used for decrypting
        try {
            $this->gpg->setDecryptKeyFromFingerprint($fingerprint, $passphrase);
        } catch (\Exception $exception) {
            try {
                $this->gpg->importServerKeyInKeyring();
                $this->gpg->setDecryptKeyFromFingerprint($fingerprint, $passphrase);
            } catch (\Exception $exception) {
                $msg = __('The OpenPGP server key defined in the config cannot be used to decrypt.') . ' ';
                $msg .= $exception->getMessage();
                throw new InternalErrorException($msg);
            }
        }
    }

    /**
     * Set user key
     * @throws BadRequestException if the user data is not valid
     * @throws InternalErrorException if the user key cannot be loaded
     */
    public function setUserKey(): void
    {
        try {
            $this->gpg->setVerifyKeyFromFingerprint($this->user->gpgkey->fingerprint);
            $this->gpg->setEncryptKeyFromFingerprint($this->user->gpgkey->fingerprint);
        } catch (\Exception $exception) {
            // Try to import the key in keyring again
            try {
                $this->gpg->importKeyIntoKeyring($this->user->gpgkey->armored_key);
                $this->gpg->setVerifyKeyFromFingerprint($this->user->gpgkey->fingerprint);
                $this->gpg->setEncryptKeyFromFingerprint($this->user->gpgkey->fingerprint);
            } catch (\Exception $exception) {
                $msg = __('Could not import the user OpenPGP key.');
                throw new InternalErrorException($msg);
            }
        }
    }

    /**
     * Load user data including OpenPGP key in $user props
     * @throws BadRequestException if the user id is missing in the request
     * @throws NotFoundException if the user cannot be found, is deleted, is not active
     * @access private
     */
    public function loadUserData(): void
    {
        $userId = $this->request->getData('user_id');
        $this->assertUserId($userId);

        try {
            /** @var \App\Model\Table\UsersTable $Users */
            $Users = TableRegistry::getTableLocator()->get('Users');

            /** @var \App\Model\Entity\User $user */
            $userData = $Users->findView($userId, Role::GUEST)
                ->contain('Gpgkeys')
                ->first();
            $this->assertUserData($userData);
            $this->user = $userData;
        } catch (\Exception $exception) {
            Log::error($exception->getMessage());
            throw new NotFoundException(__('The user could does not exist or has been deleted.'));
        }
    }

    /**
     * @throws \InvalidArgumentException if the challenge is missing
     * @throws BadRequestException if the challenge is invalid
     * @return string
     */
    public function verifyChallenge(): string
    {
        // Sanity check
        $armoredChallenge = $this->request->getData('challenge');
        $this->assertArmoredChallenge($armoredChallenge);

        // Decrypt
        try {
            $this->assertUserSignature($armoredChallenge);
            $clearTextChallenge = $this->gpg->decrypt($armoredChallenge);
        } catch(\Exception $exception) {
            Log::error($exception->getMessage());
            throw new BadRequestException(__('The challenge cannot be decrypted.'));
        }

        // Deserialize JSON
        try {
            $jsonChallenge = json_decode($clearTextChallenge, false, 1, JSON_THROW_ON_ERROR);
            list(
                'version' => $version,
                'domain' => $domain,
                'verify_token' => $verifyToken,
                'verify_token_expiry' => $verifyTokenExpiry
            ) = $jsonChallenge;
        } catch(\Exception $exception) {
            Log::error($exception->getMessage() . "\n" . $clearTextChallenge);
            throw new BadRequestException(__('The challenge is invalid.'));
        }

        // Challenge sanity check
        try {
            $this->assertVersion($version);
            $this->assertDomain($domain);
            $this->assertVerifyTokenExpiry($verifyTokenExpiry);
            $this->assertVerifyToken($verifyToken);
        } catch(\Exception $exception) {
            Log::error($exception->getMessage() . "\n" . $jsonChallenge);
            throw new BadRequestException(__('The challenge is invalid.'));
        }

        return $verifyToken;
    }

    /**
     * @param mixed $fingerprint
     * @throws InternalErrorException
     */
    public function assertServerFingerprint($fingerprint): void
    {
        if (!is_string($fingerprint) || !GpgkeysTable::isValidFingerprint($fingerprint)) {
            $msg = __('The config for the server private key fingerprint is not available or incomplete.');
            throw new InternalErrorException($msg);
        }
    }

    /**
     * @param mixed $passphrase
     * @throws InternalErrorException
     */
    public function assertServerPassphrase($passphrase): void
    {
        if (!is_string($passphrase)) {
            $msg = __('The config for the server private key passphrase is invalid.');
            throw new InternalErrorException($msg);
        }
    }

    /**
     * @param mixed $userId uuid
     * @throws BadRequestException
     */
    public function assertUserId($userId): void
    {
        if (!is_string($userId) || !Validation::uuid($userId)) {
            $msg = __('The user id is missing or invalid.');
            throw new BadRequestException($msg);
        }
    }

    /**
     * @param mixed $userData data
     * @throws BadRequestException
     */
    public function assertUserData($userData): void
    {
        if (!isset($userData->gpgkey) ||
            !isset($userData->gpgkey->fingerprint) ||
            !isset($userData->gpgkey->armored_key) ||
            !is_string($userData->gpgkey->fingerprint) ||
            !GpgkeysTable::isValidFingerprint($userData->gpgkey->fingerprint) ||
            !is_string($userData->gpgkey->armored_key)) {
            throw new BadRequestException(__('The user key could does not exist or has been deleted.'));
        }
    }

    /**
     * @param mixed $armoredChallenge challenge
     * @throws \Exception if armored challenge is invalid
     * @return void
     */
    public function assertUserSignature(string $armoredChallenge): void
    {
        try {
            $this->gpg->verify($armoredChallenge);
        } catch (\Exception $exception) {
            Log::error($exception->getMessage());
            throw new BadRequestException(__('The user signature is invalid.'));
        }
    }

    /**
     * @param mixed $armoredChallenge challenge
     * @throws \InvalidArgumentException if armored challenge is invalid
     * @return void
     */
    public function assertArmoredChallenge($armoredChallenge): void
    {
        if (!isset($armoredChallenge) ||
            !is_string($armoredChallenge) ||
            !$this->gpg->isValidMessage($armoredChallenge)) {
            throw new \InvalidArgumentException(__('The user challenge is missing or invalid.'));
        }
    }

    /**
     * @param mixed $version version
     * @throws \Exception if version is not supported
     * @return void
     */
    public function assertVersion($version): void
    {
        if (!isset($version) || !is_string($version) || $version !== self::PROTOCOL_VERSION) {
            throw new \Exception(__('The version is invalid.'));
        }
    }

    /**
     * Assert domain
     * @param mixed $domain domain
     * @throws \Exception if domain is invalid
     * @return void
     */
    public function assertDomain($domain): void
    {
        if (!isset($domain) ||
            !is_string($domain) ||
            rtrim($domain, '/') !== rtrim(Router::url(true), '/')
        ) {
            throw new \Exception(__('The domain is invalid.'));
        }
    }

    /**
     * Assert verify token
     * @param mixed $verifyToken
     * @throws \Exception if version is not supported
     * @return void
     */
    public function assertVerifyToken($verifyToken): void
    {
        if (!isset($verifyToken) || !is_string($verifyToken) || preg_match('/^([a-f0-9]{64})$/', $verifyToken) !== 1) {
            throw new \Exception(__('The verify token is invalid.'));
        }
        // TODO check token nonce
    }

    /**
     * Assert very token expiry
     * @param $verifyTokenExpiry
     * @throws \Exception if version is not supported
     * @return void
     */
    public function assertVerifyTokenExpiry($verifyTokenExpiry): void
    {
        if (!isset($verifyTokenExpiry) ||
            !is_int($verifyTokenExpiry) ||
            $verifyTokenExpiry < time()
        ) {
            throw new \Exception(__('The verify token is invalid.'));
        }
    }
}
