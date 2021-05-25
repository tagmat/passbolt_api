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
namespace App\Service\JwtAuthentication;

class CreateJwtKeysService
{
    protected $secretService;

    protected $publicService;

    /**
     * CreateJwtKeysService constructor.
     *
     * @param \App\Service\JwtAuthentication\GetJwtUserTokenSecretService|null $secretService JWT Secret Service
     * @param \App\Service\JwtAuthentication\GetJwksPublicService|null $publicService JWT Public Service
     */
    public function __construct(
        ?GetJwtUserTokenSecretService $secretService = null,
        ?GetJwksPublicService $publicService = null
    ) {
        $this->secretService = $secretService ?? new GetJwtUserTokenSecretService();
        $this->publicService = $publicService ?? new GetJwksPublicService();
    }

    /**
     * @return bool
     */
    public function createKeyPair(): bool
    {
        $secretFile = $this->secretService->getKeyPath();
        $publicFile = $this->publicService->getKeyPath();

        if (!is_readable($secretFile)) {
            # generate private key
            exec('openssl genrsa -out ' . $secretFile . ' 1024');
        }

        if (!is_readable($publicFile)) {
            # generate public key
            exec('openssl rsa -in ' . $secretFile . ' -outform PEM -pubout -out ' . $publicFile);
        }

        return true;
    }
}
