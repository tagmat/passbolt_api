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

use App\Error\Exception\JWT\JwtKeyPairNotValidException;

abstract class JwtAbstractService
{
    /**
     * @var string
     */
    protected $keyPath;

    /**
     * @param string $path Path to the secret/private key file
     * @return void
     */
    public function setKeyPath(string $path): void
    {
        $this->keyPath = $path;
    }

    /**
     * @return string Path to the secret/private key file
     */
    public function getKeyPath(): string
    {
        return $this->keyPath;
    }

    /**
     * @return string Content of the secret/private key file
     * @throws \App\Error\Exception\JWT\JwtKeyPairNotValidException if the file is not found or not readable.
     */
    protected function readKeyFileContent(): string
    {
        if (!is_readable($this->keyPath)) {
            throw new JwtKeyPairNotValidException(__(
                'The key pair for JWT Authentication is not set. The following file could not be read: {0}.',
                $this->keyPath
            ));
        }

        return file_get_contents($this->keyPath);
    }
}
