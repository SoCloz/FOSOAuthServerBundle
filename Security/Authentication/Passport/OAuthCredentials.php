<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Security\Authentication\Passport;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CredentialsInterface;

/**
 * Implements credentials checking for an OAuth token.
 *
 * @author  Israel J. Carberry <iisisrael@gmail.com>
 *
 * @final
 */
class OAuthCredentials implements CredentialsInterface
{
    private bool $resolved = false;

    public function __construct(
        private ?string $tokenString,
        private string $scope,
    ) {
    }

    public function getRoles(UserInterface $user): array
    {
        $roles = $user->getRoles();

        if (empty($this->scope)) {
            return $roles;
        }

        foreach (explode(' ', $this->scope) as $role) {
            $roles[] = 'ROLE_'.mb_strtoupper($role);
        }

        return array_unique($roles, SORT_REGULAR);
    }

    public function getTokenString(): ?string
    {
        return $this->tokenString;
    }

    public function markResolved(): void
    {
        $this->resolved = true;
    }

    public function isResolved(): bool
    {
        return $this->resolved;
    }
}
