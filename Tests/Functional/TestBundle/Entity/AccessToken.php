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

namespace FOS\OAuthServerBundle\Tests\Functional\TestBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use FOS\OAuthServerBundle\Entity\AccessToken as BaseAccessToken;
use FOS\OAuthServerBundle\Model\ClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 * @ORM\Table(name="access_tokens")
 */
class AccessToken extends BaseAccessToken
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @ORM\ManyToOne(targetEntity="Client")
     * @ORM\JoinColumn(nullable=false)
     * @var ClientInterface
     */
    protected $client;

    /**
     * @ORM\ManyToOne(targetEntity="User")
     *
     * @var UserInterface
     */
    protected $user;
}
