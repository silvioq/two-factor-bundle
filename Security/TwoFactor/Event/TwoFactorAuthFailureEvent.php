<?php

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class  TwoFactorAuthFailureEvent extends Event
{
    const  NAME = 'scheb_two_factor.authentication.failure';

    /**
     * @var TokenInterface
     */
    private  $token;

    public  function  __construct( TokenInterface $token )
    {
        $this->token = $token;
    }

    /**
     * @return TokenInterface
     */
    public  function  getToken( )
    {
        return  $this->token;
    }
}
