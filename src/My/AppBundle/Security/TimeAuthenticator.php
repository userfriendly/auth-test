<?php

namespace My\AppBundle\Security;

use Symfony\Component\Security\Core\Authentication\SimpleFormAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\Request;

class TimeAuthenticator implements SimpleFormAuthenticatorInterface
{
    const LOGIN_START = 19;
    const LOGIN_END   = 20;

    private $encoderFactory;
    private $logger;

    public function __construct(EncoderFactoryInterface $encoderFactory, $logger)
    {
        $logger->info( "INSTANTIATED AUTHENTICATOR" );
        $this->encoderFactory = $encoderFactory;
        $this->logger = $logger;
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        $logger->info( "CALLED AUTHENTICATOR'S METHOD authenticateToken()" );
        try {
            $user = $userProvider->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $e) {
            throw new AuthenticationException('Invalid username or password');
        }

        $encoder = $this->encoderFactory->getEncoder($user);
        $passwordValid = $encoder->isPasswordValid(
            $user->getPassword(),
            $token->getCredentials(),
            $user->getSalt()
        );

        if ($passwordValid) {
            $currentHour = date('G');
            if ($currentHour < self::LOGIN_START || $currentHour > self::LOGIN_END) {
                throw new AuthenticationException(
                    'You can not log in at this time!',
                    100
                );
            }

            return new UsernamePasswordToken(
                $user,
                $user->getPassword(),
                $providerKey,
                $user->getRoles()
            );
        }

        throw new AuthenticationException('Invalid username or password');
    }

    public function supportsToken(TokenInterface $token, $providerKey)
    {
        $logger->info( "CALLED AUTHENTICATOR'S METHOD supportsToken()" );
        return $token instanceof UsernamePasswordToken
            && $token->getProviderKey() === $providerKey;
    }

    public function createToken(Request $request, $username, $password, $providerKey)
    {
        $logger->info( "CALLED AUTHENTICATOR'S METHOD supportsToken()" );
        return new UsernamePasswordToken($username, $password, $providerKey);
    }
}
