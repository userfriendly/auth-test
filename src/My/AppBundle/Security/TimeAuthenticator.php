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
        $logger->info( "INSTANTIATED AUTHENTICATOR" ); // shows up in dev.log
        $this->encoderFactory = $encoderFactory;
        $this->logger = $logger;
    }

    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        $this->logger->info( "CALLED AUTHENTICATOR'S METHOD authenticateToken()" ); // does not show up in dev.log
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
        $this->logger->info( "CALLED AUTHENTICATOR'S METHOD supportsToken()" ); // does not show up in dev.log
        return $token instanceof UsernamePasswordToken
            && $token->getProviderKey() === $providerKey;
    }

    public function createToken(Request $request, $username, $password, $providerKey)
    {
        $this->logger->info( "CALLED AUTHENTICATOR'S METHOD supportsToken()" ); // does not show up in dev.log
        return new UsernamePasswordToken($username, $password, $providerKey);
    }
}
