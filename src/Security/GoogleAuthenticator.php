<?php

namespace App\Security;

use App\Entity\User;
use App\Security\Exception\EmailNotVerifiedException;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use League\OAuth2\Client\Provider\GoogleUser;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class GoogleAuthenticator extends AbstractOAuthAuthenticator
{
    protected string $serviceName = 'google';

    public function authenticate(Request $request): Passport
    {
        /** @var GoogleClient $client */
        $client = $this->getClient();

        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {

                /** @var GoogleUser $googleUser */
                $googleUser = $client->fetchUserFromToken($accessToken);

                $existingUser = $this->userRepository->findOneBy(['googleId' => $googleUser->getId()]);

                if ($existingUser) {
                    return $existingUser;
                }

                if ($googleUser->toArray()['email_verified'] !== true) {
                    throw new EmailNotVerifiedException();
                }

                //Verify Email to secure
                $user = $this->userRepository->findOneBy(['email' => $googleUser->getEmail()]);

                if ($user) {
                    $user->setGoogleId($googleUser->getId());
                    $this->em->flush();
                    return $user;
                }

                // Create user if not found
                $user = (new User())
                    ->setGoogleId($googleUser->getId())
                    ->setEmail($googleUser->getEmail())
                    ->setRoles(['ROLE_USER']);
                $this->em->persist($user);
                $this->em->flush();
                return $user;
            })
        );
    }
}
