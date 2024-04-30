<?php

namespace App\Security;

use App\Entity\User;
use App\Security\Exception\EmailNotVerifiedException;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class GithubAuthenticator extends AbstractOAuthAuthenticator
{
    protected string $serviceName = 'github';

    public function authenticate(Request $request): Passport
    {
        /** @var GithubClient $client */
        $client = $this->getClient();

        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {

                /** @var GithubResourceOwner $githubUser */
                $githubUser = $client->fetchUserFromToken($accessToken);

                $existingUser = $this->userRepository->findOneBy(['githubId' => $githubUser->getId()]);

                if ($existingUser) {
                    return $existingUser;
                }

                //On récupère l'émail de l'utilisateur
                $response = HttpClient::create()->request(
                    'GET',
                    'https://api.github.com/user/emails',
                    [
                        'headers' => [
                            'authorization' => "token {$accessToken->getToken()}"
                        ]
                    ]
                );

                $emails = json_decode($response->getContent(), true);

                foreach ($emails as $email) {
                    if ($email['primary'] === true && $email['verified'] === true) {
                        $data = $githubUser->toArray();
                        $data['email'] = $email['email'];
                        $githubUser = new GithubResourceOwner($data);
                        break;
                    }
                }

                if ($githubUser->getEmail() === null) {
                    throw new EmailNotVerifiedException();
                }

                //Verify Email to secure
                $user = $this->userRepository->findOneBy(['email' => $githubUser->getEmail()]);

                if ($user) {
                    $user->setGithubId($githubUser->getId());
                    $this->em->flush();
                    return $user;
                }

                // Create user if not found
                $user = (new User())
                    ->setGithubId($githubUser->getId())
                    ->setEmail($githubUser->getEmail())
                    ->setRoles(['ROLE_USER']);
                $this->em->persist($user);
                $this->em->flush();
                return $user;
            })
        );
    }
}