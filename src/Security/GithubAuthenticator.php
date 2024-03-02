<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Security\Exception\EmailNotVerifiedException;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class GithubAuthenticator extends OAuth2Authenticator
{
    use TargetPathTrait;

    public function __construct(
        private readonly ClientRegistry $clientRegistry,
        private readonly UserRepository $userRepository,
        private readonly EntityManagerInterface $em,
        private readonly RouterInterface $router
    )
    {
    }

    public function supports(Request $request): bool
    {
        // continue ONLY if the current ROUTE matches the check ROUTE
        return $request->attributes->get('_route') === 'oauth_check' && $request->get('service') === "github";
    }

    public function authenticate(Request $request): Passport
    {
        /** @var GithubClient $client */
        $client = $this->clientRegistry->getClient('github');

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

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $targetPath = $this->getTargetPath($request->getSession(), $firewallName);

        if ($targetPath) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse('/');
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($request->hasSession()) {
            $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->router->generate('app_login'));
    }
}